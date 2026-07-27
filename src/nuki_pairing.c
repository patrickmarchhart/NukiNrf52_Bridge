#include "nuki_pairing.h"
#include "nuki_protocol.h"
#include "nuki_crypto.h"

#include <string.h>
#include <errno.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(nuki_pairing, LOG_LEVEL_INF);

#define RECV_TIMEOUT K_SECONDS(15)

#define NUKI_APP_NAME "NRF52840 Central"

static int send_plain(struct nuki_transport *gdio, uint16_t cmd, const uint8_t *payload,
		       size_t payload_len)
{
	uint8_t frame[NUKI_FRAME_MAX_LEN];
	size_t len = nuki_frame_build_plain(frame, sizeof(frame), cmd, payload, payload_len);

	if (!len) {
		return -EINVAL;
	}
	return nuki_transport_write(gdio, frame, len);
}

/* Waits for a plain frame whose payload is exactly payload_len bytes,
 * verifies command id + CRC, and copies the payload out.
 *
 * The expected total length is only known once we see which command the
 * lock actually replied with: if it rejects our previous message, it may
 * send a short ErrorReport/Status instead of the awaited command, and
 * blindly waiting for the originally-expected (longer) length would just
 * hang until RECV_TIMEOUT with no diagnostic. So this peeks the command id
 * first and dispatches to that command's real length.
 */
static int recv_plain(struct nuki_transport *gdio, uint16_t expect_cmd, uint8_t *payload_out,
		       size_t payload_len)
{
	uint8_t frame[NUKI_FRAME_MAX_LEN];
	uint8_t hdr[2];
	uint16_t cmd;
	const uint8_t *payload;
	size_t got_len;
	size_t frame_len;
	int err;

	err = nuki_transport_wait_min(gdio, 2, RECV_TIMEOUT);
	if (err) {
		LOG_ERR("timeout waiting for command 0x%04x (no response at all)", expect_cmd);
		return err;
	}
	nuki_transport_peek(gdio, hdr, sizeof(hdr));
	cmd = sys_get_le16(hdr);

	if (cmd == NUKI_CMD_ERROR_REPORT) {
		frame_len = 2 + 3 + 2; /* errorCode(1) + rejected cmdId(2) */
	} else if (cmd == NUKI_CMD_STATUS) {
		frame_len = 2 + 1 + 2;
	} else {
		frame_len = 2 + payload_len + 2; /* assume it's the expected command */
	}

	err = nuki_transport_wait_min(gdio, frame_len, RECV_TIMEOUT);
	if (err) {
		size_t got = nuki_transport_len(gdio);
		uint8_t partial[NUKI_FRAME_MAX_LEN];

		if (got > sizeof(partial)) {
			got = sizeof(partial);
		}
		nuki_transport_peek(gdio, partial, got);
		LOG_ERR("timeout waiting for command 0x%04x (saw start of 0x%04x, wanted %zu "
			"bytes, only got %zu)",
			expect_cmd, cmd, frame_len, got);
		LOG_HEXDUMP_ERR(partial, got, "partial data received:");
		return err;
	}
	nuki_transport_peek(gdio, frame, frame_len);
	nuki_transport_reset(gdio);

	err = nuki_frame_parse_plain(frame, frame_len, &cmd, &payload, &got_len);
	if (err) {
		LOG_ERR("frame parse/CRC failed (%d)", err);
		return err;
	}

	if (cmd == NUKI_CMD_ERROR_REPORT && got_len == 3) {
		LOG_ERR("lock rejected the previous message: error code %d for command 0x%04x",
			(int8_t)payload[0], sys_get_le16(&payload[1]));
		return -EIO;
	}

	if (cmd == NUKI_CMD_STATUS && got_len == 1 && expect_cmd != NUKI_CMD_STATUS) {
		LOG_ERR("lock sent Status 0x%02x instead of command 0x%04x", payload[0],
			expect_cmd);
		return -EBADMSG;
	}

	if (cmd != expect_cmd || got_len != payload_len) {
		LOG_ERR("unexpected response: cmd=0x%04x len=%zu (expected 0x%04x/%zu)", cmd,
			got_len, expect_cmd, payload_len);
		return -EBADMSG;
	}

	memcpy(payload_out, payload, payload_len);
	return 0;
}

int nuki_pairing_run(struct nuki_transport *gdio, struct nuki_pairing_data *out)
{
	uint8_t sl_pub[NUKI_KEY_LEN];
	uint8_t cl_pub[NUKI_KEY_LEN], cl_priv[NUKI_KEY_LEN];
	uint8_t dh_result[NUKI_KEY_LEN], shared_key[NUKI_KEY_LEN];
	uint8_t challenge[32];
	uint8_t authenticator[32], expected_authenticator[32];
	uint8_t hmac_input[128];
	uint8_t req_payload[2];
	uint32_t app_id;
	uint8_t name[NUKI_NAME_LEN] = {0};
	uint8_t nonce_abf[32];
	uint8_t auth_data_payload[32 + 1 + 4 + NUKI_NAME_LEN + 32];
	/* authenticator(32) + authId(4) + uuid(16) + nonceK(32) - confirmed on
	 * real hardware (CRC-validated): no trailing Nonce n A/B/F field is
	 * actually transmitted here, despite it being listed in the spec's
	 * field table (it's authenticator-input-only, not on the wire).
	 */
	uint8_t auth_id_payload[32 + 4 + 16 + 32];
	/* authenticator(32) + authId(4) only - nonceK is used in the HMAC
	 * (see below) but, like the two prior messages, is not itself
	 * transmitted here.
	 */
	uint8_t confirm_payload[32 + 4];
	uint32_t auth_id;
	uint8_t lock_uuid[16];
	uint8_t nonce_k2[32];
	uint8_t status_payload[1];
	int err;

	err = nuki_crypto_init();
	if (err) {
		return err;
	}

	/* 1-4: request the lock's public key, receive it. */
	sys_put_le16(NUKI_CMD_PUBLIC_KEY, req_payload);
	err = send_plain(gdio, NUKI_CMD_REQUEST_DATA, req_payload, sizeof(req_payload));
	if (err) {
		return err;
	}
	err = recv_plain(gdio, NUKI_CMD_PUBLIC_KEY, sl_pub, sizeof(sl_pub));
	if (err) {
		return err;
	}

	/* 5-6: generate our own keypair, send our public key. */
	err = nuki_crypto_keypair(cl_pub, cl_priv);
	if (err) {
		return err;
	}
	err = send_plain(gdio, NUKI_CMD_PUBLIC_KEY, cl_pub, sizeof(cl_pub));
	if (err) {
		return err;
	}

	/* 7-8: derive the long-term shared secret. */
	err = nuki_crypto_dh1(dh_result, cl_priv, sl_pub);
	if (err) {
		return err;
	}
	nuki_crypto_kdf1(shared_key, dh_result);

	/* 9-13: first challenge -> authenticator = h1(s, cl_pub || sl_pub || nonce). */
	err = recv_plain(gdio, NUKI_CMD_CHALLENGE, challenge, sizeof(challenge));
	if (err) {
		return err;
	}
	memcpy(hmac_input, cl_pub, 32);
	memcpy(hmac_input + 32, sl_pub, 32);
	memcpy(hmac_input + 64, challenge, 32);
	err = nuki_crypto_h1(authenticator, shared_key, hmac_input, 96);
	if (err) {
		return err;
	}
	err = send_plain(gdio, NUKI_CMD_AUTH_AUTHENTICATOR, authenticator, sizeof(authenticator));
	if (err) {
		return err;
	}

	/* 14-16: second challenge -> AuthorizationData (idType|appId|name|nonceABF). */
	err = recv_plain(gdio, NUKI_CMD_CHALLENGE, challenge, sizeof(challenge));
	if (err) {
		return err;
	}

	sys_rand_get(&app_id, sizeof(app_id));
	memcpy(name, NUKI_APP_NAME, MIN(sizeof(NUKI_APP_NAME) - 1, sizeof(name)));
	sys_rand_get(nonce_abf, sizeof(nonce_abf));

	{
		uint8_t body[1 + 4 + NUKI_NAME_LEN + 32];

		body[0] = NUKI_ID_TYPE_APP;
		sys_put_le32(app_id, &body[1]);
		memcpy(&body[5], name, NUKI_NAME_LEN);
		memcpy(&body[5 + NUKI_NAME_LEN], nonce_abf, 32);

		memcpy(hmac_input, body, sizeof(body));
		memcpy(hmac_input + sizeof(body), challenge, 32);
		err = nuki_crypto_h1(authenticator, shared_key, hmac_input, sizeof(body) + 32);
		if (err) {
			return err;
		}

		memcpy(auth_data_payload, authenticator, 32);
		memcpy(auth_data_payload + 32, body, sizeof(body));
	}

	err = send_plain(gdio, NUKI_CMD_AUTH_DATA, auth_data_payload, sizeof(auth_data_payload));
	if (err) {
		return err;
	}

	/* 17-20: AuthorizationId: authenticator|authId|uuid|nonceK.
	 * The authenticator covers this message's own fields (authId, uuid,
	 * nonceK) plus OUR nonceABF from the AuthorizationData step - the
	 * same mutual pattern used everywhere else in this handshake (each
	 * side's authenticator = h1(s, own fields || other side's most
	 * recent nonce contribution)).
	 */
	err = recv_plain(gdio, NUKI_CMD_AUTH_ID, auth_id_payload, sizeof(auth_id_payload));
	if (err) {
		return err;
	}

	memcpy(hmac_input, auth_id_payload + 32, sizeof(auth_id_payload) - 32);
	memcpy(hmac_input + (sizeof(auth_id_payload) - 32), nonce_abf, 32);
	err = nuki_crypto_h1(expected_authenticator, shared_key, hmac_input,
			      (sizeof(auth_id_payload) - 32) + 32);
	if (err) {
		return err;
	}
	if (memcmp(expected_authenticator, auth_id_payload, 32) != 0) {
		LOG_ERR("AuthorizationId authenticator mismatch");
		return -EBADMSG;
	}

	auth_id = sys_get_le32(&auth_id_payload[32]);
	memcpy(lock_uuid, &auth_id_payload[36], 16);
	memcpy(nonce_k2, &auth_id_payload[52], 32);

	/* 21: AuthorizationIdConfirmation: wire = authenticator|authId.
	 * HMAC input = authId|nonceK (nonceK not itself transmitted).
	 */
	{
		uint8_t hmac_body[4 + 32];

		sys_put_le32(auth_id, hmac_body);
		memcpy(hmac_body + 4, nonce_k2, 32);

		err = nuki_crypto_h1(authenticator, shared_key, hmac_body, sizeof(hmac_body));
		if (err) {
			return err;
		}

		memcpy(confirm_payload, authenticator, 32);
		sys_put_le32(auth_id, confirm_payload + 32);
	}

	err = send_plain(gdio, NUKI_CMD_AUTH_ID_CONFIRMATION, confirm_payload,
			  sizeof(confirm_payload));
	if (err) {
		return err;
	}

	/* 22: final Status COMPLETE. */
	err = recv_plain(gdio, NUKI_CMD_STATUS, status_payload, sizeof(status_payload));
	if (err) {
		return err;
	}
	if (status_payload[0] != NUKI_STATUS_COMPLETE) {
		LOG_ERR("pairing finished with status 0x%02x, expected COMPLETE",
			status_payload[0]);
		return -EBADMSG;
	}

	memset(out, 0, sizeof(*out));
	out->auth_id = auth_id;
	out->app_id = app_id;
	memcpy(out->shared_key, shared_key, NUKI_KEY_LEN);
	memcpy(out->lock_uuid, lock_uuid, sizeof(lock_uuid));

	LOG_INF("pairing complete, authorization id %u", auth_id);
	return 0;
}
