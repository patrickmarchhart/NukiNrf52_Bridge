#include "nuki_command.h"
#include "nuki_crypto.h"

#include <string.h>
#include <errno.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(nuki_command, LOG_LEVEL_INF);

#define ADATA_HDR_LEN 30 /* nonce(24) + authId(4) + msgLen(2) */
#define RECV_TIMEOUT K_SECONDS(10)
#define MAX_PLAINTEXT 200

static int send_encrypted(struct nuki_transport *usdio, uint32_t auth_id,
			   const uint8_t shared_key[NUKI_KEY_LEN], uint16_t cmd,
			   const uint8_t *payload, size_t payload_len)
{
	uint8_t plain[NUKI_FRAME_MAX_LEN];
	uint8_t nonce[NUKI_NONCE_LEN];
	uint8_t wire[ADATA_HDR_LEN + NUKI_TAG_LEN + NUKI_FRAME_MAX_LEN];
	size_t plain_len;
	int err;

	plain_len = nuki_frame_build_auth(plain, sizeof(plain), auth_id, cmd, payload,
					   payload_len);
	if (!plain_len) {
		return -EINVAL;
	}

	sys_rand_get(nonce, sizeof(nonce));

	err = nuki_crypto_e1(wire + ADATA_HDR_LEN, plain, plain_len, nonce, shared_key);
	if (err) {
		return err;
	}

	memcpy(wire, nonce, NUKI_NONCE_LEN);
	sys_put_le32(auth_id, wire + 24);
	sys_put_le16(NUKI_TAG_LEN + plain_len, wire + 28);

	return nuki_transport_write(usdio, wire, ADATA_HDR_LEN + NUKI_TAG_LEN + plain_len);
}

/* Waits for one complete encrypted USDIO message, decrypts and parses it. */
static int recv_encrypted(struct nuki_transport *usdio, const uint8_t shared_key[NUKI_KEY_LEN],
			   uint16_t *cmd, uint8_t *payload_out, size_t *payload_len,
			   size_t payload_max)
{
	uint8_t header[ADATA_HDR_LEN];
	uint8_t nonce[NUKI_NONCE_LEN];
	uint8_t wire[ADATA_HDR_LEN + NUKI_TAG_LEN + MAX_PLAINTEXT];
	uint8_t plain[NUKI_TAG_LEN + MAX_PLAINTEXT];
	size_t ct_len;
	size_t total_len;
	uint32_t frame_auth_id;
	const uint8_t *payload;
	size_t got_len;
	int err;

	err = nuki_transport_wait_min(usdio, ADATA_HDR_LEN, RECV_TIMEOUT);
	if (err) {
		return err;
	}
	nuki_transport_peek(usdio, header, ADATA_HDR_LEN);

	memcpy(nonce, header, NUKI_NONCE_LEN);
	ct_len = sys_get_le16(&header[28]);
	if (ct_len < NUKI_TAG_LEN || ct_len > sizeof(wire) - ADATA_HDR_LEN) {
		LOG_ERR("implausible encrypted message length %zu", ct_len);
		nuki_transport_reset(usdio);
		return -EBADMSG;
	}
	total_len = ADATA_HDR_LEN + ct_len;

	err = nuki_transport_wait_min(usdio, total_len, RECV_TIMEOUT);
	if (err) {
		return err;
	}
	nuki_transport_peek(usdio, wire, total_len);
	nuki_transport_reset(usdio);

	size_t plain_len = ct_len - NUKI_TAG_LEN;

	err = nuki_crypto_d1(plain, wire + ADATA_HDR_LEN, plain_len, nonce, shared_key);
	if (err) {
		LOG_ERR("decrypt/authenticate failed (%d)", err);
		return err;
	}

	err = nuki_frame_parse_auth(plain, plain_len, &frame_auth_id, cmd, &payload, &got_len);
	if (err) {
		LOG_ERR("plaintext frame parse/CRC failed (%d)", err);
		return err;
	}

	if (got_len > payload_max) {
		return -ENOMEM;
	}
	memcpy(payload_out, payload, got_len);
	*payload_len = got_len;

	return 0;
}

int nuki_command_get_state(struct nuki_transport *usdio, uint32_t auth_id,
			    const uint8_t shared_key[NUKI_KEY_LEN],
			    struct nuki_keyturner_state *state)
{
	uint8_t req_payload[2];
	uint8_t payload[MAX_PLAINTEXT];
	size_t payload_len;
	uint16_t cmd;
	int err;

	sys_put_le16(NUKI_CMD_KEYTURNER_STATES, req_payload);
	err = send_encrypted(usdio, auth_id, shared_key, NUKI_CMD_REQUEST_DATA, req_payload,
			     sizeof(req_payload));
	if (err) {
		return err;
	}

	err = recv_encrypted(usdio, shared_key, &cmd, payload, &payload_len, sizeof(payload));
	if (err) {
		return err;
	}
	if (cmd != NUKI_CMD_KEYTURNER_STATES) {
		LOG_ERR("expected KeyturnerStates, got 0x%04x", cmd);
		return -EBADMSG;
	}

	return nuki_keyturner_state_parse(state, payload, payload_len);
}

/* Requests a fresh Challenge and returns its 32-byte nonce. */
static int request_challenge(struct nuki_transport *usdio, uint32_t auth_id,
			      const uint8_t shared_key[NUKI_KEY_LEN], uint8_t nonce_k[32])
{
	uint8_t req_payload[2];
	uint8_t challenge_payload[MAX_PLAINTEXT];
	size_t challenge_len;
	uint16_t cmd;
	int err;

	sys_put_le16(NUKI_CMD_CHALLENGE, req_payload);
	err = send_encrypted(usdio, auth_id, shared_key, NUKI_CMD_REQUEST_DATA, req_payload,
			     sizeof(req_payload));
	if (err) {
		return err;
	}
	err = recv_encrypted(usdio, shared_key, &cmd, challenge_payload, &challenge_len,
			     sizeof(challenge_payload));
	if (err) {
		return err;
	}
	if (cmd != NUKI_CMD_CHALLENGE || challenge_len != 32) {
		LOG_ERR("expected Challenge(32), got 0x%04x/%zu", cmd, challenge_len);
		return -EBADMSG;
	}
	memcpy(nonce_k, challenge_payload, 32);
	return 0;
}

/* Drains responses (Status ACCEPTED, KeyturnerStates updates...) until a
 * terminal Status COMPLETE or an ErrorReport arrives.
 */
static int drain_until_complete(struct nuki_transport *usdio,
				 const uint8_t shared_key[NUKI_KEY_LEN])
{
	for (int i = 0; i < 10; i++) {
		uint8_t payload[MAX_PLAINTEXT];
		size_t payload_len;
		uint16_t cmd;
		int err = recv_encrypted(usdio, shared_key, &cmd, payload, &payload_len,
					  sizeof(payload));

		if (err) {
			return err;
		}

		if (cmd == NUKI_CMD_ERROR_REPORT) {
			LOG_ERR("lock returned ErrorReport (code %d)", (int8_t)payload[0]);
			return -EIO;
		}

		if (cmd == NUKI_CMD_STATUS) {
			if (payload_len != 1) {
				return -EBADMSG;
			}
			if (payload[0] == NUKI_STATUS_COMPLETE) {
				return 0;
			}
			/* ACCEPTED: keep waiting for COMPLETE. */
			continue;
		}

		/* KeyturnerStates or other intermediate updates: ignore and
		 * keep waiting for the terminal Status.
		 */
	}

	LOG_ERR("gave up waiting for Status COMPLETE");
	return -ETIMEDOUT;
}

int nuki_command_lock_action(struct nuki_transport *usdio, uint32_t auth_id, uint32_t app_id,
			      const uint8_t shared_key[NUKI_KEY_LEN], uint8_t action)
{
	uint8_t nonce_k[32];
	uint8_t action_payload[1 + 4 + 1 + 32];
	int err;

	err = request_challenge(usdio, auth_id, shared_key, nonce_k);
	if (err) {
		return err;
	}

	/* LockAction: action | appId | flags(0) | nonceK  (no NameSuffix) */
	action_payload[0] = action;
	sys_put_le32(app_id, &action_payload[1]);
	action_payload[5] = 0; /* flags: no auto-unlock, no force */
	memcpy(&action_payload[6], nonce_k, 32);

	err = send_encrypted(usdio, auth_id, shared_key, NUKI_CMD_LOCK_ACTION, action_payload,
			     sizeof(action_payload));
	if (err) {
		return err;
	}

	return drain_until_complete(usdio, shared_key);
}

int nuki_command_calibrate(struct nuki_transport *usdio, uint32_t auth_id,
			    const uint8_t shared_key[NUKI_KEY_LEN], uint16_t security_pin)
{
	uint8_t nonce_k[32];
	uint8_t payload[32 + 2];
	int err;

	err = request_challenge(usdio, auth_id, shared_key, nonce_k);
	if (err) {
		return err;
	}

	/* Request Calibration: nonceK | Security-PIN (uint16, Gen 1-4). */
	memcpy(payload, nonce_k, 32);
	sys_put_le16(security_pin, &payload[32]);

	err = send_encrypted(usdio, auth_id, shared_key, NUKI_CMD_REQUEST_CALIBRATION, payload,
			     sizeof(payload));
	if (err) {
		return err;
	}

	return drain_until_complete(usdio, shared_key);
}
