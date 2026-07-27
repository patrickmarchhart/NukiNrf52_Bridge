/* nuki_protocol.h - GATT UUIDs, command IDs and wire-frame (de)serialization
 * for the Nuki Smart Lock BLE API (Smart Lock 1st-4th Generation), per the
 * official "Nuki Smart Lock API V2.3.0" specification, sections 2, 3 and 5.
 */
#ifndef NUKI_PROTOCOL_H_
#define NUKI_PROTOCOL_H_

#include <stdint.h>
#include <stddef.h>
#include <zephyr/bluetooth/uuid.h>

/* Keyturner Pairing Service (Smart Lock 1st-4th Generation).
 * GDIO characteristic is always unencrypted.
 */
#define NUKI_PAIRING_SERVICE_UUID_VAL                                                             \
	BT_UUID_128_ENCODE(0xa92ee100, 0x5501, 0x11e4, 0x916c, 0x0800200c9a66)
#define NUKI_PAIRING_GDIO_UUID_VAL                                                                \
	BT_UUID_128_ENCODE(0xa92ee101, 0x5501, 0x11e4, 0x916c, 0x0800200c9a66)

/* Keyturner Service. USDIO is always encrypted with the paired shared key. */
#define NUKI_KEYTURNER_SERVICE_UUID_VAL                                                           \
	BT_UUID_128_ENCODE(0xa92ee200, 0x5501, 0x11e4, 0x916c, 0x0800200c9a66)
#define NUKI_KEYTURNER_USDIO_UUID_VAL                                                             \
	BT_UUID_128_ENCODE(0xa92ee202, 0x5501, 0x11e4, 0x916c, 0x0800200c9a66)

extern const struct bt_uuid_128 nuki_pairing_service_uuid;
extern const struct bt_uuid_128 nuki_pairing_gdio_uuid;
extern const struct bt_uuid_128 nuki_keyturner_service_uuid;
extern const struct bt_uuid_128 nuki_keyturner_usdio_uuid;

/* Command identifiers (section 5). Only the subset needed for pairing,
 * lock/unlock/unlatch and state/battery reporting is used by this project;
 * the rest of the official list is kept for reference and future use.
 */
enum nuki_command_id {
	NUKI_CMD_REQUEST_DATA = 0x0001,
	NUKI_CMD_PUBLIC_KEY = 0x0003,
	NUKI_CMD_CHALLENGE = 0x0004,
	NUKI_CMD_AUTH_AUTHENTICATOR = 0x0005,
	NUKI_CMD_AUTH_DATA = 0x0006,
	NUKI_CMD_AUTH_ID = 0x0007,
	NUKI_CMD_REMOVE_USER_AUTHORIZATION = 0x0008,
	NUKI_CMD_REQUEST_AUTH_ENTRIES = 0x0009,
	NUKI_CMD_AUTH_ENTRY = 0x000A,
	NUKI_CMD_KEYTURNER_STATES = 0x000C,
	NUKI_CMD_LOCK_ACTION = 0x000D,
	NUKI_CMD_STATUS = 0x000E,
	NUKI_CMD_BATTERY_REPORT = 0x0011,
	NUKI_CMD_ERROR_REPORT = 0x0012,
	NUKI_CMD_REQUEST_CONFIG = 0x0014,
	NUKI_CMD_CONFIG = 0x0015,
	NUKI_CMD_SET_SECURITY_PIN = 0x0019,
	NUKI_CMD_REQUEST_CALIBRATION = 0x001A,
	NUKI_CMD_AUTH_ID_CONFIRMATION = 0x001E,
};

enum nuki_status_code {
	NUKI_STATUS_COMPLETE = 0x00,
	NUKI_STATUS_ACCEPTED = 0x01,
};

enum nuki_lock_action {
	NUKI_LOCK_ACTION_UNLOCK = 0x01,
	NUKI_LOCK_ACTION_LOCK = 0x02,
	NUKI_LOCK_ACTION_UNLATCH = 0x03,
	NUKI_LOCK_ACTION_LOCK_N_GO = 0x04,
	NUKI_LOCK_ACTION_LOCK_N_GO_UNLATCH = 0x05,
	NUKI_LOCK_ACTION_FULL_LOCK = 0x06,
};

enum nuki_id_type {
	NUKI_ID_TYPE_APP = 0,
	NUKI_ID_TYPE_BRIDGE = 1,
	NUKI_ID_TYPE_FOB = 2,
	NUKI_ID_TYPE_KEYPAD = 3,
};

#define NUKI_NAME_LEN 32

/* Largest unencrypted/plaintext frame (command_id + payload + crc, or
 * authId + command_id + payload + crc) this project ever builds or parses.
 * The largest is AuthorizationData: cmdId(2) + authenticator(32) + idType(1)
 * + appId(4) + name(32) + nonceABF(32) + nonceK(32) + crc(2) = 137 bytes.
 */
#define NUKI_FRAME_MAX_LEN 160

/* Largest full USDIO wire message this project ever receives:
 * nonce(24) + authId(4) + msgLen(2) + tag(16) + ciphertext(<=200).
 * Sizes nuki_transport's reassembly buffer - must cover both GDIO pairing
 * frames (well under 128 bytes) and USDIO encrypted frames.
 */
#define NUKI_WIRE_MAX_LEN 256

/*
 * Build the unencrypted GDIO wire frame used during pairing:
 *   command_id(2, LE) | payload(payload_len) | crc16(2, LE)
 * Returns the number of bytes written to out, or 0 if out_size is too small.
 */
size_t nuki_frame_build_plain(uint8_t *out, size_t out_size, uint16_t command_id,
			       const uint8_t *payload, size_t payload_len);

/*
 * Parse and CRC-validate a plain GDIO frame. On success, *command_id is set
 * and *payload (together with *payload_len) points into the input buffer.
 * Returns 0 on success, -EINVAL if too short, -EBADMSG on CRC mismatch.
 */
int nuki_frame_parse_plain(const uint8_t *frame, size_t frame_len, uint16_t *command_id,
			    const uint8_t **payload, size_t *payload_len);

/*
 * Build the plaintext PDATA that gets encrypted (nuki_crypto_e1) for USDIO:
 *   authId(4, LE) | command_id(2, LE) | payload(payload_len) | crc16(2, LE)
 */
size_t nuki_frame_build_auth(uint8_t *out, size_t out_size, uint32_t auth_id, uint16_t command_id,
			     const uint8_t *payload, size_t payload_len);

/* Parse a decrypted PDATA frame (authId | command_id | payload | crc). */
int nuki_frame_parse_auth(const uint8_t *frame, size_t frame_len, uint32_t *auth_id,
			   uint16_t *command_id, const uint8_t **payload, size_t *payload_len);

struct nuki_keyturner_state {
	uint8_t nuki_state;
	uint8_t lock_state;
	uint8_t trigger;
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
	int16_t timezone_offset_min;
	bool critical_battery;
	uint8_t battery_percent; /* 0 if not present in this payload */
	uint8_t door_sensor_state; /* 0xFF (Unknown) if not present */
};

/* Parses the fixed-size prefix common to every Smart Lock generation
 * (nukiState, lockState, trigger, currentTime, timezoneOffset,
 * criticalBatteryState); newer/optional trailing fields are decoded
 * opportunistically if the payload is long enough.
 */
int nuki_keyturner_state_parse(struct nuki_keyturner_state *state, const uint8_t *payload,
				size_t len);

const char *nuki_lock_state_to_str(uint8_t lock_state);
const char *nuki_door_sensor_state_to_str(uint8_t state);

#endif /* NUKI_PROTOCOL_H_ */
