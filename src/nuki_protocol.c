#include "nuki_protocol.h"
#include "nuki_crypto.h"

#include <errno.h>
#include <string.h>
#include <zephyr/sys/byteorder.h>

const struct bt_uuid_128 nuki_pairing_service_uuid =
	BT_UUID_INIT_128(NUKI_PAIRING_SERVICE_UUID_VAL);
const struct bt_uuid_128 nuki_pairing_gdio_uuid = BT_UUID_INIT_128(NUKI_PAIRING_GDIO_UUID_VAL);
const struct bt_uuid_128 nuki_keyturner_service_uuid =
	BT_UUID_INIT_128(NUKI_KEYTURNER_SERVICE_UUID_VAL);
const struct bt_uuid_128 nuki_keyturner_usdio_uuid =
	BT_UUID_INIT_128(NUKI_KEYTURNER_USDIO_UUID_VAL);

size_t nuki_frame_build_plain(uint8_t *out, size_t out_size, uint16_t command_id,
			       const uint8_t *payload, size_t payload_len)
{
	size_t total = 2 + payload_len + 2;

	if (total > out_size) {
		return 0;
	}

	sys_put_le16(command_id, out);
	if (payload_len) {
		memcpy(out + 2, payload, payload_len);
	}
	uint16_t crc = nuki_crc16(out, 2 + payload_len);

	sys_put_le16(crc, out + 2 + payload_len);
	return total;
}

int nuki_frame_parse_plain(const uint8_t *frame, size_t frame_len, uint16_t *command_id,
			    const uint8_t **payload, size_t *payload_len)
{
	if (frame_len < 4) {
		return -EINVAL;
	}

	size_t body_len = frame_len - 2;
	uint16_t expected_crc = nuki_crc16(frame, body_len);
	uint16_t got_crc = sys_get_le16(frame + body_len);

	if (expected_crc != got_crc) {
		return -EBADMSG;
	}

	*command_id = sys_get_le16(frame);
	*payload = frame + 2;
	*payload_len = body_len - 2;
	return 0;
}

size_t nuki_frame_build_auth(uint8_t *out, size_t out_size, uint32_t auth_id, uint16_t command_id,
			     const uint8_t *payload, size_t payload_len)
{
	size_t total = 4 + 2 + payload_len + 2;

	if (total > out_size) {
		return 0;
	}

	sys_put_le32(auth_id, out);
	sys_put_le16(command_id, out + 4);
	if (payload_len) {
		memcpy(out + 6, payload, payload_len);
	}
	uint16_t crc = nuki_crc16(out, 6 + payload_len);

	sys_put_le16(crc, out + 6 + payload_len);
	return total;
}

int nuki_frame_parse_auth(const uint8_t *frame, size_t frame_len, uint32_t *auth_id,
			   uint16_t *command_id, const uint8_t **payload, size_t *payload_len)
{
	if (frame_len < 8) {
		return -EINVAL;
	}

	size_t body_len = frame_len - 2;
	uint16_t expected_crc = nuki_crc16(frame, body_len);
	uint16_t got_crc = sys_get_le16(frame + body_len);

	if (expected_crc != got_crc) {
		return -EBADMSG;
	}

	*auth_id = sys_get_le32(frame);
	*command_id = sys_get_le16(frame + 4);
	*payload = frame + 6;
	*payload_len = body_len - 6;
	return 0;
}

int nuki_keyturner_state_parse(struct nuki_keyturner_state *state, const uint8_t *payload,
				size_t len)
{
	/* Fixed prefix common to every Smart Lock generation (API section
	 * 5, "Keyturner States"): nukiState, lockState, trigger,
	 * currentTime[7], timezoneOffset, criticalBatteryState.
	 */
	if (len < 13) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	state->nuki_state = payload[0];
	state->lock_state = payload[1];
	state->trigger = payload[2];
	state->year = sys_get_le16(&payload[3]);
	state->month = payload[5];
	state->day = payload[6];
	state->hour = payload[7];
	state->minute = payload[8];
	state->second = payload[9];
	state->timezone_offset_min = (int16_t)sys_get_le16(&payload[10]);
	state->critical_battery = payload[12] & 0x01;
	state->battery_percent = (uint8_t)((payload[12] >> 2) * 2);
	state->door_sensor_state = 0xFF;

	/* Optional trailing fields (configUpdateCount, lockNgoTimer,
	 * lastLockAction, lastLockActionTrigger,
	 * lastLockActionCompletionStatus, doorSensorState, ...).
	 */
	if (len >= 19) {
		state->door_sensor_state = payload[18];
	}

	return 0;
}

const char *nuki_lock_state_to_str(uint8_t lock_state)
{
	switch (lock_state) {
	case 0x00:
		return "uncalibrated";
	case 0x01:
		return "locked";
	case 0x02:
		return "unlocking";
	case 0x03:
		return "unlocked";
	case 0x04:
		return "locking";
	case 0x05:
		return "unlatched";
	case 0x06:
		return "unlocked (lock'n'go active)";
	case 0x07:
		return "unlatching";
	case 0xFC:
		return "calibration";
	case 0xFD:
		return "boot run";
	case 0xFE:
		return "motor blocked";
	default:
		return "undefined";
	}
}

const char *nuki_door_sensor_state_to_str(uint8_t state)
{
	switch (state) {
	case 0x00:
		return "unavailable";
	case 0x01:
		return "deactivated";
	case 0x02:
		return "door closed";
	case 0x03:
		return "door opened";
	case 0x04:
		return "door state unknown";
	case 0x05:
		return "calibrating";
	case 0x10:
		return "uncalibrated";
	case 0xF0:
		return "tampered";
	default:
		return "unknown";
	}
}
