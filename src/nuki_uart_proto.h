/* nuki_uart_proto.h - binary frame protocol for an external Loxone module,
 * carried over the second UART (uart1) so it stays separate from the
 * interactive shell/log console (uart0). See
 * boards/nrf52840dk_nrf52840.overlay for the pin mapping and
 * LOXONE_UART_PROTOCOL.md for the full protocol reference.
 *
 * Wire format, all multi-byte fields little-endian:
 *
 *   Offset  Size  Field
 *   0       1     SOF     NUKI_UART_FRAME_SOF_REQ (0xA5) for a request,
 *                         NUKI_UART_FRAME_SOF_RESP (0x5A) for a response -
 *                         distinguishing the two by their first byte alone
 *                         makes captured traffic (e.g. on a logic analyzer)
 *                         self-describing without tracking direction.
 *   1       1     CMD     command code, see enum nuki_uart_cmd
 *   2       1     LEN     number of PAYLOAD bytes that follow (0..NUKI_UART_MAX_PAYLOAD)
 *   3       LEN   PAYLOAD raw bytes of the request/response struct for CMD
 *
 * No checksum/CRC - this is a short, direct point-to-point wire between two
 * boards, not a noisy/shared link, so integrity checking was deliberately
 * left out to keep both ends simple.
 *
 * Request frames (Loxone -> board): CMD selects the operation, PAYLOAD is
 * the matching "nuki_uart_req_*" struct below (most commands take none).
 * Response frames (board -> Loxone): CMD echoes the command it answers,
 * PAYLOAD is the matching "nuki_uart_resp_*" struct, which always starts
 * with an int32_t `rc` (0 on success, a negative errno on failure - the
 * remaining fields are zeroed and meaningless whenever rc != 0).
 */
#ifndef NUKI_UART_PROTO_H_
#define NUKI_UART_PROTO_H_

#include <stdint.h>
#include <zephyr/toolchain.h>

#define NUKI_UART_FRAME_SOF_REQ 0xA5
#define NUKI_UART_FRAME_SOF_RESP 0x5A
#define NUKI_UART_MAX_PAYLOAD 32

enum nuki_uart_cmd {
	NUKI_UART_CMD_STATUS = 1,
	NUKI_UART_CMD_PAIR = 2,
	NUKI_UART_CMD_STATE = 3,
	NUKI_UART_CMD_LOCK = 4,
	NUKI_UART_CMD_UNLOCK = 5,
	NUKI_UART_CMD_UNLATCH = 6,
	NUKI_UART_CMD_CALIBRATE = 7,
};

/* --- request payloads (Loxone -> board) --------------------------------- */

/* STATUS/PAIR/STATE/LOCK/UNLOCK/UNLATCH take no request payload (LEN = 0). */

struct nuki_uart_req_calibrate {
	uint16_t pin;
} __packed;

/* --- response payloads (board -> Loxone) --------------------------------- */

struct nuki_uart_resp_status {
	int32_t rc;
	uint8_t paired;
	uint8_t connected;
	uint8_t ready;
} __packed;

/* Response to PAIR, LOCK, UNLOCK, UNLATCH and CALIBRATE - the result carries
 * no data beyond success/failure.
 */
struct nuki_uart_resp_simple {
	int32_t rc;
} __packed;

struct nuki_uart_resp_state {
	int32_t rc;
	uint8_t lock_state;
	uint8_t battery_percent;
	uint8_t critical_battery;
	uint8_t door_sensor_state;
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
	int16_t timezone_offset_min;
	int32_t age_sec;
} __packed;

/* Call once at boot, after nuki_app_init(). Starts the uart1 RX interrupt
 * and the frame-processing thread.
 */
int nuki_uart_proto_init(void);

#endif /* NUKI_UART_PROTO_H_ */
