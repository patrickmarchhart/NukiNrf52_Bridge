/* nuki_uart_proto.c - see nuki_uart_proto.h for the wire format.
 *
 * RX side: serial_cb() (UART ISR) runs a small byte-at-a-time state machine
 * that hunts for SOF, then collects CMD/LEN/PAYLOAD into a struct rx_frame;
 * once the payload is complete it's handed to nuki_uart_msgq for
 * nuki_uart_thread_fn() to dispatch. A bogus LEN drops back to hunting for
 * the next SOF instead of getting stuck waiting for payload bytes that will
 * never come.
 *
 * TX side: send_frame() builds a complete frame in a stack buffer and
 * writes it out with uart_poll_out() (replies are short and infrequent
 * enough that a second interrupt-driven TX path isn't worth it).
 */
#include "nuki_uart_proto.h"
#include "nuki_app.h"
#include "nuki_protocol.h"

#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(nuki_uart_proto, LOG_LEVEL_INF);

#define NUKI_UART_NODE DT_NODELABEL(uart1)
#define THREAD_STACK_SIZE 2048
#define THREAD_PRIORITY 7

static const struct device *const uart_dev = DEVICE_DT_GET(NUKI_UART_NODE);

/* A fully received request frame, as handed from serial_cb() to
 * nuki_uart_thread_fn() via nuki_uart_msgq.
 */
struct rx_frame {
	uint8_t cmd;
	uint8_t len;
	uint8_t payload[NUKI_UART_MAX_PAYLOAD];
};

K_MSGQ_DEFINE(nuki_uart_msgq, sizeof(struct rx_frame), 4, 4);

/* Only ever touched from the UART ISR - no locking needed. */
enum rx_state {
	RX_WAIT_SOF,
	RX_WAIT_CMD,
	RX_WAIT_LEN,
	RX_WAIT_PAYLOAD,
};
static enum rx_state rx_state = RX_WAIT_SOF;
static struct rx_frame rx_frame;
static uint8_t rx_payload_pos;

static K_THREAD_STACK_DEFINE(nuki_uart_thread_stack, THREAD_STACK_SIZE);
static struct k_thread nuki_uart_thread_data;

static void serial_cb(const struct device *dev, void *user_data)
{
	ARG_UNUSED(user_data);
	uint8_t c;

	if (!uart_irq_update(dev) || !uart_irq_rx_ready(dev)) {
		return;
	}

	while (uart_fifo_read(dev, &c, 1) == 1) {
		switch (rx_state) {
		case RX_WAIT_SOF:
			if (c == NUKI_UART_FRAME_SOF_REQ) {
				rx_state = RX_WAIT_CMD;
			}
			break;
		case RX_WAIT_CMD:
			rx_frame.cmd = c;
			rx_state = RX_WAIT_LEN;
			break;
		case RX_WAIT_LEN:
			if (c > NUKI_UART_MAX_PAYLOAD) {
				/* Bogus length - resync on the next SOF. */
				rx_state = RX_WAIT_SOF;
				break;
			}
			rx_frame.len = c;
			rx_payload_pos = 0;
			if (rx_frame.len == 0) {
				/* Full queue: frame silently dropped. */
				k_msgq_put(&nuki_uart_msgq, &rx_frame, K_NO_WAIT);
				rx_state = RX_WAIT_SOF;
			} else {
				rx_state = RX_WAIT_PAYLOAD;
			}
			break;
		case RX_WAIT_PAYLOAD:
			rx_frame.payload[rx_payload_pos++] = c;
			if (rx_payload_pos == rx_frame.len) {
				/* Full queue: frame silently dropped. */
				k_msgq_put(&nuki_uart_msgq, &rx_frame, K_NO_WAIT);
				rx_state = RX_WAIT_SOF;
			}
			break;
		}
	}
}

static void send_frame(uint8_t cmd, const void *payload, uint8_t len)
{
	uint8_t out[1 + 2 + NUKI_UART_MAX_PAYLOAD];
	size_t n = 0;

	out[n++] = NUKI_UART_FRAME_SOF_RESP;
	out[n++] = cmd;
	out[n++] = len;
	if (len) {
		memcpy(&out[n], payload, len);
		n += len;
	}

	for (size_t i = 0; i < n; i++) {
		uart_poll_out(uart_dev, out[i]);
	}
}

static void send_simple_response(uint8_t cmd, int32_t rc)
{
	struct nuki_uart_resp_simple resp = {.rc = rc};

	send_frame(cmd, &resp, sizeof(resp));
}

static void handle_status(void)
{
	struct nuki_uart_resp_status resp = {
		.rc = 0,
		.paired = nuki_app_is_paired() ? 1 : 0,
		.connected = nuki_app_is_connected() ? 1 : 0,
		.ready = nuki_app_is_ready() ? 1 : 0,
	};

	send_frame(NUKI_UART_CMD_STATUS, &resp, sizeof(resp));
}

static void handle_pair(void)
{
	int err = nuki_app_pair();

	send_simple_response(NUKI_UART_CMD_PAIR, err);
}

static void handle_state(void)
{
	struct nuki_uart_resp_state resp = {0};
	struct nuki_keyturner_state state;
	int32_t age_sec;
	/* Served from the background poller's cache (see
	 * nuki_app_get_cached_state()) instead of a live BLE read, so this
	 * answers instantly.
	 */
	int err = nuki_app_get_cached_state(&state, &age_sec);

	resp.rc = err;
	if (!err) {
		resp.lock_state = state.lock_state;
		resp.battery_percent = state.battery_percent;
		resp.critical_battery = state.critical_battery ? 1 : 0;
		resp.door_sensor_state = state.door_sensor_state;
		resp.year = state.year;
		resp.month = state.month;
		resp.day = state.day;
		resp.hour = state.hour;
		resp.minute = state.minute;
		resp.second = state.second;
		resp.timezone_offset_min = state.timezone_offset_min;
		resp.age_sec = age_sec;
	}
	send_frame(NUKI_UART_CMD_STATE, &resp, sizeof(resp));
}

static void handle_lock_action(uint8_t action, uint8_t cmd)
{
	int err = nuki_app_lock_action(action);

	send_simple_response(cmd, err);
}

static void handle_calibrate(const struct rx_frame *frame)
{
	struct nuki_uart_req_calibrate req;
	int err;

	if (frame->len != sizeof(req)) {
		send_simple_response(NUKI_UART_CMD_CALIBRATE, -EINVAL);
		return;
	}
	memcpy(&req, frame->payload, sizeof(req));

	err = nuki_app_calibrate(req.pin);
	send_simple_response(NUKI_UART_CMD_CALIBRATE, err);
}

static void dispatch_frame(const struct rx_frame *frame)
{
	switch (frame->cmd) {
	case NUKI_UART_CMD_STATUS:
		handle_status();
		break;
	case NUKI_UART_CMD_PAIR:
		handle_pair();
		break;
	case NUKI_UART_CMD_STATE:
		handle_state();
		break;
	case NUKI_UART_CMD_LOCK:
		handle_lock_action(NUKI_LOCK_ACTION_LOCK, NUKI_UART_CMD_LOCK);
		break;
	case NUKI_UART_CMD_UNLOCK:
		handle_lock_action(NUKI_LOCK_ACTION_UNLOCK, NUKI_UART_CMD_UNLOCK);
		break;
	case NUKI_UART_CMD_UNLATCH:
		handle_lock_action(NUKI_LOCK_ACTION_UNLATCH, NUKI_UART_CMD_UNLATCH);
		break;
	case NUKI_UART_CMD_CALIBRATE:
		handle_calibrate(frame);
		break;
	default:
		send_simple_response(frame->cmd, -EINVAL);
		break;
	}
}

static void nuki_uart_thread_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	struct rx_frame frame;

	while (k_msgq_get(&nuki_uart_msgq, &frame, K_FOREVER) == 0) {
		dispatch_frame(&frame);
	}
}

int nuki_uart_proto_init(void)
{
	int err;

	if (!device_is_ready(uart_dev)) {
		LOG_ERR("uart1 device not ready (enabled in the board overlay?)");
		return -ENODEV;
	}

	err = uart_irq_callback_user_data_set(uart_dev, serial_cb, NULL);
	if (err) {
		LOG_ERR("failed to set uart1 IRQ callback (%d)", err);
		return err;
	}
	uart_irq_rx_enable(uart_dev);

	k_thread_create(&nuki_uart_thread_data, nuki_uart_thread_stack, THREAD_STACK_SIZE,
			nuki_uart_thread_fn, NULL, NULL, NULL, K_PRIO_COOP(THREAD_PRIORITY), 0,
			K_NO_WAIT);
	k_thread_name_set(&nuki_uart_thread_data, "nuki_uart_proto");

	LOG_INF("Loxone module UART frame protocol ready on uart1");
	return 0;
}
