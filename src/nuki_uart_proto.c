/* nuki_uart_proto.c - see nuki_uart_proto.h.
 *
 * Protocol (one command per line, newline-terminated, case-insensitive):
 *   STATUS                  -> OK PAIRED=0|1 CONNECTED=0|1 READY=0|1
 *   PAIR                    -> OK PAIRED                | ERR <errno> <code>
 *   STATE                   -> OK LOCK_STATE=<n> LOCK_STATE_NAME=<s> BATTERY=<pct>
 *                               CRITICAL=0|1 DOOR_STATE=<n> DOOR_STATE_NAME=<s>
 *                               YEAR=.. MONTH=.. DAY=.. HOUR=.. MIN=.. SEC=.. TZ=<min>
 *                               AGE_S=<seconds>
 *                               Answered instantly from a cache kept fresh by a
 *                               background poll every ~60s (see nuki_app.c) rather
 *                               than a live BLE read; AGE_S says how stale that
 *                               snapshot is. "ERR -61 NO_DATA_YET" if no poll has
 *                               completed yet (e.g. right after boot).
 *   LOCK / UNLOCK / UNLATCH -> OK LOCKED | OK UNLOCKED | OK UNLATCHED
 *   CALIBRATE <pin>         -> OK CALIBRATED
 * Errors: "ERR <errno> <STABLE_CODE>", e.g. "ERR -2 NOT_PAIRED".
 */
#include "nuki_uart_proto.h"
#include "nuki_app.h"
#include "nuki_protocol.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(nuki_uart_proto, LOG_LEVEL_INF);

#define NUKI_UART_NODE DT_NODELABEL(uart1)
#define LINE_MAX 64
#define REPLY_MAX 200
#define THREAD_STACK_SIZE 2048
#define THREAD_PRIORITY 7

static const struct device *const uart_dev = DEVICE_DT_GET(NUKI_UART_NODE);

K_MSGQ_DEFINE(nuki_uart_msgq, LINE_MAX, 4, 4);

/* Only ever touched from the UART ISR - no locking needed. */
static char rx_buf[LINE_MAX];
static size_t rx_buf_pos;

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
		if (c == '\n' || c == '\r') {
			if (rx_buf_pos > 0) {
				rx_buf[rx_buf_pos] = '\0';
				/* Full queue: message silently dropped. */
				k_msgq_put(&nuki_uart_msgq, rx_buf, K_NO_WAIT);
				rx_buf_pos = 0;
			}
		} else if (rx_buf_pos < sizeof(rx_buf) - 1) {
			rx_buf[rx_buf_pos++] = (char)c;
		}
		/* else: characters beyond the line buffer are dropped. */
	}
}

static void send_line(const char *line)
{
	for (size_t i = 0; line[i] != '\0'; i++) {
		uart_poll_out(uart_dev, line[i]);
	}
	uart_poll_out(uart_dev, '\n');
}

static const char *err_code(int err)
{
	switch (err) {
	case -ENOTCONN:
		return "NOT_CONNECTED";
	case -ENOENT:
		return "NOT_PAIRED";
	case -ENODATA:
		return "NO_DATA_YET";
	case -ETIMEDOUT:
	case -EAGAIN:
		return "TIMEOUT";
	case -EBADMSG:
		return "BADMSG";
	case -ENOTSUP:
		return "UNSUPPORTED";
	case -EINVAL:
		return "INVALID_ARGS";
	default:
		return "ERROR";
	}
}

static void reply_ok(const char *details)
{
	char line[REPLY_MAX];

	if (details && details[0] != '\0') {
		snprintf(line, sizeof(line), "OK %s", details);
	} else {
		snprintf(line, sizeof(line), "OK");
	}
	send_line(line);
}

static void reply_err(int err)
{
	char line[48];

	snprintf(line, sizeof(line), "ERR %d %s", err, err_code(err));
	send_line(line);
}

static void handle_status(void)
{
	char details[64];

	snprintf(details, sizeof(details), "PAIRED=%d CONNECTED=%d READY=%d",
		 nuki_app_is_paired() ? 1 : 0, nuki_app_is_connected() ? 1 : 0,
		 nuki_app_is_ready() ? 1 : 0);
	reply_ok(details);
}

static void handle_pair(void)
{
	int err = nuki_app_pair();

	if (err) {
		reply_err(err);
		return;
	}
	reply_ok("PAIRED");
}

static void handle_state(void)
{
	struct nuki_keyturner_state state;
	char details[REPLY_MAX - 3];
	int32_t age_sec;
	/* Served from the background poller's cache (see nuki_app_get_cached_state())
	 * instead of a live BLE read, so this answers instantly.
	 */
	int err = nuki_app_get_cached_state(&state, &age_sec);

	if (err) {
		reply_err(err);
		return;
	}

	snprintf(details, sizeof(details),
		 "LOCK_STATE=%u LOCK_STATE_NAME=%s BATTERY=%u CRITICAL=%d DOOR_STATE=%u "
		 "DOOR_STATE_NAME=%s YEAR=%u MONTH=%u DAY=%u HOUR=%u MIN=%u SEC=%u TZ=%d AGE_S=%d",
		 state.lock_state, nuki_lock_state_to_str(state.lock_state),
		 state.battery_percent, state.critical_battery ? 1 : 0, state.door_sensor_state,
		 nuki_door_sensor_state_to_str(state.door_sensor_state), state.year, state.month,
		 state.day, state.hour, state.minute, state.second, state.timezone_offset_min,
		 age_sec);
	reply_ok(details);
}

static void handle_lock_action(uint8_t action, const char *ok_word)
{
	int err = nuki_app_lock_action(action);

	if (err) {
		reply_err(err);
		return;
	}
	reply_ok(ok_word);
}

static void handle_calibrate(const char *arg)
{
	char *endptr;
	unsigned long pin;
	int err;

	if (!arg) {
		reply_err(-EINVAL);
		return;
	}

	pin = strtoul(arg, &endptr, 10);
	if (*endptr != '\0' || pin > 0xFFFF) {
		reply_err(-EINVAL);
		return;
	}

	err = nuki_app_calibrate((uint16_t)pin);
	if (err) {
		reply_err(err);
		return;
	}
	reply_ok("CALIBRATED");
}

static void dispatch_line(char *line)
{
	char *saveptr;
	char *cmd = strtok_r(line, " \t", &saveptr);
	char *arg = strtok_r(NULL, " \t", &saveptr);

	if (!cmd) {
		return;
	}

	for (char *p = cmd; *p != '\0'; p++) {
		*p = (char)toupper((unsigned char)*p);
	}

	if (strcmp(cmd, "STATUS") == 0) {
		handle_status();
	} else if (strcmp(cmd, "PAIR") == 0) {
		handle_pair();
	} else if (strcmp(cmd, "STATE") == 0) {
		handle_state();
	} else if (strcmp(cmd, "LOCK") == 0) {
		handle_lock_action(NUKI_LOCK_ACTION_LOCK, "LOCKED");
	} else if (strcmp(cmd, "UNLOCK") == 0) {
		handle_lock_action(NUKI_LOCK_ACTION_UNLOCK, "UNLOCKED");
	} else if (strcmp(cmd, "UNLATCH") == 0) {
		handle_lock_action(NUKI_LOCK_ACTION_UNLATCH, "UNLATCHED");
	} else if (strcmp(cmd, "CALIBRATE") == 0) {
		handle_calibrate(arg);
	} else {
		send_line("ERR -22 UNKNOWN_COMMAND");
	}
}

static void nuki_uart_thread_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	char line[LINE_MAX];

	while (k_msgq_get(&nuki_uart_msgq, line, K_FOREVER) == 0) {
		dispatch_line(line);
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

	LOG_INF("Loxone module UART protocol ready on uart1");
	return 0;
}
