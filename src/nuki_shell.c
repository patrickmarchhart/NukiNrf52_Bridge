/* nuki_shell.c - interactive "nuki" shell commands, since this project has
 * no phone app UI: nuki pair | lock | unlock | unlatch | state.
 */
#include "nuki_app.h"
#include "nuki_protocol.h"

#include <zephyr/shell/shell.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static const char *err_to_str(int err)
{
	switch (err) {
	case -ENOTCONN:
		return "not connected/discovered yet";
	case -ENOENT:
		return "not paired yet - run 'nuki pair' first";
	case -ETIMEDOUT:
	case -EAGAIN:
		return "timed out";
	case -EBADMSG:
		return "authentication/CRC check failed";
	case -ENOTSUP:
		return "lock did not offer its Pairing Service on this connection";
	default:
		return "error";
	}
}

static int cmd_nuki_pair(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	shell_print(sh, "pairing - make sure the lock's button is held for 5s (pairing mode)...");

	int err = nuki_app_pair();

	if (err) {
		shell_error(sh, "pairing failed: %s (%d)", err_to_str(err), err);
		return err;
	}

	shell_print(sh, "paired successfully");
	return 0;
}

static int cmd_nuki_state(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	struct nuki_keyturner_state state;
	int err = nuki_app_get_state(&state);

	if (err) {
		shell_error(sh, "failed to read state: %s (%d)", err_to_str(err), err);
		return err;
	}

	shell_print(sh, "lock state:      %s (0x%02x)", nuki_lock_state_to_str(state.lock_state),
		    state.lock_state);
	shell_print(sh, "door sensor:     %s", nuki_door_sensor_state_to_str(state.door_sensor_state));
	shell_print(sh, "battery:         %u%% %s", state.battery_percent,
		    state.critical_battery ? "(CRITICAL)" : "");
	shell_print(sh, "lock time:       %04u-%02u-%02u %02u:%02u:%02u (tz offset %d min)",
		    state.year, state.month, state.day, state.hour, state.minute, state.second,
		    state.timezone_offset_min);
	return 0;
}

static int do_lock_action(const struct shell *sh, uint8_t action, const char *name)
{
	shell_print(sh, "%s...", name);
	int err = nuki_app_lock_action(action);

	if (err) {
		shell_error(sh, "%s failed: %s (%d)", name, err_to_str(err), err);
		return err;
	}
	shell_print(sh, "%s complete", name);
	return 0;
}

static int cmd_nuki_lock(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	return do_lock_action(sh, NUKI_LOCK_ACTION_LOCK, "lock");
}

static int cmd_nuki_unlock(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	return do_lock_action(sh, NUKI_LOCK_ACTION_UNLOCK, "unlock");
}

static int cmd_nuki_unlatch(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	return do_lock_action(sh, NUKI_LOCK_ACTION_UNLATCH, "unlatch");
}

static int cmd_nuki_calibrate(const struct shell *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		shell_error(sh, "usage: nuki calibrate <security-pin>");
		return -EINVAL;
	}

	char *endptr;
	unsigned long pin = strtoul(argv[1], &endptr, 10);

	if (*endptr != '\0' || pin > 0xFFFF) {
		shell_error(sh, "invalid PIN '%s' (expected a 4-digit number, e.g. 0000-9999)",
			    argv[1]);
		return -EINVAL;
	}

	shell_warn(sh, "calibrating - the lock will rotate through its full range now...");
	int err = nuki_app_calibrate((uint16_t)pin);

	if (err) {
		shell_error(sh, "calibration failed: %s (%d)", err_to_str(err), err);
		return err;
	}
	shell_print(sh, "calibration complete");
	return 0;
}

static int cmd_nuki_status(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_print(sh, "paired: %s", nuki_app_is_paired() ? "yes" : "no");
	shell_print(sh, "connected right now: %s (ready: %s)",
		    nuki_app_is_connected() ? "yes" : "no", nuki_app_is_ready() ? "yes" : "no");
	shell_print(sh, "(each command connects on demand and disconnects afterwards, so this "
			"is usually 'no' between commands - that's expected, it leaves the "
			"lock's BLE connection free for the Nuki app)");
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	nuki_cmds,
	SHELL_CMD(status, NULL, "Show connection/pairing status", cmd_nuki_status),
	SHELL_CMD(pair, NULL, "Pair with the Nuki lock (hold its button 5s first)",
		  cmd_nuki_pair),
	SHELL_CMD(state, NULL, "Read lock state, battery and door sensor", cmd_nuki_state),
	SHELL_CMD(lock, NULL, "Lock the door", cmd_nuki_lock),
	SHELL_CMD(unlock, NULL, "Unlock the door", cmd_nuki_unlock),
	SHELL_CMD(unlatch, NULL, "Unlatch (open) the door", cmd_nuki_unlatch),
	SHELL_CMD_ARG(calibrate, NULL,
		      "Calibrate the lock (full motor range run) - requires the Security-PIN",
		      cmd_nuki_calibrate, 2, 0),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(nuki, &nuki_cmds, "Control a Nuki Smart Lock over BLE", NULL);
