/* nuki_app.h - top-level orchestration: scan for the Nuki lock, connect,
 * discover the Pairing and Keyturner services, and expose blocking
 * pair/get-state/lock-action operations for nuki_shell.c to call into.
 */
#ifndef NUKI_APP_H_
#define NUKI_APP_H_

#include <stdbool.h>
#include "nuki_protocol.h"

/* Call once at boot, after bt_enable() and settings_load(). Starts
 * scanning for the lock (by stored address if already paired, otherwise by
 * the Keyturner Service UUID) and connects/discovers automatically.
 */
int nuki_app_init(void);

bool nuki_app_is_connected(void);
bool nuki_app_is_ready(void); /* connected AND both services discovered */
bool nuki_app_is_paired(void);

/* Runs the pairing handshake (lock must be in pairing mode - button held
 * 5s). Blocks until it completes, fails, or times out. Persists the result
 * on success.
 */
int nuki_app_pair(void);

int nuki_app_get_state(struct nuki_keyturner_state *out);
int nuki_app_lock_action(uint8_t action);

/* Returns the most recent state captured by the background poller (roughly
 * every 15 min, see nuki_app.c) without touching BLE - use this for a fast
 * status query (e.g. from the Loxone UART protocol) instead of
 * nuki_app_get_state(), which always does a live BLE round trip. *age_sec
 * is set to how many seconds old the returned snapshot is. Returns
 * -ENODATA if no poll has completed successfully yet.
 */
int nuki_app_get_cached_state(struct nuki_keyturner_state *out, int32_t *age_sec);

/* Triggers lock calibration (full-range motor run to relearn the
 * mechanical end-stops - the same action the Nuki app performs during
 * initial setup). Requires the lock's Security-PIN.
 */
int nuki_app_calibrate(uint16_t security_pin);

#endif /* NUKI_APP_H_ */
