/* nuki_command.h - encrypted Keyturner commands (state read, lock/unlock/
 * unlatch) over the USDIO characteristic, once a pairing exists.
 */
#ifndef NUKI_COMMAND_H_
#define NUKI_COMMAND_H_

#include "nuki_transport.h"
#include "nuki_protocol.h"
#include "nuki_crypto.h"

/* Reads the current Keyturner State (lock state, battery, door sensor...). */
int nuki_command_get_state(struct nuki_transport *usdio, uint32_t auth_id,
			    const uint8_t shared_key[NUKI_KEY_LEN],
			    struct nuki_keyturner_state *state);

/* Requests a fresh challenge and performs a lock action (see enum
 * nuki_lock_action). app_id must be the same one used during pairing.
 * Blocks until the lock reports Status COMPLETE (or an error/timeout).
 *
 * The lock conveniently pushes an intermediate KeyturnerStates update while
 * processing the action, sparing callers a separate nuki_command_get_state()
 * round trip. If state_out and got_state are both non-NULL, *got_state is
 * set to whether one was actually captured (best-effort - not guaranteed on
 * every action), and *state_out is only filled in that case. Pass NULL for
 * both if the caller doesn't need this.
 */
int nuki_command_lock_action(struct nuki_transport *usdio, uint32_t auth_id, uint32_t app_id,
			      const uint8_t shared_key[NUKI_KEY_LEN], uint8_t action,
			      struct nuki_keyturner_state *state_out, bool *got_state);

/* Requests a fresh challenge and triggers calibration: the lock rotates
 * through its full range once to relearn its mechanical end-stops (same
 * action the Nuki app performs during initial setup). Requires the lock's
 * Security-PIN (Smart Lock 1st-4th Generation: 4-digit, uint16). Blocks
 * until Status COMPLETE (or an error/timeout) - the lock may refuse with
 * an ErrorReport if the PIN is wrong or the battery is too low.
 */
int nuki_command_calibrate(struct nuki_transport *usdio, uint32_t auth_id,
			    const uint8_t shared_key[NUKI_KEY_LEN], uint16_t security_pin);

#endif /* NUKI_COMMAND_H_ */
