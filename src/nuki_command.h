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
 */
int nuki_command_lock_action(struct nuki_transport *usdio, uint32_t auth_id, uint32_t app_id,
			      const uint8_t shared_key[NUKI_KEY_LEN], uint8_t action);

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
