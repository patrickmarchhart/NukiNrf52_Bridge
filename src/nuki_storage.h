/* nuki_storage.h - persists the pairing result (authorization id + shared
 * secret) across reboots via the Zephyr settings subsystem, so pairing only
 * has to be done once (button press on the lock).
 */
#ifndef NUKI_STORAGE_H_
#define NUKI_STORAGE_H_

#include <stdint.h>
#include <stdbool.h>
#include <zephyr/bluetooth/addr.h>
#include "nuki_crypto.h"

struct nuki_pairing_data {
	bt_addr_le_t addr;
	uint32_t auth_id;
	uint32_t app_id;
	uint8_t shared_key[NUKI_KEY_LEN];
	uint8_t lock_uuid[16];
};

bool nuki_storage_has_pairing(void);
const struct nuki_pairing_data *nuki_storage_get_pairing(void);

/* Persists pairing data to flash. Call once pairing completes. */
int nuki_storage_save_pairing(const struct nuki_pairing_data *data);

/* Erases any stored pairing (e.g. to force a fresh "nuki pair"). */
int nuki_storage_clear_pairing(void);

#endif /* NUKI_STORAGE_H_ */
