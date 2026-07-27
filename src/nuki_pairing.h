/* nuki_pairing.h - "Authorize App" handshake (Smart Lock 1st-4th Generation),
 * per "Nuki Smart Lock API V2.3.0", section 9. Runs entirely over the
 * unencrypted GDIO characteristic of the Pairing Service.
 */
#ifndef NUKI_PAIRING_H_
#define NUKI_PAIRING_H_

#include "nuki_transport.h"
#include "nuki_storage.h"

/* Blocks until pairing completes, fails, or times out (the lock must be in
 * pairing mode - button held 5s - before/while this runs). On success,
 * out->auth_id, out->shared_key and out->lock_uuid are filled in; the
 * caller fills out->addr from the active connection.
 *
 * Returns 0 on success, -ETIMEDOUT / -EBADMSG / -EIO on failure.
 */
int nuki_pairing_run(struct nuki_transport *gdio, struct nuki_pairing_data *out);

#endif /* NUKI_PAIRING_H_ */
