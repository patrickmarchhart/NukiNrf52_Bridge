/* nuki_transport.h - blocking write + fragmented-indication reassembly for
 * one Nuki GATT characteristic (GDIO during pairing, or USDIO afterwards).
 *
 * The Nuki lock may split its response across several ATT indications
 * (older firmware always does this in ~20 byte chunks; newer firmware with
 * ATT MTU exchange support may use fewer, larger ones) - this layer hides
 * that by accumulating indications until the caller-specified number of
 * bytes has arrived, and only then handing back one contiguous frame.
 *
 * This project relies on ATT MTU exchange (see nuki_transport_init) to keep
 * every write within a single ATT "Write Request", rather than implementing
 * the GATT queued/long-write procedure.
 */
#ifndef NUKI_TRANSPORT_H_
#define NUKI_TRANSPORT_H_

#include <zephyr/kernel.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include "nuki_protocol.h"

struct nuki_transport {
	struct bt_conn *conn;
	uint16_t value_handle;
	struct bt_gatt_subscribe_params sub_params;
	struct bt_gatt_write_params write_params;

	struct k_mutex rx_lock;
	struct k_sem rx_sem;
	uint8_t rx_buf[NUKI_WIRE_MAX_LEN];
	size_t rx_len;

	struct k_sem write_sem;
	int write_err;
};

/* value_handle/ccc_handle come from bt_gatt_dm discovery of the GDIO or
 * USDIO characteristic. Subscribes for indications and performs an ATT MTU
 * exchange.
 */
int nuki_transport_init(struct nuki_transport *t, struct bt_conn *conn, uint16_t value_handle,
			 uint16_t ccc_handle);

void nuki_transport_release(struct nuki_transport *t);

/* Blocking write of one complete frame. */
int nuki_transport_write(struct nuki_transport *t, const uint8_t *data, size_t len);

/*
 * Reading a full response is a 3-step dance so that variable-length
 * messages (e.g. USDIO's msgLen-prefixed frames) can be read without
 * discarding bytes that arrived past the first known-size chunk:
 *
 *   nuki_transport_wait_min(t, 30, timeout);      // wait for the ADATA header
 *   nuki_transport_peek(t, header, 30);           // inspect msgLen etc.
 *   nuki_transport_wait_min(t, 30 + msg_len, tmo); // wait for the rest
 *   nuki_transport_peek(t, full, 30 + msg_len);    // get the complete frame
 *   nuki_transport_reset(t);                      // done - clear for next frame
 */

/* Blocks until at least min_len bytes have been reassembled from incoming
 * indications since the last nuki_transport_reset(). Does not consume them.
 */
int nuki_transport_wait_min(struct nuki_transport *t, size_t min_len, k_timeout_t timeout);

/* Copies out the first len bytes currently accumulated. Caller must have
 * already waited for at least len bytes via nuki_transport_wait_min().
 */
void nuki_transport_peek(struct nuki_transport *t, uint8_t *out, size_t len);

/* Clears the accumulator, e.g. once a full frame has been fully consumed. */
void nuki_transport_reset(struct nuki_transport *t);

/* Diagnostic: current number of bytes accumulated since the last reset. */
size_t nuki_transport_len(struct nuki_transport *t);

#endif /* NUKI_TRANSPORT_H_ */
