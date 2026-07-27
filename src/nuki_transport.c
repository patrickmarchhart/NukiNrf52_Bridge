#include "nuki_transport.h"

#include <errno.h>
#include <string.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(nuki_transport, LOG_LEVEL_INF);

static uint8_t notify_cb(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
			  const void *data, uint16_t length)
{
	struct nuki_transport *t = CONTAINER_OF(params, struct nuki_transport, sub_params);

	if (!data) {
		LOG_WRN("subscription removed (unsubscribed/disconnected)");
		return BT_GATT_ITER_STOP;
	}

	k_mutex_lock(&t->rx_lock, K_FOREVER);
	size_t space = sizeof(t->rx_buf) - t->rx_len;
	size_t copy = MIN(space, length);

	memcpy(&t->rx_buf[t->rx_len], data, copy);
	t->rx_len += copy;
	size_t total_now = t->rx_len;

	k_mutex_unlock(&t->rx_lock);

	LOG_INF("indication: +%u bytes (total now %zu)", length, total_now);

	k_sem_give(&t->rx_sem);

	return BT_GATT_ITER_CONTINUE;
}

static void write_cb(struct bt_conn *conn, uint8_t err, struct bt_gatt_write_params *params)
{
	struct nuki_transport *t = CONTAINER_OF(params, struct nuki_transport, write_params);

	t->write_err = err;
	k_sem_give(&t->write_sem);
}

static void exchange_cb(struct bt_conn *conn, uint8_t err, struct bt_gatt_exchange_params *params)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(params);
	if (err) {
		/* Not fatal: falls back to the default 23-byte ATT_MTU. Every
		 * frame this project sends/receives must then be small enough
		 * to fit, which the caller is responsible for ensuring.
		 */
	}
}

int nuki_transport_init(struct nuki_transport *t, struct bt_conn *conn, uint16_t value_handle,
			 uint16_t ccc_handle)
{
	static struct bt_gatt_exchange_params exchange_params;
	int err;

	memset(t, 0, sizeof(*t));
	t->conn = bt_conn_ref(conn);
	t->value_handle = value_handle;

	k_mutex_init(&t->rx_lock);
	k_sem_init(&t->rx_sem, 0, K_SEM_MAX_LIMIT);
	k_sem_init(&t->write_sem, 0, 1);

	t->sub_params.notify = notify_cb;
	t->sub_params.value_handle = value_handle;
	t->sub_params.ccc_handle = ccc_handle;
	t->sub_params.value = BT_GATT_CCC_INDICATE;

	err = bt_gatt_subscribe(conn, &t->sub_params);
	if (err) {
		bt_conn_unref(t->conn);
		return err;
	}

	exchange_params.func = exchange_cb;
	(void)bt_gatt_exchange_mtu(conn, &exchange_params);

	return 0;
}

void nuki_transport_release(struct nuki_transport *t)
{
	if (t->conn) {
		bt_gatt_unsubscribe(t->conn, &t->sub_params);
		bt_conn_unref(t->conn);
		t->conn = NULL;
	}
}

int nuki_transport_write(struct nuki_transport *t, const uint8_t *data, size_t len)
{
	int err;

	t->write_params.func = write_cb;
	t->write_params.handle = t->value_handle;
	t->write_params.offset = 0;
	t->write_params.data = data;
	t->write_params.length = len;

	k_sem_reset(&t->write_sem);

	err = bt_gatt_write(t->conn, &t->write_params);
	if (err) {
		return err;
	}

	err = k_sem_take(&t->write_sem, K_SECONDS(5));
	if (err) {
		return -ETIMEDOUT;
	}

	return t->write_err ? -EIO : 0;
}

int nuki_transport_wait_min(struct nuki_transport *t, size_t min_len, k_timeout_t timeout)
{
	__ASSERT_NO_MSG(min_len <= sizeof(t->rx_buf));

	k_timepoint_t end = sys_timepoint_calc(timeout);

	while (true) {
		k_mutex_lock(&t->rx_lock, K_FOREVER);
		bool done = (t->rx_len >= min_len);
		k_mutex_unlock(&t->rx_lock);

		if (done) {
			return 0;
		}

		k_timeout_t remaining = sys_timepoint_timeout(end);

		if (K_TIMEOUT_EQ(remaining, K_NO_WAIT)) {
			return -EAGAIN;
		}
		k_sem_take(&t->rx_sem, remaining);
	}
}

void nuki_transport_peek(struct nuki_transport *t, uint8_t *out, size_t len)
{
	k_mutex_lock(&t->rx_lock, K_FOREVER);
	__ASSERT_NO_MSG(len <= t->rx_len);
	memcpy(out, t->rx_buf, len);
	k_mutex_unlock(&t->rx_lock);
}

void nuki_transport_reset(struct nuki_transport *t)
{
	k_mutex_lock(&t->rx_lock, K_FOREVER);
	t->rx_len = 0;
	k_mutex_unlock(&t->rx_lock);
	k_sem_reset(&t->rx_sem);
}

size_t nuki_transport_len(struct nuki_transport *t)
{
	k_mutex_lock(&t->rx_lock, K_FOREVER);
	size_t len = t->rx_len;

	k_mutex_unlock(&t->rx_lock);
	return len;
}
