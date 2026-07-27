#include "nuki_app.h"
#include "nuki_protocol.h"
#include "nuki_transport.h"
#include "nuki_pairing.h"
#include "nuki_command.h"
#include "nuki_storage.h"

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <bluetooth/gatt_dm.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(nuki_app, LOG_LEVEL_INF);

/*
 * Most Nuki Smart Locks (1st-3rd Generation) only accept a single BLE
 * connection at a time. To avoid permanently hogging that one slot (which
 * would block the official Nuki app from ever connecting directly), this
 * module connects only for the duration of one operation - pair/get-state/
 * lock-action/calibrate - and disconnects again immediately afterwards,
 * instead of staying connected in the background.
 */

#define SCAN_TIMEOUT_SEC 15
#define SCAN_TIMEOUT K_SECONDS(SCAN_TIMEOUT_SEC)
#define CONNECT_TIMEOUT K_SECONDS(20)
#define DISCONNECT_TIMEOUT K_SECONDS(5)

/* Short connection interval (15 ms, in 1.25 ms units), no peripheral
 * latency, 4 s supervision timeout - every operation here is a handful of
 * sequential GATT round trips, so a short interval matters more than power
 * use for a device that's only connected for a couple of seconds at a time.
 * Not using the BLE-minimum 7.5 ms: that proved less robust (occasional
 * "failed to establish, RF noise?" connection failures) in a busy 2.4 GHz
 * environment - 15 ms is still 2-3x faster than the usual ~30-50 ms default
 * while leaving more margin for the radio to sync reliably.
 */
#define NUKI_CONN_PARAM BT_LE_CONN_PARAM(0x000C, 0x000C, 0, 400)

static struct bt_conn *g_conn;
static struct nuki_transport g_gdio;
static struct nuki_transport g_usdio;
static bool g_gdio_ready;
static bool g_usdio_ready;
static bool g_need_gdio; /* whether the in-progress connect() needs the
			   * Pairing Service (only nuki_app_pair() does).
			   */

/* Given once the connect+discovery sequence reaches a terminal state
 * (fully ready, or any failure) - see connect_to_lock().
 */
static struct k_sem g_ready_sem;
static int g_connect_err;
static bool g_connecting; /* true from connect_to_lock() until the first
			    * finish_connect_attempt() call for this attempt.
			    */

/* Given once disconnected() has finished cleaning up - see
 * disconnect_from_lock().
 */
static struct k_sem g_disconnected_sem;

static struct k_work_delayable g_scan_timeout_work;

/* Serializes all BLE operations (pair/get-state/lock-action/calibrate):
 * the shell (uart0), the Loxone machine protocol (uart1) and the periodic
 * status poller below can all trigger one of these independently, but the
 * connect/discover/operate/disconnect state machine above is not written
 * to handle two callers at once.
 */
static struct k_mutex g_op_lock;

/* --- periodic status cache --------------------------------------------- */

/* How often to poll the lock's state in the background so a UART query
 * (see nuki_uart_proto.c) can answer instantly from cache instead of
 * paying for a fresh BLE connect+read (a couple of seconds) every time.
 * 15 min, in line with the official Nuki Bridge's default poll interval
 * (30 min) - frequent enough for Loxone, without materially shortening the
 * lock's own battery life via extra connection cycles.
 */
#define STATE_POLL_INTERVAL_SEC (15 * 60)

static struct k_work_delayable g_state_poll_work;
static struct k_mutex g_cache_lock;
static struct nuki_keyturner_state g_cached_state;
static bool g_cache_valid;
static int64_t g_cache_uptime_ms;

/* --- advertising data matching -------------------------------------------- */

struct uuid_match_ctx {
	const struct bt_uuid *target;
	bool found;
};

static bool uuid128_matches(const uint8_t *bytes, const struct bt_uuid *target)
{
	struct bt_uuid_128 candidate;

	candidate.uuid.type = BT_UUID_TYPE_128;
	memcpy(candidate.val, bytes, 16);
	return bt_uuid_cmp(&candidate.uuid, target) == 0;
}

static bool ad_uuid_cb(struct bt_data *data, void *user_data)
{
	struct uuid_match_ctx *ctx = user_data;

	switch (data->type) {
	case BT_DATA_UUID128_ALL:
	case BT_DATA_UUID128_SOME:
		/* A concatenated list of 16-byte UUIDs. */
		for (size_t i = 0; i + 16 <= data->data_len; i += 16) {
			if (uuid128_matches(&data->data[i], ctx->target)) {
				ctx->found = true;
				return false;
			}
		}
		break;
	case BT_DATA_SVC_DATA128:
		/* Service Data (128-bit UUID): the first 16 bytes are the
		 * UUID, followed by service-specific payload. Nuki locks
		 * advertise this way (e.g. their own lock-state "beacon"
		 * data) rather than via a plain service UUID list.
		 */
		if (data->data_len >= 16 && uuid128_matches(data->data, ctx->target)) {
			ctx->found = true;
			return false;
		}
		break;
	default:
		break;
	}
	return true;
}

static bool ad_has_uuid(struct net_buf_simple *ad, const struct bt_uuid *target)
{
	struct uuid_match_ctx ctx = {.target = target, .found = false};
	struct net_buf_simple copy;

	net_buf_simple_clone(ad, &copy);
	bt_data_parse(&copy, ad_uuid_cb, &ctx);
	return ctx.found;
}

static bool ad_name_cb(struct bt_data *data, void *user_data)
{
	char *name = user_data;

	if (data->type == BT_DATA_NAME_COMPLETE || data->type == BT_DATA_NAME_SHORTENED) {
		size_t len = MIN(data->data_len, 30);

		memcpy(name, data->data, len);
		name[len] = '\0';
		return false;
	}
	return true;
}

static void ad_get_name(struct net_buf_simple *ad, char *out, size_t out_size)
{
	struct net_buf_simple copy;

	out[0] = '\0';
	net_buf_simple_clone(ad, &copy);
	bt_data_parse(&copy, ad_name_cb, out);
	ARG_UNUSED(out_size); /* ad_name_cb already caps at 30 chars, see log_advertisement */
}

/* Nuki locks advertise as "Nuki_<8 hex chars>" (confirmed on real hardware -
 * see the "adv seen" diagnostic log). This is checked in addition to the
 * service UUID / service-data matching below, since which AD field actually
 * carries the service identifier can vary/be missed depending on timing.
 */
#define NUKI_NAME_PREFIX "Nuki_"

static bool ad_has_nuki_name(struct net_buf_simple *ad)
{
	char name[31];

	ad_get_name(ad, name, sizeof(name));
	return strncmp(name, NUKI_NAME_PREFIX, strlen(NUKI_NAME_PREFIX)) == 0;
}

/* Diagnostic aid used while dialing in the scan filter: logs every
 * advertisement seen during a scan window. Left in at LOG_DBG (compiled out
 * by the module's LOG_LEVEL_INF registration below, so no runtime cost) in
 * case scan-matching ever needs to be debugged again - bump the module's
 * registered level to LOG_LEVEL_DBG to re-enable.
 */
static void log_advertisement(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			       struct net_buf_simple *ad)
{
	char addr_str[BT_ADDR_LE_STR_LEN];
	char name[31];

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
	ad_get_name(ad, name, sizeof(name));

	LOG_DBG("adv seen: %s rssi=%d type=%u name=\"%s\" ad_len=%u", addr_str, rssi, type, name,
		ad->len);
}

static void finish_connect_attempt(int err)
{
	/* Guard against a late/duplicate call (e.g. disconnected() firing
	 * shortly after an earlier discovery failure already disconnected
	 * and reported its own error) clobbering the result that was
	 * already recorded and may already have been consumed.
	 */
	if (!g_connecting) {
		return;
	}
	g_connecting = false;

	g_connect_err = err;
	k_work_cancel_delayable(&g_scan_timeout_work);
	k_sem_give(&g_ready_sem);
}

static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			  struct net_buf_simple *ad)
{
	int err;

	if (g_conn) {
		return;
	}

	log_advertisement(addr, rssi, type, ad);

	/*
	 * Deliberately not filtering by adv `type` here: many peripherals
	 * (including Nuki locks) put their 128-bit service UUID list in the
	 * scan response rather than the primary advertising PDU to fit
	 * within the legacy 31-byte AD budget. With active scanning we get a
	 * separate callback invocation per PDU (primary adv AND scan
	 * response), so the UUID match below needs to run against both.
	 * A non-connectable match would simply fail in bt_conn_le_create()
	 * below, which is harmless.
	 */
	const struct nuki_pairing_data *paired = nuki_storage_get_pairing();
	bool match;

	if (paired) {
		match = bt_addr_le_cmp(addr, &paired->addr) == 0;
	} else {
		match = ad_has_uuid(ad, &nuki_keyturner_service_uuid.uuid) || ad_has_nuki_name(ad);
	}

	if (!match) {
		return;
	}

	LOG_INF("Nuki lock found: %s", bt_addr_le_str(addr));

	if (bt_le_scan_stop()) {
		return;
	}
	k_work_cancel_delayable(&g_scan_timeout_work);

	err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN, NUKI_CONN_PARAM, &g_conn);
	if (err) {
		LOG_ERR("create conn failed (%d)", err);
		finish_connect_attempt(err);
	}
}

static void scan_timeout_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	bt_le_scan_stop();
	LOG_WRN("no Nuki lock found within %d s", SCAN_TIMEOUT_SEC);
	finish_connect_attempt(-ETIMEDOUT);
}

/* --- GATT discovery -------------------------------------------------------- */

static void usdio_discovered(struct bt_gatt_dm *dm, void *ctx);

static void usdio_not_found(struct bt_conn *conn, void *ctx)
{
	ARG_UNUSED(ctx);
	LOG_ERR("Keyturner service not found - disconnecting");
	bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	finish_connect_attempt(-ENOTSUP);
}

static void usdio_discovery_error(struct bt_conn *conn, int err, void *ctx)
{
	ARG_UNUSED(ctx);
	LOG_ERR("Keyturner service discovery failed (%d) - disconnecting", err);
	bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	finish_connect_attempt(-EIO);
}

static const struct bt_gatt_dm_cb usdio_dm_cb = {
	.completed = usdio_discovered,
	.service_not_found = usdio_not_found,
	.error_found = usdio_discovery_error,
};

static void discover_keyturner_service(struct bt_conn *conn)
{
	int rc = bt_gatt_dm_start(conn, &nuki_keyturner_service_uuid.uuid, &usdio_dm_cb, NULL);

	if (rc) {
		LOG_ERR("gatt_dm_start (keyturner service) failed (%d)", rc);
		finish_connect_attempt(rc);
	}
}

static void gdio_not_found(struct bt_conn *conn, void *ctx)
{
	ARG_UNUSED(ctx);
	/* A missing Pairing Service isn't fatal here - a lock that is
	 * already paired with someone else may not offer it, but the
	 * Keyturner Service (discovered next) is what normal operation
	 * actually needs.
	 */
	discover_keyturner_service(conn);
}

static void gdio_discovery_error(struct bt_conn *conn, int err, void *ctx)
{
	ARG_UNUSED(err);
	ARG_UNUSED(ctx);
	discover_keyturner_service(conn);
}

static void gdio_discovered(struct bt_gatt_dm *dm, void *ctx)
{
	const struct bt_gatt_dm_attr *chrc, *ccc;
	struct bt_gatt_chrc *chrc_val;
	struct bt_conn *conn = bt_gatt_dm_conn_get(dm);

	chrc = bt_gatt_dm_char_by_uuid(dm, &nuki_pairing_gdio_uuid.uuid);
	if (!chrc) {
		LOG_ERR("GDIO characteristic not found");
	} else {
		chrc_val = bt_gatt_dm_attr_chrc_val(chrc);
		ccc = bt_gatt_dm_desc_by_uuid(dm, chrc, BT_UUID_GATT_CCC);

		if (nuki_transport_init(&g_gdio, conn, chrc_val->value_handle,
					 ccc ? ccc->handle : 0) == 0) {
			g_gdio_ready = true;
			LOG_INF("Pairing service discovered");
		}
	}

	bt_gatt_dm_data_release(dm);
	discover_keyturner_service(conn);
}

static const struct bt_gatt_dm_cb gdio_dm_cb = {
	.completed = gdio_discovered,
	.service_not_found = gdio_not_found,
	.error_found = gdio_discovery_error,
};

static void usdio_discovered(struct bt_gatt_dm *dm, void *ctx)
{
	const struct bt_gatt_dm_attr *chrc, *ccc;
	struct bt_gatt_chrc *chrc_val;

	chrc = bt_gatt_dm_char_by_uuid(dm, &nuki_keyturner_usdio_uuid.uuid);
	if (!chrc) {
		LOG_ERR("USDIO characteristic not found");
		bt_gatt_dm_data_release(dm);
		finish_connect_attempt(-ENOTSUP);
		return;
	}
	chrc_val = bt_gatt_dm_attr_chrc_val(chrc);
	ccc = bt_gatt_dm_desc_by_uuid(dm, chrc, BT_UUID_GATT_CCC);

	int err = nuki_transport_init(&g_usdio, bt_gatt_dm_conn_get(dm), chrc_val->value_handle,
				       ccc ? ccc->handle : 0);

	bt_gatt_dm_data_release(dm);

	if (err) {
		finish_connect_attempt(err);
		return;
	}

	g_usdio_ready = true;
	LOG_INF("Keyturner service discovered - ready");
	finish_connect_attempt(0);
}

static void start_discovery(struct bt_conn *conn)
{
	int err;

	if (!g_need_gdio) {
		/* state/lock/unlock/calibrate only ever use the Keyturner
		 * Service - skip the Pairing Service discovery round trip
		 * entirely (saves roughly a second per command).
		 */
		discover_keyturner_service(conn);
		return;
	}

	err = bt_gatt_dm_start(conn, &nuki_pairing_service_uuid.uuid, &gdio_dm_cb, NULL);
	if (err) {
		LOG_ERR("gatt_dm_start (pairing service) failed (%d)", err);
		finish_connect_attempt(err);
	}
}

/* --- connection callbacks --------------------------------------------------- */

static void connected(struct bt_conn *conn, uint8_t err)
{
	if (err) {
		LOG_ERR("failed to connect: %s", bt_hci_err_to_str(err));
		bt_conn_unref(g_conn);
		g_conn = NULL;
		finish_connect_attempt(-EIO);
		return;
	}

	if (conn != g_conn) {
		return;
	}

	LOG_INF("connected: %s", bt_conn_dst_str(conn));
	start_discovery(conn);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	if (conn != g_conn) {
		return;
	}

	LOG_INF("disconnected: 0x%02x %s", reason, bt_hci_err_to_str(reason));

	if (g_gdio_ready) {
		nuki_transport_release(&g_gdio);
		g_gdio_ready = false;
	}
	if (g_usdio_ready) {
		nuki_transport_release(&g_usdio);
		g_usdio_ready = false;
	}

	bt_conn_unref(g_conn);
	g_conn = NULL;

	/* If we disconnected before connect_to_lock()'s wait was satisfied
	 * (e.g. the lock dropped the link mid-discovery), unblock it with an
	 * error instead of leaving it to wait out the full connect timeout.
	 */
	finish_connect_attempt(-ENOTCONN);
	k_sem_give(&g_disconnected_sem);
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
};

/* --- connect-on-demand helpers ---------------------------------------------- */

static int connect_to_lock(bool need_gdio)
{
	int err;

	k_sem_reset(&g_ready_sem);
	g_connect_err = 0;
	g_need_gdio = need_gdio;
	g_connecting = true;

	/* _CONTINUOUS sets scan window == interval (100% duty cycle) instead
	 * of the ~50% default, so we don't miss/delay catching the lock's
	 * next advertisement while the radio is "off" between windows.
	 */
	err = bt_le_scan_start(BT_LE_SCAN_ACTIVE_CONTINUOUS, device_found);
	if (err) {
		LOG_ERR("scanning failed to start (%d)", err);
		return err;
	}
	LOG_INF("scanning for Nuki lock...");
	k_work_schedule(&g_scan_timeout_work, SCAN_TIMEOUT);

	err = k_sem_take(&g_ready_sem, CONNECT_TIMEOUT);
	if (err) {
		LOG_ERR("timed out connecting to the lock");
		g_connecting = false;
		bt_le_scan_stop();
		if (g_conn) {
			bt_conn_disconnect(g_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		}
		return -ETIMEDOUT;
	}

	return g_connect_err;
}

static void disconnect_from_lock(void)
{
	if (!g_conn) {
		return;
	}
	k_sem_reset(&g_disconnected_sem);
	bt_conn_disconnect(g_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	k_sem_take(&g_disconnected_sem, DISCONNECT_TIMEOUT);
}

/* --- periodic status polling ------------------------------------------- */

static void state_poll_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	struct nuki_keyturner_state state;
	int err;

	/* Only poll once actually paired - otherwise every poll would just
	 * fail with -ENOENT and spam the log.
	 */
	if (nuki_app_is_paired()) {
		err = nuki_app_get_state(&state);
		if (!err) {
			k_mutex_lock(&g_cache_lock, K_FOREVER);
			g_cached_state = state;
			g_cache_valid = true;
			g_cache_uptime_ms = k_uptime_get();
			k_mutex_unlock(&g_cache_lock);
			LOG_DBG("background state poll ok");
		} else {
			LOG_WRN("background state poll failed (%d)", err);
		}
	}

	k_work_schedule(&g_state_poll_work, K_SECONDS(STATE_POLL_INTERVAL_SEC));
}

/* --- public API -------------------------------------------------------------- */

int nuki_app_init(void)
{
	k_sem_init(&g_ready_sem, 0, 1);
	k_sem_init(&g_disconnected_sem, 0, 1);
	k_mutex_init(&g_op_lock);
	k_mutex_init(&g_cache_lock);
	k_work_init_delayable(&g_scan_timeout_work, scan_timeout_handler);
	k_work_init_delayable(&g_state_poll_work, state_poll_handler);
	k_work_schedule(&g_state_poll_work, K_SECONDS(STATE_POLL_INTERVAL_SEC));
	return 0;
}

bool nuki_app_is_connected(void)
{
	return g_conn != NULL;
}

bool nuki_app_is_ready(void)
{
	return g_conn != NULL && g_usdio_ready;
}

bool nuki_app_is_paired(void)
{
	return nuki_storage_get_pairing() != NULL;
}

/* Returns the most recent state captured by the background poller (see
 * state_poll_handler above) without touching BLE at all. *age_sec is set to
 * how many seconds old that snapshot is. Returns -ENODATA if no successful
 * poll has completed yet (e.g. right after boot).
 */
int nuki_app_get_cached_state(struct nuki_keyturner_state *out, int32_t *age_sec)
{
	int err = 0;

	k_mutex_lock(&g_cache_lock, K_FOREVER);
	if (g_cache_valid) {
		*out = g_cached_state;
		*age_sec = (int32_t)((k_uptime_get() - g_cache_uptime_ms) / 1000);
	} else {
		err = -ENODATA;
	}
	k_mutex_unlock(&g_cache_lock);

	return err;
}

static int pair_locked(void)
{
	struct nuki_pairing_data data;
	int err;

	err = connect_to_lock(true);
	if (err) {
		return err;
	}

	if (!g_gdio_ready) {
		LOG_ERR("lock did not offer the Pairing Service on this connection");
		disconnect_from_lock();
		return -ENOTSUP;
	}

	err = nuki_pairing_run(&g_gdio, &data);
	if (!err) {
		bt_addr_le_copy(&data.addr, bt_conn_get_dst(g_conn));
		err = nuki_storage_save_pairing(&data);
	}

	disconnect_from_lock();
	return err;
}

static int get_state_locked(struct nuki_keyturner_state *out)
{
	const struct nuki_pairing_data *p = nuki_storage_get_pairing();
	int err;

	if (!p) {
		return -ENOENT;
	}

	err = connect_to_lock(false);
	if (err) {
		return err;
	}

	err = nuki_command_get_state(&g_usdio, p->auth_id, p->shared_key, out);
	disconnect_from_lock();
	return err;
}

static int lock_action_locked(uint8_t action)
{
	const struct nuki_pairing_data *p = nuki_storage_get_pairing();
	int err;

	if (!p) {
		return -ENOENT;
	}

	err = connect_to_lock(false);
	if (err) {
		return err;
	}

	err = nuki_command_lock_action(&g_usdio, p->auth_id, p->app_id, p->shared_key, action);
	disconnect_from_lock();
	return err;
}

static int calibrate_locked(uint16_t security_pin)
{
	const struct nuki_pairing_data *p = nuki_storage_get_pairing();
	int err;

	if (!p) {
		return -ENOENT;
	}

	err = connect_to_lock(false);
	if (err) {
		return err;
	}

	err = nuki_command_calibrate(&g_usdio, p->auth_id, p->shared_key, security_pin);
	disconnect_from_lock();
	return err;
}

int nuki_app_pair(void)
{
	int err;

	k_mutex_lock(&g_op_lock, K_FOREVER);
	err = pair_locked();
	k_mutex_unlock(&g_op_lock);
	return err;
}

int nuki_app_get_state(struct nuki_keyturner_state *out)
{
	int err;

	k_mutex_lock(&g_op_lock, K_FOREVER);
	err = get_state_locked(out);
	k_mutex_unlock(&g_op_lock);
	return err;
}

int nuki_app_lock_action(uint8_t action)
{
	int err;

	k_mutex_lock(&g_op_lock, K_FOREVER);
	err = lock_action_locked(action);
	k_mutex_unlock(&g_op_lock);
	return err;
}

int nuki_app_calibrate(uint16_t security_pin)
{
	int err;

	k_mutex_lock(&g_op_lock, K_FOREVER);
	err = calibrate_locked(security_pin);
	k_mutex_unlock(&g_op_lock);
	return err;
}
