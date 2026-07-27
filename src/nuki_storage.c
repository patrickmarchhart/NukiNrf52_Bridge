#include "nuki_storage.h"

#include <errno.h>
#include <string.h>
#include <zephyr/settings/settings.h>

static struct nuki_pairing_data pairing;
static bool have_pairing;

static int nuki_settings_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
	if (settings_name_steq(name, "pairing", NULL) && len == sizeof(pairing)) {
		ssize_t rc = read_cb(cb_arg, &pairing, sizeof(pairing));

		if (rc < 0) {
			return rc;
		}
		have_pairing = true;
		return 0;
	}

	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(nuki, "nuki", NULL, nuki_settings_set, NULL, NULL);

bool nuki_storage_has_pairing(void)
{
	return have_pairing;
}

const struct nuki_pairing_data *nuki_storage_get_pairing(void)
{
	return have_pairing ? &pairing : NULL;
}

int nuki_storage_save_pairing(const struct nuki_pairing_data *data)
{
	pairing = *data;
	have_pairing = true;
	return settings_save_one("nuki/pairing", &pairing, sizeof(pairing));
}

int nuki_storage_clear_pairing(void)
{
	have_pairing = false;
	memset(&pairing, 0, sizeof(pairing));
	return settings_delete("nuki/pairing");
}
