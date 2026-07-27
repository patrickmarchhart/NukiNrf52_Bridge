/* main.c - Nuki Smart Lock BLE controller.
 *
 * Scans for and connects to a Nuki Smart Lock (1st-4th Generation),
 * discovers its Pairing and Keyturner GATT services, and lets the user
 * pair with it and control it (lock/unlock/unlatch, read state) via the
 * "nuki" shell command (see nuki_shell.c) on uart0, or via the plain-text
 * machine protocol for an external Loxone module on uart1 (see
 * nuki_uart_proto.c). All actual protocol/crypto work lives in
 * nuki_crypto/nuki_protocol/nuki_pairing/nuki_command/nuki_app.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/settings/settings.h>

#include "nuki_crypto.h"
#include "nuki_app.h"
#include "nuki_uart_proto.h"

int main(void)
{
	int err;

	err = bt_enable(NULL);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return 0;
	}
	printk("Bluetooth initialized\n");

	err = nuki_crypto_init();
	if (err) {
		printk("Crypto init failed (err %d)\n", err);
		return 0;
	}

	err = settings_subsys_init();
	if (err) {
		printk("Settings subsys init failed (err %d)\n", err);
		return 0;
	}
	settings_load();

	nuki_app_init();

	err = nuki_uart_proto_init();
	if (err) {
		printk("Loxone module UART protocol init failed (err %d) - continuing without it\n",
		       err);
	}

	return 0;
}
