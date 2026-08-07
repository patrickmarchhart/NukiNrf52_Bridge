Nuki nRF52 Bridge
##################

Overview
********

Firmware for an nRF52840 (nRF Connect SDK / Zephyr) that turns the board into
a standalone Bluetooth LE controller for a Nuki Smart Lock (1st-4th
Generation). It performs the full Nuki pairing handshake itself (no phone
app / Nuki Bridge required), and can then lock/unlock/unlatch/calibrate the
lock and read back its state (lock state, battery, door sensor).

Two ways to control it:

* An interactive ``nuki`` shell command on the console UART (``uart0``), for
  manual use and testing.
* A dedicated, machine-readable line protocol on a second UART (``uart1``)
  for integrating with an external home-automation controller (built for and
  tested against a custom Loxone module) - see
  `LOXONE_UART_PROTOCOL.md <LOXONE_UART_PROTOCOL.md>`_ for the full command
  reference.

Core features
*************

Pairing
=======

``nuki pair`` (shell) or ``PAIR`` (UART protocol) runs the Nuki BLE pairing
handshake (Curve25519 key exchange, HSalsa20/Salsa20/Poly1305 encryption,
HMAC-SHA256 authentication - see ``src/nuki_crypto.c`` and
``src/nuki_pairing.c``) against a lock in pairing mode (button held ~5 s).
The resulting authorization ID and shared key are persisted via Zephyr's
``settings`` subsystem and survive a reboot.

Connect-on-demand
==================

Most Nuki locks only accept a single BLE connection at a time. To avoid
permanently occupying that slot (which would block the official Nuki app),
this firmware connects only for the duration of one operation - pairing,
a status read, or a lock action - and disconnects immediately afterwards
(see ``src/nuki_app.c``).

Background status cache
========================

A background timer polls the lock's state periodically (every 15 minutes by
default, matching the official Nuki Bridge's own default poll interval) and
caches the result. A ``STATE``/``nuki state`` query then normally answers
from that cache instead of paying for a multi-second BLE round trip; the
response includes the cache's age so a caller can judge freshness.

Loxone UART protocol
=====================

A second, dedicated UART (``uart1``, pins configurable via
``boards/nrf52840dk_nrf52840.overlay``) speaks a binary frame protocol -
every request and response is a fixed C struct (see ``nuki_uart_proto.h``),
wrapped in a ``SOF | CMD | LEN | PAYLOAD`` frame (no CRC - a short, direct
point-to-point link), with distinct SOF bytes for requests (``0xA5``) and
responses (``0x5A``) so a captured frame's direction is obvious from its
first byte - kept separate from the human-oriented shell/log console on
``uart0``. See `LOXONE_UART_PROTOCOL.md <LOXONE_UART_PROTOCOL.md>`_ for the
full byte-level reference.

Requirements
************

* nRF Connect SDK v3.4.0 / Zephyr 4.4.0
* A board with Bluetooth LE support; developed and tested on
  ``nrf52840dk/nrf52840``
* A Nuki Smart Lock (1st-4th Generation)

Building and running
*********************

.. code-block:: console

   west build -b nrf52840dk/nrf52840 .
   west flash

Usage (shell, on uart0)
========================

.. code-block:: console

   uart:~$ nuki status
   uart:~$ nuki pair       # hold the lock's button for ~5s first
   uart:~$ nuki state
   uart:~$ nuki lock
   uart:~$ nuki unlock
   uart:~$ nuki unlatch
   uart:~$ nuki calibrate <security-pin>

Usage (Loxone / machine protocol, on uart1)
=============================================

115200 8N1 by default (see the board overlay). A binary ``SOF | CMD | LEN |
PAYLOAD`` frame in each direction, e.g. requesting ``STATE`` (``CMD`` ``3``,
no payload) and getting back a ``struct nuki_uart_resp_state``:

.. code-block:: text

   > A5 03 00
   < 5A 03 15 00 00 00 00 03 57 00 03 EA 07 08 07 0E 02 0A 00 00 2A 00 00 00

Full command/error reference: `LOXONE_UART_PROTOCOL.md <LOXONE_UART_PROTOCOL.md>`_.

Tests
*****

``tests/nuki_crypto`` contains a Twister test case for the crypto primitives
(``dh1``/``kdf1``/``h1``/``e1``/``d1``/CRC16) in ``src/nuki_crypto.c``,
checked against vectors from the official Nuki BLE API documentation.

Project layout
**************

.. code-block:: text

   src/
     nuki_crypto.c/h     Curve25519/HSalsa20/Salsa20/Poly1305/HMAC-SHA256/CRC16 primitives
     nuki_protocol.c/h   Nuki BLE GATT UUIDs, command IDs, frame build/parse
     nuki_storage.c/h    Persisted pairing data (settings/NVS)
     nuki_transport.c/h  GATT read/write/indication plumbing for one characteristic
     nuki_pairing.c/h    The pairing handshake state machine
     nuki_command.c/h    Encrypted state/lock-action/calibrate commands
     nuki_app.c/h        Scan/connect/discover orchestration, connect-on-demand,
                          background status cache, top-level public API
     nuki_shell.c        Interactive "nuki ..." shell commands (uart0)
     nuki_uart_proto.c/h Loxone machine protocol (uart1)
     main.c
   boards/
     nrf52840dk_nrf52840.overlay   Enables/pinmuxes uart1 for the Loxone protocol
   tests/nuki_crypto/               Twister test for the crypto primitives
