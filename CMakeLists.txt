# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(Nuki)

target_sources(app PRIVATE
  src/main.c
  src/nuki_crypto.c
  src/nuki_protocol.c
  src/nuki_storage.c
  src/nuki_transport.c
  src/nuki_pairing.c
  src/nuki_command.c
  src/nuki_app.c
  src/nuki_shell.c
  src/nuki_uart_proto.c
)

zephyr_library_include_directories(${ZEPHYR_BASE}/samples/bluetooth)
