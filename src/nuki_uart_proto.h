/* nuki_uart_proto.h - plain-text line command protocol for an external
 * Loxone module, carried over the second UART (uart1) so it stays separate
 * from the interactive shell/log console (uart0). See
 * boards/nrf52840dk_nrf52840.overlay for the pin mapping.
 */
#ifndef NUKI_UART_PROTO_H_
#define NUKI_UART_PROTO_H_

/* Call once at boot, after nuki_app_init(). Starts the uart1 RX interrupt
 * and the command-processing thread.
 */
int nuki_uart_proto_init(void);

#endif /* NUKI_UART_PROTO_H_ */
