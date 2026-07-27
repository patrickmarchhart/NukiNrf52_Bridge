/* nuki_crypto.h - Cryptographic primitives required by the Nuki Smart Lock
 * BLE API (see "Nuki Smart Lock API V2.3.0", section 4, "Encryption").
 *
 * Nuki bases its protocol on the NaCl Cryptography Toolbox:
 *   dh1   -> crypto_scalarmult_curve25519      (X25519 ECDH)
 *   kdf1  -> crypto_core_hsalsa20               (long-term key derivation)
 *   h1    -> HMAC-SHA256                        (authenticators)
 *   e1/d1 -> crypto_secretbox_xsalsa20poly1305   (encrypted command frames)
 *
 * X25519 and HMAC-SHA256 are delegated to the PSA Crypto API (available via
 * NCS nrf_security / mbedTLS). HSalsa20/Salsa20/Poly1305 have no PSA
 * equivalent (PSA only exposes ChaCha20-Poly1305, not the XSalsa20 variant
 * NaCl uses), so they are implemented here directly from the public NaCl/
 * djb reference algorithm.
 */
#ifndef NUKI_CRYPTO_H_
#define NUKI_CRYPTO_H_

#include <stdint.h>
#include <stddef.h>

#define NUKI_KEY_LEN     32
#define NUKI_NONCE_LEN   24
#define NUKI_TAG_LEN     16

/* Largest plaintext command payload (authId+cmdId+payload+crc) we ever
 * encrypt/decrypt. Generously covers every command used by this project.
 */
#define NUKI_CRYPTO_MAX_MSG_LEN 256

/* Must be called once (e.g. from main()) before any other nuki_crypto_*
 * function - initializes the PSA Crypto backend used for X25519 and
 * HMAC-SHA256.
 */
int nuki_crypto_init(void);

/* Generate a Curve25519 keypair for the initial pairing handshake. */
int nuki_crypto_keypair(uint8_t pub[NUKI_KEY_LEN], uint8_t priv[NUKI_KEY_LEN]);

/* dh1: X25519 scalar multiplication, out = priv * pub (raw ECDH result). */
int nuki_crypto_dh1(uint8_t out[NUKI_KEY_LEN], const uint8_t priv[NUKI_KEY_LEN],
		    const uint8_t pub[NUKI_KEY_LEN]);

/* kdf1: derive the long-term shared secret from the raw DH output. */
void nuki_crypto_kdf1(uint8_t out[NUKI_KEY_LEN], const uint8_t dh_result[NUKI_KEY_LEN]);

/* h1: HMAC-SHA256(key, data) used for all pairing authenticators. */
int nuki_crypto_h1(uint8_t out[32], const uint8_t key[NUKI_KEY_LEN],
		   const uint8_t *data, size_t len);

/*
 * e1: crypto_secretbox_xsalsa20poly1305.
 * out must be able to hold NUKI_TAG_LEN + msg_len bytes:
 *   out[0..16)          = Poly1305 authentication tag
 *   out[16..16+msg_len) = XSalsa20 ciphertext
 * Returns -EINVAL if msg_len > NUKI_CRYPTO_MAX_MSG_LEN.
 */
int nuki_crypto_e1(uint8_t *out, const uint8_t *msg, size_t msg_len,
		   const uint8_t nonce[NUKI_NONCE_LEN], const uint8_t key[NUKI_KEY_LEN]);

/*
 * d1: inverse of e1. in is tag(16) || ciphertext(msg_len).
 * Returns 0 and writes msg_len plaintext bytes to out on success,
 * -EBADMSG if the authentication tag does not match (out is not written).
 */
int nuki_crypto_d1(uint8_t *out, const uint8_t *in, size_t msg_len,
		   const uint8_t nonce[NUKI_NONCE_LEN], const uint8_t key[NUKI_KEY_LEN]);

/*
 * CRC16-CCITT ("normal"/non-reflected, poly 0x1021, init 0xFFFF) as used to
 * terminate every unencrypted and decrypted Nuki command payload. This is
 * NOT the same algorithm as Zephyr's crc16_ccitt() (which is the reflected
 * X.25/Kermit variant) - Nuki's "normal" representation matches Zephyr's
 * generic crc16(poly, seed, ...) instead.
 */
uint16_t nuki_crc16(const uint8_t *data, size_t len);

#endif /* NUKI_CRYPTO_H_ */
