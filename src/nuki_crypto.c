/* nuki_crypto.c - see nuki_crypto.h.
 *
 * The Salsa20 core, HSalsa20, and Poly1305 (crypto_onetimeauth) below are a
 * straight port of the public-domain TweetNaCl reference implementation
 * (tweetnacl.cr.yp.to, "core", "crypto_stream_salsa20_xor",
 * "crypto_onetimeauth", "crypto_secretbox"/"crypto_secretbox_open" - by
 * D. J. Bernstein, T. Lange, P. Schwabe), adapted to stdint types and to the
 * tag||ciphertext wire framing used by the Nuki BLE protocol (no leading
 * zero-padding bytes on the wire, unlike the raw NaCl secretbox convention).
 * X25519 and HMAC-SHA256 are delegated to PSA Crypto, which this NCS build
 * provides via nrf_security/mbedTLS.
 */

#include "nuki_crypto.h"

#include <string.h>
#include <errno.h>
#include <psa/crypto.h>

/* ---------------------------------------------------------------------- */
/* Salsa20 / HSalsa20 core (TweetNaCl "core")                              */
/* ---------------------------------------------------------------------- */

static const uint8_t sigma[16] = "expand 32-byte k";

static uint32_t rotl32(uint32_t x, int c)
{
	return (x << c) | (x >> (32 - c));
}

static uint32_t load_le32(const uint8_t *x)
{
	uint32_t u = x[3];

	u = (u << 8) | x[2];
	u = (u << 8) | x[1];
	return (u << 8) | x[0];
}

static void store_le32(uint8_t *x, uint32_t u)
{
	for (int i = 0; i < 4; i++) {
		x[i] = (uint8_t)u;
		u >>= 8;
	}
}

/* h=0: full Salsa20 permutation (64-byte out). h=1: HSalsa20 (32-byte out). */
static void salsa_core(uint8_t *out, const uint8_t *in, const uint8_t *k,
			const uint8_t *c, int h)
{
	uint32_t w[16], x[16], y[16], t[4];

	for (int i = 0; i < 4; i++) {
		x[5 * i] = load_le32(c + 4 * i);
		x[1 + i] = load_le32(k + 4 * i);
		x[6 + i] = load_le32(in + 4 * i);
		x[11 + i] = load_le32(k + 16 + 4 * i);
	}

	for (int i = 0; i < 16; i++) {
		y[i] = x[i];
	}

	for (int i = 0; i < 20; i++) {
		for (int j = 0; j < 4; j++) {
			for (int m = 0; m < 4; m++) {
				t[m] = x[(5 * j + 4 * m) % 16];
			}
			t[1] ^= rotl32(t[0] + t[3], 7);
			t[2] ^= rotl32(t[1] + t[0], 9);
			t[3] ^= rotl32(t[2] + t[1], 13);
			t[0] ^= rotl32(t[3] + t[2], 18);
			for (int m = 0; m < 4; m++) {
				w[4 * j + (j + m) % 4] = t[m];
			}
		}
		for (int m = 0; m < 16; m++) {
			x[m] = w[m];
		}
	}

	if (h) {
		for (int i = 0; i < 16; i++) {
			x[i] += y[i];
		}
		for (int i = 0; i < 4; i++) {
			x[5 * i] -= load_le32(c + 4 * i);
			x[6 + i] -= load_le32(in + 4 * i);
		}
		for (int i = 0; i < 4; i++) {
			store_le32(out + 4 * i, x[5 * i]);
			store_le32(out + 16 + 4 * i, x[6 + i]);
		}
	} else {
		for (int i = 0; i < 16; i++) {
			store_le32(out + 4 * i, x[i] + y[i]);
		}
	}
}

static void core_salsa20(uint8_t out[64], const uint8_t in[16], const uint8_t k[32])
{
	salsa_core(out, in, k, sigma, 0);
}

static void core_hsalsa20(uint8_t out[32], const uint8_t in[16], const uint8_t k[32])
{
	salsa_core(out, in, k, sigma, 1);
}

/* XOR (or just generate, if m is NULL) len bytes of Salsa20 keystream,
 * using n (8-byte nonce) as the running block counter state.
 */
static void stream_salsa20_xor(uint8_t *c, const uint8_t *m, size_t len,
				const uint8_t n[8], const uint8_t k[32])
{
	uint8_t z[16] = {0};
	uint8_t x[64];
	uint32_t u;

	memcpy(z, n, 8);

	while (len >= 64) {
		core_salsa20(x, z, k);
		for (int i = 0; i < 64; i++) {
			c[i] = (m ? m[i] : 0) ^ x[i];
		}
		u = 1;
		for (int i = 8; i < 16; i++) {
			u += z[i];
			z[i] = (uint8_t)u;
			u >>= 8;
		}
		len -= 64;
		c += 64;
		if (m) {
			m += 64;
		}
	}
	if (len) {
		core_salsa20(x, z, k);
		for (size_t i = 0; i < len; i++) {
			c[i] = (m ? m[i] : 0) ^ x[i];
		}
	}
}

/* XSalsa20: derive a subkey via HSalsa20 from the first 16 bytes of the
 * 24-byte nonce, then run Salsa20 keyed with that subkey using the last 8
 * nonce bytes as the block-counter nonce.
 */
static void xsalsa20_xor(uint8_t *c, const uint8_t *m, size_t len,
			  const uint8_t n[NUKI_NONCE_LEN], const uint8_t k[32])
{
	uint8_t subkey[32];

	core_hsalsa20(subkey, n, k);
	stream_salsa20_xor(c, m, len, n + 16, subkey);
}

/* ---------------------------------------------------------------------- */
/* Poly1305 (TweetNaCl "crypto_onetimeauth")                               */
/* ---------------------------------------------------------------------- */

static void add1305(uint32_t h[17], const uint32_t c[17])
{
	uint32_t u = 0;

	for (int j = 0; j < 17; j++) {
		u += h[j] + c[j];
		h[j] = u & 255;
		u >>= 8;
	}
}

static const uint32_t minusp[17] = {
	5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
};

/* out[16] = Poly1305(m[0..n), key = k[0..32) ) */
static void poly1305(uint8_t out[16], const uint8_t *m, size_t n, const uint8_t k[32])
{
	uint32_t s, x[17], r[17], h[17], c[17], g[17];
	size_t j;

	for (j = 0; j < 17; j++) {
		r[j] = h[j] = 0;
	}
	for (j = 0; j < 16; j++) {
		r[j] = k[j];
	}
	r[3] &= 15;
	r[4] &= 252;
	r[7] &= 15;
	r[8] &= 252;
	r[11] &= 15;
	r[12] &= 252;
	r[15] &= 15;

	while (n > 0) {
		for (j = 0; j < 17; j++) {
			c[j] = 0;
		}
		for (j = 0; j < 16 && j < n; j++) {
			c[j] = m[j];
		}
		c[j] = 1;
		m += j;
		n -= j;
		add1305(h, c);
		for (size_t i = 0; i < 17; i++) {
			x[i] = 0;
			for (j = 0; j < 17; j++) {
				x[i] += h[j] * ((j <= i) ? r[i - j] : 320U * r[i + 17 - j]);
			}
		}
		for (size_t i = 0; i < 17; i++) {
			h[i] = x[i];
		}
		uint32_t u = 0;

		for (j = 0; j < 16; j++) {
			u += h[j];
			h[j] = u & 255;
			u >>= 8;
		}
		u += h[16];
		h[16] = u & 3;
		u = 5 * (u >> 2);
		for (j = 0; j < 16; j++) {
			u += h[j];
			h[j] = u & 255;
			u >>= 8;
		}
		u += h[16];
		h[16] = u;
	}

	for (j = 0; j < 17; j++) {
		g[j] = h[j];
	}
	add1305(h, minusp);
	s = -(h[16] >> 7);
	for (j = 0; j < 17; j++) {
		h[j] ^= s & (g[j] ^ h[j]);
	}

	for (j = 0; j < 16; j++) {
		c[j] = k[j + 16];
	}
	c[16] = 0;
	add1305(h, c);
	for (j = 0; j < 16; j++) {
		out[j] = (uint8_t)h[j];
	}
}

static int constant_time_eq16(const uint8_t *x, const uint8_t *y)
{
	uint32_t d = 0;

	for (int i = 0; i < 16; i++) {
		d |= x[i] ^ y[i];
	}
	return d == 0;
}

/* ---------------------------------------------------------------------- */
/* Public API                                                              */
/* ---------------------------------------------------------------------- */

int nuki_crypto_init(void)
{
	psa_status_t status = psa_crypto_init();

	return (status == PSA_SUCCESS) ? 0 : -EIO;
}

int nuki_crypto_keypair(uint8_t pub[NUKI_KEY_LEN], uint8_t priv[NUKI_KEY_LEN])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	size_t out_len;
	psa_status_t status;

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attr, 255);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

	status = psa_generate_key(&attr, &key);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	status = psa_export_key(key, priv, NUKI_KEY_LEN, &out_len);
	if (status != PSA_SUCCESS || out_len != NUKI_KEY_LEN) {
		psa_destroy_key(key);
		return -EIO;
	}

	status = psa_export_public_key(key, pub, NUKI_KEY_LEN, &out_len);
	psa_destroy_key(key);
	if (status != PSA_SUCCESS || out_len != NUKI_KEY_LEN) {
		return -EIO;
	}

	return 0;
}

int nuki_crypto_dh1(uint8_t out[NUKI_KEY_LEN], const uint8_t priv[NUKI_KEY_LEN],
		    const uint8_t pub[NUKI_KEY_LEN])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	size_t out_len;
	psa_status_t status;

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attr, 255);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

	status = psa_import_key(&attr, priv, NUKI_KEY_LEN, &key);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	status = psa_raw_key_agreement(PSA_ALG_ECDH, key, pub, NUKI_KEY_LEN,
					out, NUKI_KEY_LEN, &out_len);
	psa_destroy_key(key);
	if (status != PSA_SUCCESS || out_len != NUKI_KEY_LEN) {
		return -EIO;
	}

	return 0;
}

void nuki_crypto_kdf1(uint8_t out[NUKI_KEY_LEN], const uint8_t dh_result[NUKI_KEY_LEN])
{
	static const uint8_t zero16[16] = {0};

	core_hsalsa20(out, zero16, dh_result);
}

int nuki_crypto_h1(uint8_t out[32], const uint8_t key[NUKI_KEY_LEN],
		   const uint8_t *data, size_t len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	size_t out_len;
	psa_status_t status;

	psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attr, NUKI_KEY_LEN * 8);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));

	status = psa_import_key(&attr, key, NUKI_KEY_LEN, &key_id);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), data, len,
				  out, 32, &out_len);
	psa_destroy_key(key_id);
	if (status != PSA_SUCCESS || out_len != 32) {
		return -EIO;
	}

	return 0;
}

int nuki_crypto_e1(uint8_t *out, const uint8_t *msg, size_t msg_len,
		   const uint8_t nonce[NUKI_NONCE_LEN], const uint8_t key[NUKI_KEY_LEN])
{
	uint8_t padded_in[32 + NUKI_CRYPTO_MAX_MSG_LEN];
	uint8_t padded_out[32 + NUKI_CRYPTO_MAX_MSG_LEN];

	if (msg_len > NUKI_CRYPTO_MAX_MSG_LEN) {
		return -EINVAL;
	}

	memset(padded_in, 0, 32);
	memcpy(padded_in + 32, msg, msg_len);

	xsalsa20_xor(padded_out, padded_in, 32 + msg_len, nonce, key);

	/* padded_out[0..32) is the raw keystream block (Poly1305 key);
	 * padded_out[32..32+msg_len) is the actual ciphertext.
	 */
	poly1305(out, padded_out + 32, msg_len, padded_out);
	memcpy(out + NUKI_TAG_LEN, padded_out + 32, msg_len);

	return 0;
}

int nuki_crypto_d1(uint8_t *out, const uint8_t *in, size_t msg_len,
		   const uint8_t nonce[NUKI_NONCE_LEN], const uint8_t key[NUKI_KEY_LEN])
{
	uint8_t block0[64];
	uint8_t tag[16];
	uint8_t padded_in[32 + NUKI_CRYPTO_MAX_MSG_LEN];
	uint8_t padded_out[32 + NUKI_CRYPTO_MAX_MSG_LEN];

	if (msg_len > NUKI_CRYPTO_MAX_MSG_LEN) {
		return -EINVAL;
	}

	/* Recompute the first keystream block to get the Poly1305 key and
	 * verify the tag before decrypting anything (verify-then-decrypt).
	 */
	xsalsa20_xor(block0, NULL, 64, nonce, key);
	poly1305(tag, in + NUKI_TAG_LEN, msg_len, block0);
	if (!constant_time_eq16(tag, in)) {
		return -EBADMSG;
	}

	memset(padded_in, 0, 32);
	memcpy(padded_in + 32, in + NUKI_TAG_LEN, msg_len);
	xsalsa20_xor(padded_out, padded_in, 32 + msg_len, nonce, key);
	memcpy(out, padded_out + 32, msg_len);

	return 0;
}

uint16_t nuki_crc16(const uint8_t *data, size_t len)
{
	uint16_t crc = 0xFFFF;

	for (size_t i = 0; i < len; i++) {
		crc ^= (uint16_t)(data[i] << 8);
		for (int j = 0; j < 8; j++) {
			if (crc & 0x8000) {
				crc = (uint16_t)((crc << 1) ^ 0x1021);
			} else {
				crc = (uint16_t)(crc << 1);
			}
		}
	}

	return crc;
}
