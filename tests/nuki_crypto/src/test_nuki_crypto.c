/* Known-answer tests for nuki_crypto.c, using the byte-exact examples from
 * the official "Nuki Smart Lock API V2.3.0" PDF, section 9 "Command usage
 * examples" (Authorize App / Read lock state). Runs on native_sim, no
 * hardware or real lock required - this is meant to catch endianness /
 * algorithm mistakes in the from-scratch Salsa20/HSalsa20/Poly1305 port
 * before ever talking to a physical Nuki lock.
 */

#include <zephyr/ztest.h>
#include <string.h>
#include "nuki_crypto.h"

static size_t test_hex2bin(uint8_t *out, const char *hex)
{
	size_t len = strlen(hex) / 2;

	for (size_t i = 0; i < len; i++) {
		unsigned int byte;

		sscanf(&hex[i * 2], "%2x", &byte);
		out[i] = (uint8_t)byte;
	}
	return len;
}

ZTEST_SUITE(nuki_crypto, NULL, NULL, NULL, NULL, NULL);

/* --- Authorize App (Smart Lock 1-4th Generation) example --- */

ZTEST(nuki_crypto, test_dh1_matches_pdf_vector)
{
	uint8_t priv[NUKI_KEY_LEN], peer_pub[NUKI_KEY_LEN];
	uint8_t expected_k[NUKI_KEY_LEN], k[NUKI_KEY_LEN];

	zassert_equal(nuki_crypto_init(), 0, "psa init failed");

	test_hex2bin(priv, "C11CFB400A3A33414E89F9E6607271C2AF076405C5407984297F1DE0E7A54B73");
	test_hex2bin(peer_pub, "DC040AFE6401550E1F7B20AB50135B80765834B9D898E6DA7129F61C62929B78");
	test_hex2bin(expected_k, "AB7D99698BF549F9AE80EA4D140D29D9B169C18533E5267D9E276F163B5C0B08");

	zassert_equal(nuki_crypto_dh1(k, priv, peer_pub), 0, "dh1 failed");
	zassert_mem_equal(k, expected_k, NUKI_KEY_LEN, "dh1 result mismatch");
}

ZTEST(nuki_crypto, test_kdf1_matches_pdf_vector)
{
	uint8_t k[NUKI_KEY_LEN], expected_s[NUKI_KEY_LEN], s[NUKI_KEY_LEN];

	test_hex2bin(k, "AB7D99698BF549F9AE80EA4D140D29D9B169C18533E5267D9E276F163B5C0B08");
	test_hex2bin(expected_s, "915561587D86815B709EDD5819D8C6F2E883DA3C86F461F13B84228B84533E04");

	nuki_crypto_kdf1(s, k);
	zassert_mem_equal(s, expected_s, NUKI_KEY_LEN, "kdf1 result mismatch");
}

/* --- Read lock state example ---
 * Shared key: 217FCB0F18CAF284E9BDEA0B94B83B8D10867ED706BFDEDBD2381F4CB3B8F730
 * Authorization-ID: 2
 * Plaintext PDATA (authId|cmdId=RequestData|payload=KeyturnerStates|crc):
 *   0200000001000C00418D
 * Full wire message (nonce[24] | authId[4] | msgLen[2] | tag[16] | ct[10]):
 *   37917F1AF31EC5940705F34D1E5550607D5B2F9FE7D496B6
 *   020000001A00
 *   670D124926004366532E8D927A33FE84E782A9594D39157D065E
 */

#define WIRE_HEX                                                                                 \
	"37917F1AF31EC5940705F34D1E5550607D5B2F9FE7D496B6"                                       \
	"020000001A00"                                                                            \
	"670D124926004366532E8D927A33FE84E782A9594D39157D065E"

#define PLAINTEXT_HEX "0200000001000C00418D"
#define SHARED_KEY_HEX "217FCB0F18CAF284E9BDEA0B94B83B8D10867ED706BFDEDBD2381F4CB3B8F730"

ZTEST(nuki_crypto, test_e1_matches_pdf_vector)
{
	uint8_t wire[128], key[NUKI_KEY_LEN], plaintext[64];
	uint8_t nonce[NUKI_NONCE_LEN];
	uint8_t out[64];
	size_t wire_len, plain_len;
	size_t ct_len;

	wire_len = test_hex2bin(wire, WIRE_HEX);
	plain_len = test_hex2bin(plaintext, PLAINTEXT_HEX);
	test_hex2bin(key, SHARED_KEY_HEX);

	/* nonce(24) | authId(4) | msgLen(2) | tag(16) | ciphertext */
	zassert_equal(wire_len, 24 + 4 + 2 + NUKI_TAG_LEN + plain_len,
		      "unexpected wire length %zu", wire_len);

	memcpy(nonce, wire, NUKI_NONCE_LEN);
	zassert_equal(wire[24], 2, "authId low byte");
	zassert_equal(wire[25], 0, "authId byte1");
	zassert_equal(wire[26], 0, "authId byte2");
	zassert_equal(wire[27], 0, "authId byte3");

	ct_len = wire[28] | (wire[29] << 8);
	zassert_equal(ct_len, NUKI_TAG_LEN + plain_len, "msgLen field mismatch");

	zassert_equal(nuki_crypto_e1(out, plaintext, plain_len, nonce, key), 0, "e1 failed");
	zassert_mem_equal(out, wire + 30, NUKI_TAG_LEN + plain_len,
			   "e1 output does not match PDF ciphertext");
}

ZTEST(nuki_crypto, test_d1_matches_pdf_vector)
{
	uint8_t wire[128], key[NUKI_KEY_LEN], expected_plain[64];
	uint8_t nonce[NUKI_NONCE_LEN];
	uint8_t decrypted[64];
	size_t plain_len;

	test_hex2bin(wire, WIRE_HEX);
	plain_len = test_hex2bin(expected_plain, PLAINTEXT_HEX);
	test_hex2bin(key, SHARED_KEY_HEX);
	memcpy(nonce, wire, NUKI_NONCE_LEN);

	zassert_equal(nuki_crypto_d1(decrypted, wire + 30, plain_len, nonce, key), 0,
		      "d1 failed to authenticate/decrypt PDF ciphertext");
	zassert_mem_equal(decrypted, expected_plain, plain_len, "d1 plaintext mismatch");
}

ZTEST(nuki_crypto, test_d1_rejects_corrupted_tag)
{
	uint8_t wire[128], key[NUKI_KEY_LEN];
	uint8_t nonce[NUKI_NONCE_LEN];
	uint8_t decrypted[64];
	uint8_t tampered[64];

	test_hex2bin(wire, WIRE_HEX);
	test_hex2bin(key, SHARED_KEY_HEX);
	memcpy(nonce, wire, NUKI_NONCE_LEN);
	memcpy(tampered, wire + 30, NUKI_TAG_LEN + 10);
	tampered[0] ^= 0xFF;

	zassert_equal(nuki_crypto_d1(decrypted, tampered, 10, nonce, key), -EBADMSG,
		      "d1 must reject a tampered tag");
}

ZTEST(nuki_crypto, test_e1_d1_self_roundtrip)
{
	uint8_t key[NUKI_KEY_LEN] = {0};
	uint8_t nonce[NUKI_NONCE_LEN] = {0};
	const uint8_t msg[] = "arbitrary Nuki command payload, any length";
	uint8_t encrypted[16 + sizeof(msg)];
	uint8_t decrypted[sizeof(msg)];

	for (int i = 0; i < NUKI_KEY_LEN; i++) {
		key[i] = (uint8_t)(i * 7 + 1);
	}
	for (int i = 0; i < NUKI_NONCE_LEN; i++) {
		nonce[i] = (uint8_t)(i * 3 + 2);
	}

	zassert_equal(nuki_crypto_e1(encrypted, msg, sizeof(msg), nonce, key), 0, "e1 failed");
	zassert_equal(nuki_crypto_d1(decrypted, encrypted, sizeof(msg), nonce, key), 0, "d1 failed");
	zassert_mem_equal(decrypted, msg, sizeof(msg), "round-trip mismatch");
}

ZTEST(nuki_crypto, test_crc16_over_pdf_plaintext)
{
	uint8_t plaintext[64];
	size_t len = test_hex2bin(plaintext, PLAINTEXT_HEX);
	uint16_t crc = nuki_crc16(plaintext, len - 2);
	uint16_t expected_le = plaintext[len - 2] | (plaintext[len - 1] << 8);
	uint16_t expected_be = (plaintext[len - 2] << 8) | plaintext[len - 1];

	zassert_true(crc == expected_le || crc == expected_be,
		     "crc16 0x%04x matches neither LE 0x%04x nor BE 0x%04x wire encoding",
		     crc, expected_le, expected_be);
}
