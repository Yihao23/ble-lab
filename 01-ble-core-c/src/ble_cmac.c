/**
 * @file  ble_cmac.c
 * @brief AES-CMAC (RFC 4493) — implementation.
 */
#include <stdbool.h>

#include "ble/ble_cmac.h"
#include "ble/ble_aes.h"
#include "ble_util.h"

/** @brief The constant Rb for a 128-bit block (RFC 4493, 2.3). */
#define CMAC_RB 0x87u

/**
 * @brief Double a 128-bit value in GF(2^128): shift left by one bit, and if
 *        a 1 fell off the top, XOR Rb into the last octet.
 *
 * Each octet takes its own bits shifted up, plus the top bit of the octet
 * after it. The XOR is done with a multiply by 0 or 1 rather than an `if`,
 * so the time taken does not depend on the secret bit.
 *
 * @param[in]  in   Value to double, MSB-first.
 * @param[out] out  Result, MSB-first. May alias @p in.
 */
static void cmac_double(const uint8_t in[16], uint8_t out[16])
{
    uint8_t msb = (uint8_t)(in[0] >> 7);

    for (unsigned i = 0; i < 15u; i++) {
        out[i] = (uint8_t)((uint8_t)(in[i] << 1) | (uint8_t)(in[i + 1u] >> 7));
    }
    out[15] = (uint8_t)((uint8_t)(in[15] << 1) ^ (uint8_t)(msb * CMAC_RB));
}

/**
 * @par Implementation
 * L = AES-128(key, 0¹²⁸), then K1 = double(L) and K2 = double(K1). L is
 * derived from the key and wiped before returning.
 */
void ble_cmac_subkeys(const uint8_t key[16], uint8_t k1[16], uint8_t k2[16])
{
    uint8_t l[16];

    ble_wipe(l, sizeof l);                  /* the all-zero block */
    ble_aes128_encrypt(key, l, l);          /* L = AES-128(key, 0) */
    cmac_double(l, k1);
    cmac_double(k1, k2);
    ble_wipe(l, sizeof l);
}

/**
 * @par Implementation
 * CBC-MAC over the message with the last block masked by a subkey:
 *
 *     X = 0
 *     for every block but the last:  X = AES(key, X ^ block)
 *     MAC = AES(key, X ^ last')
 *
 * where last' is the last block XOR K1 if it is a full 16 bytes, or the
 * remaining bytes padded with 0x80 then zeros and XOR K2 if it is not. An
 * empty message is one padded block. The message is read in place, one block
 * at a time; only X, the subkeys and last' live on the stack, and all of them
 * are wiped before returning.
 */
void ble_aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t mac[16])
{
    uint8_t k1[16], k2[16];
    uint8_t x[16];                          /* the running CBC state */
    uint8_t last[16];                       /* the last block, padded and masked */

    ble_cmac_subkeys(key, k1, k2);

    /* Number of blocks, and whether the last one is complete. */
    size_t n = (len + 15u) / 16u;
    bool complete = (n > 0u) && (len % 16u == 0u);
    if (n == 0u) {
        n = 1u;                             /* the empty message is one padded block */
    }

    /* Every block but the last: X = AES(key, X ^ block). */
    ble_wipe(x, sizeof x);
    for (size_t b = 0; b + 1u < n; b++) {
        const uint8_t *block = &msg[16u * b];
        for (unsigned i = 0; i < 16u; i++) {
            x[i] ^= block[i];
        }
        ble_aes128_encrypt(key, x, x);
    }

    /* The last block: complete -> XOR K1; partial -> pad 80 00 .. 00, XOR K2. */
    size_t off = 16u * (n - 1u);
    size_t rem = len - off;                 /* bytes of message in the last block, 0..16 */
    const uint8_t *k = complete ? k1 : k2;
    for (unsigned i = 0; i < 16u; i++) {
        uint8_t m;
        if (i < rem) {
            m = msg[off + i];
        } else if (i == rem) {
            m = 0x80u;                      /* the single 1 bit that starts the padding */
        } else {
            m = 0x00u;
        }
        last[i] = (uint8_t)(m ^ k[i]);
    }

    for (unsigned i = 0; i < 16u; i++) {
        x[i] ^= last[i];
    }
    ble_aes128_encrypt(key, x, mac);

    ble_wipe(k1, sizeof k1);
    ble_wipe(k2, sizeof k2);
    ble_wipe(x, sizeof x);
    ble_wipe(last, sizeof last);
}
