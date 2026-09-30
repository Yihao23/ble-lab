/**
 * @file  ble_sc.c
 * @brief LE Secure Connections pairing functions — implementation.
 */
#include "ble/ble_sc.h"
#include "ble/ble_cmac.h"
#include "ble_util.h"

/**
 * @par Implementation
 * Lays out m = U || V || Y (32 + 32 + 16 = 80 octets) on the stack in the
 * order the spec gives, MSB-first, takes AES-CMAC over it with X as the key,
 * and reads the last four octets of the MAC as a big-endian integer: that is
 * the "mod 2^32". The message and MAC are wiped before returning.
 */
uint32_t ble_sc_g2(const uint8_t u[32], const uint8_t v[32],
                   const uint8_t x[16], const uint8_t y[16])
{
    uint8_t m[32 + 32 + 16];
    uint8_t mac[16];

    ble_copy(&m[0],  u, 32);
    ble_copy(&m[32], v, 32);
    ble_copy(&m[64], y, 16);
    ble_aes_cmac(x, m, sizeof m, mac);

    uint32_t g2 = ((uint32_t)mac[12] << 24) | ((uint32_t)mac[13] << 16) |
                  ((uint32_t)mac[14] << 8)  |  (uint32_t)mac[15];

    ble_wipe(m, sizeof m);
    ble_wipe(mac, sizeof mac);
    return g2;
}

/**
 * @par Implementation
 * The six least significant decimal digits: the remainder after dividing by
 * one million. The result always fits in six digits, so the caller pads it
 * with leading zeros when displaying (42 is shown as "000042").
 */
uint32_t ble_sc_compare_value(uint32_t g2)
{
    return g2 % 1000000u;
}
