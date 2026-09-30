/**
 * @file  ble_cmac.h
 * @brief AES-CMAC (RFC 4493): the MAC every LE Secure Connections function uses.
 *
 * f4 (confirm values), f5 (key generation), f6 (DHKey checks), g2 (numeric
 * comparison), h6 and h7 (key conversion) are all one AES-CMAC call with
 * differently arranged inputs (Core Vol 3 Part H, 2.2.5 to 2.2.11).
 *
 * @par Byte order
 * Keys, messages and MACs are MSB-first, as in RFC 4493 and in the test
 * vectors of Core Vol 3 Part H Appendix D.
 *
 * @defgroup ble_cmac AES-CMAC
 * @brief AES-CMAC over a contiguous message, built on ble_aes128_encrypt().
 * @{
 */
#ifndef BLE_CMAC_H
#define BLE_CMAC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Derive the CMAC subkeys K1 and K2 (RFC 4493, 2.3).
 *
 * L = AES-128(key, 0¹²⁸). K1 = L << 1, XORed with Rb = 0x87 in the last
 * octet if the most significant bit of L was 1. K2 is K1 treated the same way.
 *
 * @param[in]  key  128-bit key, MSB-first.
 * @param[out] k1   Subkey K1, used when the last block is complete.
 * @param[out] k2   Subkey K2, used when the last block had to be padded.
 */
void ble_cmac_subkeys(const uint8_t key[16], uint8_t k1[16], uint8_t k2[16]);

/**
 * @brief Compute AES-CMAC over a message (RFC 4493, 2.4).
 *
 * @param[in]  key  128-bit key, MSB-first.
 * @param[in]  msg  Message; may be NULL when @p len is 0.
 * @param[in]  len  Message length in bytes, any value including 0.
 * @param[out] mac  128-bit MAC, MSB-first. Must not overlap @p key or @p msg.
 *
 * @note No heap and no copy of the message: it is read one 16-byte block at
 *       a time. Subkeys and intermediate state are wiped before returning.
 */
void ble_aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t mac[16]);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* BLE_CMAC_H */
