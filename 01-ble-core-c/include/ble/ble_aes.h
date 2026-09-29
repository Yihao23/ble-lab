/**
 * @file  ble_aes.h
 * @brief AES-128 block encryption — the only cipher operation BLE security needs.
 *
 * The Bluetooth security toolbox (Core Spec Vol 3 Part H, section 2.2) builds
 * every function on e(key, plaintext) = AES-128 encrypt. Decryption is never
 * used, so it is not implemented: less flash, less attack surface.
 *
 * @par Byte order
 * FIPS-197 order, most significant octet first. This is also the order the
 * spec prints its test vectors in. Over the air and over HCI, BLE sends keys
 * least significant octet first — callers must reverse at that boundary, and
 * that boundary is where most BLE crypto bugs live.
 *
 * @defgroup ble_aes AES-128
 * @brief Single-block AES-128 encryption for the BLE security functions.
 * @{
 */
#ifndef BLE_AES_H
#define BLE_AES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypt one 16-byte block with AES-128: `out = AES-128(key, in)`.
 *
 * The expanded key schedule (176 bytes) lives on the stack and is wiped
 * before returning, so no key material outlives the call.
 *
 * @param[in]  key  128-bit key, MSB-first.
 * @param[in]  in   Plaintext block, MSB-first.
 * @param[out] out  Ciphertext block, MSB-first. May alias @p in.
 *
 * @note Uses a lookup-table S-box: not constant-time against cache-timing
 *       attacks. Irrelevant on a cache-less Cortex-M0+; on larger cores use
 *       the controller's `HCI_LE_Encrypt` or a hardware AES block.
 */
void ble_aes128_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* BLE_AES_H */
