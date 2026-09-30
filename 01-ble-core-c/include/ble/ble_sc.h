/**
 * @file  ble_sc.h
 * @brief LE Secure Connections pairing functions (Core Vol 3 Part H, 2.2).
 *
 * @par Numeric comparison
 * During pairing with numeric comparison, both devices compute
 * g2(PKax, PKbx, Na, Nb) from the two public keys' x-coordinates and the two
 * nonces, and show its last six decimal digits. The user confirms that both
 * screens agree. A man in the middle, holding a different key pair with each
 * side, makes the two numbers differ.
 *
 * @par Byte order
 * All inputs MSB-first, as in the test vectors of Appendix D. Over the air
 * SMP sends public keys and nonces least significant octet first: reverse
 * them before calling.
 *
 * @defgroup ble_sc LE Secure Connections
 * @brief Numeric comparison value generation.
 * @{
 */
#ifndef BLE_SC_H
#define BLE_SC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The numeric comparison value generation function g2 (Core Vol 3
 *        Part H, 2.2.9).
 *
 * @f[ g2(U, V, X, Y) = \mathrm{AES\text{-}CMAC}_X(U \,\|\, V \,\|\, Y) \bmod 2^{32} @f]
 *
 * @param[in] u  256 bits, PKax: x-coordinate of the initiator's public key.
 * @param[in] v  256 bits, PKbx: x-coordinate of the responder's public key.
 * @param[in] x  128 bits, Na: the initiator's nonce, used as the CMAC key.
 * @param[in] y  128 bits, Nb: the responder's nonce.
 * @return The 32 least significant bits of the MAC, as an integer.
 *
 * @par Test vector (Core Vol 3 Part H, Appendix D.5)
 * AES-CMAC `1536d18d e3d20df9 9b7044c1 2f9ed5ba` → g2 = `0x2f9ed5ba`.
 */
uint32_t ble_sc_g2(const uint8_t u[32], const uint8_t v[32],
                   const uint8_t x[16], const uint8_t y[16]);

/**
 * @brief The six digits a user compares: g2 mod 10⁶.
 *
 * @param[in] g2  Output of ble_sc_g2().
 * @return 0 to 999999. Display it zero-padded to six digits.
 *
 * @par Example (Core Vol 3 Part H, 2.2.9)
 * 0x012eb72a = 19838762 → 838762.
 */
uint32_t ble_sc_compare_value(uint32_t g2);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* BLE_SC_H */
