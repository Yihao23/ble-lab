/**
 * @file  ble_rpa.h
 * @brief BLE device addresses and Resolvable Private Addresses (RPA).
 *
 * A BLE device broadcasts its address in every advertising packet. A fixed
 * address lets anyone with a radio follow the device from room to room. An
 * RPA changes every few minutes, yet a bonded peer that holds the device's
 * Identity Resolving Key (IRK) can still recognise it. Everyone else sees an
 * unlinkable stream of fresh addresses (Lecture 10: identifier rotation).
 *
 * @par Byte order
 * Addresses are **LSB-first**, exactly as they appear in HCI packets, on air,
 * and in Linux's `bdaddr_t`. So `addr[5]` is the most significant octet — the
 * "AA" in the human string AA:BB:CC:DD:EE:FF. Keys, `prand` and hashes are
 * **MSB-first**, as in the spec's test vectors.
 *
 * @par RPA layout (Core Spec Vol 6 Part B, 1.3.2.2)
 * @verbatim
   MSB                                              LSB
   | 01 | prand (22 random bits) |      hash (24 bits)     |
   addr[5]  addr[4]   addr[3]     addr[2]  addr[1]  addr[0]

   hash = ah(IRK, prand)
   @endverbatim
 *
 * @defgroup ble_rpa Addresses and RPA
 * @brief Classify addresses; make and resolve Resolvable Private Addresses.
 * @{
 */
#ifndef BLE_RPA_H
#define BLE_RPA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Kind of a BLE device address, decided by the type bit and the top two bits. */
typedef enum {
    BLE_ADDR_PUBLIC = 0,        /**< IEEE-assigned, never changes. */
    BLE_ADDR_RANDOM_STATIC,     /**< Random, top bits `11`; fixed until power cycle. */
    BLE_ADDR_RPA,               /**< Resolvable private address, top bits `01`. */
    BLE_ADDR_NRPA,              /**< Non-resolvable private address, top bits `00`. */
    BLE_ADDR_RANDOM_RESERVED    /**< Top bits `10`: not a valid random address. */
} ble_addr_kind_t;

/**
 * @brief Classify an address.
 *
 * @param[in] is_random  The TxAdd/RxAdd bit, i.e. `HCI address type & 1`.
 * @param[in] addr       6-byte address, LSB-first.
 * @return The address kind. A reserved random address is reported as
 *         ::BLE_ADDR_RANDOM_RESERVED, never rejected: a parser of the air must
 *         describe what it saw.
 */
ble_addr_kind_t ble_addr_classify(bool is_random, const uint8_t addr[6]);

/**
 * @brief Human-readable name of an address kind, for logs and tools.
 *
 * @param[in] kind  Any value, including ones outside the enum.
 * @return A static string such as `"rpa"`; `"unknown"` for out-of-range
 *         values. Never NULL.
 */
const char *ble_addr_kind_str(ble_addr_kind_t kind);

/**
 * @brief The random address hash function `ah` (Core Vol 3 Part H, 2.2.2).
 *
 * @f[ ah(k, r) = e(k, r') \bmod 2^{24}, \qquad r' = 0^{104} \,\|\, r @f]
 *
 * @param[in]  irk   Identity Resolving Key, 16 bytes, MSB-first.
 * @param[in]  r     24-bit `prand`, 3 bytes, MSB-first.
 * @param[out] hash  24-bit result, 3 bytes, MSB-first.
 *
 * @par Test vector (Core Vol 3 Part H, Appendix D.7)
 * IRK `ec0234a357c8ad05341010a60a397d9b`, prand `708194` → hash `0dfbaa`.
 */
void ble_ah(const uint8_t irk[16], const uint8_t r[3], uint8_t hash[3]);

/**
 * @brief Build an RPA from an IRK and 24 bits of randomness.
 *
 * The two most significant bits of @p prand are overwritten with `01`.
 *
 * @param[in]  irk    Identity Resolving Key, MSB-first.
 * @param[in]  prand  24 random bits, MSB-first (e.g. from the controller's
 *                    `HCI_LE_Rand` or a TRNG).
 * @param[out] addr   The RPA, 6 bytes, LSB-first.
 * @retval true   @p addr holds a valid RPA.
 * @retval false  The 22 random bits are all 0 or all 1, which the spec forbids
 *                (Vol 6 Part B 1.3.2.2); @p addr is left untouched.
 */
bool ble_rpa_make(const uint8_t irk[16], const uint8_t prand[3], uint8_t addr[6]);

/**
 * @brief Check whether an address is an RPA generated with a given IRK.
 *
 * Recomputes `ah(IRK, prand)` and compares it with the hash part of the
 * address without an early exit, so the time taken does not reveal how many
 * hash bytes matched.
 *
 * @param[in] irk   Identity Resolving Key, MSB-first.
 * @param[in] addr  Address to test, LSB-first.
 * @retval true   @p addr is an RPA and resolves with @p irk.
 * @retval false  It is not an RPA (top bits not `01`), or the hash differs.
 */
bool ble_rpa_resolve(const uint8_t irk[16], const uint8_t addr[6]);

/**
 * @brief Resolve an address against a list of IRKs, e.g. a bonding table.
 *
 * Every key is tried even after a match — one AES per key regardless — so
 * the time taken is set by the length of the list, not by which bonded
 * device the address belongs to.
 *
 * @param[in] irks    Array of @p n_irks keys, each MSB-first.
 * @param[in] n_irks  Number of keys; 0 is allowed.
 * @param[in] addr    Address to resolve, LSB-first.
 * @return Index of the first matching IRK, or -1 if none matches.
 */
int ble_rpa_resolve_any(const uint8_t (*irks)[16], size_t n_irks, const uint8_t addr[6]);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* BLE_RPA_H */
