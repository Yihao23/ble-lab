/**
 * @file  ble_rpa.c
 * @brief Address classification and Resolvable Private Addresses — implementation.
 *
 * Byte-order bridge: `ah()` works MSB-first like the spec's test vectors,
 * addresses are LSB-first like HCI. The reversals happen here and nowhere else.
 */
#include "ble/ble_rpa.h"
#include "ble/ble_aes.h"
#include "ble_util.h"

/**
 * @par Implementation
 * Classify an address by the type bit and the two most significant bits.
 *
 * `addr[5] >> 6` extracts the top two bits of the most significant octet,
 * which is the last byte in LSB-first order.
 */
ble_addr_kind_t ble_addr_classify(bool is_random, const uint8_t addr[6])
{
    if (!is_random) {
        return BLE_ADDR_PUBLIC;
    }
    switch (addr[5] >> 6) {             /* two most significant bits */
    case 0x3: return BLE_ADDR_RANDOM_STATIC;
    case 0x1: return BLE_ADDR_RPA;
    case 0x0: return BLE_ADDR_NRPA;
    default:  return BLE_ADDR_RANDOM_RESERVED;
    }
}

/**
 * @par Implementation
 * Map an address kind to a fixed string.
 *
 * The switch has no default so the compiler warns if a kind is added without
 * a name; the return after it catches values outside the enum.
 */
const char *ble_addr_kind_str(ble_addr_kind_t kind)
{
    switch (kind) {
    case BLE_ADDR_PUBLIC:          return "public";
    case BLE_ADDR_RANDOM_STATIC:   return "random-static";
    case BLE_ADDR_RPA:             return "rpa";
    case BLE_ADDR_NRPA:            return "nrpa";
    case BLE_ADDR_RANDOM_RESERVED: return "reserved";
    }
    return "unknown";
}

/**
 * @par Implementation
 * Compute `ah(IRK, r)`.
 *
 * Builds r' by placing r in the last three octets of a zeroed block (MSB-first,
 * so these are the least significant), encrypts, and keeps the last three
 * octets of the result, which is the "mod 2^24". The full ciphertext is wiped.
 *
 * The block is zeroed with ble_wipe(), not `= {0}`: for that initialiser GCC
 * emitted a call to memset on Cortex-M0+, which a build without libc cannot
 * link. Stores through a volatile pointer cannot be turned into a call.
 */
void ble_ah(const uint8_t irk[16], const uint8_t r[3], uint8_t hash[3])
{
    uint8_t block[16];
    uint8_t enc[16];

    ble_wipe(block, sizeof block);

    /* r' = 104 zero bits || r: r sits in the three least significant octets. */
    block[13] = r[0];
    block[14] = r[1];
    block[15] = r[2];
    ble_aes128_encrypt(irk, block, enc);

    /* mod 2^24: keep the three least significant octets. */
    hash[0] = enc[13];
    hash[1] = enc[14];
    hash[2] = enc[15];
    ble_wipe(enc, sizeof enc);
}

/**
 * @par Implementation
 * Build an RPA: force the top bits of prand to 01, reject a degenerate
 * random part, hash, and lay the result out LSB-first.
 *
 * The all-zeros / all-ones test masks off the two type bits first: only the
 * 22 random bits are constrained. @p addr is written only after the check
 * passes.
 */
bool ble_rpa_make(const uint8_t irk[16], const uint8_t prand[3], uint8_t addr[6])
{
    uint8_t p[3] = {(uint8_t)((prand[0] & 0x3Fu) | 0x40u), prand[1], prand[2]};
    uint8_t hash[3];

    /* The 22 random bits of prand shall not be all 0 or all 1 (Vol 6 B 1.3.2.2). */
    uint8_t lo6 = (uint8_t)(p[0] & 0x3Fu);
    bool all0 = (lo6 == 0x00u) && (p[1] == 0x00u) && (p[2] == 0x00u);
    bool all1 = (lo6 == 0x3Fu) && (p[1] == 0xFFu) && (p[2] == 0xFFu);
    if (all0 || all1) {
        return false;
    }

    ble_ah(irk, p, hash);
    addr[5] = p[0];
    addr[4] = p[1];
    addr[3] = p[2];
    addr[2] = hash[0];
    addr[1] = hash[1];
    addr[0] = hash[2];
    return true;
}

/**
 * @par Implementation
 * Resolve one address against one IRK.
 *
 * Reverses prand out of the LSB-first address into MSB-first order, recomputes
 * the hash, and compares with an OR of XORs instead of `memcmp`, so there is
 * no early exit on the first differing byte. A non-RPA is rejected before
 * any AES is spent on it.
 */
bool ble_rpa_resolve(const uint8_t irk[16], const uint8_t addr[6])
{
    if ((addr[5] >> 6) != 0x1u) {
        return false;                   /* not an RPA at all */
    }
    const uint8_t prand[3] = {addr[5], addr[4], addr[3]};
    uint8_t hash[3];
    ble_ah(irk, prand, hash);

    /* Compare without an early exit, so time does not depend on where it differs. */
    uint8_t diff = (uint8_t)((hash[0] ^ addr[2]) | (hash[1] ^ addr[1]) | (hash[2] ^ addr[0]));
    return diff == 0u;
}

/**
 * @par Implementation
 * Resolve an address against every IRK in a list.
 *
 * Runs ble_rpa_resolve() for all @p n_irks keys and remembers the first hit,
 * so the number of AES operations depends only on the list length, not on
 * which entry matched.
 */
int ble_rpa_resolve_any(const uint8_t (*irks)[16], size_t n_irks, const uint8_t addr[6])
{
    /* No early exit: every key costs one AES whether or not an earlier one
     * matched, so the time taken does not say which bonded device this was. */
    int found = -1;
    for (size_t i = 0; i < n_irks; i++) {
        bool hit = ble_rpa_resolve(irks[i], addr);
        if (hit && found < 0) {
            found = (int)i;
        }
    }
    return found;
}
