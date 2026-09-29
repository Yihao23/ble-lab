/**
 * @file  test_rpa.c
 * @brief Tests for address classification, `ah()` and RPA make/resolve.
 */
#include "check.h"
#include "ble/ble_rpa.h"

/** @brief IRK from Core Spec Vol 3 Part H, Appendix D.7, MSB-first. */
static const unsigned char SPEC_IRK[16] = {
    0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05,
    0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
static const unsigned char SPEC_PRAND[3] = {0x70, 0x81, 0x94};   /**< prand from Appendix D.7. */
static const unsigned char SPEC_HASH[3]  = {0x0d, 0xfb, 0xaa};   /**< Expected `ah(SPEC_IRK, SPEC_PRAND)`. */

/**
 * @brief RPA tests.
 *
 * The spec's `ah()` vector; make() on the spec's prand; resolve with the
 * right key, and not with a wrong key, a flipped hash bit, or a static
 * address; resolve_any() returning the first matching index; make() forcing
 * the top bits to 01 and refusing an all-0 or all-1 random part; all four
 * top-bit patterns plus a public address; ble_addr_kind_str().
 */
void suite_rpa(void)
{
    SUITE("rpa");
    unsigned char hash[3];

    /* The spec's own test vector. */
    ble_ah(SPEC_IRK, SPEC_PRAND, hash);
    CHECK_MEM(hash, SPEC_HASH, 3);

    /* 0x70 = 0b0111_0000: prand already starts 01, so make() keeps it as is.
     * The RPA is 70:81:94:0D:FB:AA, stored LSB-first. */
    unsigned char addr[6];
    const unsigned char expect[6] = {0xaa, 0xfb, 0x0d, 0x94, 0x81, 0x70};
    CHECK(ble_rpa_make(SPEC_IRK, SPEC_PRAND, addr));
    CHECK_MEM(addr, expect, 6);

    /* It resolves with the right IRK ... */
    CHECK(ble_rpa_resolve(SPEC_IRK, addr));
    CHECK_EQ(ble_addr_classify(true, addr), BLE_ADDR_RPA);

    /* ... and not with any other. */
    unsigned char other[16];
    memcpy(other, SPEC_IRK, 16);
    other[15] ^= 0x01;
    CHECK(!ble_rpa_resolve(other, addr));

    /* One flipped bit in the hash breaks resolution. */
    unsigned char bad[6];
    memcpy(bad, addr, 6);
    bad[0] ^= 0x01;
    CHECK(!ble_rpa_resolve(SPEC_IRK, bad));

    /* A static address never resolves, even if its low bytes happen to match. */
    memcpy(bad, addr, 6);
    bad[5] = (unsigned char)((bad[5] & 0x3F) | 0xC0);
    CHECK(!ble_rpa_resolve(SPEC_IRK, bad));

    /* resolve_any returns the index of the IRK that matches. */
    unsigned char list[3][16];
    memcpy(list[0], other, 16);
    memcpy(list[1], SPEC_IRK, 16);
    memcpy(list[2], SPEC_IRK, 16);
    CHECK_EQ(ble_rpa_resolve_any((const unsigned char (*)[16])list, 3, addr), 1);
    CHECK_EQ(ble_rpa_resolve_any((const unsigned char (*)[16])list, 1, addr), -1);

    /* make() forces the top two bits to 01 whatever prand contains. */
    const unsigned char hi[3] = {0xFF, 0x12, 0x34};
    CHECK(ble_rpa_make(SPEC_IRK, hi, addr));
    CHECK_EQ(addr[5] >> 6, 1);
    CHECK(ble_rpa_resolve(SPEC_IRK, addr));

    /* The 22 random bits may not be all 0 or all 1. */
    const unsigned char zeros[3] = {0x40, 0x00, 0x00};
    const unsigned char ones[3]  = {0x7F, 0xFF, 0xFF};
    CHECK(!ble_rpa_make(SPEC_IRK, zeros, addr));
    CHECK(!ble_rpa_make(SPEC_IRK, ones, addr));

    /* Classification by the two most significant bits of addr[5]. */
    unsigned char a[6] = {0, 0, 0, 0, 0, 0};
    a[5] = 0xC1; CHECK_EQ(ble_addr_classify(true, a),  BLE_ADDR_RANDOM_STATIC);
    a[5] = 0x41; CHECK_EQ(ble_addr_classify(true, a),  BLE_ADDR_RPA);
    a[5] = 0x01; CHECK_EQ(ble_addr_classify(true, a),  BLE_ADDR_NRPA);
    a[5] = 0x81; CHECK_EQ(ble_addr_classify(true, a),  BLE_ADDR_RANDOM_RESERVED);
    a[5] = 0x41; CHECK_EQ(ble_addr_classify(false, a), BLE_ADDR_PUBLIC);
    CHECK(strcmp(ble_addr_kind_str(BLE_ADDR_RPA), "rpa") == 0);
}
