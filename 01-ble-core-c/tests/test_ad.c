/**
 * @file  test_ad.c
 * @brief Tests for the Advertising Data iterator and helpers.
 */
#include "check.h"
#include "ble/ble_ad.h"

/**
 * @brief AD parser tests.
 *
 * A four-structure payload walked field by field (flags, name, UUID16 list,
 * Apple manufacturer data), including an out-of-range UUID index and a
 * sticky END; find() hit and miss; zero padding; a length that overruns the
 * buffer; a dangling length byte; a type-only structure; empty and NULL
 * input; and manufacturer data too short for a company ID.
 */
void suite_ad(void)
{
    SUITE("ad");
    ble_ad_iter_t it;
    ble_ad_t ad;

    /* flags | complete name "BLE-Lab" | UUID16 list 0x180D 0x180F | Apple mfr data */
    const unsigned char adv[] = {
        0x02, 0x01, 0x06,
        0x08, 0x09, 'B', 'L', 'E', '-', 'L', 'a', 'b',
        0x05, 0x03, 0x0D, 0x18, 0x0F, 0x18,
        0x05, 0xFF, 0x4C, 0x00, 0x12, 0x34};

    ble_ad_iter_init(&it, adv, sizeof adv);
    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_OK);
    CHECK_EQ(ad.type, BLE_AD_FLAGS);
    CHECK_EQ(ad.len, 1);
    CHECK_EQ(ad.data[0], BLE_AD_FLAG_LE_GENERAL | BLE_AD_FLAG_NO_BREDR);

    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_OK);
    CHECK_EQ(ad.type, BLE_AD_NAME_COMPLETE);
    CHECK_EQ(ad.len, 7);
    CHECK(memcmp(ad.data, "BLE-Lab", 7) == 0);

    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_OK);
    CHECK_EQ(ble_ad_uuid16_count(&ad), 2);
    CHECK_EQ(ble_ad_uuid16_at(&ad, 0), 0x180D);
    CHECK_EQ(ble_ad_uuid16_at(&ad, 1), 0x180F);
    CHECK_EQ(ble_ad_uuid16_at(&ad, 2), 0);          /* out of range is 0, not a read */

    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_OK);
    unsigned short cid = 0;
    const unsigned char *pl = NULL;
    unsigned char pl_len = 0;
    CHECK(ble_ad_manufacturer(&ad, &cid, &pl, &pl_len));
    CHECK_EQ(cid, 0x004C);                          /* little-endian on air */
    CHECK_EQ(pl_len, 2);
    CHECK_EQ(pl[0], 0x12);

    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_END);
    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_END);    /* END is sticky */
    CHECK(ble_ad_is_well_formed(adv, sizeof adv));

    /* find() */
    CHECK(ble_ad_find(adv, sizeof adv, BLE_AD_NAME_COMPLETE, &ad));
    CHECK_EQ(ad.len, 7);
    CHECK(!ble_ad_find(adv, sizeof adv, BLE_AD_TX_POWER, &ad));

    /* Zero-length field = padding: everything after it is ignored. */
    const unsigned char padded[] = {0x02, 0x01, 0x06, 0x00, 0xFF, 0xFF, 0xFF};
    CHECK(ble_ad_is_well_formed(padded, sizeof padded));
    ble_ad_iter_init(&it, padded, sizeof padded);
    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_OK);
    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_END);

    /* Length says 5, only 3 bytes follow: reported, not over-read. */
    const unsigned char trunc[] = {0x02, 0x01, 0x06, 0x05, 0x09, 'a', 'b'};
    ble_ad_iter_init(&it, trunc, sizeof trunc);
    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_OK);
    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_ERR_TRUNCATED);
    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_END);
    CHECK(!ble_ad_is_well_formed(trunc, sizeof trunc));

    /* A length byte as the very last byte, pointing at nothing. */
    const unsigned char dangling[] = {0x02, 0x01, 0x06, 0x03};
    CHECK(!ble_ad_is_well_formed(dangling, sizeof dangling));

    /* A structure that is exactly type-only (len 1) is legal: zero data bytes. */
    const unsigned char type_only[] = {0x01, 0x09};
    ble_ad_iter_init(&it, type_only, sizeof type_only);
    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_OK);
    CHECK_EQ(ad.len, 0);

    /* Empty and NULL buffers end immediately. */
    ble_ad_iter_init(&it, adv, 0);
    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_END);
    ble_ad_iter_init(&it, NULL, 99);
    CHECK_EQ(ble_ad_next(&it, &ad), BLE_AD_END);

    /* Manufacturer data too short to hold a company ID. */
    const unsigned char short_mfr[] = {0x02, 0xFF, 0x4C};
    CHECK(ble_ad_find(short_mfr, sizeof short_mfr, BLE_AD_MANUFACTURER, &ad));
    CHECK(!ble_ad_manufacturer(&ad, &cid, &pl, &pl_len));
}
