/**
 * @file  test_ad_helpers.c
 * @brief Task 1: tests for ble_ad_flags(), ble_ad_name() and
 *        ble_ad_service_data16(). Written before the implementation.
 */
#include "check.h"
#include "ble/ble_ad.h"

/**
 * @brief Tests for the three AD convenience functions.
 *
 * Each group covers the normal case, the "not there" case, and at least one
 * malformed or boundary case.
 */
void suite_ad_helpers(void)
{
    SUITE("ad helpers (task 1)");

    /* ---- ble_ad_flags ---------------------------------------------------- */
    {
        /* flags 0x06 | complete name "ab" */
        const unsigned char adv[] = {0x02, 0x01, 0x06, 0x03, 0x09, 'a', 'b'};
        uint8_t f = 0xEE;
        CHECK(ble_ad_flags(adv, sizeof adv, &f));
        CHECK_EQ(f, 0x06);

        /* no flags structure at all */
        const unsigned char no_flags[] = {0x03, 0x09, 'a', 'b'};
        f = 0xEE;
        CHECK(!ble_ad_flags(no_flags, sizeof no_flags, &f));
        CHECK_EQ(f, 0xEE);                      /* untouched on failure */

        /* flags structure with no data byte: length 1 = type only */
        const unsigned char empty_flags[] = {0x01, 0x01};
        CHECK(!ble_ad_flags(empty_flags, sizeof empty_flags, &f));

        /* malformed before the flags: must not be trusted */
        const unsigned char bad_first[] = {0x09, 0x09, 'a', 0x02, 0x01, 0x06};
        CHECK(!ble_ad_flags(bad_first, sizeof bad_first, &f));

        /* empty payload */
        CHECK(!ble_ad_flags(NULL, 0, &f));

        /* two Flags structures: the first wins, and only one byte is written.
         * Red first: the *flags++ version wrote the second value past f. */
        const unsigned char two_flags[] = {0x02, 0x01, 0x06, 0x02, 0x01, 0x05};
        uint8_t guard[2] = {0xEE, 0xEE};
        CHECK(ble_ad_flags(two_flags, sizeof two_flags, &guard[0]));
        CHECK_EQ(guard[0], 0x06);
        CHECK_EQ(guard[1], 0xEE);               /* the byte after is untouched */
    }

    /* ---- ble_ad_name ----------------------------------------------------- */
    {
        const uint8_t *n = NULL;
        uint8_t nl = 0xEE;

        /* complete name */
        const unsigned char complete[] = {0x02, 0x01, 0x06, 0x08, 0x09, 'B', 'L', 'E', '-', 'L', 'a', 'b'};
        CHECK(ble_ad_name(complete, sizeof complete, &n, &nl));
        CHECK_EQ(nl, 7);
        CHECK(n != NULL && memcmp(n, "BLE-Lab", 7) == 0);

        /* only a shortened name */
        const unsigned char shortened[] = {0x04, 0x08, 'B', 'L', 'E'};
        CHECK(ble_ad_name(shortened, sizeof shortened, &n, &nl));
        CHECK_EQ(nl, 3);
        CHECK(n != NULL && memcmp(n, "BLE", 3) == 0);

        /* both, shortened FIRST: the complete one must still win */
        const unsigned char both[] = {0x04, 0x08, 'B', 'L', 'E', 0x08, 0x09, 'B', 'L', 'E', '-', 'L', 'a', 'b'};
        CHECK(ble_ad_name(both, sizeof both, &n, &nl));
        CHECK_EQ(nl, 7);

        /* both, complete FIRST: the shortened one after it must not replace it */
        const unsigned char complete_first[] = {0x08, 0x09, 'B', 'L', 'E', '-', 'L', 'a', 'b', 0x04, 0x08, 'B', 'L', 'E'};
        CHECK(ble_ad_name(complete_first, sizeof complete_first, &n, &nl));
        CHECK_EQ(nl, 7);

        /* an empty complete name is still a name */
        const unsigned char empty_name[] = {0x01, 0x09};
        CHECK(ble_ad_name(empty_name, sizeof empty_name, &n, &nl));
        CHECK_EQ(nl, 0);

        /* no name */
        const unsigned char no_name[] = {0x02, 0x01, 0x06};
        n = NULL;
        nl = 0xEE;
        CHECK(!ble_ad_name(no_name, sizeof no_name, &n, &nl));
        CHECK(n == NULL);
        CHECK_EQ(nl, 0xEE);

        /* the length byte of the name overruns the buffer */
        const unsigned char overrun[] = {0x09, 0x09, 'B', 'L', 'E'};
        CHECK(!ble_ad_name(overrun, sizeof overrun, &n, &nl));
    }

    /* ---- ble_ad_service_data16 ------------------------------------------ */
    {
        ble_ad_t ad;
        uint16_t uuid = 0;
        const uint8_t *pl = NULL;
        uint8_t pl_len = 0xEE;

        /* UUID 0xFEF3 (little-endian on air: f3 fe) + 2 payload bytes */
        const unsigned char sd[] = {0x05, 0x16, 0xF3, 0xFE, 0x01, 0x02};
        CHECK(ble_ad_find(sd, sizeof sd, BLE_AD_SERVICE_DATA16, &ad));
        CHECK(ble_ad_service_data16(&ad, &uuid, &pl, &pl_len));
        CHECK_EQ(uuid, 0xFEF3);
        CHECK_EQ(pl_len, 2);
        CHECK(pl != NULL && pl[0] == 0x01 && pl[1] == 0x02);

        /* exactly a UUID, no payload */
        const unsigned char uuid_only[] = {0x03, 0x16, 0x0F, 0x18};
        CHECK(ble_ad_find(uuid_only, sizeof uuid_only, BLE_AD_SERVICE_DATA16, &ad));
        CHECK(ble_ad_service_data16(&ad, &uuid, &pl, &pl_len));
        CHECK_EQ(uuid, 0x180F);
        CHECK_EQ(pl_len, 0);

        /* one byte: not even a whole UUID */
        const unsigned char too_short[] = {0x02, 0x16, 0xF3};
        CHECK(ble_ad_find(too_short, sizeof too_short, BLE_AD_SERVICE_DATA16, &ad));
        uuid = 0x1234;
        CHECK(!ble_ad_service_data16(&ad, &uuid, &pl, &pl_len));
        CHECK_EQ(uuid, 0x1234);                 /* untouched on failure */

        /* right bytes, wrong AD type (manufacturer data) */
        const unsigned char mfr[] = {0x05, 0xFF, 0xF3, 0xFE, 0x01, 0x02};
        CHECK(ble_ad_find(mfr, sizeof mfr, BLE_AD_MANUFACTURER, &ad));
        CHECK(!ble_ad_service_data16(&ad, &uuid, &pl, &pl_len));
    }
}
