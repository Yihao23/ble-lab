/**
 * @file  test_fuzz.c
 * @brief Random bytes in, no crash out.
 *
 * Every input is malloc'd at exactly its length, so reading even one byte
 * past the end lands in AddressSanitizer's redzone and aborts the run. Build
 * with -DBLE_SANITIZE=ON to arm that; without it this is only a smoke test.
 * Deterministic seed, so a failure reproduces.
 */
#include <stdlib.h>
#include "check.h"
#include "ble/ble_ad.h"
#include "ble/ble_hci.h"

static unsigned int rng_state = 0x2545F491u;   /**< Fixed seed: a failure reproduces. */

/**
 * @brief Marsaglia's xorshift32 PRNG: fast, deterministic, good enough for fuzzing.
 * @return The next 32-bit pseudo-random value.
 */
static unsigned int xorshift32(void)
{
    unsigned int x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return rng_state = x;
}

/**
 * @brief Fuzz the AD and HCI parsers with 200 000 inputs.
 *
 * Each input is 0–299 random bytes in a heap block of exactly that length.
 * Half of them are steered into the report parser by overwriting the first
 * four bytes with an LE Meta header (subevent 0x02 or 0x0D, 1–3 reports, a
 * parameter length at or just below the real one). Each input is walked as
 * AD data and as an HCI event, and every report's AD data is walked too.
 * Under ASan any read past the block aborts the run; the suite also checks
 * that every returned pointer and length stays inside the input.
 */
void suite_fuzz(void)
{
    SUITE("fuzz");
    const int iterations = 200000;
    int reports = 0, ads = 0, bounds_ok = 1;

    for (int i = 0; i < iterations; i++) {
        size_t len = xorshift32() % 300u;
        unsigned char *buf = malloc(len ? len : 1);
        if (buf == NULL) {
            break;
        }
        for (size_t k = 0; k < len; k++) {
            buf[k] = (unsigned char)xorshift32();
        }
        /* Steer half the inputs into the interesting paths. */
        if (len >= 4 && (xorshift32() & 1u)) {
            buf[0] = 0x3E;
            buf[1] = (unsigned char)(len - 2u - (xorshift32() % 3u));
            buf[2] = (xorshift32() & 1u) ? 0x0D : 0x02;
            buf[3] = (unsigned char)(1u + xorshift32() % 3u);
        }

        ble_ad_iter_t ai;
        ble_ad_t ad;
        ble_ad_iter_init(&ai, buf, len);
        while (ble_ad_next(&ai, &ad) == BLE_AD_OK) {
            ads++;
            if (ad.data < buf || ad.data + ad.len > buf + len) {
                bounds_ok = 0;
            }
        }

        ble_adv_iter_t hi;
        ble_adv_report_t r;
        if (ble_hci_adv_iter_init(&hi, buf, len) == BLE_HCI_OK) {
            while (ble_hci_adv_next(&hi, &r) == BLE_HCI_OK) {
                reports++;
                if (r.data < buf || r.data + r.data_len > buf + len) {
                    bounds_ok = 0;
                }
                ble_ad_iter_t di;
                ble_ad_iter_init(&di, r.data, r.data_len);
                while (ble_ad_next(&di, &ad) == BLE_AD_OK) {
                }
            }
        }
        free(buf);
    }

    CHECK(bounds_ok);
    CHECK(reports > 0);                 /* the steering did reach the report parser */
    printf("  %d inputs, %d AD structures, %d reports parsed, all in bounds\n",
           iterations, ads, reports);
}
