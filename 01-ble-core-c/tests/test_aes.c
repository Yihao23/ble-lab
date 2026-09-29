/**
 * @file  test_aes.c
 * @brief Known-answer tests for ble_aes128_encrypt().
 */
#include "check.h"
#include "ble/ble_aes.h"

/**
 * @brief AES-128 known-answer tests.
 *
 * FIPS-197 Appendix C.1, and the same vector encrypted in place (input and
 * output the same buffer).
 */
void suite_aes(void)
{
    SUITE("aes");

    /* FIPS-197 Appendix C.1: the canonical AES-128 known-answer test. */
    const unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const unsigned char pt[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    const unsigned char ct[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    unsigned char out[16];
    ble_aes128_encrypt(key, pt, out);
    CHECK_MEM(out, ct, 16);

    /* In-place: in and out may alias. */
    unsigned char buf[16];
    memcpy(buf, pt, 16);
    ble_aes128_encrypt(key, buf, buf);
    CHECK_MEM(buf, ct, 16);
}
