/**
 * @file  bleg2.c
 * @brief Command-line driver: the numeric comparison value from the four
 *        values a pairing sends over the air.
 *
 * @verbatim
   bleg2 PKax PKbx Na Nb
   @endverbatim
 * Each argument is hex exactly as the SMP packet carries it — least
 * significant octet first, as Wireshark prints the field. The tool reverses
 * them into the MSB-first order ble_sc_g2() takes, and prints g2 and the six
 * digits both screens should show. PKax and Na belong to the initiator, the
 * device that sent Pairing Request. Used by tools/pairing_from_capture.py.
 */
#include <stdio.h>
#include <string.h>

#include "ble/ble_sc.h"

/**
 * @brief Parse on-air hex (LSB first) into MSB-first bytes.
 * @param[in]  hex  Exactly 2 * @p n hex digits.
 * @param[out] out  @p n bytes, most significant first.
 * @param[in]  n    Number of bytes.
 * @return 0 on success, -1 if @p hex has the wrong length or a non-hex digit.
 */
static int from_air(const char *hex, unsigned char *out, size_t n)
{
    if (strlen(hex) != 2u * n) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned b;
        if (sscanf(hex + 2u * i, "%2x", &b) != 1) {
            return -1;
        }
        out[n - 1u - i] = (unsigned char)b;
    }
    return 0;
}

/**
 * @brief Parse the four arguments, compute g2, print it.
 * @param[in] argc  Argument count; must be 5.
 * @param[in] argv  PKax, PKbx, Na, Nb as on air.
 * @return 0 on success, 2 on bad arguments.
 */
int main(int argc, char **argv)
{
    unsigned char u[32], v[32], x[16], y[16];

    if (argc != 5 || from_air(argv[1], u, 32) || from_air(argv[2], v, 32) ||
        from_air(argv[3], x, 16) || from_air(argv[4], y, 16)) {
        fprintf(stderr, "usage: bleg2 PKax PKbx Na Nb   (hex, as on air: LSB first)\n");
        return 2;
    }
    uint32_t g2 = ble_sc_g2(u, v, x, y);
    printf("g2 0x%08lx  compare value %06lu\n",
           (unsigned long)g2, (unsigned long)ble_sc_compare_value(g2));
    return 0;
}
