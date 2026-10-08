/**
 * @file  blerpa.c
 * @brief Command-line driver: does this address resolve with this IRK?
 *
 * One query per line on stdin:
 * @verbatim
   IRK ADDRESS
   @endverbatim
 * both hex exactly as they travel — least significant octet first: the IRK
 * as SMP's Identity Information carries it, the address as HCI events carry
 * it. One line out per query:
 * @verbatim
   kind  resolves
   @endverbatim
 * where kind is ble_addr_kind_str() of the address taken as random, and
 * resolves is 1 or 0 from ble_rpa_resolve(). A malformed line gives "error".
 * Used by bleprivacy's IRK check (project 04) to confirm its Python ah()
 * against this library on real addresses.
 */
#include <stdio.h>
#include <string.h>

#include "ble/ble_rpa.h"

/**
 * @brief Parse @p n octets of hex, keeping or reversing their order.
 * @param[in]  hex      At least 2 * @p n hex digits.
 * @param[out] out      @p n octets.
 * @param[in]  n        Number of octets.
 * @param[in]  reverse  Store the first octet last (LSB-first in, MSB-first out).
 * @return 0 on success, -1 on a non-hex digit.
 */
static int parse_hex(const char *hex, unsigned char *out, size_t n, int reverse)
{
    for (size_t i = 0; i < n; i++) {
        unsigned b;
        if (sscanf(hex + 2u * i, "%2x", &b) != 1) {
            return -1;
        }
        out[reverse ? n - 1u - i : i] = (unsigned char)b;
    }
    return 0;
}

/**
 * @brief Answer each query line until EOF.
 * @return Always 0; a malformed line is reported in its output line.
 */
int main(void)
{
    char irk_hex[64], addr_hex[64];
    unsigned char irk[16], addr[6];

    while (scanf("%63s %63s", irk_hex, addr_hex) == 2) {
        if (strlen(irk_hex) != 32 || strlen(addr_hex) != 12 ||
            parse_hex(irk_hex, irk, 16, 1) || parse_hex(addr_hex, addr, 6, 0)) {
            printf("error\n");
            continue;
        }
        printf("%s\t%d\n", ble_addr_kind_str(ble_addr_classify(true, addr)),
               ble_rpa_resolve(irk, addr) ? 1 : 0);
    }
    return 0;
}
