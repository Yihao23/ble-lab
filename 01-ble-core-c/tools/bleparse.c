/**
 * @file  bleparse.c
 * @brief Command-line driver: HCI events as hex in, one TSV row per report out.
 *
 * Reads HCI events as hex, one event per line on stdin, and prints every
 * advertising report ble_hci.c finds in them:
 * @verbatim
   line  subevent  evt_type  addr_type  addr  rssi  tx_power  data_len  ad_ok
   @endverbatim
 * A line whose event is not an advertising report prints `ERR_INIT` and the
 * status; a report that overruns its event prints `ERR_MALFORMED`.
 *
 * Used by `tools/diff_vs_tshark.py` to compare this parser with Wireshark's
 * on every report in a capture. The hex/stdio code lives here, in the tool,
 * so the library itself stays free of I/O.
 */
#include <stdio.h>
#include <string.h>

#include "ble/ble_ad.h"
#include "ble/ble_hci.h"

/**
 * @brief Value of one hex digit.
 * @param[in] c  Character.
 * @return 0–15, or -1 if @p c is not a hex digit (such separators are skipped).
 */
static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * @brief Parse stdin line by line until EOF.
 * @return Always 0; errors are reported per line on stdout.
 */
int main(void)
{
    static char line[4096];
    static unsigned char evt[2048];
    unsigned long lineno = 0;

    while (fgets(line, sizeof line, stdin) != NULL) {
        lineno++;
        size_t n = 0;
        for (size_t i = 0; line[i] != '\0' && line[i + 1] != '\0'; ) {
            int hi = hexval((unsigned char)line[i]);
            int lo = hexval((unsigned char)line[i + 1]);
            if (hi < 0 || lo < 0) {
                i++;
                continue;
            }
            if (n < sizeof evt) {
                evt[n++] = (unsigned char)((hi << 4) | lo);
            }
            i += 2;
        }

        ble_adv_iter_t it;
        ble_adv_report_t r;
        ble_hci_status_t st = ble_hci_adv_iter_init(&it, evt, n);
        if (st != BLE_HCI_OK) {
            printf("%lu\tERR_INIT\t%d\n", lineno, (int)st);
            continue;
        }
        while ((st = ble_hci_adv_next(&it, &r)) == BLE_HCI_OK) {
            printf("%lu\t0x%02x\t0x%04x\t%u\t%02x:%02x:%02x:%02x:%02x:%02x\t%d\t%d\t%u\t%d\n",
                   lineno, (unsigned)it.subevent, (unsigned)r.evt_type, (unsigned)r.addr_type,
                   r.addr[5], r.addr[4], r.addr[3], r.addr[2], r.addr[1], r.addr[0],
                   (int)r.rssi, (int)r.tx_power, (unsigned)r.data_len,
                   ble_ad_is_well_formed(r.data, r.data_len) ? 1 : 0);
        }
        if (st == BLE_HCI_ERR_MALFORMED) {
            printf("%lu\tERR_MALFORMED\n", lineno);
        }
    }
    return 0;
}
