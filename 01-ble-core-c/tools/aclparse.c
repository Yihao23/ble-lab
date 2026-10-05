/**
 * @file  aclparse.c
 * @brief Command-line driver: HCI ACL packets as hex in, one TSV row per
 *        packet out.
 *
 * One packet per line on stdin, starting at the handle field. For each:
 * @verbatim
   line  handle  pb  l2cap_status  cid  l2cap_len  att_status  opcode  handle  err_code  mtu  start  end
   @endverbatim
 * Fields that do not apply are "-". Used by tools/diff_acl_vs_tshark.py to
 * compare this library with Wireshark on every ACL packet of a capture.
 */
#include <stdio.h>
#include <string.h>

#include "ble/ble_att.h"
#include "ble/ble_l2cap.h"

/**
 * @brief Value of one hex digit.
 * @param[in] c  Character.
 * @return 0–15, or -1 if @p c is not a hex digit.
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
 * @return Always 0; a packet the library refuses is reported in its row.
 */
int main(void)
{
    static char line[8192];
    static unsigned char pkt[4096];
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
            if (n < sizeof pkt) {
                pkt[n++] = (unsigned char)((hi << 4) | lo);
            }
            i += 2;
        }

        ble_acl_t acl;
        ble_l2cap_t l2;
        ble_att_pdu_t p;
        if (ble_acl_parse(pkt, n, &acl) != BLE_ACL_OK) {
            printf("%lu\tACL_MALFORMED\n", lineno);
            continue;
        }
        printf("%lu\t0x%03x\t%u", lineno, (unsigned)acl.handle, (unsigned)acl.pb);
        ble_l2cap_status_t ls = ble_l2cap_parse(&acl, &l2);
        if (ls != BLE_L2CAP_OK) {
            printf("\tL2CAP_%d\n", (int)ls);
            continue;
        }
        printf("\tOK\t0x%04x\t%u", (unsigned)l2.cid, (unsigned)l2.len);
        if (l2.cid != BLE_L2CAP_CID_ATT) {
            printf("\t-\n");
            continue;
        }
        if (ble_att_parse(l2.payload, l2.len, &p) != BLE_ATT_OK) {
            printf("\tATT_MALFORMED\n");
            continue;
        }
        printf("\tOK\t0x%02x", (unsigned)p.opcode);
        if (p.has_handle) printf("\t0x%04x", (unsigned)p.handle); else printf("\t-");
        if (p.opcode == BLE_ATT_ERROR_RSP) printf("\t0x%02x", (unsigned)p.err_code); else printf("\t-");
        if (p.mtu) printf("\t%u", (unsigned)p.mtu); else printf("\t-");
        if (p.has_range) printf("\t0x%04x\t0x%04x\n", (unsigned)p.start_handle, (unsigned)p.end_handle);
        else printf("\t-\t-\n");
    }
    return 0;
}
