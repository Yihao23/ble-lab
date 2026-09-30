/**
 * @file  test_hci_multi.c
 * @brief Task 3: legacy LE Advertising Report events carrying several reports.
 *
 * The layout these events are written in — each report complete before the
 * next — is the one Core Vol 4 Part E §5.2 prescribes and Linux parses.
 * See docs/multi-report.md.
 */
#include "check.h"
#include "ble/ble_hci.h"
#include "ble/ble_ad.h"

/**
 * @brief Fill in the parameter-length byte of a hand-written event.
 * @param[in,out] evt    Event starting at the event code.
 * @param[in]     total  Total event length in bytes, including the 2-byte header.
 */
static void set_param_len(unsigned char *evt, size_t total)
{
    evt[1] = (unsigned char)(total - 2u);
}

/**
 * @brief Multi-report tests.
 *
 * Three valid reports of different lengths, each field checked so that a
 * wrong layout would read the wrong values; a bad length in the second of
 * three, which must not cost the first or read past the event; an event
 * reporting zero reports; and a Data_Length above the spec's 31, which is
 * accepted on purpose (see docs/multi-report.md, section 4).
 */
void suite_hci_multi(void)
{
    SUITE("hci multi-report (task 3)");
    ble_adv_iter_t it;
    ble_adv_report_t r;

    /* ---- case 1: three valid reports, data lengths 0, 3 and 5 ------------
     * Every report has its own event type, address type, address and RSSI,
     * so reading a field from the wrong report shows up as a wrong value. */
    unsigned char three[] = {
        0x3E, 0x00, 0x02, 0x03,                         /* LE Meta, 0x02, 3 reports */
        /* report 0: ADV_IND, public, no data, RSSI -60 */
        0x00, 0x00, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
        0x00,
        0xC4,
        /* report 1: ADV_NONCONN_IND, random, Flags 0x06, RSSI -80 */
        0x03, 0x01, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xC6,
        0x03, 0x02, 0x01, 0x06,
        0xB0,
        /* report 2: SCAN_RSP, random, name "abc", RSSI -40 */
        0x04, 0x01, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xD6,
        0x05, 0x04, 0x09, 'a', 'b', 'c',
        0xD8};
    set_param_len(three, sizeof three);
    CHECK_EQ(ble_hci_adv_iter_init(&it, three, sizeof three), BLE_HCI_OK);

    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_OK);
    CHECK(r.from_legacy_event);
    CHECK_EQ(r.evt_type, 0x00);
    CHECK_EQ(r.addr_type, BLE_HCI_ADDR_PUBLIC);
    CHECK_EQ(r.addr[0], 0xA1);
    CHECK_EQ(r.addr[5], 0xA6);
    CHECK_EQ(r.data_len, 0);
    CHECK_EQ(r.rssi, -60);

    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_OK);
    CHECK_EQ(r.evt_type, 0x03);
    CHECK_EQ(r.addr_type, BLE_HCI_ADDR_RANDOM);
    CHECK_EQ(r.addr[0], 0xB1);
    CHECK_EQ(r.addr[5], 0xC6);
    CHECK_EQ(r.data_len, 3);
    CHECK_EQ(r.data[2], 0x06);                      /* the Flags value */
    CHECK(ble_ad_is_well_formed(r.data, r.data_len));
    CHECK_EQ(r.rssi, -80);

    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_OK);
    CHECK_EQ(r.evt_type, 0x04);
    CHECK_EQ(r.addr[0], 0xC1);
    CHECK_EQ(r.addr[5], 0xD6);
    CHECK_EQ(r.data_len, 5);
    CHECK(ble_ad_is_well_formed(r.data, r.data_len));
    CHECK_EQ(r.rssi, -40);

    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_END);

    /* ---- case 2: the second of three claims 200 bytes of data ------------
     * The first report is still good and must come back. The second must be
     * refused without reading past the event, and the walk must stop there:
     * nothing after a bad length can be trusted to be where it claims. */
    unsigned char bad_second[] = {
        0x3E, 0x00, 0x02, 0x03,
        /* report 0: fine */
        0x00, 0x00, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
        0x00,
        0xC4,
        /* report 1: Data_Length 200, only 4 bytes follow */
        0x03, 0x01, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xC6,
        0xC8,
        0x02, 0x01, 0x06, 0xB0};
    set_param_len(bad_second, sizeof bad_second);
    CHECK_EQ(ble_hci_adv_iter_init(&it, bad_second, sizeof bad_second), BLE_HCI_OK);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_OK);
    CHECK_EQ(r.addr[0], 0xA1);
    CHECK_EQ(r.rssi, -60);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_ERR_MALFORMED);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_END);

    /* ---- case 3: Num_Reports = 0 -----------------------------------------
     * Reserved by the spec (valid range 0x01-0x19). Nothing to read, and
     * nothing is read. */
    unsigned char zero[] = {0x3E, 0x02, 0x02, 0x00};
    CHECK_EQ(ble_hci_adv_iter_init(&it, zero, sizeof zero), BLE_HCI_OK);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_END);

    /* ---- case 4: Data_Length 32, one above the spec's 0x1F ---------------
     * Accepted on purpose: every byte is inside the event, so there is no
     * memory-safety question, and a parser of the air describes what it
     * received. The reason is in docs/multi-report.md, section 4. If this
     * decision changes, this test is the one that has to change with it. */
    unsigned char long_data[4 + 9 + 32 + 1];
    long_data[0] = 0x3E;
    long_data[2] = 0x02;
    long_data[3] = 0x01;
    long_data[4] = 0x00;                            /* ADV_IND */
    long_data[5] = 0x00;                            /* public */
    for (unsigned k = 0; k < 6u; k++) {
        long_data[6u + k] = (unsigned char)(0x10u + k);
    }
    long_data[12] = 32;                             /* Data_Length */
    for (unsigned k = 0; k < 32u; k++) {
        long_data[13u + k] = 0x00;                  /* zero padding: well-formed AD */
    }
    long_data[45] = 0xC4;                           /* RSSI -60 */
    set_param_len(long_data, sizeof long_data);
    CHECK_EQ(ble_hci_adv_iter_init(&it, long_data, sizeof long_data), BLE_HCI_OK);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_OK);
    CHECK_EQ(r.data_len, 32);
    CHECK_EQ(r.rssi, -60);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_END);
}
