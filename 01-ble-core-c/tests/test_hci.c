/**
 * @file  test_hci.c
 * @brief Tests for the HCI advertising report parser, on synthetic events and
 *        on real ones from fixtures.h (expected values decoded by tshark).
 */
#include "check.h"
#include "ble/ble_hci.h"
#include "ble/ble_ad.h"
#include "fixtures.h"

/**
 * @brief Fill in the parameter-length byte of a hand-written event.
 *
 * The test events below are written out byte by byte; computing their
 * parameter length from `sizeof` instead of by hand keeps them correct when
 * a byte is added or removed.
 *
 * @param[in,out] evt    Event starting at the event code.
 * @param[in]     total  Total event length in bytes, including the 2-byte header.
 */
static void set_param_len(unsigned char *evt, size_t total)
{
    evt[1] = (unsigned char)(total - 2u);
}

/**
 * @brief HCI parser tests.
 *
 * A legacy report and an extended report decoded field by field; two legacy
 * reports back to back in one event; Command Complete and LE Connection
 * Complete rejected as not advertising reports; a header claiming more
 * parameters than the buffer holds; a report whose data runs past the event;
 * an event too short for a header; and every real fixture compared with the
 * values Wireshark decoded, including the offset of the scrubbed address.
 */
void suite_hci(void)
{
    SUITE("hci");
    ble_adv_iter_t it;
    ble_adv_report_t r;

    /* Legacy 0x02: ADV_IND from random 11:22:33:44:55:C6, flags only, RSSI -59. */
    unsigned char legacy[] = {
        0x3E, 0x00, 0x02, 0x01,
        0x00, 0x01, 0xC6, 0x55, 0x44, 0x33, 0x22, 0x11,   /* LSB-first */
        0x03, 0x02, 0x01, 0x06,
        0xC5};
    set_param_len(legacy, sizeof legacy);
    CHECK_EQ(ble_hci_adv_iter_init(&it, legacy, sizeof legacy), BLE_HCI_OK);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_OK);
    CHECK(r.from_legacy_event);
    CHECK_EQ(r.addr_type, BLE_HCI_ADDR_RANDOM);
    CHECK_EQ(r.addr[0], 0xC6);
    CHECK_EQ(r.addr[5], 0x11);
    CHECK_EQ(r.rssi, -59);
    CHECK_EQ(r.data_len, 3);
    CHECK(ble_ad_is_well_formed(r.data, r.data_len));
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_END);

    /* Two legacy reports back to back in one event. */
    unsigned char two[] = {
        0x3E, 0x00, 0x02, 0x02,
        0x03, 0x00, 1, 2, 3, 4, 5, 6, 0x00, 0xD0,
        0x04, 0x01, 7, 8, 9, 10, 11, 0xC0, 0x02, 0x01, 0x06, 0xB0};
    set_param_len(two, sizeof two);
    CHECK_EQ(ble_hci_adv_iter_init(&it, two, sizeof two), BLE_HCI_OK);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_OK);
    CHECK_EQ(r.data_len, 0);
    CHECK_EQ(r.rssi, -48);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_OK);
    CHECK_EQ(r.evt_type, 0x04);                     /* SCAN_RSP */
    CHECK_EQ(r.rssi, -80);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_END);

    /* Extended 0x0D, legacy bit set, TX power +4, RSSI -71, name "ab". */
    unsigned char ext[] = {
        0x3E, 0x00, 0x0D, 0x01,
        0x13, 0x00,                                   /* conn|scan|legacy */
        0x01, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,     /* random 60:50:40:30:20:10 */
        0x01, 0x00, 0xFF,                             /* 1M, none, no SID */
        0x04, 0xB9,                                   /* tx +4, rssi -71 */
        0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0,           /* interval, direct addr */
        0x04, 0x03, 0x09, 'a', 'b'};
    set_param_len(ext, sizeof ext);
    CHECK_EQ(ble_hci_adv_iter_init(&it, ext, sizeof ext), BLE_HCI_OK);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_OK);
    CHECK(!r.from_legacy_event);
    CHECK_EQ(r.evt_type & BLE_EXT_EVT_LEGACY, BLE_EXT_EVT_LEGACY);
    CHECK_EQ(r.addr[5], 0x60);
    CHECK_EQ(r.tx_power, 4);
    CHECK_EQ(r.rssi, -71);
    CHECK_EQ(r.primary_phy, 1);
    CHECK_EQ(r.data_len, 4);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_END);

    /* Not an advertising report: Command Complete, and LE Connection Complete. */
    const unsigned char cmd_complete[] = {0x0E, 0x04, 0x01, 0x0C, 0x20, 0x00};
    CHECK_EQ(ble_hci_adv_iter_init(&it, cmd_complete, sizeof cmd_complete), BLE_HCI_NOT_ADV_REPORT);
    const unsigned char conn_complete[] = {0x3E, 0x02, 0x01, 0x00};
    CHECK_EQ(ble_hci_adv_iter_init(&it, conn_complete, sizeof conn_complete), BLE_HCI_NOT_ADV_REPORT);

    /* Header claims more parameters than the buffer holds. */
    unsigned char lying[sizeof legacy];
    memcpy(lying, legacy, sizeof legacy);
    lying[1] = 0xFF;
    CHECK_EQ(ble_hci_adv_iter_init(&it, lying, sizeof lying), BLE_HCI_ERR_MALFORMED);

    /* A report whose data length runs past the event: caught, then iteration stops. */
    memcpy(lying, legacy, sizeof legacy);
    lying[12] = 0x40;                               /* data_len 64, only 4 bytes there */
    CHECK_EQ(ble_hci_adv_iter_init(&it, lying, sizeof lying), BLE_HCI_OK);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_ERR_MALFORMED);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_END);

    /* Too short to even hold a header. */
    CHECK_EQ(ble_hci_adv_iter_init(&it, legacy, 3), BLE_HCI_ERR_MALFORMED);

    /* Real events captured from an Intel AX201 on BlueZ 5.72 (addresses anonymised). */
    for (size_t i = 0; i < REAL_EVENT_COUNT; i++) {
        const real_event_t *e = &REAL_EVENTS[i];
        CHECK_EQ(ble_hci_adv_iter_init(&it, e->bytes, e->len), BLE_HCI_OK);
        CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_OK);
        CHECK_EQ(r.addr_type, e->addr_type);
        CHECK_EQ(r.addr[0], 0x11);                /* scrubbed address: proves the offset */
        CHECK_EQ(r.addr[4], 0x55);
        CHECK_EQ(r.addr[5] & 0x3F, 0x2A);
        CHECK_EQ(r.rssi, e->rssi);
        CHECK_EQ(r.tx_power, e->tx_power);
        CHECK_EQ(r.data_len, e->data_len);
        CHECK_EQ(r.evt_type, e->evt_type);
        CHECK(ble_ad_is_well_formed(r.data, r.data_len));
        CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_END);
    }
}
