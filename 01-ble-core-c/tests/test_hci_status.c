/**
 * @file  test_hci_status.c
 * @brief Task 2: tests for ble_adv_report_data_status(). Written before the
 *        implementation.
 */
#include "check.h"
#include "ble/ble_hci.h"

/**
 * @brief Build a report with only the fields the data status depends on.
 * @param[in] legacy    Value for @c from_legacy_event.
 * @param[in] evt_type  Value for @c evt_type.
 * @return The report, every other field zero.
 */
static ble_adv_report_t report(bool legacy, uint16_t evt_type)
{
    ble_adv_report_t r;
    memset(&r, 0, sizeof r);
    r.from_legacy_event = legacy;
    r.evt_type = evt_type;
    return r;
}

/**
 * @brief Data status tests.
 *
 * All four values of bits 5–6; the other event-type bits must not leak into
 * the answer; a legacy 0x02 report is complete whatever its event type holds;
 * and one extended event parsed end to end with ble_hci_adv_next().
 */
void suite_hci_status(void)
{
    SUITE("hci data status (task 2)");
    ble_adv_report_t r;

    /* ---- the four values of bits 5-6 ------------------------------------- */
    r = report(false, 0x0000);
    CHECK_EQ(ble_adv_report_data_status(&r), BLE_ADV_DATA_COMPLETE);
    r = report(false, 0x0020);
    CHECK_EQ(ble_adv_report_data_status(&r), BLE_ADV_DATA_MORE);
    r = report(false, 0x0040);
    CHECK_EQ(ble_adv_report_data_status(&r), BLE_ADV_DATA_TRUNCATED);
    r = report(false, 0x0060);
    CHECK_EQ(ble_adv_report_data_status(&r), BLE_ADV_DATA_RESERVED);

    /* ---- the other bits must not change the answer ----------------------- */
    /* 0x0013 = legacy | scannable | connectable: what the capture is full of */
    r = report(false, 0x0013);
    CHECK_EQ(ble_adv_report_data_status(&r), BLE_ADV_DATA_COMPLETE);
    /* connectable + more data */
    r = report(false, 0x0021);
    CHECK_EQ(ble_adv_report_data_status(&r), BLE_ADV_DATA_MORE);
    /* every bit set except the status: still complete */
    r = report(false, (uint16_t)(0xFFFFu & ~0x0060u));
    CHECK_EQ(ble_adv_report_data_status(&r), BLE_ADV_DATA_COMPLETE);
    /* every bit set: reserved */
    r = report(false, 0xFFFF);
    CHECK_EQ(ble_adv_report_data_status(&r), BLE_ADV_DATA_RESERVED);

    /* ---- legacy 0x02 reports have no status bits ------------------------ */
    r = report(true, 0x04);                     /* SCAN_RSP */
    CHECK_EQ(ble_adv_report_data_status(&r), BLE_ADV_DATA_COMPLETE);
    /* a reserved legacy event type whose bits 5-6 happen to be set:
     * it is not a status, and must not be read as one */
    r = report(true, 0x60);
    CHECK_EQ(ble_adv_report_data_status(&r), BLE_ADV_DATA_COMPLETE);

    /* ---- end to end: an extended event saying "more data follows" -------- */
    const unsigned char evt[] = {
        0x3E, 26, 0x0D, 0x01,                       /* LE Meta, 26 bytes, 0x0D, 1 report */
        0x21, 0x00,                                 /* event type: connectable | more data */
        0x01,                                       /* random address */
        0x11, 0x22, 0x33, 0x44, 0x55, 0xC6,         /* address, LSB first */
        0x01, 0x02, 0x03,                           /* PHY 1M, secondary 2M, SID 3 */
        0x7F, 0xC4,                                 /* TX power n/a, RSSI -60 */
        0x00, 0x00,                                 /* no periodic advertising */
        0x00, 0, 0, 0, 0, 0, 0,                     /* no direct address */
        0x00};                                      /* data length 0 */
    ble_adv_iter_t it;
    CHECK_EQ(ble_hci_adv_iter_init(&it, evt, sizeof evt), BLE_HCI_OK);
    CHECK_EQ(ble_hci_adv_next(&it, &r), BLE_HCI_OK);
    CHECK_EQ(ble_adv_report_data_status(&r), BLE_ADV_DATA_MORE);
}
