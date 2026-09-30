/**
 * @file  ble_hci.c
 * @brief HCI LE advertising report parser — implementation.
 *
 * Every bound is written as "bytes left < n", never as `p + n > end`: forming
 * a pointer past the end of the buffer is already undefined behaviour.
 */
#include "ble/ble_hci.h"
#include "ble_util.h"

/**
 * @brief Fixed part of one legacy (`0x02`) report, before its data and RSSI:
 *        evt_type(1) addr_type(1) addr(6) data_len(1).
 */
#define LEGACY_FIXED 9u

/**
 * @brief Fixed part of one extended (`0x0D`) report, before its data:
 *        evt_type(2) addr_type(1) addr(6) primary_phy(1) secondary_phy(1)
 *        sid(1) tx_power(1) rssi(1) periodic_interval(2) direct_addr_type(1)
 *        direct_addr(6) data_len(1).
 */
#define EXT_FIXED    24u

/** @brief Bits 5–6 of the extended event type hold the data status. */
#define DATA_STATUS_SHIFT 5u

/**
 * @par Implementation
 * Validate the LE Meta header and set the iterator to the first report.
 *
 * Event layout: code(1) param_len(1) subevent(1) num_reports(1) reports...
 * The iterator is reset first, so even on failure a later
 * ble_hci_adv_next() call returns ::BLE_HCI_END. The end pointer comes from
 * the event's own parameter length, never from @p len, so trailing bytes
 * after the event are ignored.
 */
ble_hci_status_t ble_hci_adv_iter_init(ble_adv_iter_t *it, const uint8_t *evt, size_t len)
{
    it->p = it->end = evt;
    it->remaining = 0u;
    it->subevent = 0u;

    if (evt == NULL || len < 4u) {
        return BLE_HCI_ERR_MALFORMED;    /* code, param_len, subevent, num_reports */
    }
    if (evt[0] != BLE_HCI_EVT_LE_META) {
        return BLE_HCI_NOT_ADV_REPORT;
    }
    size_t param_len = evt[1];
    if (param_len + 2u > len) {
        return BLE_HCI_ERR_MALFORMED;    /* header claims more than we were given */
    }
    if (evt[2] != BLE_HCI_SUBEVT_ADV_REPORT && evt[2] != BLE_HCI_SUBEVT_EXT_ADV_REPORT) {
        return BLE_HCI_NOT_ADV_REPORT;
    }
    if (param_len < 2u) {
        return BLE_HCI_ERR_MALFORMED;
    }

    it->subevent  = evt[2];
    it->remaining = evt[3];
    it->p   = &evt[4];
    it->end = &evt[2u + param_len];
    return BLE_HCI_OK;
}

/*
 * Implementation note: reports are taken to be laid out one after another,
 * each complete (type, address, data, rssi) before the next begins — the
 * layout the Linux kernel parses and every controller we captured sends.
 * Num_Reports is almost always 1 in practice.
 */
/**
 * @par Implementation
 * Decode one report and advance past it.
 *
 * Both lengths are checked before any field is copied: first the fixed part
 * (::LEGACY_FIXED or ::EXT_FIXED), then the fixed part plus the data length
 * the report declares (plus the trailing RSSI byte for legacy reports).
 * A legacy report is widened to the common ::ble_adv_report_t with
 * tx_power set to ::BLE_TX_POWER_UNAVAILABLE and PHYs and SID set to 0,
 * which the legacy format does not carry. On a malformed report the
 * remaining count is zeroed so the iterator cannot be walked further.
 */
ble_hci_status_t ble_hci_adv_next(ble_adv_iter_t *it, ble_adv_report_t *out)
{
    if (it->remaining == 0u) {
        return BLE_HCI_END;
    }
    size_t avail = (size_t)(it->end - it->p);
    const uint8_t *p = it->p;

    if (it->subevent == BLE_HCI_SUBEVT_ADV_REPORT) {
        if (avail < LEGACY_FIXED) {
            goto malformed;
        }
        uint8_t dlen = p[8];
        if (avail < LEGACY_FIXED + dlen + 1u) {      /* +1: trailing RSSI byte */
            goto malformed;
        }
        out->from_legacy_event = true;
        out->evt_type      = p[0];
        out->addr_type     = p[1];
        ble_copy(out->addr, &p[2], 6);
        out->data_len      = dlen;
        out->data          = &p[9];
        out->rssi          = (int8_t)p[9u + dlen];
        out->tx_power      = BLE_TX_POWER_UNAVAILABLE;
        out->primary_phy   = 0u;
        out->secondary_phy = 0u;
        out->sid           = 0u;
        it->p += LEGACY_FIXED + dlen + 1u;
    } else {
        if (avail < EXT_FIXED) {
            goto malformed;
        }
        uint8_t dlen = p[23];
        if (avail < EXT_FIXED + dlen) {
            goto malformed;
        }
        out->from_legacy_event = false;
        out->evt_type      = ble_le16(&p[0]);
        out->addr_type     = p[2];
        ble_copy(out->addr, &p[3], 6);
        out->primary_phy   = p[9];
        out->secondary_phy = p[10];
        out->sid           = p[11];
        out->tx_power      = (int8_t)p[12];
        out->rssi          = (int8_t)p[13];
        out->data_len      = dlen;
        out->data          = &p[24];
        it->p += EXT_FIXED + dlen;
    }
    it->remaining--;
    return BLE_HCI_OK;

malformed:
    it->remaining = 0u;                 /* refuse to walk any further */
    return BLE_HCI_ERR_MALFORMED;
}

/**
 * @par Implementation
 * A legacy report is answered before evt_type is read: in that format the
 * field is a 1-byte PDU type with no status bits. Otherwise mask bits 5–6
 * and shift them down, which maps 00/01/10/11 straight onto the enum.
 */
ble_adv_data_status_t ble_adv_report_data_status(const ble_adv_report_t *r)
{
    if (r->from_legacy_event) {
        return BLE_ADV_DATA_COMPLETE;
    }
    uint16_t status_bits = (uint16_t)(r->evt_type & BLE_EXT_EVT_DATA_STATUS_MASK);  /* bits 5-6 */
    status_bits >>= DATA_STATUS_SHIFT;
    return (ble_adv_data_status_t)status_bits;
}
