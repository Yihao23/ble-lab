/**
 * @file  ble_hci.h
 * @brief HCI LE advertising report parser.
 *
 * When the host asks the controller to scan, every advertisement heard comes
 * back as an HCI LE Meta event (Core Spec Vol 4 Part E, 7.7.65). Two formats
 * exist:
 *
 * | Subevent | Name                           | Used by                      |
 * |----------|--------------------------------|------------------------------|
 * | `0x02`   | LE Advertising Report          | Bluetooth 4.x legacy scanning |
 * | `0x0D`   | LE Extended Advertising Report | Bluetooth 5 extended scanning |
 *
 * Which one a host receives depends on how it enabled scanning, not on what
 * the advertiser sent: a BlueZ 5.72 host on an Intel AX201 enables extended
 * scanning, so even a Bluetooth 4.0 beacon arrives as `0x0D` with the legacy
 * bit set. Handling only `0x02` — the format most tutorials show — silently
 * drops every report on modern controllers.
 *
 * The parser takes an HCI event starting at the event code byte (no H4
 * packet indicator) and walks the reports in it without copying.
 *
 * @par Example
 * @code
 * ble_adv_iter_t it;
 * ble_adv_report_t r;
 * if (ble_hci_adv_iter_init(&it, evt, evt_len) == BLE_HCI_OK) {
 *     while (ble_hci_adv_next(&it, &r) == BLE_HCI_OK) {
 *         // r.addr, r.rssi, r.data[0 .. r.data_len-1]
 *     }
 * }
 * @endcode
 *
 * @defgroup ble_hci HCI advertising reports
 * @brief Walk the reports inside an HCI LE (Extended) Advertising Report event.
 * @{
 */
#ifndef BLE_HCI_H
#define BLE_HCI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name Event codes
 * @{
 */
#define BLE_HCI_EVT_LE_META              0x3Eu  /**< HCI LE Meta event code. */
#define BLE_HCI_SUBEVT_ADV_REPORT        0x02u  /**< LE Advertising Report subevent. */
#define BLE_HCI_SUBEVT_EXT_ADV_REPORT    0x0Du  /**< LE Extended Advertising Report subevent. */
/** @} */

/**
 * @name Extended report event-type bits
 * @{
 */
#define BLE_EXT_EVT_CONNECTABLE          0x0001u  /**< Connectable advertising. */
#define BLE_EXT_EVT_SCANNABLE            0x0002u  /**< Scannable advertising. */
#define BLE_EXT_EVT_DIRECTED             0x0004u  /**< Directed advertising. */
#define BLE_EXT_EVT_SCAN_RSP             0x0008u  /**< This report is a scan response. */
#define BLE_EXT_EVT_LEGACY               0x0010u  /**< Received as a legacy (4.x) PDU. */
#define BLE_EXT_EVT_DATA_STATUS_MASK     0x0060u  /**< Data status: 00 complete, 01 more, 10 truncated. */
/** @} */

/**
 * @name HCI address types in advertising reports
 * @{
 */
#define BLE_HCI_ADDR_PUBLIC              0x00u  /**< Public device address. */
#define BLE_HCI_ADDR_RANDOM              0x01u  /**< Random device address. */
#define BLE_HCI_ADDR_PUBLIC_IDENTITY     0x02u  /**< Public identity; the controller already resolved an RPA. */
#define BLE_HCI_ADDR_RANDOM_IDENTITY     0x03u  /**< Random (static) identity; resolved by the controller. */
#define BLE_HCI_ADDR_ANONYMOUS           0xFFu  /**< Anonymous advertising: no address. */
/** @} */

#define BLE_RSSI_UNAVAILABLE             127    /**< RSSI value meaning "not available". */
#define BLE_TX_POWER_UNAVAILABLE         127    /**< TX power value meaning "not available". */

/** @brief One advertising report, in a format common to both subevents. */
typedef struct {
    bool           from_legacy_event;  /**< Parsed from `0x02` rather than `0x0D`. */
    uint16_t       evt_type;           /**< Raw event type (1 byte for `0x02`, `BLE_EXT_EVT_*` bits for `0x0D`). */
    uint8_t        addr_type;          /**< One of `BLE_HCI_ADDR_*`. */
    uint8_t        addr[6];            /**< Advertiser address, LSB-first. */
    int8_t         rssi;               /**< dBm, or ::BLE_RSSI_UNAVAILABLE. */
    int8_t         tx_power;           /**< dBm; ::BLE_TX_POWER_UNAVAILABLE for `0x02` and legacy PDUs. */
    uint8_t        primary_phy;        /**< 1 = LE 1M, 3 = LE Coded; 0 for `0x02`. */
    uint8_t        secondary_phy;      /**< 0 = none; 0 for `0x02`. */
    uint8_t        sid;                /**< Advertising set ID; 0xFF = none; 0 for `0x02`. */
    const uint8_t *data;               /**< AD structures, pointing into the event buffer. */
    uint8_t        data_len;           /**< Length of @ref data. */
} ble_adv_report_t;

/**
 * @brief Iterator over the reports of one event. Initialise with
 *        ble_hci_adv_iter_init(); treat as opaque.
 */
typedef struct {
    const uint8_t *p;           /**< Start of the next report. */
    const uint8_t *end;         /**< One past the last parameter byte. */
    uint8_t        subevent;    /**< ::BLE_HCI_SUBEVT_ADV_REPORT or ::BLE_HCI_SUBEVT_EXT_ADV_REPORT. */
    uint8_t        remaining;   /**< Reports not yet returned. */
} ble_adv_iter_t;

/** @brief Result of the HCI iterator functions. */
typedef enum {
    BLE_HCI_ERR_MALFORMED   = -2,  /**< Lengths do not add up. */
    BLE_HCI_NOT_ADV_REPORT  = -1,  /**< A valid event, just not an advertising report. */
    BLE_HCI_END             = 0,   /**< No more reports. */
    BLE_HCI_OK              = 1    /**< Success. */
} ble_hci_status_t;

/**
 * @brief Start walking an HCI event.
 *
 * @param[out] it   Iterator to initialise.
 * @param[in]  evt  Event, starting at the event code (no H4 indicator); may be NULL.
 * @param[in]  len  Number of bytes available at @p evt.
 * @retval BLE_HCI_OK              An advertising report event; call ble_hci_adv_next().
 * @retval BLE_HCI_NOT_ADV_REPORT  Some other event or LE subevent.
 * @retval BLE_HCI_ERR_MALFORMED   Shorter than a header, or the parameter
 *                                 length claims more bytes than @p len.
 */
ble_hci_status_t ble_hci_adv_iter_init(ble_adv_iter_t *it, const uint8_t *evt, size_t len);

/**
 * @brief Return the next report of the event.
 *
 * @param[in,out] it   Iterator from ble_hci_adv_iter_init().
 * @param[out]    out  Receives the report on ::BLE_HCI_OK.
 * @retval BLE_HCI_OK             @p out holds the next report.
 * @retval BLE_HCI_END            All reports returned.
 * @retval BLE_HCI_ERR_MALFORMED  A report overruns the event. The iterator
 *                                then refuses to walk further.
 */
ble_hci_status_t ble_hci_adv_next(ble_adv_iter_t *it, ble_adv_report_t *out);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* BLE_HCI_H */
