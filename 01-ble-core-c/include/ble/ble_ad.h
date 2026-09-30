/**
 * @file  ble_ad.h
 * @brief Advertising Data (AD) parser — zero copy, bounds-checked.
 *
 * An advertising payload is a sequence of AD structures (Core Spec Vol 3
 * Part C, section 11):
 * @verbatim
   | len | type | data (len - 1 bytes) | len | type | data | ... | 0 padding
   @endverbatim
 *
 * The payload arrives from the air, so every byte is attacker-controlled. A
 * `len` that points past the end of the buffer is the classic way to make a
 * parser read memory it does not own. This parser never does: it reports the
 * structure as malformed and stops.
 *
 * Nothing is copied. Each ::ble_ad_t points into the caller's buffer, which
 * must outlive it.
 *
 * @par Example
 * @code
 * ble_ad_iter_t it;
 * ble_ad_t ad;
 * ble_ad_iter_init(&it, data, data_len);
 * while (ble_ad_next(&it, &ad) == BLE_AD_OK) {
 *     if (ad.type == BLE_AD_NAME_COMPLETE) {
 *         // ad.data[0 .. ad.len-1] is the name, not NUL-terminated
 *     }
 * }
 * @endcode
 *
 * @defgroup ble_ad Advertising Data
 * @brief Iterate and query AD structures in an advertising payload.
 * @{
 */
#ifndef BLE_AD_H
#define BLE_AD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name AD types
 * From Bluetooth Assigned Numbers, "Common Data Types".
 * @{
 */
#define BLE_AD_FLAGS                0x01u   /**< Flags (discoverable mode, BR/EDR support). */
#define BLE_AD_UUID16_INCOMPLETE    0x02u   /**< Incomplete list of 16-bit service UUIDs. */
#define BLE_AD_UUID16_COMPLETE      0x03u   /**< Complete list of 16-bit service UUIDs. */
#define BLE_AD_UUID128_INCOMPLETE   0x06u   /**< Incomplete list of 128-bit service UUIDs. */
#define BLE_AD_UUID128_COMPLETE     0x07u   /**< Complete list of 128-bit service UUIDs. */
#define BLE_AD_NAME_SHORT           0x08u   /**< Shortened local name. */
#define BLE_AD_NAME_COMPLETE        0x09u   /**< Complete local name. */
#define BLE_AD_TX_POWER             0x0Au   /**< TX power level, signed dBm. */
#define BLE_AD_SERVICE_DATA16       0x16u   /**< Service data with a 16-bit UUID. */
#define BLE_AD_APPEARANCE           0x19u   /**< Appearance, 16-bit little-endian. */
#define BLE_AD_MANUFACTURER         0xFFu   /**< Manufacturer specific data. */
/** @} */

/**
 * @name Flags AD bits
 * @{
 */
#define BLE_AD_FLAG_LE_LIMITED      0x01u   /**< LE Limited Discoverable Mode (max 180 s). */
#define BLE_AD_FLAG_LE_GENERAL      0x02u   /**< LE General Discoverable Mode. */
#define BLE_AD_FLAG_NO_BREDR        0x04u   /**< BR/EDR Not Supported. */
/** @} */

/** @brief One AD structure, pointing into the caller's buffer. */
typedef struct {
    uint8_t        type;    /**< AD type, one of the `BLE_AD_*` values or any other. */
    uint8_t        len;     /**< Length of @ref data, excluding the type byte. */
    const uint8_t *data;    /**< First data byte; valid while the source buffer is. */
} ble_ad_t;

/**
 * @brief Iterator state. Initialise with ble_ad_iter_init(); treat as opaque.
 */
typedef struct {
    const uint8_t *buf;     /**< Payload being walked. */
    size_t         len;     /**< Payload length in bytes. */
    size_t         pos;     /**< Offset of the next length byte. */
} ble_ad_iter_t;

/** @brief Result of ble_ad_next(). */
typedef enum {
    BLE_AD_ERR_TRUNCATED = -1,  /**< A length field runs past the buffer. */
    BLE_AD_END           = 0,   /**< No more structures (end of buffer or zero padding). */
    BLE_AD_OK            = 1    /**< A structure was returned. */
} ble_ad_status_t;

/**
 * @brief Start iterating over an advertising payload.
 *
 * @param[out] it   Iterator to initialise.
 * @param[in]  buf  Payload; may be NULL, which is treated as empty.
 * @param[in]  len  Payload length in bytes.
 */
void ble_ad_iter_init(ble_ad_iter_t *it, const uint8_t *buf, size_t len);

/**
 * @brief Advance to the next AD structure.
 *
 * @param[in,out] it   Iterator.
 * @param[out]    out  Receives the structure when ::BLE_AD_OK is returned;
 *                     untouched otherwise.
 * @retval BLE_AD_OK             @p out holds the next structure.
 * @retval BLE_AD_END            End of the payload or start of zero padding.
 * @retval BLE_AD_ERR_TRUNCATED  A length byte points past the end. No byte
 *                               beyond the buffer is read.
 *
 * After ::BLE_AD_END or ::BLE_AD_ERR_TRUNCATED, every further call returns
 * ::BLE_AD_END.
 */
ble_ad_status_t ble_ad_next(ble_ad_iter_t *it, ble_ad_t *out);

/**
 * @brief Find the first AD structure of a given type.
 *
 * @param[in]  buf   Payload.
 * @param[in]  len   Payload length.
 * @param[in]  type  AD type to look for.
 * @param[out] out   Receives the structure if found.
 * @retval true   Found; @p out is set.
 * @retval false  Absent, or the payload became malformed before it was reached.
 */
bool ble_ad_find(const uint8_t *buf, size_t len, uint8_t type, ble_ad_t *out);

/**
 * @brief Check that a whole payload parses cleanly to its end.
 *
 * @param[in] buf  Payload.
 * @param[in] len  Payload length.
 * @retval true   Every structure fits in the buffer (zero padding allowed).
 * @retval false  Some length field overruns the buffer.
 */
bool ble_ad_is_well_formed(const uint8_t *buf, size_t len);

/**
 * @brief Split a Manufacturer Specific Data structure.
 *
 * @param[in]  ad           A structure of type ::BLE_AD_MANUFACTURER.
 * @param[out] company_id   Bluetooth SIG company identifier (little-endian on air).
 * @param[out] payload      Bytes after the company identifier.
 * @param[out] payload_len  Number of payload bytes; may be 0.
 * @retval true   @p ad is manufacturer data with at least a company identifier.
 * @retval false  Wrong type or shorter than 2 bytes; outputs untouched.
 */
bool ble_ad_manufacturer(const ble_ad_t *ad, uint16_t *company_id,
                         const uint8_t **payload, uint8_t *payload_len);

/**
 * @brief Number of 16-bit UUIDs in a UUID16 list.
 *
 * @param[in] ad  Any AD structure.
 * @return The count for ::BLE_AD_UUID16_COMPLETE / ::BLE_AD_UUID16_INCOMPLETE;
 *         0 for any other type. A trailing odd byte is ignored.
 */
uint8_t  ble_ad_uuid16_count(const ble_ad_t *ad);

/**
 * @brief The i-th UUID of a UUID16 list.
 *
 * @param[in] ad  A UUID16 list structure.
 * @param[in] i   Index, less than ble_ad_uuid16_count().
 * @return The UUID, or 0 if @p i is out of range or @p ad is not a UUID16 list.
 */
uint16_t ble_ad_uuid16_at(const ble_ad_t *ad, uint8_t i);

/**
 * @brief Read the value of the Flags AD structure.
 *
 * @param[in]  buf    Payload.
 * @param[in]  len    Payload length.
 * @param[out] flags  Receives the first data byte of the Flags structure.
 * @retval true   A Flags structure with at least one data byte was found.
 * @retval false  No Flags structure, an empty one, or the payload became
 *                malformed before one was reached. @p flags untouched.
 */
bool ble_ad_flags(const uint8_t *buf, size_t len, uint8_t *flags);

/**
 * @brief Find the device name: the Complete Local Name if present,
 *        otherwise the Shortened Local Name.
 *
 * The name is not NUL-terminated; it points into @p buf.
 *
 * @param[in]  buf       Payload.
 * @param[in]  len       Payload length.
 * @param[out] name      Receives a pointer to the first name byte.
 * @param[out] name_len  Receives the name length; 0 for an empty name.
 * @retval true   A name was found (possibly empty).
 * @retval false  No name structure before the end or before a malformed
 *                structure. Outputs untouched.
 */
bool ble_ad_name(const uint8_t *buf, size_t len, const uint8_t **name, uint8_t *name_len);

/**
 * @brief Split a Service Data – 16-bit UUID structure (AD type 0x16).
 *
 * The first two data bytes are the UUID, little-endian; the rest is the
 * service's payload.
 *
 * @param[in]  ad           AD structure.
 * @param[out] uuid         Service UUID.
 * @param[out] payload      Bytes after the UUID; points into the source buffer.
 * @param[out] payload_len  Number of payload bytes; may be 0.
 * @retval true   @p ad is 16-bit service data with at least a UUID.
 * @retval false  Wrong type or shorter than 2 bytes. Outputs untouched.
 */
bool ble_ad_service_data16(const ble_ad_t *ad, uint16_t *uuid,
                           const uint8_t **payload, uint8_t *payload_len);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* BLE_AD_H */
