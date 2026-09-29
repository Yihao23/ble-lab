/**
 * @file  ble_ad.c
 * @brief Advertising Data parser — implementation.
 *
 * All the bounds checking is in ble_ad_next(); every other function is built
 * on it, so there is exactly one place that reads a length byte.
 */
#include "ble/ble_ad.h"
#include "ble_util.h"

/**
 * @par Implementation
 * Start iterating over an advertising payload.
 *
 * A NULL buffer is normalised to length 0 here, so ble_ad_next() never has
 * to test the pointer.
 */
void ble_ad_iter_init(ble_ad_iter_t *it, const uint8_t *buf, size_t len)
{
    it->buf = buf;
    it->len = (buf != NULL) ? len : 0u;
    it->pos = 0u;
}

/**
 * @par Implementation
 * Advance to the next AD structure — the only function that reads a length byte.
 *
 * Checks, in order: end of buffer; a zero length byte (padding: jump to the
 * end); a length that would run past the buffer, tested as
 * `field_len > len - pos - 1`, which cannot overflow because `pos < len`
 * holds here. On any stop condition @c pos is set to @c len, so every later
 * call returns ::BLE_AD_END without touching the buffer.
 */
ble_ad_status_t ble_ad_next(ble_ad_iter_t *it, ble_ad_t *out)
{
    if (it->pos >= it->len) {
        return BLE_AD_END;
    }

    size_t field_len = it->buf[it->pos];
    if (field_len == 0u) {
        /* A zero length field marks the start of padding: nothing follows. */
        it->pos = it->len;
        return BLE_AD_END;
    }

    /* The field is 1 length byte plus field_len bytes of type+data. */
    if (field_len > it->len - it->pos - 1u) {
        it->pos = it->len;              /* stop: never read past the buffer */
        return BLE_AD_ERR_TRUNCATED;
    }

    out->type = it->buf[it->pos + 1u];
    out->len  = (uint8_t)(field_len - 1u);
    out->data = &it->buf[it->pos + 2u];
    it->pos  += 1u + field_len;
    return BLE_AD_OK;
}

/**
 * @par Implementation
 * Find the first AD structure of a given type.
 *
 * A linear walk with ble_ad_next(); stops at the first match, at the end, or
 * at the first malformed structure — nothing after a bad length is trusted.
 */
bool ble_ad_find(const uint8_t *buf, size_t len, uint8_t type, ble_ad_t *out)
{
    ble_ad_iter_t it;
    ble_ad_t ad;
    ble_ad_iter_init(&it, buf, len);
    while (ble_ad_next(&it, &ad) == BLE_AD_OK) {
        if (ad.type == type) {
            *out = ad;
            return true;
        }
    }
    return false;
}

/**
 * @par Implementation
 * Check that a whole payload parses cleanly to its end.
 *
 * Walks every structure and reports whether the walk ended with
 * ::BLE_AD_END rather than ::BLE_AD_ERR_TRUNCATED.
 */
bool ble_ad_is_well_formed(const uint8_t *buf, size_t len)
{
    ble_ad_iter_t it;
    ble_ad_t ad;
    ble_ad_status_t st;
    ble_ad_iter_init(&it, buf, len);
    while ((st = ble_ad_next(&it, &ad)) == BLE_AD_OK) {
    }
    return st == BLE_AD_END;
}

/**
 * @par Implementation
 * Split a Manufacturer Specific Data structure into company ID and payload.
 *
 * The company identifier is the first two data bytes, little-endian. The
 * payload pointer aliases the caller's buffer.
 */
bool ble_ad_manufacturer(const ble_ad_t *ad, uint16_t *company_id,
                         const uint8_t **payload, uint8_t *payload_len)
{
    if (ad->type != BLE_AD_MANUFACTURER || ad->len < 2u) {
        return false;
    }
    *company_id  = ble_le16(ad->data);
    *payload     = ad->data + 2;
    *payload_len = (uint8_t)(ad->len - 2u);
    return true;
}

/**
 * @par Implementation
 * Number of 16-bit UUIDs in a UUID16 list.
 *
 * Integer division by 2 drops a trailing odd byte instead of reading half a UUID.
 */
uint8_t ble_ad_uuid16_count(const ble_ad_t *ad)
{
    if (ad->type != BLE_AD_UUID16_COMPLETE && ad->type != BLE_AD_UUID16_INCOMPLETE) {
        return 0u;
    }
    return (uint8_t)(ad->len / 2u);
}

/**
 * @par Implementation
 * The i-th UUID of a UUID16 list.
 *
 * Bounds-checked through ble_ad_uuid16_count(), which also rejects other AD types.
 */
uint16_t ble_ad_uuid16_at(const ble_ad_t *ad, uint8_t i)
{
    if (i >= ble_ad_uuid16_count(ad)) {
        return 0u;
    }
    return ble_le16(&ad->data[2u * i]);
}
