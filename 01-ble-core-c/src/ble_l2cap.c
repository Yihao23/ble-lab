/**
 * @file  ble_l2cap.c
 * @brief HCI ACL data packets and the L2CAP header — implementation.
 *
 * Every length is checked before the bytes it covers are read, and every
 * comparison is between sizes already known to be in range, so no
 * subtraction can wrap.
 */
#include "ble/ble_l2cap.h"
#include "ble_util.h"

/** @brief Size of the HCI ACL data packet header: handle and flags (2), length (2). */
#define ACL_HEADER_LEN   4u

/** @brief Size of the L2CAP basic header: PDU Length (2), Channel ID (2). */
#define L2CAP_HEADER_LEN 4u

/**
 * @par Implementation
 * The first two octets are one little-endian 16-bit word: Connection_Handle
 * in bits 0–11, Packet_Boundary_Flag in bits 12–13, Broadcast_Flag in bits
 * 14–15 (Core Vol 4 Part E, 5.4.2). The next two are Data Total Length,
 * which must account for exactly the rest of the packet: a packet that claims
 * more would be read past its end, one that claims less hides trailing bytes
 * whose meaning nobody knows. @p out is written only once all of that holds.
 */
ble_acl_status_t ble_acl_parse(const uint8_t *pkt, size_t len, ble_acl_t *out)
{
    if (pkt == NULL || len < ACL_HEADER_LEN) {
        return BLE_ACL_ERR_MALFORMED;
    }

    uint16_t hdr = ble_le16(&pkt[0]);
    uint16_t data_len = ble_le16(&pkt[2]);
    if ((size_t)data_len != len - ACL_HEADER_LEN) {
        return BLE_ACL_ERR_MALFORMED;
    }

    out->handle = (uint16_t)(hdr & 0x0FFFu);
    out->pb     = (uint8_t)((hdr >> 12) & 0x3u);
    out->bc     = (uint8_t)((hdr >> 14) & 0x3u);
    out->data   = &pkt[ACL_HEADER_LEN];
    out->len    = data_len;
    return BLE_ACL_OK;
}

/**
 * @par Implementation
 * A continuing fragment carries no L2CAP header — its first bytes are the
 * middle of some earlier PDU — so it is reported before anything is read.
 * Otherwise the PDU Length in the header is compared with what this packet
 * actually brought after the header: equal is a whole PDU, larger is the
 * first part of one that continues, smaller means bytes nobody accounts for.
 */
ble_l2cap_status_t ble_l2cap_parse(const ble_acl_t *acl, ble_l2cap_t *out)
{
    if (acl->pb == BLE_ACL_PB_CONTINUING) {
        return BLE_L2CAP_CONTINUATION;
    }
    if (acl->len < L2CAP_HEADER_LEN) {
        return BLE_L2CAP_ERR_MALFORMED;
    }

    uint16_t pdu_len = ble_le16(&acl->data[0]);
    uint16_t present = (uint16_t)(acl->len - L2CAP_HEADER_LEN);
    if (pdu_len < present) {
        return BLE_L2CAP_ERR_MALFORMED;
    }

    out->cid     = ble_le16(&acl->data[2]);
    out->len     = pdu_len;
    out->payload = &acl->data[L2CAP_HEADER_LEN];
    return (pdu_len > present) ? BLE_L2CAP_FRAGMENTED : BLE_L2CAP_OK;
}

/** @brief Reassembler states. */
enum {
    REASM_IDLE,        /**< No PDU in progress. */
    REASM_COLLECTING,  /**< Copying a PDU into the buffer. */
    REASM_SKIPPING     /**< Counting off the fragments of a PDU too long to keep. */
};

/** @brief Size of the PDU Length field, the part of the header needed to size the PDU. */
#define L2CAP_LEN_FIELD 2u

/**
 * @par Implementation
 * Checks before it writes: @p r is filled only once both arguments are
 * known good, so a failed call leaves it as it was.
 */
int ble_l2cap_reasm_init(ble_l2cap_reasm_t *r, uint8_t *buf, size_t cap)
{
    if (buf == NULL || cap < BLE_L2CAP_REASM_MIN) {
        return 0;
    }
    r->buf = buf;
    r->cap = cap;
    r->state = REASM_IDLE;
    r->handle = 0;
    r->have = 0;
    r->want = 0;
    r->lost = 0;
    return 1;
}

/**
 * @brief Take @p n more octets of the PDU in progress, after the header
 *        octets have been dealt with: overrun, too long, or copy.
 * @param[in,out] r    Context, collecting, @c want known.
 * @param[in]     src  The octets.
 * @param[in]     n    How many.
 * @param[out]    out  Receives the PDU if this completes it.
 * @return The status for the caller.
 */
static ble_l2cap_reasm_status_t reasm_take(ble_l2cap_reasm_t *r, const uint8_t *src, size_t n,
                                           ble_l2cap_t *out)
{
    if (n > r->want - r->have) {
        r->state = REASM_IDLE;
        r->lost++;
        return BLE_L2CAP_REASM_ERR_OVERRUN;
    }
    if (r->want > r->cap) {
        r->lost++;
        r->have += n;
        r->state = (r->have == r->want) ? REASM_IDLE : REASM_SKIPPING;
        return BLE_L2CAP_REASM_ERR_TOO_LONG;
    }
    ble_copy(&r->buf[r->have], src, n);
    r->have += n;
    if (r->have < r->want) {
        return BLE_L2CAP_REASM_PENDING;
    }
    r->state = REASM_IDLE;
    out->cid = ble_le16(&r->buf[2]);
    out->len = (uint16_t)(r->want - L2CAP_HEADER_LEN);
    out->payload = &r->buf[L2CAP_HEADER_LEN];
    return BLE_L2CAP_REASM_COMPLETE;
}

/**
 * @brief Append to the PDU in progress, reading the PDU Length as soon as
 *        its two octets are in.
 * @param[in,out] r    Context, collecting.
 * @param[in]     src  The octets.
 * @param[in]     n    How many.
 * @param[out]    out  Receives the PDU if this completes it.
 * @return The status for the caller.
 */
static ble_l2cap_reasm_status_t reasm_append(ble_l2cap_reasm_t *r, const uint8_t *src, size_t n,
                                             ble_l2cap_t *out)
{
    if (r->want == 0) {
        /* The length field is not complete yet. Its octets always fit:
           cap >= 4. */
        size_t k = L2CAP_LEN_FIELD - r->have;
        if (k > n) {
            k = n;
        }
        ble_copy(&r->buf[r->have], src, k);
        r->have += k;
        src += k;
        n -= k;
        if (r->have < L2CAP_LEN_FIELD) {
            return BLE_L2CAP_REASM_PENDING;
        }
        r->want = L2CAP_HEADER_LEN + (size_t)ble_le16(r->buf);
    }
    return reasm_take(r, src, n, out);
}

/**
 * @par Implementation
 * Three states: idle, collecting into the buffer, and skipping a PDU too
 * long for it, where only the octets are counted so that its last fragment
 * is recognised and the next start is not mistaken for an orphan. The
 * rules are the table in ble_l2cap.h, in its order. Every comparison is
 * between sizes already known to be in range: @c have never exceeds
 * @c want once @c want is known, so <tt>want - have</tt> cannot wrap.
 */
ble_l2cap_reasm_status_t ble_l2cap_reasm_push(ble_l2cap_reasm_t *r, const ble_acl_t *acl,
                                              ble_l2cap_t *out)
{
    if (acl->pb == 0x3u) {
        return BLE_L2CAP_REASM_ERR_MALFORMED;
    }

    if (acl->pb != BLE_ACL_PB_CONTINUING) {
        if (r->state == REASM_COLLECTING) {
            r->lost++;                       /* interrupted */
        }
        r->state = REASM_IDLE;

        if (acl->len >= L2CAP_LEN_FIELD) {
            size_t want = L2CAP_HEADER_LEN + (size_t)ble_le16(acl->data);
            if (acl->len > want) {
                r->lost++;
                return BLE_L2CAP_REASM_ERR_OVERRUN;
            }
            if (acl->len == want) {          /* whole: hand it out in place */
                out->cid = ble_le16(&acl->data[2]);
                out->len = (uint16_t)(want - L2CAP_HEADER_LEN);
                out->payload = &acl->data[L2CAP_HEADER_LEN];
                return BLE_L2CAP_REASM_COMPLETE;
            }
        }
        r->state = REASM_COLLECTING;
        r->handle = acl->handle;
        r->have = 0;
        r->want = 0;
        return reasm_append(r, acl->data, acl->len, out);
    }

    if (r->state == REASM_IDLE) {
        return BLE_L2CAP_REASM_ERR_ORPHAN;
    }
    if (acl->handle != r->handle) {
        return BLE_L2CAP_REASM_ERR_HANDLE;
    }
    if (r->state == REASM_SKIPPING) {
        if (acl->len > r->want - r->have) {
            r->state = REASM_IDLE;
            return BLE_L2CAP_REASM_ERR_OVERRUN;
        }
        r->have += acl->len;
        if (r->have == r->want) {
            r->state = REASM_IDLE;
        }
        return BLE_L2CAP_REASM_ERR_TOO_LONG;
    }
    return reasm_append(r, acl->data, acl->len, out);
}
