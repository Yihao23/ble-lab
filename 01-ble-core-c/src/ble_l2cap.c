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
