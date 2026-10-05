/**
 * @file  ble_l2cap.h
 * @brief HCI ACL data packets and the L2CAP header inside them.
 *
 * Once a link is up, everything above the controller — ATT, SMP, L2CAP
 * signalling — travels in HCI ACL data packets (Core Vol 4 Part E, 5.4.2):
 * @verbatim
   | Handle 12 bits | PB 2 | BC 2 | Data Total Length 16 | data ...
   @endverbatim
 * and the data of a packet that starts a message opens with the L2CAP basic
 * header (Core Vol 3 Part A, 3.1):
 * @verbatim
   | PDU Length 16 | Channel ID 16 | payload (PDU Length octets) |
   @endverbatim
 * All multi-octet fields little-endian. On an LE link the channel says which
 * protocol the payload is: ATT on 0x0004, LE signalling on 0x0005, SMP on 0x0006.
 *
 * @par Fragmentation
 * An L2CAP PDU longer than one ACL packet arrives as a first packet followed
 * by continuing fragments (PB = 0b01). This version does not reassemble: it
 * recognises both cases and reports them, so a caller never mistakes part
 * of a PDU for the whole of one.
 *
 * Nothing is copied: every pointer points into the caller's buffer.
 *
 * @defgroup ble_l2cap HCI ACL and L2CAP
 * @brief Split an HCI ACL data packet into connection, channel and payload.
 * @{
 */
#ifndef BLE_L2CAP_H
#define BLE_L2CAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name Packet_Boundary_Flag values (Core Vol 4 Part E, 5.4.2)
 * @{
 */
#define BLE_ACL_PB_FIRST_NON_FLUSHABLE 0x0u  /**< Start of a message, host to controller. */
#define BLE_ACL_PB_CONTINUING          0x1u  /**< A continuing fragment, either direction. */
#define BLE_ACL_PB_FIRST_FLUSHABLE     0x2u  /**< Start of a message; controller to host on LE. */
/** @} */

/**
 * @name Fixed L2CAP channels (Core Vol 3 Part A, 2.1)
 * @{
 */
#define BLE_L2CAP_CID_SIGNALING        0x0001u  /**< BR/EDR signalling channel (ACL-U only). */
#define BLE_L2CAP_CID_ATT              0x0004u  /**< Attribute Protocol. */
#define BLE_L2CAP_CID_LE_SIGNALING     0x0005u  /**< LE signalling channel. */
#define BLE_L2CAP_CID_SMP              0x0006u  /**< Security Manager Protocol. */
/** @} */

/** @brief One HCI ACL data packet, header decoded. */
typedef struct {
    uint16_t       handle;  /**< Connection_Handle, 12 bits. */
    uint8_t        pb;      /**< Packet_Boundary_Flag, 2 bits: `BLE_ACL_PB_*`. */
    uint8_t        bc;      /**< Broadcast_Flag, 2 bits; 0 on LE. */
    const uint8_t *data;    /**< First data octet, in the caller's buffer. */
    uint16_t       len;     /**< Data Total Length. */
} ble_acl_t;

/** @brief Result of ble_acl_parse(). */
typedef enum {
    BLE_ACL_ERR_MALFORMED = -1,  /**< Shorter than the header, or the length field disagrees with the packet. */
    BLE_ACL_OK            = 1    /**< @p out holds the packet. */
} ble_acl_status_t;

/**
 * @brief Decode an HCI ACL data packet header.
 *
 * @param[in]  pkt  The packet, starting at the handle field (no H4 indicator,
 *                  no monitor header). May be NULL when @p len is 0.
 * @param[in]  len  Bytes available at @p pkt.
 * @param[out] out  Receives the packet on ::BLE_ACL_OK; untouched otherwise.
 * @retval BLE_ACL_OK            Header decoded; Data Total Length equals len - 4.
 * @retval BLE_ACL_ERR_MALFORMED Fewer than 4 bytes, or Data Total Length is not
 *                               exactly the number of bytes after the header.
 *
 * A handle in the reserved range above 0x0EFF is reported as it is, not
 * rejected: a parser of captured traffic describes what it received.
 */
ble_acl_status_t ble_acl_parse(const uint8_t *pkt, size_t len, ble_acl_t *out);

/** @brief An L2CAP basic-mode PDU (B-frame) header and payload. */
typedef struct {
    uint16_t       cid;      /**< Channel ID: `BLE_L2CAP_CID_*` or any other. */
    uint16_t       len;      /**< PDU Length from the header: the whole payload's size. */
    const uint8_t *payload;  /**< First payload octet, in the caller's buffer. */
} ble_l2cap_t;

/** @brief Result of ble_l2cap_parse(). */
typedef enum {
    BLE_L2CAP_ERR_MALFORMED = -3,  /**< Data too short for the L2CAP header, or longer than the PDU it claims. */
    BLE_L2CAP_CONTINUATION  = -2,  /**< This packet continues an earlier PDU (PB = 0b01); no header to read. */
    BLE_L2CAP_FRAGMENTED    = -1,  /**< First packet of a PDU that continues in later packets. */
    BLE_L2CAP_OK            = 1    /**< The whole PDU is in this packet. */
} ble_l2cap_status_t;

/**
 * @brief Read the L2CAP basic header from the data of an ACL packet.
 *
 * @param[in]  acl  A packet from ble_acl_parse().
 * @param[out] out  On ::BLE_L2CAP_OK: channel, length and payload. On
 *                  ::BLE_L2CAP_FRAGMENTED: channel and the full PDU Length,
 *                  with @c payload pointing at the part present in this
 *                  packet (acl->len - 4 octets). Untouched otherwise.
 * @retval BLE_L2CAP_OK            acl->len - 4 equals PDU Length.
 * @retval BLE_L2CAP_FRAGMENTED    PDU Length is larger: later packets carry the rest.
 * @retval BLE_L2CAP_CONTINUATION acl->pb is ::BLE_ACL_PB_CONTINUING.
 * @retval BLE_L2CAP_ERR_MALFORMED Fewer than 4 data octets in a first packet, or
 *                                 more payload than PDU Length allows.
 */
ble_l2cap_status_t ble_l2cap_parse(const ble_acl_t *acl, ble_l2cap_t *out);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* BLE_L2CAP_H */
