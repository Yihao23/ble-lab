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
 * by continuing fragments (PB = 0b01). ble_l2cap_parse() recognises both
 * cases and reports them, so a caller never mistakes part of a PDU for the
 * whole of one; ble_l2cap_reasm_push() puts the parts back together.
 *
 * The parsers copy nothing: every pointer points into the caller's buffer.
 * The reassembler copies a fragmented PDU into a buffer the caller gives it
 * once, and nothing else: no heap.
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

/**
 * @name Reassembly
 * @{
 */

/** @brief Smallest buffer ble_l2cap_reasm_init() accepts: one L2CAP basic header. */
#define BLE_L2CAP_REASM_MIN 4u

/**
 * @brief Reassembly state for one connection in one direction.
 *
 * Fragments of two PDUs never interleave on one connection and direction,
 * so one context per connection (and per direction, for a capture that
 * holds both) is enough. Treat the fields as private: they are public only
 * so the context can live on the stack or in a static, without a heap.
 */
typedef struct {
    uint8_t  *buf;     /**< Storage for a fragmented PDU, header included. */
    size_t    cap;     /**< Size of @ref buf. */
    uint8_t   state;   /**< Idle, collecting or skipping; see ble_l2cap.c. */
    uint16_t  handle;  /**< Connection of the PDU in progress. */
    size_t    have;    /**< Octets of the PDU in progress received so far, header included. */
    size_t    want;    /**< 4 + PDU Length once the length field has arrived; 0 before. */
    uint32_t  lost;    /**< PDUs started but never delivered. Only ever grows. */
} ble_l2cap_reasm_t;

/** @brief Result of ble_l2cap_reasm_push(). */
typedef enum {
    BLE_L2CAP_REASM_ERR_MALFORMED = -5,  /**< PB = 0b11, reserved on LE. Packet ignored, state unchanged. */
    BLE_L2CAP_REASM_ERR_OVERRUN   = -4,  /**< More octets than PDU Length allows. That PDU is dropped. */
    BLE_L2CAP_REASM_ERR_TOO_LONG  = -3,  /**< The PDU does not fit the buffer. It and its later fragments are dropped. */
    BLE_L2CAP_REASM_ERR_HANDLE    = -2,  /**< A continuation for another connection. Ignored; the PDU in progress is kept. */
    BLE_L2CAP_REASM_ERR_ORPHAN    = -1,  /**< A continuation with no PDU in progress. Ignored. */
    BLE_L2CAP_REASM_PENDING       = 0,   /**< Taken; the PDU needs more fragments. */
    BLE_L2CAP_REASM_COMPLETE      = 1    /**< A whole PDU is in @p out. */
} ble_l2cap_reasm_status_t;

/**
 * @brief Prepare a context, with the storage it may use.
 *
 * @param[out] r    Context to initialise: idle, @c lost = 0.
 * @param[in]  buf  Storage for fragmented PDUs; must outlive @p r. The
 *                  largest PDU it can rebuild is @p cap octets, header
 *                  included: for ATT, 4 + the negotiated MTU.
 * @param[in]  cap  Size of @p buf.
 * @return 1 if ready; 0, with @p r untouched, if @p buf is NULL or
 *         @p cap is below ::BLE_L2CAP_REASM_MIN.
 */
int ble_l2cap_reasm_init(ble_l2cap_reasm_t *r, uint8_t *buf, size_t cap);

/**
 * @brief Feed one ACL packet; get a whole L2CAP PDU when one is complete.
 *
 * @param[in,out] r    Context from ble_l2cap_reasm_init().
 * @param[in]     acl  A packet from ble_acl_parse(), on the connection and
 *                     in the direction @p r is for.
 * @param[out]    out  On ::BLE_L2CAP_REASM_COMPLETE: channel, PDU Length
 *                     and payload. Untouched otherwise.
 * @return One of ::ble_l2cap_reasm_status_t.
 *
 * Rules, in the order they apply:
 * | Packet | State | Result |
 * |---|---|---|
 * | PB 0b11 | any | ERR_MALFORMED; nothing changes |
 * | start (PB 0b00 or 0b10) | collecting | the PDU in progress is dropped (@c lost + 1), then as below |
 * | start | skipping | skipping ends (that PDU was counted already), then as below |
 * | start, holding the whole PDU | | COMPLETE, @c payload points into @p acl: nothing copied |
 * | start, more octets than its PDU Length | | ERR_OVERRUN, @c lost + 1 |
 * | start, PDU larger than @c cap | | ERR_TOO_LONG, @c lost + 1; later fragments skipped |
 * | start, part of a PDU | | PENDING, copied; the header may be split too |
 * | continuation (PB 0b01) | idle | ERR_ORPHAN |
 * | continuation | other handle | ERR_HANDLE |
 * | continuation | collecting | PENDING, or COMPLETE with @c payload in @c buf; ERR_OVERRUN (@c lost + 1) if it brings more than the PDU lacks; ERR_TOO_LONG (@c lost + 1) if the length now known exceeds @c cap |
 * | continuation | skipping | ERR_TOO_LONG until the PDU's octets are all seen; ERR_OVERRUN if it brings more |
 *
 * A start always begins a new PDU, on its own handle. Where two errors
 * apply at once, the earlier row and, within a cell, the first named wins.
 *
 * A start fragment may carry fewer than 4 octets — even none — so the PDU
 * Length can arrive in a continuation; Linux handles the same case. The
 * size check is made as soon as the length is known.
 *
 * A @c payload in @c buf stays valid until the next call with @p r; one in
 * @p acl as long as the caller's packet does.
 */
ble_l2cap_reasm_status_t ble_l2cap_reasm_push(ble_l2cap_reasm_t *r, const ble_acl_t *acl,
                                              ble_l2cap_t *out);
/** @} */

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* BLE_L2CAP_H */
