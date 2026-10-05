/**
 * @file  ble_att.h
 * @brief Attribute Protocol PDUs: what a GATT read, write or notification
 *        looks like on the L2CAP channel 0x0004.
 *
 * Every ATT PDU starts with one opcode octet (Core Vol 3 Part F, 3.3.1):
 * @verbatim
   bit 7: Authentication Signature Flag   bit 6: Command Flag   bits 5-0: Method
   @endverbatim
 * followed by parameters whose layout the opcode decides, little-endian
 * except for attribute values, whose byte order belongs to the profile.
 *
 * ble_att_parse() decodes the parameters every PDU of a kind shares — a
 * handle, a handle range, an error, an MTU, an offset — and points at the
 * rest as @c value. It checks each length against the format in Core Vol 3
 * Part F, 3.4, so a PDU one octet short is refused, not read past.
 *
 * @defgroup ble_att Attribute Protocol
 * @brief Decode an ATT PDU's fixed parameters.
 * @{
 */
#ifndef BLE_ATT_H
#define BLE_ATT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name Attribute opcodes (Core Vol 3 Part F, 3.4.8)
 * @{
 */
#define BLE_ATT_ERROR_RSP              0x01u  /**< Request Opcode In Error, Handle, Error Code. */
#define BLE_ATT_EXCHANGE_MTU_REQ       0x02u  /**< Client Rx MTU. */
#define BLE_ATT_EXCHANGE_MTU_RSP       0x03u  /**< Server Rx MTU. */
#define BLE_ATT_FIND_INFORMATION_REQ   0x04u  /**< Starting Handle, Ending Handle. */
#define BLE_ATT_FIND_INFORMATION_RSP   0x05u  /**< Format, Information Data. */
#define BLE_ATT_FIND_BY_TYPE_VALUE_REQ 0x06u  /**< Range, Attribute Type (2), Attribute Value. */
#define BLE_ATT_FIND_BY_TYPE_VALUE_RSP 0x07u  /**< Handles Information List. */
#define BLE_ATT_READ_BY_TYPE_REQ       0x08u  /**< Range, UUID (2 or 16). */
#define BLE_ATT_READ_BY_TYPE_RSP       0x09u  /**< Length, Attribute Data List. */
#define BLE_ATT_READ_REQ               0x0Au  /**< Attribute Handle. */
#define BLE_ATT_READ_RSP               0x0Bu  /**< Attribute Value. */
#define BLE_ATT_READ_BLOB_REQ          0x0Cu  /**< Attribute Handle, Value Offset. */
#define BLE_ATT_READ_BLOB_RSP          0x0Du  /**< Part Attribute Value. */
#define BLE_ATT_READ_BY_GROUP_TYPE_REQ 0x10u  /**< Range, UUID (2 or 16). */
#define BLE_ATT_READ_BY_GROUP_TYPE_RSP 0x11u  /**< Length, Attribute Data List. */
#define BLE_ATT_WRITE_REQ              0x12u  /**< Attribute Handle, Attribute Value. */
#define BLE_ATT_WRITE_RSP              0x13u  /**< No parameters. */
#define BLE_ATT_HANDLE_VALUE_NTF       0x1Bu  /**< Attribute Handle, Attribute Value. */
#define BLE_ATT_HANDLE_VALUE_IND       0x1Du  /**< Attribute Handle, Attribute Value. */
#define BLE_ATT_HANDLE_VALUE_CFM       0x1Eu  /**< No parameters. */
#define BLE_ATT_WRITE_CMD              0x52u  /**< Attribute Handle, Attribute Value. */
#define BLE_ATT_SIGNED_WRITE_CMD       0xD2u  /**< Handle, Value, 12-octet Authentication Signature. */
/** @} */

/** @brief Length of the Authentication Signature on a signed PDU. */
#define BLE_ATT_SIGNATURE_LEN 12u

/** @brief One ATT PDU, fixed parameters decoded. Fields not used by the opcode are 0. */
typedef struct {
    uint8_t        opcode;          /**< The whole opcode octet. */
    uint8_t        method;          /**< Bits 5-0 of the opcode. */
    bool           command;         /**< Bit 6: a command, which gets no response. */
    bool           is_signed;       /**< Bit 7: a 12-octet signature ends the PDU. */
    bool           has_handle;      /**< @ref handle is meaningful. */
    uint16_t       handle;          /**< Attribute Handle (or Attribute Handle In Error). */
    bool           has_range;       /**< @ref start_handle and @ref end_handle are meaningful. */
    uint16_t       start_handle;    /**< Starting Handle of a range request. */
    uint16_t       end_handle;      /**< Ending Handle of a range request. */
    uint8_t        err_req_opcode;  /**< ATT_ERROR_RSP: the request that failed. */
    uint8_t        err_code;        /**< ATT_ERROR_RSP: why. */
    uint16_t       mtu;             /**< Client or Server Rx MTU. */
    uint16_t       offset;          /**< ATT_READ_BLOB_REQ: Value Offset. */
    const uint8_t *value;           /**< Everything after the fixed parameters (signature excluded). */
    uint16_t       value_len;       /**< Length of @ref value; may be 0. */
} ble_att_pdu_t;

/** @brief Result of ble_att_parse(). */
typedef enum {
    BLE_ATT_ERR_MALFORMED = -1,  /**< Empty, too long, or the wrong length for its opcode. */
    BLE_ATT_OK            = 1    /**< @p out holds the PDU. */
} ble_att_status_t;

/**
 * @brief Decode the fixed parameters of an ATT PDU.
 *
 * @param[in]  pdu  The PDU, starting at the opcode: an L2CAP payload on
 *                  channel 0x0004. May be NULL when @p len is 0.
 * @param[in]  len  Length of the PDU.
 * @param[out] out  Receives the PDU on ::BLE_ATT_OK, every unused field 0;
 *                  untouched otherwise.
 * @retval BLE_ATT_OK            Decoded.
 * @retval BLE_ATT_ERR_MALFORMED Empty, longer than 65535 octets (more than
 *                               one L2CAP PDU can carry), or a length the
 *                               opcode does not allow.
 *
 * Lengths, in octets including the opcode:
 * | Opcode | Fields set | Length |
 * |---|---|---|
 * | ERROR_RSP | handle, err_req_opcode, err_code | exactly 5 |
 * | EXCHANGE_MTU_REQ / _RSP | mtu | exactly 3 |
 * | FIND_INFORMATION_REQ | range | exactly 5 |
 * | FIND_BY_TYPE_VALUE_REQ | range; value = Attribute Type + Value | at least 7 |
 * | READ_BY_TYPE_REQ, READ_BY_GROUP_TYPE_REQ | range; value = UUID | exactly 7 or 21 |
 * | READ_REQ | handle | exactly 3 |
 * | READ_BLOB_REQ | handle, offset | exactly 5 |
 * | WRITE_REQ, WRITE_CMD, HANDLE_VALUE_NTF, HANDLE_VALUE_IND | handle; value | at least 3 |
 * | SIGNED_WRITE_CMD | handle; value, without the signature | at least 15 |
 * | any other opcode | value = all parameters | at least 1 |
 *
 * "Any other" covers the responses whose parameters are lists (FIND_*_RSP,
 * READ_*_RSP, ...) and opcodes this version does not know: they are
 * reported, not refused, as a parser of captured traffic should.
 */
ble_att_status_t ble_att_parse(const uint8_t *pdu, size_t len, ble_att_pdu_t *out);

/**
 * @brief Name of an opcode, for logs and tools.
 * @param[in] opcode  Any value.
 * @return The spec name without the "ATT_" prefix, e.g. "READ_REQ";
 *         "UNKNOWN" for opcodes not listed above. Never NULL.
 */
const char *ble_att_opcode_name(uint8_t opcode);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* BLE_ATT_H */
