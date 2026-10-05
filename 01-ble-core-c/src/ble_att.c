/**
 * @file  ble_att.c
 * @brief Attribute Protocol PDUs — implementation.
 */
#include "ble/ble_att.h"
#include "ble_util.h"

/** @brief Which fixed parameters follow the opcode. */
typedef enum {
    SHAPE_VALUE,         /**< None: every parameter is @c value. */
    SHAPE_ERROR,         /**< Request Opcode In Error, Handle, Error Code. */
    SHAPE_MTU,           /**< Rx MTU. */
    SHAPE_RANGE,         /**< Starting Handle, Ending Handle, then @c value. */
    SHAPE_HANDLE,        /**< Attribute Handle, then @c value. */
    SHAPE_HANDLE_OFFSET  /**< Attribute Handle, Value Offset. */
} att_shape_t;

/**
 * @par Implementation
 * Two steps, so that nothing is written until the whole PDU is known good.
 * First a switch on the opcode gives its shape, the length of its fixed
 * part (opcode included) and the lengths it allows, straight from the table
 * in ble_att.h; the PDU is checked against them. Only then is @p out filled:
 * every field cleared, the opcode bits split, the fixed parameters read for
 * the shape, and whatever follows them — minus the signature on a signed
 * PDU — pointed at as @c value.
 *
 * A PDU longer than 65535 octets is refused as well: it cannot have come
 * out of one L2CAP PDU, whose length field is 16 bits, and @c value_len
 * could not hold it.
 */
ble_att_status_t ble_att_parse(const uint8_t *pdu, size_t len, ble_att_pdu_t *out)
{
    if (pdu == NULL || len == 0 || len > 0xFFFFu) {
        return BLE_ATT_ERR_MALFORMED;
    }

    uint8_t op = pdu[0];
    att_shape_t shape = SHAPE_VALUE;
    size_t fixed = 1;      /* opcode and fixed parameters */
    size_t tail = 0;       /* signature after the value */
    bool exact = false;    /* fixed parameters only, no value */
    bool ok;

    switch (op) {
    case BLE_ATT_ERROR_RSP:
        shape = SHAPE_ERROR; fixed = 5; exact = true;
        break;
    case BLE_ATT_EXCHANGE_MTU_REQ:
    case BLE_ATT_EXCHANGE_MTU_RSP:
        shape = SHAPE_MTU; fixed = 3; exact = true;
        break;
    case BLE_ATT_FIND_INFORMATION_REQ:
        shape = SHAPE_RANGE; fixed = 5; exact = true;
        break;
    case BLE_ATT_FIND_BY_TYPE_VALUE_REQ:
        shape = SHAPE_RANGE; fixed = 5;
        break;
    case BLE_ATT_READ_BY_TYPE_REQ:
    case BLE_ATT_READ_BY_GROUP_TYPE_REQ:
        shape = SHAPE_RANGE; fixed = 5;
        break;
    case BLE_ATT_READ_REQ:
        shape = SHAPE_HANDLE; fixed = 3; exact = true;
        break;
    case BLE_ATT_READ_BLOB_REQ:
        shape = SHAPE_HANDLE_OFFSET; fixed = 5; exact = true;
        break;
    case BLE_ATT_WRITE_REQ:
    case BLE_ATT_WRITE_CMD:
    case BLE_ATT_HANDLE_VALUE_NTF:
    case BLE_ATT_HANDLE_VALUE_IND:
        shape = SHAPE_HANDLE; fixed = 3;
        break;
    case BLE_ATT_SIGNED_WRITE_CMD:
        shape = SHAPE_HANDLE; fixed = 3; tail = BLE_ATT_SIGNATURE_LEN;
        break;
    default:
        break;
    }

    if (op == BLE_ATT_READ_BY_TYPE_REQ || op == BLE_ATT_READ_BY_GROUP_TYPE_REQ) {
        ok = (len == fixed + 2u || len == fixed + 16u);  /* 16- or 128-bit UUID */
    } else if (op == BLE_ATT_FIND_BY_TYPE_VALUE_REQ) {
        ok = (len >= fixed + 2u);                        /* Attribute Type */
    } else if (exact) {
        ok = (len == fixed);
    } else {
        ok = (len >= fixed + tail);
    }
    if (!ok) {
        return BLE_ATT_ERR_MALFORMED;
    }

    out->opcode         = op;
    out->method         = (uint8_t)(op & 0x3Fu);
    out->command        = (op & 0x40u) != 0;
    out->is_signed      = (op & 0x80u) != 0;
    out->has_handle     = false;
    out->handle         = 0;
    out->has_range      = false;
    out->start_handle   = 0;
    out->end_handle     = 0;
    out->err_req_opcode = 0;
    out->err_code       = 0;
    out->mtu            = 0;
    out->offset         = 0;

    switch (shape) {
    case SHAPE_ERROR:
        out->err_req_opcode = pdu[1];
        out->has_handle     = true;
        out->handle         = ble_le16(&pdu[2]);
        out->err_code       = pdu[4];
        break;
    case SHAPE_MTU:
        out->mtu = ble_le16(&pdu[1]);
        break;
    case SHAPE_RANGE:
        out->has_range    = true;
        out->start_handle = ble_le16(&pdu[1]);
        out->end_handle   = ble_le16(&pdu[3]);
        break;
    case SHAPE_HANDLE:
        out->has_handle = true;
        out->handle     = ble_le16(&pdu[1]);
        break;
    case SHAPE_HANDLE_OFFSET:
        out->has_handle = true;
        out->handle     = ble_le16(&pdu[1]);
        out->offset     = ble_le16(&pdu[3]);
        break;
    case SHAPE_VALUE:
        break;
    }

    out->value_len = (uint16_t)(len - fixed - tail);
    out->value     = &pdu[fixed];
    return BLE_ATT_OK;
}

/**
 * @par Implementation
 * A switch over the opcodes named in ble_att.h; anything else is "UNKNOWN".
 */
const char *ble_att_opcode_name(uint8_t opcode)
{
    switch (opcode) {
    case BLE_ATT_ERROR_RSP:              return "ERROR_RSP";
    case BLE_ATT_EXCHANGE_MTU_REQ:       return "EXCHANGE_MTU_REQ";
    case BLE_ATT_EXCHANGE_MTU_RSP:       return "EXCHANGE_MTU_RSP";
    case BLE_ATT_FIND_INFORMATION_REQ:   return "FIND_INFORMATION_REQ";
    case BLE_ATT_FIND_INFORMATION_RSP:   return "FIND_INFORMATION_RSP";
    case BLE_ATT_FIND_BY_TYPE_VALUE_REQ: return "FIND_BY_TYPE_VALUE_REQ";
    case BLE_ATT_FIND_BY_TYPE_VALUE_RSP: return "FIND_BY_TYPE_VALUE_RSP";
    case BLE_ATT_READ_BY_TYPE_REQ:       return "READ_BY_TYPE_REQ";
    case BLE_ATT_READ_BY_TYPE_RSP:       return "READ_BY_TYPE_RSP";
    case BLE_ATT_READ_REQ:               return "READ_REQ";
    case BLE_ATT_READ_RSP:               return "READ_RSP";
    case BLE_ATT_READ_BLOB_REQ:          return "READ_BLOB_REQ";
    case BLE_ATT_READ_BLOB_RSP:          return "READ_BLOB_RSP";
    case BLE_ATT_READ_BY_GROUP_TYPE_REQ: return "READ_BY_GROUP_TYPE_REQ";
    case BLE_ATT_READ_BY_GROUP_TYPE_RSP: return "READ_BY_GROUP_TYPE_RSP";
    case BLE_ATT_WRITE_REQ:              return "WRITE_REQ";
    case BLE_ATT_WRITE_RSP:              return "WRITE_RSP";
    case BLE_ATT_HANDLE_VALUE_NTF:       return "HANDLE_VALUE_NTF";
    case BLE_ATT_HANDLE_VALUE_IND:       return "HANDLE_VALUE_IND";
    case BLE_ATT_HANDLE_VALUE_CFM:       return "HANDLE_VALUE_CFM";
    case BLE_ATT_WRITE_CMD:              return "WRITE_CMD";
    case BLE_ATT_SIGNED_WRITE_CMD:       return "SIGNED_WRITE_CMD";
    default:                             return "UNKNOWN";
    }
}
