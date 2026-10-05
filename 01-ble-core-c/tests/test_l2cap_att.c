/**
 * @file  test_l2cap_att.c
 * @brief Task 7: HCI ACL, L2CAP and ATT parsing. Written before the
 *        implementation.
 *
 * Three kinds of test: hand-written PDUs at every length boundary the spec
 * sets; 16 real packets from a phone session against project 02, with the
 * expected values decoded by Wireshark (acl_fixtures.h); and random input
 * in exactly-sized buffers, so ASan stops on a one-byte over-read.
 */
#include <stdlib.h>
#include "check.h"
#include "ble/ble_l2cap.h"
#include "ble/ble_att.h"
#include "acl_fixtures.h"

/**
 * @brief Whether an opcode's PDU has an Attribute Handle field on the wire.
 *
 * Wireshark also shows a handle for READ_RSP and WRITE_RSP, which have none:
 * it takes it from the request it matched the response to. The comparison
 * with Wireshark only makes sense where the handle is really in the packet.
 *
 * @param[in] op  Opcode.
 * @return true for PDUs that carry a handle.
 */
static bool has_handle_field(int op)
{
    switch (op) {
    case BLE_ATT_ERROR_RSP: case BLE_ATT_READ_REQ: case BLE_ATT_READ_BLOB_REQ:
    case BLE_ATT_WRITE_REQ: case BLE_ATT_WRITE_CMD: case BLE_ATT_HANDLE_VALUE_NTF:
    case BLE_ATT_HANDLE_VALUE_IND: case BLE_ATT_SIGNED_WRITE_CMD:
        return true;
    default:
        return false;
    }
}

/**
 * @brief Parse and count the result as a check; tell the caller whether
 *        @p out may be read. A test must fail, not crash, on a wrong parser.
 * @param[in]  pdu  PDU bytes.
 * @param[in]  len  PDU length.
 * @param[out] out  Decoded PDU.
 * @return true if ble_att_parse() returned ::BLE_ATT_OK.
 */
static bool att_ok(const unsigned char *pdu, size_t len, ble_att_pdu_t *out)
{
    bool ok = ble_att_parse(pdu, len, out) == BLE_ATT_OK;
    CHECK(ok);
    return ok;
}

/**
 * @brief ACL and L2CAP: header fields, every length rule, fragmentation
 *        recognised and not misread, and the 16 real packets.
 */
void suite_l2cap(void)
{
    SUITE("acl + l2cap (task 7a)");
    ble_acl_t acl;
    ble_l2cap_t l2;
    memset(&acl, 0, sizeof acl);    /* deterministic results even if a parse writes nothing */
    memset(&l2, 0, sizeof l2);

    /* ---- ACL header ------------------------------------------------------ */
    /* handle 0x801, PB 0b10, BC 0b00: 0x2801 little-endian; 7 data bytes:
     * L2CAP length 3, CID 4, ATT Read Request for handle 0x0024 */
    const unsigned char read_req[] = {0x01, 0x28, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00,
                                      0x0a, 0x24, 0x00};
    CHECK_EQ(ble_acl_parse(read_req, sizeof read_req, &acl), BLE_ACL_OK);
    CHECK_EQ(acl.handle, 0x801);
    CHECK_EQ(acl.pb, BLE_ACL_PB_FIRST_FLUSHABLE);
    CHECK_EQ(acl.bc, 0);
    CHECK_EQ(acl.len, 7);
    CHECK(acl.data == &read_req[4]);

    /* the broadcast flag is bits 6-7 of the second octet */
    const unsigned char bc1[] = {0x01, 0x68, 0x00, 0x00};
    CHECK_EQ(ble_acl_parse(bc1, sizeof bc1, &acl), BLE_ACL_OK);
    CHECK_EQ(acl.pb, 2);
    CHECK_EQ(acl.bc, 1);
    CHECK_EQ(acl.len, 0);

    /* a reserved handle is reported, not refused */
    const unsigned char reserved[] = {0x00, 0x0f, 0x00, 0x00};
    CHECK_EQ(ble_acl_parse(reserved, sizeof reserved, &acl), BLE_ACL_OK);
    CHECK_EQ(acl.handle, 0xf00);

    /* the length field must match the packet exactly, both ways */
    acl.handle = 0x123;
    const unsigned char claims_more[] = {0x01, 0x28, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7};
    CHECK_EQ(ble_acl_parse(claims_more, sizeof claims_more, &acl), BLE_ACL_ERR_MALFORMED);
    const unsigned char claims_less[] = {0x01, 0x28, 0x06, 0x00, 1, 2, 3, 4, 5, 6, 7};
    CHECK_EQ(ble_acl_parse(claims_less, sizeof claims_less, &acl), BLE_ACL_ERR_MALFORMED);
    CHECK_EQ(ble_acl_parse(read_req, 3, &acl), BLE_ACL_ERR_MALFORMED);
    CHECK_EQ(ble_acl_parse(NULL, 0, &acl), BLE_ACL_ERR_MALFORMED);
    CHECK_EQ(acl.handle, 0x123);                    /* untouched on failure */

    /* ---- L2CAP header ---------------------------------------------------- */
    CHECK_EQ(ble_acl_parse(read_req, sizeof read_req, &acl), BLE_ACL_OK);
    CHECK_EQ(ble_l2cap_parse(&acl, &l2), BLE_L2CAP_OK);
    CHECK_EQ(l2.cid, BLE_L2CAP_CID_ATT);
    CHECK_EQ(l2.len, 3);
    CHECK(l2.payload == &read_req[8]);

    /* an empty payload is a valid PDU */
    const unsigned char empty_pdu[] = {0x00, 0x00, 0x05, 0x00};
    ble_acl_t a = {0x40, BLE_ACL_PB_FIRST_FLUSHABLE, 0, empty_pdu, sizeof empty_pdu};
    CHECK_EQ(ble_l2cap_parse(&a, &l2), BLE_L2CAP_OK);
    CHECK_EQ(l2.cid, BLE_L2CAP_CID_LE_SIGNALING);
    CHECK_EQ(l2.len, 0);

    /* first packet of a 20-byte PDU that only brought 3 of them */
    const unsigned char first_part[] = {0x14, 0x00, 0x04, 0x00, 0x1b, 0x24, 0x00};
    a.data = first_part;
    a.len = sizeof first_part;
    CHECK_EQ(ble_l2cap_parse(&a, &l2), BLE_L2CAP_FRAGMENTED);
    CHECK_EQ(l2.cid, BLE_L2CAP_CID_ATT);
    CHECK_EQ(l2.len, 20);                           /* the whole PDU's length */
    CHECK(l2.payload == &first_part[4]);

    /* a continuing fragment has no L2CAP header to read */
    a.pb = BLE_ACL_PB_CONTINUING;
    l2.cid = 0x777;
    CHECK_EQ(ble_l2cap_parse(&a, &l2), BLE_L2CAP_CONTINUATION);
    CHECK_EQ(l2.cid, 0x777);                        /* untouched */

    /* too short for the header, and more payload than the header allows */
    a.pb = BLE_ACL_PB_FIRST_FLUSHABLE;
    a.len = 3;
    CHECK_EQ(ble_l2cap_parse(&a, &l2), BLE_L2CAP_ERR_MALFORMED);
    const unsigned char too_long[] = {0x01, 0x00, 0x04, 0x00, 0x0a, 0x24, 0x00};
    a.data = too_long;
    a.len = sizeof too_long;
    CHECK_EQ(ble_l2cap_parse(&a, &l2), BLE_L2CAP_ERR_MALFORMED);
    CHECK_EQ(l2.cid, 0x777);                        /* untouched */

    /* ---- 16 real packets, against Wireshark ------------------------------- */
    for (size_t i = 0; i < sizeof ACL_FIXTURES / sizeof ACL_FIXTURES[0]; i++) {
        const acl_fixture_t *f = &ACL_FIXTURES[i];
        if (ble_acl_parse(f->bytes, f->len, &acl) != BLE_ACL_OK) {
            CHECK(!"real packet refused by ble_acl_parse");
            continue;                               /* acl is not valid: read nothing from it */
        }
        CHECK_EQ(acl.handle, f->handle);
        CHECK_EQ(acl.pb, f->pb);
        CHECK_EQ(acl.len, f->acl_len);
        CHECK_EQ(acl.pb, f->sent ? BLE_ACL_PB_FIRST_NON_FLUSHABLE : BLE_ACL_PB_FIRST_FLUSHABLE);
        if (ble_l2cap_parse(&acl, &l2) != BLE_L2CAP_OK) {
            CHECK(!"real packet refused by ble_l2cap_parse");
            continue;
        }
        CHECK_EQ(l2.cid, f->cid);
        CHECK_EQ(l2.len, f->l2cap_len);
    }
}

/**
 * @brief ATT: every length rule in ble_att.h, the flags in the opcode,
 *        unused fields zeroed, and the 16 real packets.
 */
void suite_att(void)
{
    SUITE("att (task 7b)");
    ble_att_pdu_t p;
    memset(&p, 0, sizeof p);    /* bools must hold 0 or 1 even if a parse writes nothing */

    /* ---- one per rule ----------------------------------------------------- */
    const unsigned char err[] = {0x01, 0x12, 0x2c, 0x00, 0x80};
    CHECK_EQ(ble_att_parse(err, sizeof err, &p), BLE_ATT_OK);
    CHECK(p.has_handle);
    CHECK_EQ(p.handle, 0x002c);
    CHECK_EQ(p.err_req_opcode, BLE_ATT_WRITE_REQ);
    CHECK_EQ(p.err_code, 0x80);
    CHECK_EQ(ble_att_parse(err, 4, &p), BLE_ATT_ERR_MALFORMED);
    const unsigned char err6[] = {0x01, 0x12, 0x2c, 0x00, 0x80, 0x00};
    CHECK_EQ(ble_att_parse(err6, sizeof err6, &p), BLE_ATT_ERR_MALFORMED);

    const unsigned char mtu[] = {0x02, 0x05, 0x02};
    CHECK_EQ(ble_att_parse(mtu, sizeof mtu, &p), BLE_ATT_OK);
    CHECK_EQ(p.mtu, 517);
    CHECK(!p.has_handle);
    CHECK_EQ(ble_att_parse(mtu, 2, &p), BLE_ATT_ERR_MALFORMED);

    const unsigned char find_info[] = {0x04, 0x01, 0x00, 0xff, 0xff};
    CHECK_EQ(ble_att_parse(find_info, sizeof find_info, &p), BLE_ATT_OK);
    CHECK(p.has_range);
    CHECK_EQ(p.start_handle, 0x0001);
    CHECK_EQ(p.end_handle, 0xffff);
    CHECK_EQ(p.value_len, 0);
    const unsigned char find_info6[] = {0x04, 0x01, 0x00, 0xff, 0xff, 0x00};
    CHECK_EQ(ble_att_parse(find_info6, sizeof find_info6, &p), BLE_ATT_ERR_MALFORMED);

    const unsigned char by_type16[] = {0x08, 0x01, 0x00, 0xff, 0xff, 0x03, 0x28};
    if (att_ok(by_type16, sizeof by_type16, &p)) {
        CHECK(p.has_range);
        CHECK_EQ(p.value_len, 2);                   /* the UUID */
        CHECK(p.value_len == 2 && p.value[1] == 0x28);
    }
    unsigned char by_type128[21] = {0x10, 0x01, 0x00, 0xff, 0xff};
    CHECK_EQ(ble_att_parse(by_type128, sizeof by_type128, &p), BLE_ATT_OK);
    CHECK_EQ(p.value_len, 16);
    CHECK_EQ(ble_att_parse(by_type128, 9, &p), BLE_ATT_ERR_MALFORMED);   /* a 4-byte UUID */

    const unsigned char by_value[] = {0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0x0f, 0x18};
    CHECK_EQ(ble_att_parse(by_value, sizeof by_value, &p), BLE_ATT_OK);
    CHECK(p.has_range);
    CHECK_EQ(p.value_len, 4);
    CHECK_EQ(ble_att_parse(by_value, 6, &p), BLE_ATT_ERR_MALFORMED);

    const unsigned char read[] = {0x0a, 0x24, 0x00};
    CHECK_EQ(ble_att_parse(read, sizeof read, &p), BLE_ATT_OK);
    CHECK(p.has_handle);
    CHECK_EQ(p.handle, 0x0024);
    CHECK_EQ(ble_att_parse(read, 2, &p), BLE_ATT_ERR_MALFORMED);
    const unsigned char read4[] = {0x0a, 0x24, 0x00, 0x00};
    CHECK_EQ(ble_att_parse(read4, sizeof read4, &p), BLE_ATT_ERR_MALFORMED);

    const unsigned char blob[] = {0x0c, 0x24, 0x00, 0x10, 0x00};
    CHECK_EQ(ble_att_parse(blob, sizeof blob, &p), BLE_ATT_OK);
    CHECK_EQ(p.handle, 0x0024);
    CHECK_EQ(p.offset, 16);

    const unsigned char write[] = {0x12, 0x2c, 0x00, 0x32, 0x00};
    if (att_ok(write, sizeof write, &p)) {
        CHECK_EQ(p.handle, 0x002c);
        CHECK_EQ(p.value_len, 2);
        CHECK(p.value_len == 2 && p.value[0] == 0x32);
        CHECK(!p.command);
    }
    CHECK_EQ(ble_att_parse(write, 3, &p), BLE_ATT_OK);   /* an empty value is allowed */
    CHECK_EQ(p.value_len, 0);
    CHECK_EQ(ble_att_parse(write, 2, &p), BLE_ATT_ERR_MALFORMED);

    const unsigned char cmd[] = {0x52, 0x2c, 0x00, 0x01};
    CHECK_EQ(ble_att_parse(cmd, sizeof cmd, &p), BLE_ATT_OK);
    CHECK(p.command);
    CHECK(!p.is_signed);
    CHECK_EQ(p.method, 0x12);                       /* same method as WRITE_REQ */
    CHECK_EQ(p.handle, 0x002c);

    const unsigned char ntf[] = {0x1b, 0x24, 0x00, 0x5f};
    if (att_ok(ntf, sizeof ntf, &p)) {
        CHECK_EQ(p.handle, 0x0024);
        CHECK_EQ(p.value_len, 1);
        CHECK(p.value_len == 1 && p.value[0] == 0x5f);
    }

    /* signed write: handle, 2 value octets, then a 12-octet signature */
    unsigned char sig[1 + 2 + 2 + BLE_ATT_SIGNATURE_LEN] = {0xd2, 0x2c, 0x00, 0xaa, 0xbb};
    if (att_ok(sig, sizeof sig, &p)) {
        CHECK(p.is_signed);
        CHECK(p.command);
        CHECK_EQ(p.handle, 0x002c);
        CHECK_EQ(p.value_len, 2);                   /* the signature is not part of the value */
        CHECK(p.value_len == 2 && p.value[1] == 0xbb);
    }
    CHECK_EQ(ble_att_parse(sig, 14, &p), BLE_ATT_ERR_MALFORMED);

    const unsigned char rsp[] = {0x0b, 0x5f};
    CHECK_EQ(ble_att_parse(rsp, sizeof rsp, &p), BLE_ATT_OK);
    CHECK(!p.has_handle);                           /* no handle on the wire */
    CHECK_EQ(p.value_len, 1);

    const unsigned char unknown[] = {0x3f, 0x01, 0x02};
    CHECK_EQ(ble_att_parse(unknown, sizeof unknown, &p), BLE_ATT_OK);   /* reported, not refused */
    CHECK_EQ(p.value_len, 2);

    /* ---- unused fields are zero; failure leaves the output alone ---------- */
    /* 0xaa in every byte: a field the parser does not set stays 0xaa.
     * Only read back after a successful parse — 0xaa is not a valid bool. */
    memset(&p, 0xaa, sizeof p);
    if (att_ok(read, sizeof read, &p)) {
        CHECK(!p.has_range);
        CHECK_EQ(p.start_handle, 0);
        CHECK_EQ(p.end_handle, 0);
        CHECK_EQ(p.err_code, 0);
        CHECK_EQ(p.err_req_opcode, 0);
        CHECK_EQ(p.mtu, 0);
        CHECK_EQ(p.offset, 0);
        CHECK_EQ(p.value_len, 0);
    }

    memset(&p, 0xaa, sizeof p);
    CHECK_EQ(ble_att_parse(NULL, 0, &p), BLE_ATT_ERR_MALFORMED);
    CHECK_EQ(p.opcode, 0xaa);                       /* a uint8_t: any value is valid to read */
    memset(&p, 0, sizeof p);

    CHECK(strcmp(ble_att_opcode_name(BLE_ATT_READ_REQ), "READ_REQ") == 0);
    CHECK(strcmp(ble_att_opcode_name(0x3f), "UNKNOWN") == 0);

    /* ---- 16 real packets, against Wireshark ------------------------------- */
    for (size_t i = 0; i < sizeof ACL_FIXTURES / sizeof ACL_FIXTURES[0]; i++) {
        const acl_fixture_t *f = &ACL_FIXTURES[i];
        ble_acl_t acl;
        ble_l2cap_t l2;
        if (f->att_opcode < 0) {
            continue;                               /* the LE signalling packet */
        }
        if (ble_acl_parse(f->bytes, f->len, &acl) != BLE_ACL_OK ||
            ble_l2cap_parse(&acl, &l2) != BLE_L2CAP_OK ||
            ble_att_parse(l2.payload, l2.len, &p) != BLE_ATT_OK) {
            CHECK(!"real ATT packet refused");
            continue;                               /* p is not valid: read nothing from it */
        }
        CHECK_EQ(p.opcode, f->att_opcode);
        CHECK_EQ(p.has_handle, has_handle_field(f->att_opcode));
        if (has_handle_field(f->att_opcode)) {
            CHECK_EQ(p.handle, f->att_handle);
        }
        CHECK_EQ(p.err_code, f->err_code);
        CHECK_EQ(p.err_req_opcode, f->err_req);
        CHECK_EQ(p.mtu, f->mtu);
        CHECK_EQ(p.start_handle, f->start);
        CHECK_EQ(p.end_handle, f->end);
    }

    /* the session as the phone saw it: 95 %, then 50 ms refused with 0x80 */
    ble_acl_t acl;
    ble_l2cap_t l2;
    int saw_battery = 0, saw_interval = 0;
    for (size_t i = 0; i < sizeof ACL_FIXTURES / sizeof ACL_FIXTURES[0]; i++) {
        const acl_fixture_t *f = &ACL_FIXTURES[i];
        bool battery = f->att_opcode == BLE_ATT_READ_RSP && f->l2cap_len == 2;
        bool interval = f->att_opcode == BLE_ATT_WRITE_REQ && f->att_handle == 0x002c;
        if (!battery && !interval) {
            continue;
        }
        if (ble_acl_parse(f->bytes, f->len, &acl) != BLE_ACL_OK ||
            ble_l2cap_parse(&acl, &l2) != BLE_L2CAP_OK ||
            ble_att_parse(l2.payload, l2.len, &p) != BLE_ATT_OK) {
            continue;                               /* already reported above */
        }
        if (battery && p.value_len == 1) {
            CHECK_EQ(p.value[0], 95);
            saw_battery = 1;
        }
        if (interval && p.value_len == 2) {
            CHECK_EQ(p.value[0] | (p.value[1] << 8), 50);   /* uint16 LE: 50 ms */
            saw_interval = 1;
        }
    }
    CHECK(saw_battery);
    CHECK(saw_interval);
}

/** @brief Fuzz state: fixed seed, so a failure reproduces. */
static unsigned int acl_rng = 0x1F2E3D4Cu;

/**
 * @brief xorshift32, as in test_fuzz.c.
 * @return The next pseudo-random value.
 */
static unsigned int acl_rand(void)
{
    unsigned int x = acl_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return acl_rng = x;
}

/**
 * @brief 100 000 random ACL packets, half with a consistent ACL length so
 *        they reach L2CAP and ATT; every returned pointer must stay inside.
 */
void suite_acl_fuzz(void)
{
    SUITE("acl + l2cap + att fuzz (task 7)");
    int in_bounds = 1, reached_att = 0;
    for (int n = 0; n < 100000; n++) {
        size_t len = acl_rand() % 64u;
        unsigned char *buf = malloc(len ? len : 1);
        if (buf == NULL) {
            break;
        }
        for (size_t k = 0; k < len; k++) {
            buf[k] = (unsigned char)acl_rand();
        }
        if (len >= 8 && (acl_rand() & 1u)) {        /* steer into L2CAP and ATT */
            buf[2] = (unsigned char)(len - 4u);
            buf[3] = 0;
            buf[4] = (unsigned char)(len - 8u + (acl_rand() % 3u));
            buf[5] = 0;
            buf[6] = 0x04;
            buf[7] = 0x00;
        }
        ble_acl_t acl;
        ble_l2cap_t l2;
        ble_att_pdu_t p;
        if (ble_acl_parse(buf, len, &acl) == BLE_ACL_OK) {
            if (acl.data < buf || acl.data + acl.len > buf + len) {
                in_bounds = 0;
            }
            ble_l2cap_status_t st = ble_l2cap_parse(&acl, &l2);
            if (st == BLE_L2CAP_OK) {
                if (l2.payload < buf || l2.payload + l2.len > buf + len) {
                    in_bounds = 0;
                }
                if (ble_att_parse(l2.payload, l2.len, &p) == BLE_ATT_OK) {
                    reached_att++;
                    if (p.value_len && (p.value < l2.payload ||
                                        p.value + p.value_len > l2.payload + l2.len)) {
                        in_bounds = 0;
                    }
                }
            }
        }
        free(buf);
    }
    CHECK(in_bounds);
    CHECK(reached_att > 1000);
}
