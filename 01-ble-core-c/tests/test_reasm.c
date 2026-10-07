/**
 * @file  test_reasm.c
 * @brief Task 7c: L2CAP reassembly. Written before the implementation.
 *
 * None of the captures holds a fragmented PDU — BlueZ and the phone fit
 * every one into a single ACL packet — so the fragments here are made by
 * cutting real PDUs: every fixture from acl_fixtures.h, at every fragment
 * size, comes back byte for byte. Around that, one test per rule in the
 * table in ble_l2cap.h, and random fragment streams in exactly-sized
 * buffers, so ASan stops on a one-byte overrun.
 */
#include <stdbool.h>
#include <stdlib.h>
#include "check.h"
#include "ble/ble_l2cap.h"
#include "acl_fixtures.h"

/**
 * @brief An ACL packet as ble_acl_parse() would return it.
 * @param[in] handle  Connection handle.
 * @param[in] pb      Packet_Boundary_Flag.
 * @param[in] data    Data octets.
 * @param[in] len     Number of data octets.
 * @return The packet.
 */
static ble_acl_t acl_of(uint16_t handle, uint8_t pb, const uint8_t *data, size_t len)
{
    ble_acl_t a;
    a.handle = handle;
    a.pb = pb;
    a.bc = 0;
    a.data = data;
    a.len = (uint16_t)len;
    return a;
}

/** @brief Shorthand: a start fragment (PB 0b10, controller to host). */
#define START(h, d, n) acl_of((h), BLE_ACL_PB_FIRST_FLUSHABLE, (d), (n))
/** @brief Shorthand: a continuing fragment. */
#define CONT(h, d, n)  acl_of((h), BLE_ACL_PB_CONTINUING, (d), (n))

/**
 * @brief An L2CAP PDU on channel 0x0004: header, then @p plen octets
 *        counting up from @p first.
 * @param[out] pdu    At least 4 + @p plen octets.
 * @param[in]  plen   Payload length.
 * @param[in]  first  Value of the first payload octet.
 * @return 4 + @p plen.
 */
static size_t make_pdu(uint8_t *pdu, size_t plen, uint8_t first)
{
    pdu[0] = (uint8_t)plen;
    pdu[1] = (uint8_t)(plen >> 8);
    pdu[2] = 0x04;
    pdu[3] = 0x00;
    for (size_t i = 0; i < plen; i++) {
        pdu[4 + i] = (uint8_t)(first + i);
    }
    return 4 + plen;
}

/**
 * @brief Push one packet; count "the status is @p want" as a check.
 * @param[in,out] r     Context.
 * @param[in]     a     The packet.
 * @param[out]    out   Passed to ble_l2cap_reasm_push().
 * @param[in]     want  Expected status.
 * @return true if the status matched and it was COMPLETE, so @p out may be read.
 */
static bool push_is(ble_l2cap_reasm_t *r, ble_acl_t a, ble_l2cap_t *out,
                    ble_l2cap_reasm_status_t want)
{
    ble_l2cap_reasm_status_t st = ble_l2cap_reasm_push(r, &a, out);
    CHECK_EQ(st, want);
    return st == want && want == BLE_L2CAP_REASM_COMPLETE;
}

/**
 * @brief Cut a PDU into a start of @p first octets and continuations of
 *        @p step, feed them, and check the PDU comes back whole.
 *
 * @param[in] pdu    The whole L2CAP PDU, header included.
 * @param[in] len    Its length.
 * @param[in] first  Octets in the start fragment (may be 0).
 * @param[in] step   Octets per continuation (at least 1).
 * @return true if every fragment gave the expected status and the
 *         result matches; false after counting the failure.
 */
static bool roundtrip(const uint8_t *pdu, size_t len, size_t first, size_t step)
{
    uint8_t buf[600];
    ble_l2cap_reasm_t r;
    ble_l2cap_t out = {0, 0, NULL};
    memset(&r, 0, sizeof r);
    if (!ble_l2cap_reasm_init(&r, buf, sizeof buf)) {
        CHECK(0);
        return false;
    }
    if (first > len) {
        first = len;
    }
    ble_acl_t a = START(0x040, pdu, first);
    ble_l2cap_reasm_status_t st = ble_l2cap_reasm_push(&r, &a, &out);
    size_t at = first;
    while (st == BLE_L2CAP_REASM_PENDING && at < len) {
        size_t n = (len - at < step) ? len - at : step;
        a = CONT(0x040, pdu + at, n);
        st = ble_l2cap_reasm_push(&r, &a, &out);
        at += n;
    }
    bool ok = st == BLE_L2CAP_REASM_COMPLETE && at == len && r.lost == 0 &&
              out.cid == (pdu[2] | (pdu[3] << 8)) && out.len == len - 4 &&
              out.payload != NULL && memcmp(out.payload, pdu + 4, len - 4) == 0;
    CHECK(ok);
    if (!ok) {
        printf("    pdu of %zu cut %zu + %zu each: status %d after %zu octets\n",
               len, first, step, (int)st, at);
    }
    return ok;
}

/** @brief One test per row of the rules table in ble_l2cap.h. */
void suite_reasm(void)
{
    SUITE("l2cap reassembly (task 7c)");
    uint8_t buf[64];
    uint8_t pdu[64], pdu2[64];
    ble_l2cap_reasm_t r;
    ble_l2cap_t out = {0, 0, NULL};
    memset(&r, 0, sizeof r);

    /* init: refuses no storage, or too little for a header */
    CHECK_EQ(ble_l2cap_reasm_init(&r, NULL, 64), 0);
    CHECK_EQ(ble_l2cap_reasm_init(&r, buf, BLE_L2CAP_REASM_MIN - 1), 0);
    memset(&r, 0xAA, sizeof r);
    CHECK_EQ(ble_l2cap_reasm_init(&r, buf, BLE_L2CAP_REASM_MIN), 1);
    CHECK_EQ(r.lost, 0);
    CHECK_EQ(ble_l2cap_reasm_init(&r, buf, sizeof buf), 1);
    CHECK_EQ(r.lost, 0);

    /* whole PDU in one packet: nothing copied, either start flag */
    {
        static const uint8_t read_req[] = {0x03, 0x00, 0x04, 0x00, 0x0a, 0x24, 0x00};
        ble_l2cap_reasm_init(&r, buf, sizeof buf);
        memset(&out, 0, sizeof out);
        if (push_is(&r, START(1, read_req, sizeof read_req), &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK_EQ(out.cid, BLE_L2CAP_CID_ATT);
            CHECK_EQ(out.len, 3);
            CHECK(out.payload == read_req + 4);        /* zero copy */
        }
        if (push_is(&r, acl_of(1, BLE_ACL_PB_FIRST_NON_FLUSHABLE, read_req, sizeof read_req),
                    &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK(out.payload == read_req + 4);
        }
        /* even a PDU larger than the buffer: it is not copied */
        uint8_t big[100];
        size_t n = make_pdu(big, 90, 0);
        ble_l2cap_reasm_init(&r, buf, 16);
        if (push_is(&r, START(1, big, n), &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK_EQ(out.len, 90);
            CHECK(out.payload == big + 4);
        }
        CHECK_EQ(r.lost, 0);
        /* an empty PDU */
        n = make_pdu(pdu, 0, 0);
        if (push_is(&r, START(1, pdu, n), &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK_EQ(out.len, 0);
        }
    }

    /* two fragments: the payload comes from the buffer, in order */
    {
        size_t n = make_pdu(pdu, 10, 0x30);
        ble_l2cap_reasm_init(&r, buf, sizeof buf);
        memset(&out, 0, sizeof out);
        push_is(&r, START(7, pdu, 8), &out, BLE_L2CAP_REASM_PENDING);
        CHECK(out.payload == NULL);                    /* untouched while pending */
        if (push_is(&r, CONT(7, pdu + 8, n - 8), &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK_EQ(out.cid, 0x0004);
            CHECK_EQ(out.len, 10);
            CHECK(out.payload == buf + 4);
            CHECK_MEM(out.payload, pdu + 4, 10);
        }
        /* idle again: a stray continuation now is an orphan */
        push_is(&r, CONT(7, pdu, 2), &out, BLE_L2CAP_REASM_ERR_ORPHAN);
        CHECK_EQ(r.lost, 0);
    }

    /* the header itself split, at every point, and one octet at a time */
    {
        size_t n = make_pdu(pdu, 5, 0x50);
        for (size_t first = 0; first < 4; first++) {
            roundtrip(pdu, n, first, 1);
            roundtrip(pdu, n, first, 3);
            roundtrip(pdu, n, first, n);
        }
        /* 2 octets: length known, channel not yet */
        roundtrip(pdu, n, 2, 2);
    }

    /* empty continuation: taken, changes nothing */
    {
        size_t n = make_pdu(pdu, 6, 0);
        ble_l2cap_reasm_init(&r, buf, sizeof buf);
        push_is(&r, START(3, pdu, 5), &out, BLE_L2CAP_REASM_PENDING);
        push_is(&r, CONT(3, pdu + 5, 0), &out, BLE_L2CAP_REASM_PENDING);
        if (push_is(&r, CONT(3, pdu + 5, n - 5), &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK_MEM(out.payload, pdu + 4, 6);
        }
    }

    /* orphan: a continuation with nothing in progress */
    ble_l2cap_reasm_init(&r, buf, sizeof buf);
    push_is(&r, CONT(1, pdu, 4), &out, BLE_L2CAP_REASM_ERR_ORPHAN);
    CHECK_EQ(r.lost, 0);

    /* a start interrupts a PDU in progress: whole new PDU */
    {
        size_t n = make_pdu(pdu, 20, 0);
        size_t n2 = make_pdu(pdu2, 3, 0xC0);
        ble_l2cap_reasm_init(&r, buf, sizeof buf);
        push_is(&r, START(1, pdu, 10), &out, BLE_L2CAP_REASM_PENDING);
        if (push_is(&r, START(1, pdu2, n2), &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK(out.payload == pdu2 + 4);
        }
        CHECK_EQ(r.lost, 1);
        /* the rest of the first PDU is now an orphan */
        push_is(&r, CONT(1, pdu + 10, n - 10), &out, BLE_L2CAP_REASM_ERR_ORPHAN);
        CHECK_EQ(r.lost, 1);
    }

    /* ... and by a fragmented one: nothing of the old PDU leaks into the new */
    {
        make_pdu(pdu, 20, 0x00);
        size_t n2 = make_pdu(pdu2, 12, 0xE0);
        ble_l2cap_reasm_init(&r, buf, sizeof buf);
        push_is(&r, START(1, pdu, 15), &out, BLE_L2CAP_REASM_PENDING);
        push_is(&r, START(1, pdu2, 6), &out, BLE_L2CAP_REASM_PENDING);
        CHECK_EQ(r.lost, 1);
        if (push_is(&r, CONT(1, pdu2 + 6, n2 - 6), &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK_EQ(out.len, 12);
            CHECK_MEM(out.payload, pdu2 + 4, 12);
        }
        CHECK_EQ(r.lost, 1);
    }

    /* a continuation for another connection is ignored; the PDU goes on */
    {
        size_t n = make_pdu(pdu, 10, 0x10);
        static const uint8_t junk[] = {0xEE, 0xEE, 0xEE};
        ble_l2cap_reasm_init(&r, buf, sizeof buf);
        push_is(&r, START(0x001, pdu, 6), &out, BLE_L2CAP_REASM_PENDING);
        push_is(&r, CONT(0x002, junk, sizeof junk), &out, BLE_L2CAP_REASM_ERR_HANDLE);
        if (push_is(&r, CONT(0x001, pdu + 6, n - 6), &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK_MEM(out.payload, pdu + 4, 10);
        }
        CHECK_EQ(r.lost, 0);
    }

    /* PB 0b11 is reserved on LE: ignored, the PDU in progress survives */
    {
        size_t n = make_pdu(pdu, 10, 0x20);
        ble_l2cap_reasm_init(&r, buf, sizeof buf);
        push_is(&r, START(1, pdu, 6), &out, BLE_L2CAP_REASM_PENDING);
        push_is(&r, acl_of(1, 3, pdu, n), &out, BLE_L2CAP_REASM_ERR_MALFORMED);
        if (push_is(&r, CONT(1, pdu + 6, n - 6), &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK_MEM(out.payload, pdu + 4, 10);
        }
        CHECK_EQ(r.lost, 0);
    }

    /* buffer size: exactly full fits, one more octet does not */
    {
        uint8_t small[16 + 4];                 /* 4 canary octets after the buffer */
        memset(small, 0x5A, sizeof small);
        size_t n = make_pdu(pdu, 12, 0x01);    /* 16 octets: fits */
        ble_l2cap_reasm_init(&r, small, 16);
        push_is(&r, START(1, pdu, 9), &out, BLE_L2CAP_REASM_PENDING);
        if (push_is(&r, CONT(1, pdu + 9, n - 9), &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK_MEM(out.payload, pdu + 4, 12);
        }

        n = make_pdu(pdu, 13, 0x01);           /* 17 octets: does not */
        push_is(&r, START(1, pdu, 9), &out, BLE_L2CAP_REASM_ERR_TOO_LONG);
        CHECK_EQ(r.lost, 1);
        push_is(&r, CONT(1, pdu + 9, 4), &out, BLE_L2CAP_REASM_ERR_TOO_LONG);
        push_is(&r, CONT(1, pdu + 13, n - 13), &out, BLE_L2CAP_REASM_ERR_TOO_LONG);
        CHECK_EQ(r.lost, 1);                   /* counted once */
        push_is(&r, CONT(1, pdu, 2), &out, BLE_L2CAP_REASM_ERR_ORPHAN);   /* skipping done */
        CHECK(small[16] == 0x5A && small[17] == 0x5A && small[18] == 0x5A && small[19] == 0x5A);

        /* too long, found out only when the length arrives in a continuation */
        ble_l2cap_reasm_init(&r, small, 16);
        n = make_pdu(pdu, 40, 0);
        push_is(&r, START(1, pdu, 1), &out, BLE_L2CAP_REASM_PENDING);
        push_is(&r, CONT(1, pdu + 1, 10), &out, BLE_L2CAP_REASM_ERR_TOO_LONG);
        CHECK_EQ(r.lost, 1);
        push_is(&r, CONT(1, pdu + 11, n - 11), &out, BLE_L2CAP_REASM_ERR_TOO_LONG);
        push_is(&r, CONT(1, pdu, 1), &out, BLE_L2CAP_REASM_ERR_ORPHAN);

        /* a start ends skipping without counting that PDU again */
        n = make_pdu(pdu, 30, 0);
        push_is(&r, START(1, pdu, 8), &out, BLE_L2CAP_REASM_ERR_TOO_LONG);
        CHECK_EQ(r.lost, 2);
        size_t n2 = make_pdu(pdu2, 2, 0x77);
        if (push_is(&r, START(1, pdu2, n2), &out, BLE_L2CAP_REASM_COMPLETE)) {
            CHECK_EQ(out.payload[0], 0x77);
        }
        CHECK_EQ(r.lost, 2);
        CHECK(small[16] == 0x5A && small[19] == 0x5A);
    }

    /* overrun: more octets than PDU Length allows */
    {
        size_t n = make_pdu(pdu, 6, 0);        /* 10 octets */
        ble_l2cap_reasm_init(&r, buf, sizeof buf);
        /* in a start: header says 6, packet carries 7 */
        push_is(&r, START(1, pdu, n + 1), &out, BLE_L2CAP_REASM_ERR_OVERRUN);
        CHECK_EQ(r.lost, 1);
        /* in a continuation: 6 + 6 > 10 */
        push_is(&r, START(1, pdu, 6), &out, BLE_L2CAP_REASM_PENDING);
        push_is(&r, CONT(1, pdu, 6), &out, BLE_L2CAP_REASM_ERR_OVERRUN);
        CHECK_EQ(r.lost, 2);
        push_is(&r, CONT(1, pdu, 1), &out, BLE_L2CAP_REASM_ERR_ORPHAN);   /* dropped */
        /* while skipping: not counted again */
        uint8_t tiny[8];
        ble_l2cap_reasm_init(&r, tiny, sizeof tiny);
        n = make_pdu(pdu, 10, 0);              /* 14 > 8 */
        push_is(&r, START(1, pdu, 6), &out, BLE_L2CAP_REASM_ERR_TOO_LONG);
        push_is(&r, CONT(1, pdu, 9), &out, BLE_L2CAP_REASM_ERR_OVERRUN);
        CHECK_EQ(r.lost, 1);
        push_is(&r, CONT(1, pdu, 1), &out, BLE_L2CAP_REASM_ERR_ORPHAN);
        /* overrun wins over too long in the same continuation */
        ble_l2cap_reasm_init(&r, tiny, sizeof tiny);
        n = make_pdu(pdu, 10, 0);
        push_is(&r, START(1, pdu, 1), &out, BLE_L2CAP_REASM_PENDING);
        push_is(&r, CONT(1, pdu + 1, n), &out, BLE_L2CAP_REASM_ERR_OVERRUN);
        CHECK_EQ(r.lost, 1);
        push_is(&r, CONT(1, pdu, 1), &out, BLE_L2CAP_REASM_ERR_ORPHAN);
    }

    /* a start that interrupts AND overruns: two PDUs lost */
    {
        size_t n = make_pdu(pdu, 6, 0);
        ble_l2cap_reasm_init(&r, buf, sizeof buf);
        push_is(&r, START(1, pdu, 5), &out, BLE_L2CAP_REASM_PENDING);
        push_is(&r, START(1, pdu, n + 2), &out, BLE_L2CAP_REASM_ERR_OVERRUN);
        CHECK_EQ(r.lost, 2);
    }
}

/**
 * @brief The 16 real packets, cut at every fragment size, come back whole.
 */
void suite_reasm_real(void)
{
    SUITE("l2cap reassembly, real PDUs cut up (task 7c)");
    int cuts = 0;
    for (size_t i = 0; i < sizeof ACL_FIXTURES / sizeof ACL_FIXTURES[0]; i++) {
        const acl_fixture_t *f = &ACL_FIXTURES[i];
        ble_acl_t acl = {0, 0, 0, NULL, 0};
        if (ble_acl_parse(f->bytes, f->len, &acl) != BLE_ACL_OK) {
            CHECK(0);
            continue;
        }
        size_t len = acl.len;                  /* the whole L2CAP PDU */
        for (size_t step = 1; step <= len; step++) {
            for (size_t first = 0; first <= len; first += (first < 6 ? 1 : step)) {
                if (!roundtrip(acl.data, len, first, step)) {
                    printf("    fixture: %s\n", f->label);
                    goto next;
                }
                cuts++;
            }
        }
next:   ;
    }
    printf("  %d ways of cutting 16 real PDUs, all rebuilt\n", cuts);
}

/** @brief Fuzz state: fixed seed, so a failure reproduces. */
static unsigned int rs_rng = 0x7C7C1234u;

/**
 * @brief xorshift32, as in test_fuzz.c.
 * @return The next pseudo-random value.
 */
static unsigned int rs_rand(void)
{
    unsigned int x = rs_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return rs_rng = x;
}

/**
 * @brief Random fragment streams.
 *
 * Two parts. First, 20 000 random PDUs cut at random points, with junk for
 * other connections and empty continuations mixed in: each must come back
 * exactly. Second, 200 000 packets of pure noise — any flag, any handle,
 * any length field — into a 32-octet buffer allocated to size: no access
 * outside it, nothing delivered from outside the buffer or the packet, and
 * @c lost never shrinks.
 */
void suite_reasm_fuzz(void)
{
    SUITE("l2cap reassembly fuzz (task 7c)");
    uint8_t buf[300], pdu[300];
    ble_l2cap_reasm_t r;
    ble_l2cap_t out = {0, 0, NULL};
    memset(&r, 0, sizeof r);
    int rebuilt = 0;
    static const uint8_t junk[5] = {1, 2, 3, 4, 5};

    for (int n = 0; n < 20000; n++) {
        size_t plen = rs_rand() % 250u;
        size_t len = make_pdu(pdu, plen, (uint8_t)rs_rand());
        ble_l2cap_reasm_init(&r, buf, sizeof buf);
        size_t at = rs_rand() % (len + 1);
        ble_acl_t a = START(9, pdu, at);
        ble_l2cap_reasm_status_t st = ble_l2cap_reasm_push(&r, &a, &out);
        int guard = 0;                             /* a wrong parser must fail, not hang */
        while ((st == BLE_L2CAP_REASM_PENDING || st == BLE_L2CAP_REASM_ERR_HANDLE) &&
               guard++ < 10000) {
            if ((rs_rand() & 7u) == 0) {           /* another connection's fragment */
                a = CONT(10, junk, sizeof junk);
            } else {
                size_t k = rs_rand() % 40u;
                if (k > len - at) {
                    k = len - at;
                }
                a = CONT(9, pdu + at, k);
                at += k;
            }
            st = ble_l2cap_reasm_push(&r, &a, &out);
        }
        if (st == BLE_L2CAP_REASM_COMPLETE && at == len && out.len == plen &&
            memcmp(out.payload, pdu + 4, plen) == 0 && r.lost == 0) {
            rebuilt++;
        }
    }
    CHECK_EQ(rebuilt, 20000);

    uint8_t *small = malloc(32);
    if (small == NULL) {
        CHECK(0);
        return;
    }
    ble_l2cap_reasm_init(&r, small, 32);
    int in_bounds = 1, monotonic = 1, completes = 0, pending = 0;
    uint32_t lost = 0;
    for (int n = 0; n < 200000; n++) {
        size_t len = rs_rand() % 48u;
        uint8_t *pkt = malloc(len ? len : 1);
        if (pkt == NULL) {
            break;
        }
        for (size_t k = 0; k < len; k++) {
            pkt[k] = (uint8_t)rs_rand();
        }
        if (len >= 4 && (rs_rand() & 1u)) {        /* steer: lengths that can be met */
            pkt[0] = (rs_rand() & 1u) ? (uint8_t)(len - 4u) : (uint8_t)(rs_rand() % 40u);
            pkt[1] = 0;
        }
        ble_acl_t a = acl_of((uint16_t)(rs_rand() % 3u), (uint8_t)(rs_rand() & 3u), pkt, len);
        if ((rs_rand() % 3u) == 0) {
            a.pb = BLE_ACL_PB_CONTINUING;
        }
        ble_l2cap_reasm_status_t st = ble_l2cap_reasm_push(&r, &a, &out);
        if (st == BLE_L2CAP_REASM_COMPLETE) {
            completes++;
            int in_pkt = out.payload >= pkt && out.payload + out.len <= pkt + len;
            int in_buf = out.payload >= small && out.payload + out.len <= small + 32;
            if (!in_pkt && !in_buf) {
                in_bounds = 0;
            }
        } else if (st == BLE_L2CAP_REASM_PENDING) {
            pending++;
        }
        if (r.lost < lost) {
            monotonic = 0;
        }
        lost = r.lost;
        free(pkt);
    }
    free(small);
    CHECK(in_bounds);
    CHECK(monotonic);
    CHECK(completes > 1000);
    CHECK(pending > 1000);
    printf("  200000 noise packets: %d PDUs delivered, %u lost, all in bounds\n",
           completes, (unsigned)lost);
}
