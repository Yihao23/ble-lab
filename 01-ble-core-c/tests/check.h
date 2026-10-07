/**
 * @file  check.h
 * @brief A test framework in 30 lines. No dependency, runs anywhere printf does.
 *
 * A failed check prints its file, line and expression and the run continues,
 * so one run reports every failure. test_main.c returns non-zero if any failed.
 */
#ifndef CHECK_H
#define CHECK_H

#include <stdio.h>
#include <string.h>

extern int g_checks;     /**< Number of checks executed. */
extern int g_failures;   /**< Number of checks that failed. */

/**
 * @brief Count one check; report it if @p cond is false.
 * @param cond  Expression expected to be true.
 */
#define CHECK(cond) do {                                                      \
        g_checks++;                                                           \
        if (!(cond)) {                                                        \
            g_failures++;                                                     \
            printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);          \
        }                                                                     \
    } while (0)

/**
 * @brief Check two integers for equality; on failure print both values.
 *
 * Both sides are widened to `long long` once, so each argument is evaluated
 * exactly once and signed/unsigned mixes compare by value.
 *
 * @param a  Actual value.
 * @param b  Expected value.
 */
#define CHECK_EQ(a, b) do {                                                   \
        long long _a = (long long)(a), _b = (long long)(b);                   \
        g_checks++;                                                           \
        if (_a != _b) {                                                       \
            g_failures++;                                                     \
            printf("  FAIL %s:%d  %s == %s  (%lld != %lld)\n",                \
                   __FILE__, __LINE__, #a, #b, _a, _b);                       \
        }                                                                     \
    } while (0)

/**
 * @brief Check that two byte buffers are equal.
 * @param a  Actual bytes.
 * @param b  Expected bytes.
 * @param n  Number of bytes to compare.
 */
#define CHECK_MEM(a, b, n) CHECK(memcmp((a), (b), (n)) == 0)

/**
 * @brief Print the name of the suite that starts here.
 * @param name  Suite name.
 */
#define SUITE(name) printf("%s\n", name)

void suite_aes(void);    /**< AES-128 against FIPS-197. See test_aes.c. */
void suite_rpa(void);    /**< Address kinds, `ah()`, RPA make/resolve. See test_rpa.c. */
void suite_ad(void);     /**< AD iterator and helpers. See test_ad.c. */
void suite_hci(void);    /**< HCI report parser, synthetic and real events. See test_hci.c. */
void suite_ad_helpers(void);   /**< Task 1: flags, name, service data. See test_ad_helpers.c. */
void suite_hci_status(void);   /**< Task 2: extended report data status. See test_hci_status.c. */
void suite_hci_multi(void);    /**< Task 3: several legacy reports in one event. See test_hci_multi.c. */
void suite_cmac(void);         /**< Task 5: AES-CMAC, RFC 4493 vectors. See test_cmac.c. */
void suite_sc(void);           /**< Task 5: g2, Core Appendix D.5. See test_cmac.c. */
void suite_l2cap(void);        /**< Task 7a: HCI ACL and L2CAP. See test_l2cap_att.c. */
void suite_att(void);          /**< Task 7b: ATT PDUs. See test_l2cap_att.c. */
void suite_reasm(void);        /**< Task 7c: L2CAP reassembly, one test per rule. See test_reasm.c. */
void suite_reasm_real(void);   /**< Task 7c: the real PDUs, cut at every size, rebuilt. See test_reasm.c. */
void suite_reasm_fuzz(void);   /**< Task 7c: random fragment streams under the sanitizers. See test_reasm.c. */
void suite_acl_fuzz(void);     /**< Task 7: random ACL packets under the sanitizers. See test_l2cap_att.c. */
void suite_fuzz(void);   /**< Random input, half shaped like LE Meta events, under the sanitizers. See test_fuzz.c. */

#endif
