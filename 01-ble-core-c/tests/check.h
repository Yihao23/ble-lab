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
void suite_fuzz(void);   /**< Random input, half shaped like LE Meta events, under the sanitizers. See test_fuzz.c. */

#endif
