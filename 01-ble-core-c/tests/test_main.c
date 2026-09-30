/**
 * @file  test_main.c
 * @brief Test runner: runs every suite and prints the totals.
 */
#include "check.h"

int g_checks;
int g_failures;

/**
 * @brief Run all suites in order.
 * @return 0 if every check passed, 1 otherwise (so ctest and CI see failure).
 */
int main(void)
{
    suite_aes();
    suite_rpa();
    suite_ad();
    suite_ad_helpers();
    suite_hci();
    suite_fuzz();

    printf("\n%d checks, %d failed\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
