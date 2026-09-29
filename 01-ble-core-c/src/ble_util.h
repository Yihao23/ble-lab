/**
 * @file  ble_util.h
 * @brief Internal byte helpers, replacing `<string.h>`.
 *
 * The library deliberately does not include `<string.h>`, so it compiles with
 * `-ffreestanding`: on a bare-metal target with no libc, it still builds and
 * links. Not part of the public API.
 *
 * @internal
 */
#ifndef BLE_UTIL_H
#define BLE_UTIL_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Copy @p n bytes; the buffers must not overlap (like `memcpy`).
 * @param[out] dst  Destination.
 * @param[in]  src  Source.
 * @param[in]  n    Number of bytes.
 */
static inline void ble_copy(uint8_t *dst, const uint8_t *src, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

/**
 * @brief Zero memory in a way the optimiser cannot drop as a dead store.
 *
 * A plain loop or `memset` on a buffer that is never read again may be
 * removed; writing through a `volatile` pointer may not. Used to erase key
 * schedules and intermediate ciphertext before a function returns.
 *
 * @param[out] p  Memory to erase.
 * @param[in]  n  Number of bytes.
 */
static inline void ble_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) {
        *v++ = 0;
    }
}

/**
 * @brief Read a little-endian 16-bit value, independent of host byte order
 *        and alignment.
 * @param[in] p  Two bytes, least significant first.
 * @return The value.
 */
static inline uint16_t ble_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

#endif /* BLE_UTIL_H */
