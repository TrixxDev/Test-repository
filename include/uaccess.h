/* uaccess.h — safe copy from/to user space.
 *
 * AuroraOS kernel runs in high half (>= 0xC0000000). User space is below that.
 * These functions validate pointers before copying to prevent kernel crashes
 * from malicious or buggy user-space code.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Kernel virtual base (from linker.ld: . = 0xC0000000 + 1M) */
#define KERNEL_VBASE 0xC0000000u

/* Check if a user pointer is valid (in user space range). */
static inline int is_user_addr(uint32_t addr, size_t len) {
    /* Must be below kernel space and not wrap around */
    if (addr >= KERNEL_VBASE)
        return 0;
    if (addr + len < addr)  /* overflow check */
        return 0;
    if (addr + len > KERNEL_VBASE)
        return 0;
    return 1;
}

/* Copy len bytes from user-space src to kernel-space dst.
 * Returns 0 on success, -1 on invalid address. */
int copy_from_user(void *dst, const void *src, size_t len);

/* Copy len bytes from kernel-space src to user-space dst.
 * Returns 0 on success, -1 on invalid address. */
int copy_to_user(void *dst, const void *src, size_t len);

/* Copy a NUL-terminated string from user-space to kernel buffer.
 * Returns length (excluding NUL) on success, -1 on error.
 * Always NUL-terminates dst if maxlen > 0. */
int copy_str_from_user(char *dst, const char *src, size_t maxlen);
