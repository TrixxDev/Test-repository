/* uaccess.c — safe copy from/to user space.
 *
 * These functions validate user-space pointers before copying to prevent
 * kernel crashes from malicious or buggy user-space code.
 */
#include "uaccess.h"
#include "kio.h"
#include <string.h>

int copy_from_user(void *dst, const void *src, size_t len) {
    if (!is_user_addr((uint32_t)src, len)) {
        kprintf("[uaccess] copy_from_user: invalid src address 0x%x (len=%u)\n",
                (uint32_t)src, len);
        return -1;
    }
    memcpy(dst, src, len);
    return 0;
}

int copy_to_user(void *dst, const void *src, size_t len) {
    if (!is_user_addr((uint32_t)dst, len)) {
        kprintf("[uaccess] copy_to_user: invalid dst address 0x%x (len=%u)\n",
                (uint32_t)dst, len);
        return -1;
    }
    memcpy(dst, src, len);
    return 0;
}

int copy_str_from_user(char *dst, const char *src, size_t maxlen) {
    if (!src || maxlen == 0) {
        if (maxlen > 0 && dst)
            dst[0] = '\0';
        return -1;
    }
    
    /* Validate the source pointer itself (we'll check bounds as we copy) */
    if ((uint32_t)src >= KERNEL_VBASE) {
        kprintf("[uaccess] copy_str_from_user: src 0x%x in kernel space\n", (uint32_t)src);
        dst[0] = '\0';
        return -1;
    }
    
    size_t i;
    for (i = 0; i < maxlen - 1; i++) {
        /* Check if we're still in user space */
        if ((uint32_t)(src + i) >= KERNEL_VBASE) {
            kprintf("[uaccess] copy_str_from_user: string crossed into kernel space at offset %u\n", i);
            dst[i] = '\0';
            return -1;
        }
        dst[i] = src[i];
        if (dst[i] == '\0')
            return (int)i;  /* success, return length */
    }
    
    /* String too long, truncate */
    dst[maxlen - 1] = '\0';
    return -1;
}
