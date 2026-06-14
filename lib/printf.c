/* Tiny printf implementation for the kernel console. */
#include "kio.h"
#include "serial.h"
#include <stdarg.h>
#include <stdbool.h>

void kputchar(char c)
{
    terminal_putchar(c);
    serial_write_char(c);
}

void kputs(const char *s)
{
    while (*s)
        kputchar(*s++);
}

static void print_uint(unsigned long value, unsigned base, bool upper)
{
    char buf[32];
    int i = 0;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";

    if (value == 0) {
        kputchar('0');
        return;
    }
    while (value) {
        buf[i++] = digits[value % base];
        value /= base;
    }
    while (i > 0)
        kputchar(buf[--i]);
}

static void print_int(long value)
{
    if (value < 0) {
        kputchar('-');
        print_uint((unsigned long)(-value), 10, false);
    } else {
        print_uint((unsigned long)value, 10, false);
    }
}

void kprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    for (const char *p = fmt; *p; p++) {
        if (*p != '%') {
            kputchar(*p);
            continue;
        }
        p++;
        switch (*p) {
        case 'c':
            kputchar((char)va_arg(ap, int));
            break;
        case 's': {
            const char *s = va_arg(ap, const char *);
            kputs(s ? s : "(null)");
            break;
        }
        case 'd':
        case 'i':
            print_int(va_arg(ap, int));
            break;
        case 'u':
            print_uint(va_arg(ap, unsigned int), 10, false);
            break;
        case 'x':
            print_uint(va_arg(ap, unsigned int), 16, false);
            break;
        case 'X':
            print_uint(va_arg(ap, unsigned int), 16, true);
            break;
        case 'p':
            kputs("0x");
            print_uint((unsigned long)(uintptr_t)va_arg(ap, void *), 16, false);
            break;
        case '%':
            kputchar('%');
            break;
        case '\0':
            va_end(ap);
            return;
        default:
            kputchar('%');
            kputchar(*p);
            break;
        }
    }

    va_end(ap);
}
