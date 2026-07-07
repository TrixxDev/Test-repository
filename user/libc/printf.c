#include "libc.h"

struct out {
    int  fd;
    char buf[256];
    int  n;
    int  total;
};

static void flush(struct out *o)
{
    if (o->n) {
        write(o->fd, o->buf, o->n);
        o->n = 0;
    }
}

static void emit(struct out *o, char c)
{
    o->buf[o->n++] = c;
    o->total++;
    if (o->n == (int)sizeof(o->buf))
        flush(o);
}

static void emits(struct out *o, const char *s)
{
    while (*s) emit(o, *s++);
}

static void emit_num(struct out *o, unsigned long v, int base, int is_signed, int upper)
{
    char tmp[32];
    int i = 0;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";

    if (is_signed && (long)v < 0) {
        emit(o, '-');
        v = (unsigned long)(-(long)v);
    }
    if (v == 0) {
        emit(o, '0');
        return;
    }
    while (v) { tmp[i++] = digits[v % base]; v /= base; }
    while (i) emit(o, tmp[--i]);
}

static int vformat(int fd, const char *fmt, va_list ap)
{
    struct out o = { fd, {0}, 0, 0 };

    for (const char *p = fmt; *p; p++) {
        if (*p != '%') { emit(&o, *p); continue; }
        p++;
        switch (*p) {
        case 'd': case 'i': emit_num(&o, (unsigned long)va_arg(ap, int), 10, 1, 0); break;
        case 'u': emit_num(&o, (unsigned long)va_arg(ap, unsigned int), 10, 0, 0); break;
        case 'x': emit_num(&o, (unsigned long)va_arg(ap, unsigned int), 16, 0, 0); break;
        case 'X': emit_num(&o, (unsigned long)va_arg(ap, unsigned int), 16, 0, 1); break;
        case 'c': emit(&o, (char)va_arg(ap, int)); break;
        case 's': { const char *s = va_arg(ap, const char *); emits(&o, s ? s : "(null)"); break; }
        case '%': emit(&o, '%'); break;
        case '\0': flush(&o); return o.total;
        default: emit(&o, '%'); emit(&o, *p); break;
        }
    }
    flush(&o);
    return o.total;
}

int fprintf(int fd, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vformat(fd, fmt, ap);
    va_end(ap);
    return r;
}

int printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vformat(1, fmt, ap);
    va_end(ap);
    return r;
}

int puts(const char *s)
{
    int n = (int)strlen(s);
    write(1, s, n);
    write(1, "\n", 1);
    return n + 1;
}

int putchar(int c)
{
    char ch = (char)c;
    write(1, &ch, 1);
    return c;
}
