/* Minimal ASN.1 DER reader — see asn1.h. */
#include "asn1.h"

int asn1_next(asn1_cursor *c, asn1_tlv *out)
{
    const uint8_t *p = c->p;

    if (p >= c->end) return -1;                 /* need the identifier octet */
    uint8_t tag = *p++;
    if ((tag & 0x1f) == 0x1f) return -1;        /* high-tag-number form unsupported */

    if (p >= c->end) return -1;                 /* need the first length octet */
    uint8_t b = *p++;

    size_t len;
    if (b < 0x80) {
        len = b;                                /* short form */
    } else {
        int n = b & 0x7f;                       /* long form: n subsequent octets */
        if (n == 0) return -1;                  /* indefinite length: forbidden in DER */
        if (n > 4) return -1;                    /* absurdly large length field */
        len = 0;
        for (int i = 0; i < n; i++) {
            if (p >= c->end) return -1;
            uint8_t lb = *p++;
            if (i == 0 && lb == 0) return -1;   /* non-minimal: leading zero octet */
            len = (len << 8) | lb;
        }
        if (len < 0x80) return -1;              /* non-minimal: short form was required */
    }

    if (len > (size_t)(c->end - p)) return -1;  /* value must fit within the buffer */

    out->tag   = tag;
    out->value = p;
    out->len   = len;
    c->p = p + len;                             /* commit: advance past the value */
    return 0;
}

int asn1_peek_tag(const asn1_cursor *c, uint8_t *tag)
{
    if (c->p >= c->end) return -1;
    if ((*c->p & 0x1f) == 0x1f) return -1;      /* high-tag-number form unsupported */
    *tag = *c->p;
    return 0;
}

int asn1_expect(asn1_cursor *c, uint8_t tag, asn1_tlv *out)
{
    asn1_cursor save = *c;
    if (asn1_next(c, out) != 0) return -1;
    if (out->tag != tag) { *c = save; return -1; }
    return 0;
}

int asn1_open(asn1_cursor *c, uint8_t tag, asn1_cursor *inner)
{
    asn1_tlv t;
    if (asn1_expect(c, tag, &t) != 0) return -1;
    inner->p   = t.value;
    inner->end = t.value + t.len;
    return 0;
}

int asn1_oid_equals(const asn1_tlv *t, const uint8_t *oid, size_t oidlen)
{
    if (t->tag != ASN1_OID || t->len != oidlen) return 0;
    for (size_t i = 0; i < oidlen; i++)
        if (t->value[i] != oid[i]) return 0;
    return 1;
}

int asn1_get_uint(const asn1_tlv *t, uint64_t *out)
{
    if (t->tag != ASN1_INTEGER || t->len == 0) return -1;
    if (t->value[0] & 0x80) return -1;                       /* negative */
    /* DER minimality: a leading 0x00 is only allowed to clear a high bit */
    if (t->len > 1 && t->value[0] == 0 && !(t->value[1] & 0x80)) return -1;

    size_t i = 0;
    if (t->value[0] == 0) i = 1;                             /* skip the sign byte */
    if (t->len - i > 8) return -1;                           /* does not fit in 64 bits */

    uint64_t v = 0;
    for (; i < t->len; i++) v = (v << 8) | t->value[i];
    *out = v;
    return 0;
}
