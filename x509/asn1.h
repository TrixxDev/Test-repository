/* Minimal ASN.1 DER reader (X.690) — the bottom of the X.509 stack. v1.
 *
 * Deliberately boring and strict: a cursor walks a byte buffer one TLV
 * (tag-length-value) at a time, and the single invariant that matters is that it
 * can NEVER read past the buffer it was given. There is no allocation, no
 * callbacks, no global state — just bounds-checked pointer advancement over a
 * caller-owned buffer, so the same source serves the host test, user space and
 * the kernel (freestanding: only <stdint.h>/<stddef.h>).
 *
 * DER (not BER) only: definite lengths, minimally encoded. Indefinite length,
 * non-minimal length, and the high-tag-number form are all rejected. Everything
 * X.509 needs uses single-byte tags and definite lengths, so this is sufficient
 * and leaves no parser ambiguity for a signature to hide behind. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Universal tags (class 0). SEQUENCE/SET also carry the constructed bit (0x20). */
#define ASN1_BOOLEAN          0x01
#define ASN1_INTEGER          0x02
#define ASN1_BIT_STRING       0x03
#define ASN1_OCTET_STRING     0x04
#define ASN1_NULL             0x05
#define ASN1_OID              0x06
#define ASN1_UTF8STRING       0x0c
#define ASN1_PRINTABLESTRING  0x13
#define ASN1_IA5STRING        0x16
#define ASN1_UTCTIME          0x17
#define ASN1_GENERALIZEDTIME  0x18
#define ASN1_SEQUENCE         0x30   /* constructed */
#define ASN1_SET              0x31   /* constructed */

/* Context-specific constructed tags used by X.509 ([0] version, [3] extensions). */
#define ASN1_CONTEXT          0x80   /* class bit; OR with the tag number */
#define ASN1_CONSTRUCTED      0x20

/* A cursor over a byte range. `p` is the next byte to read; `end` is one past the
 * last valid byte. p <= end always holds. */
typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} asn1_cursor;

/* One parsed element: its identifier octet and a view of its contents. The view
 * always lies within the cursor it was read from. */
typedef struct {
    uint8_t        tag;
    const uint8_t *value;
    size_t         len;
} asn1_tlv;

static inline void asn1_cursor_init(asn1_cursor *c, const uint8_t *buf, size_t len)
{
    c->p = buf;
    c->end = buf + len;
}

static inline int asn1_cursor_empty(const asn1_cursor *c) { return c->p >= c->end; }

/* Read one TLV at the cursor. On success fills *out, advances the cursor past the
 * value, and returns 0. Returns -1 on any malformed or out-of-bounds input;
 * the cursor is left unchanged on failure. */
int asn1_next(asn1_cursor *c, asn1_tlv *out);

/* Peek the next element's tag without consuming it. Returns -1 if no element. */
int asn1_peek_tag(const asn1_cursor *c, uint8_t *tag);

/* Like asn1_next but fails (and leaves the cursor unchanged) unless the element's
 * tag equals `tag`. */
int asn1_expect(asn1_cursor *c, uint8_t tag, asn1_tlv *out);

/* Read a constructed element of the given tag and set *inner to a cursor over its
 * contents. Returns 0 on success, -1 otherwise. */
int asn1_open(asn1_cursor *c, uint8_t tag, asn1_cursor *inner);

/* True if the TLV is an OID whose contents equal the given raw encoding. */
int asn1_oid_equals(const asn1_tlv *t, const uint8_t *oid, size_t oidlen);

/* Decode an INTEGER as an unsigned value. Fails if negative (high bit set), if it
 * is non-minimally encoded, or if it does not fit in 64 bits. */
int asn1_get_uint(const asn1_tlv *t, uint64_t *out);
