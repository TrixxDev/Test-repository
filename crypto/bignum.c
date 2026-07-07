/* Fixed-size big-integer arithmetic — see bignum.h. */
#include "bignum.h"

void bignum_zero(bignum *a) { for (int i = 0; i < BN_LIMBS; i++) a->v[i] = 0; }

void bignum_copy(bignum *r, const bignum *a) { for (int i = 0; i < BN_LIMBS; i++) r->v[i] = a->v[i]; }

void bignum_set_u32(bignum *a, uint32_t x) { bignum_zero(a); a->v[0] = x; }

int bignum_is_zero(const bignum *a)
{
    for (int i = 0; i < BN_LIMBS; i++) if (a->v[i]) return 0;
    return 1;
}

int bignum_from_bytes(bignum *a, const uint8_t *buf, size_t len)
{
    bignum_zero(a);
    /* buf is big-endian: buf[len-1] is the least significant byte */
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = buf[len - 1 - i];
        size_t limb = i / 4;
        if (limb >= BN_LIMBS) { if (byte) return -1; continue; }
        a->v[limb] |= (uint32_t)byte << ((i % 4) * 8);
    }
    return 0;
}

int bignum_to_bytes(const bignum *a, uint8_t *buf, size_t len)
{
    /* anything above `len` bytes must be zero, or it doesn't fit */
    for (size_t i = len; i < (size_t)BN_LIMBS * 4; i++) {
        uint8_t byte = (uint8_t)(a->v[i / 4] >> ((i % 4) * 8));
        if (byte) return -1;
    }
    for (size_t i = 0; i < len; i++) {
        uint32_t limbv = (i / 4 < BN_LIMBS) ? a->v[i / 4] : 0;
        buf[len - 1 - i] = (uint8_t)(limbv >> ((i % 4) * 8));
    }
    return 0;
}

int bignum_cmp(const bignum *a, const bignum *b)
{
    for (int i = BN_LIMBS - 1; i >= 0; i--)
        if (a->v[i] != b->v[i]) return a->v[i] > b->v[i] ? 1 : -1;
    return 0;
}

int bignum_bit(const bignum *a, size_t i)
{
    if (i >= (size_t)BN_LIMBS * 32) return 0;
    return (a->v[i / 32] >> (i % 32)) & 1;
}

size_t bignum_bitlen(const bignum *a)
{
    for (int i = BN_LIMBS - 1; i >= 0; i--) {
        if (a->v[i]) {
            uint32_t x = a->v[i];
            size_t b = 0;
            while (x) { x >>= 1; b++; }
            return (size_t)i * 32 + b;
        }
    }
    return 0;
}

uint32_t bignum_add(bignum *r, const bignum *a, const bignum *b)
{
    uint64_t carry = 0;
    for (int i = 0; i < BN_LIMBS; i++) {
        uint64_t s = (uint64_t)a->v[i] + b->v[i] + carry;
        r->v[i] = (uint32_t)s;
        carry = s >> 32;
    }
    return (uint32_t)carry;
}

uint32_t bignum_sub(bignum *r, const bignum *a, const bignum *b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < BN_LIMBS; i++) {
        uint64_t d = (uint64_t)a->v[i] - b->v[i] - borrow;
        r->v[i] = (uint32_t)d;
        borrow = (d >> 63) & 1;     /* high bit set => underflow */
    }
    return (uint32_t)borrow;
}

void bignum_shl1(bignum *r, const bignum *a)
{
    uint32_t carry = 0;
    for (int i = 0; i < BN_LIMBS; i++) {
        uint32_t next = a->v[i] >> 31;
        r->v[i] = (a->v[i] << 1) | carry;
        carry = next;
    }
}

void bignum_mul(bignum *r, const bignum *a, const bignum *b)
{
    bignum t; bignum_zero(&t);
    for (int i = 0; i < BN_LIMBS; i++) {
        if (a->v[i] == 0) continue;
        uint64_t carry = 0;
        for (int j = 0; i + j < BN_LIMBS; j++) {
            uint64_t cur = (uint64_t)t.v[i + j] + (uint64_t)a->v[i] * b->v[j] + carry;
            t.v[i + j] = (uint32_t)cur;
            carry = cur >> 32;
        }
        /* carry past the top limb is overflow; inputs are bounded so it is 0 */
    }
    bignum_copy(r, &t);
}

void bignum_mod(bignum *r, const bignum *a, const bignum *m)
{
    /* binary long division: bring down one bit of `a` at a time (MSB first),
     * subtracting `m` whenever the running remainder reaches it. */
    bignum rem; bignum_zero(&rem);
    size_t top = bignum_bitlen(a);
    for (size_t i = top; i-- > 0; ) {
        bignum_shl1(&rem, &rem);
        rem.v[0] |= (uint32_t)bignum_bit(a, i);
        if (bignum_cmp(&rem, m) >= 0) bignum_sub(&rem, &rem, m);
    }
    bignum_copy(r, &rem);
}

void bignum_modmul(bignum *r, const bignum *a, const bignum *b, const bignum *m)
{
    bignum prod;
    bignum_mul(&prod, a, b);
    bignum_mod(r, &prod, m);
}

void bignum_modexp(bignum *r, const bignum *base, const bignum *e, const bignum *m)
{
    bignum result, b;
    bignum_set_u32(&result, 1);
    bignum_mod(&b, base, m);                 /* base mod m */
    size_t bits = bignum_bitlen(e);
    for (size_t i = bits; i-- > 0; ) {
        bignum_modmul(&result, &result, &result, m);          /* square */
        if (bignum_bit(e, i)) bignum_modmul(&result, &result, &b, m);  /* multiply */
    }
    bignum_mod(r, &result, m);               /* normalize (handles m == 1) */
}
