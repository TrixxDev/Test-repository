/* Fixed-size big-integer arithmetic — the math under RSA. v1.
 *
 * Deliberately the simplest thing that can be correct: a fixed array of 32-bit
 * limbs (little-endian), schoolbook multiply, and binary long division for the
 * modulus. No Montgomery, no Karatsuba, no allocation — RSA certificate checks
 * happen a handful of times, not millions per second, so clarity wins over speed.
 * Freestanding: only <stdint.h>/<stddef.h>, so the same source serves the host
 * test, user space, and the kernel. Knows nothing about RSA or certificates.
 *
 * Sized for products of two ≤4096-bit operands, i.e. up to RSA-4096. */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define BN_BITS   8192
#define BN_LIMBS  (BN_BITS / 32)   /* 256 limbs */

typedef struct { uint32_t v[BN_LIMBS]; } bignum;

void   bignum_zero(bignum *a);
void   bignum_copy(bignum *r, const bignum *a);
void   bignum_set_u32(bignum *a, uint32_t x);
int    bignum_is_zero(const bignum *a);

/* big-endian byte I/O. from_bytes returns -1 if the value does not fit;
 * to_bytes writes exactly `len` bytes (left-padded with zeros) and returns -1 if
 * the value needs more than `len` bytes. */
int    bignum_from_bytes(bignum *a, const uint8_t *buf, size_t len);
int    bignum_to_bytes(const bignum *a, uint8_t *buf, size_t len);

int    bignum_cmp(const bignum *a, const bignum *b);   /* -1 / 0 / 1 */
int    bignum_bit(const bignum *a, size_t i);          /* bit i (0 = LSB) */
size_t bignum_bitlen(const bignum *a);                 /* index of top set bit + 1 */

uint32_t bignum_add(bignum *r, const bignum *a, const bignum *b);  /* returns carry */
uint32_t bignum_sub(bignum *r, const bignum *a, const bignum *b);  /* returns borrow */
void     bignum_shl1(bignum *r, const bignum *a);                  /* r = a << 1 */

void   bignum_mul(bignum *r, const bignum *a, const bignum *b);    /* r = a * b   */
void   bignum_mod(bignum *r, const bignum *a, const bignum *m);    /* r = a mod m */
void   bignum_modmul(bignum *r, const bignum *a, const bignum *b, const bignum *m);
void   bignum_modexp(bignum *r, const bignum *base, const bignum *e, const bignum *m);
