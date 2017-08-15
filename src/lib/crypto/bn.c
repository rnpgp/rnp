/*-
 * Copyright (c) 2012 Alistair Crooks <agc@NetBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "config.h"
#include <stdlib.h>

#include "crypto.h"
#include "crypto/bn.h"

#ifndef USE_ARG
#define USE_ARG(x) /*LINTED*/ (void) &x
#endif

/**************************************************************************/

/* OpenSSL BIGNUM emulation layer */

/* essentiually, these are just wrappers around the botan functions */
/* usually the order of args changes */
/* the PGPV_BIGNUM API tends to have more const poisoning */
/* these wrappers also check the arguments passed for sanity */

PGPV_BIGNUM *
PGPV_BN_bin2bn(const uint8_t *data, int len, PGPV_BIGNUM *ret)
{
    if (data == NULL) {
        return PGPV_BN_new();
    }
    if (ret == NULL) {
        ret = PGPV_BN_new();
    }

    if (ret == NULL) {
        return NULL;
    }

    return (botan_mp_from_bin(ret->mp, data, len) == 0) ? ret : NULL;
}

/* store in unsigned [big endian] format */
int
PGPV_BN_bn2bin(const PGPV_BIGNUM *a, unsigned char *b)
{
    if (a == NULL || b == NULL) {
        return -1;
    }

    return botan_mp_to_bin(a->mp, b);
}

PGPV_BIGNUM *
PGPV_BN_new(void)
{
    PGPV_BIGNUM *a;

    a = calloc(1, sizeof(*a));
    if (a == NULL) {
        return NULL;
    }
    botan_mp_init(&a->mp);
    return a;
}

void
PGPV_BN_free(PGPV_BIGNUM *a)
{
    if (a != NULL) {
        botan_mp_destroy(a->mp);
        free(a);
    }
}

/* copy, b = a */
int
PGPV_BN_copy(PGPV_BIGNUM *to, const PGPV_BIGNUM *from)
{
    if (from == NULL || to == NULL) {
        return -1;
    }
    return botan_mp_set_from_mp(to->mp, from->mp);
}

PGPV_BIGNUM *
PGPV_BN_dup(const PGPV_BIGNUM *a)
{
    PGPV_BIGNUM *ret;

    if (a == NULL) {
        return NULL;
    }
    if ((ret = PGPV_BN_new()) != NULL) {
        PGPV_BN_copy(ret, a);
    }
    return ret;
}

void
PGPV_BN_swap(PGPV_BIGNUM *a, PGPV_BIGNUM *b)
{
    if (a && b) {
        botan_mp_swap(a->mp, b->mp);
    }
}

int
PGPV_BN_lshift(PGPV_BIGNUM *r, const PGPV_BIGNUM *a, int n)
{
    if (r == NULL || a == NULL || n < 0) {
        return 0;
    }
    return botan_mp_lshift(r->mp, a->mp, n) == 0;
}

int
PGPV_BN_lshift1(PGPV_BIGNUM *r, PGPV_BIGNUM *a)
{
    return PGPV_BN_lshift(r, a, 1);
}

int
PGPV_BN_rshift(PGPV_BIGNUM *r, const PGPV_BIGNUM *a, int n)
{
    if (r == NULL || a == NULL || n < 0) {
        return -1;
    }
    return botan_mp_lshift(r->mp, a->mp, n) == 0;
}

int
PGPV_BN_rshift1(PGPV_BIGNUM *r, PGPV_BIGNUM *a)
{
    return PGPV_BN_rshift(r, a, 1);
}

int
PGPV_BN_add(PGPV_BIGNUM *r, const PGPV_BIGNUM *a, const PGPV_BIGNUM *b)
{
    if (a == NULL || b == NULL || r == NULL) {
        return 0;
    }
    return botan_mp_add(r->mp, a->mp, b->mp) == 0;
}

int
PGPV_BN_sub(PGPV_BIGNUM *r, const PGPV_BIGNUM *a, const PGPV_BIGNUM *b)
{
    if (a == NULL || b == NULL || r == NULL) {
        return 0;
    }
    return botan_mp_sub(r->mp, a->mp, b->mp) == 0;
}

int
PGPV_BN_mul(PGPV_BIGNUM *r, const PGPV_BIGNUM *a, const PGPV_BIGNUM *b)
{
    if (a == NULL || b == NULL || r == NULL) {
        return 0;
    }
    return botan_mp_mul(r->mp, a->mp, b->mp) == 0;
}

int
PGPV_BN_div(PGPV_BIGNUM *dv, PGPV_BIGNUM *rem, const PGPV_BIGNUM *a, const PGPV_BIGNUM *d)
{
    if ((dv == NULL) || (rem == NULL) || (a == NULL) || (d == NULL)) {
        return 0;
    }
    return botan_mp_div(dv->mp, rem->mp, a->mp, d->mp) == 0;
}

void
PGPV_BN_clear(PGPV_BIGNUM *a)
{
    if (a) {
        botan_mp_clear(a->mp);
    }
}

void
PGPV_BN_clear_free(PGPV_BIGNUM *a)
{
    /* Same as BN_free in Botan */
    PGPV_BN_free(a);
}

int
PGPV_BN_num_bytes(const PGPV_BIGNUM *a)
{
    size_t num_bytes;
    if (a == NULL) {
        return -1;
    }

    if (botan_mp_num_bytes(a->mp, &num_bytes) < 0) {
        return -1;
    }
    return num_bytes;
}

int
PGPV_BN_num_bits(const PGPV_BIGNUM *a)
{
    size_t num_bits;
    if (a == NULL) {
        return -1;
    }

    if (botan_mp_num_bits(a->mp, &num_bits) < 0) {
        return -1;
    }
    return num_bits;
}

void
PGPV_BN_set_negative(PGPV_BIGNUM *a, int n)
{
    if (a) {
        /** BN_set_negative sets sign of a BIGNUM
         * \param  b  pointer to the BIGNUM object
         * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
         */

        int a_is_currently_negative = (botan_mp_is_negative(a->mp) == 1);

        if (n == 0) // set a to positive
        {
            // if a is negative, flip it to positive
            if (a_is_currently_negative) {
                botan_mp_flip_sign(a->mp);
            }
        } else {
            // if a is not negative, flip it to negative
            if (!a_is_currently_negative) {
                botan_mp_flip_sign(a->mp);
            }
        }
    }
}

int
PGPV_BN_cmp(PGPV_BIGNUM *a, PGPV_BIGNUM *b)
{
    int cmp_result;

    if (a == NULL || b == NULL) {
        return -1;
    }

    botan_mp_cmp(&cmp_result, a->mp, b->mp);
    return cmp_result;
}

int
PGPV_BN_mod_exp(PGPV_BIGNUM *Y, PGPV_BIGNUM *G, PGPV_BIGNUM *X, PGPV_BIGNUM *P)
{
    if (Y == NULL || G == NULL || X == NULL || P == NULL) {
        return -1;
    }
    return botan_mp_powmod(Y->mp, G->mp, X->mp, P->mp) == 0;
}

PGPV_BIGNUM *
PGPV_BN_mod_inverse(PGPV_BIGNUM *r, PGPV_BIGNUM *a, const PGPV_BIGNUM *n)
{
    if (r == NULL || a == NULL || n == NULL) {
        return NULL;
    }
    return (botan_mp_mod_inverse(r->mp, a->mp, n->mp) == 0) ? r : NULL;
}

int
PGPV_BN_mod_mul(PGPV_BIGNUM *ret, PGPV_BIGNUM *a, PGPV_BIGNUM *b, const PGPV_BIGNUM *m)
{
    if (ret == NULL || a == NULL || b == NULL || m == NULL) {
        return 0;
    }
    return (botan_mp_mod_mul(ret->mp, a->mp, b->mp, m->mp) < 0) ? 0 : 1;
}

char *
PGPV_BN_bn2hex(const PGPV_BIGNUM *a)
{
    return PGPV_BN_bn2radix(a, 16);
}

char *
PGPV_BN_bn2dec(const PGPV_BIGNUM *a)
{
    return PGPV_BN_bn2radix(a, 10);
}

char *
PGPV_BN_bn2radix(const PGPV_BIGNUM *a, unsigned radix)
{
    char * out;
    size_t out_len;
    int    rc;

    /* TODO scale this based on magnitude of a */
    const size_t initial_guess = 512;

    out_len = initial_guess;
    out = malloc(out_len);

    rc = botan_mp_to_str(a->mp, radix, out, &out_len);

    if (rc == 0) {
        return out;
    } else if (out_len != initial_guess) {
        /* need to retry with longer buffer... */
        out = realloc(out, out_len);
        rc = botan_mp_to_str(a->mp, radix, out, &out_len);
        if (rc == 0) {
            return out;
        }
    }

    // error case
    free(out);
    return NULL;
}

int
PGPV_BN_print_fp(FILE *fp, const PGPV_BIGNUM *a)
{
    int    ret;
    size_t num_bytes;
    char * buf;

    if (fp == NULL || a == NULL) {
        return 0;
    }
    if (botan_mp_num_bytes(a->mp, &num_bytes)) {
        return 0;
    }

    if (botan_mp_is_negative(a->mp)) {
        fprintf(fp, "-");
    }

    buf = calloc(num_bytes * 2 + 2, 1);
    botan_mp_to_hex(a->mp, buf);
    ret = fprintf(fp, "%s", buf);
    free(buf);
    return ret;
}

int
PGPV_BN_rand(PGPV_BIGNUM *rnd, int bits, int top, int bottom)
{
    int rc;

    if (rnd == NULL) {
        return 0;
    }

    {
        botan_rng_t rng;
        rc = botan_rng_init(&rng, NULL);
        if (rc == 0) {
            rc = botan_mp_rand_bits(rnd->mp, rng, bits);
            botan_rng_destroy(rng);
        }
    }

    if (rc < 0) {
        return 0;
    }

    if (top == 0) {
        botan_mp_set_bit(rnd->mp, bits);
    } else if (top == 1) {
        botan_mp_set_bit(rnd->mp, bits);
        botan_mp_set_bit(rnd->mp, bits - 1);
    }
    if (bottom) {
        botan_mp_set_bit(rnd->mp, 0);
    }
    return 1;
}

int
PGPV_BN_rand_range(PGPV_BIGNUM *rnd, PGPV_BIGNUM *range)
{
    if (rnd == NULL || range == NULL || PGPV_BN_is_zero(range)) {
        return 0;
    }

    // bigint_rand_range(rnd, zero, range);
    // PGPV_BN_rand(rnd, PGPV_BN_num_bits(range), 1, 0);
    // return modulo(rnd, range, rnd) == MP_OKAY;
    return -1;
}

size_t
PGPV_BN_words_used(const PGPV_BIGNUM *n)
{
    size_t num_bits;

    if (n == NULL) {
        return -1;
    }
    if (botan_mp_num_bits(n->mp, &num_bits) < 0) {
        return -1;
    }

    /*
     * The word size of Botan's BigInt is not exposed through the C API.
     * Assume 32-bit words are in use to match PGPV_BN_ULONG
     */
    return (num_bits / 32) + ((num_bits % 32) ? 1 : 0);
}

PGPV_BN_ULONG
PGPV_BN_get_word(const PGPV_BIGNUM *n)
{
    uint32_t n32;

    if (n == NULL) {
        return -1;
    }

    if (botan_mp_to_uint32(n->mp, &n32) < 0) {
        return -1;
    }

    return n32;
}

int
PGPV_BN_set_word(PGPV_BIGNUM *a, PGPV_BN_ULONG w)
{
    if (a == NULL) {
        return -1;
    }
    /* FIXME: w is treated as signed int here */
    return botan_mp_set_from_int(a->mp, w);
}

int
PGPV_BN_is_even(const PGPV_BIGNUM *n)
{
    if (n == NULL) {
        return -1;
    }
    return botan_mp_is_even(n->mp);
}

int
PGPV_BN_is_odd(const PGPV_BIGNUM *n)
{
    if (n == NULL) {
        return -1;
    }
    return botan_mp_is_odd(n->mp);
}

int
PGPV_BN_is_zero(const PGPV_BIGNUM *n)
{
    if (n == NULL) {
        return -1;
    }
    return botan_mp_is_zero(n->mp);
}

int
PGPV_BN_is_negative(const PGPV_BIGNUM *n)
{
    if (n == NULL) {
        return -1;
    }
    return botan_mp_is_negative(n->mp);
}

int
PGPV_BN_is_prime(const PGPV_BIGNUM *a,
                 int                checks,
                 void (*callback)(int, int, void *),
                 void *cb_arg)
{
    int ret;
    int test_prob;

    if (a == NULL || checks <= 0) {
        return -1;
    }
    USE_ARG(cb_arg);
    USE_ARG(callback);

    test_prob = 4 * checks;

    {
        botan_rng_t rng;
        botan_rng_init(&rng, NULL);
        ret = botan_mp_is_prime(a->mp, rng, test_prob);
        botan_rng_destroy(rng);
    }

    return ret;
}

const PGPV_BIGNUM *
PGPV_BN_value_one(void)
{
    static PGPV_BIGNUM one;

    /* race condition here if multiple threads call BN_value_one */
    if (one.mp == NULL) {
        botan_mp_init(&one.mp);
        botan_mp_set_from_int(one.mp, 1);
    }

    return &one;
}

int
PGPV_BN_hex2bn(PGPV_BIGNUM **a, const char *str)
{
    return PGPV_BN_radix2bn(a, str, 16);
}

int
PGPV_BN_dec2bn(PGPV_BIGNUM **a, const char *str)
{
    return PGPV_BN_radix2bn(a, str, 10);
}

int
PGPV_BN_radix2bn(PGPV_BIGNUM **bn, const char *str, unsigned radix)
{
    return -1;
    if (*bn == NULL) {
        *bn = PGPV_BN_new();
    }

    return botan_mp_set_from_radix_str((*bn)->mp, str, radix);
}

int
PGPV_BN_is_bit_set(const PGPV_BIGNUM *a, int n)
{
    if (a == NULL || n < 0) {
        return 0;
    }
    return botan_mp_get_bit(a->mp, n);
}

/* get greatest common divisor */
int
PGPV_BN_gcd(PGPV_BIGNUM *r, PGPV_BIGNUM *a, PGPV_BIGNUM *b)
{
    return botan_mp_gcd(r->mp, a->mp, b->mp);
}

BIGNUM *
new_BN_take_mp(botan_mp_t mp)
{
    PGPV_BIGNUM *a;
    a = calloc(1, sizeof(*a));
    if (a) {
        a->mp = mp;
    }
    return a;
}

void
destroy_BN_mp(BIGNUM **a)
{
    free(*a);
    *a = NULL;
}

DSA_SIG *
DSA_SIG_new()
{
    DSA_SIG *sig = calloc(1, sizeof(DSA_SIG));
    if (sig) {
        sig->r = BN_new();
        sig->s = BN_new();
    }
    return sig;
}

void
DSA_SIG_free(DSA_SIG *sig)
{
    if (sig) {
        BN_clear_free(sig->r);
        BN_clear_free(sig->s);
        free(sig);
    }
}
