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
#include <botan/ffi.h>

#include "hash.h"
#include "crypto.h"
#include "crypto/bn.h"

#ifndef USE_ARG
#define USE_ARG(x) /*LINTED*/ (void) &x
#endif

/**************************************************************************/

/* OpenSSL bignum_t emulation layer */

/* essentiually, these are just wrappers around the botan functions */
/* usually the order of args changes */
/* the bignum_t API tends to have more const poisoning */
/* these wrappers also check the arguments passed for sanity */

bignum_t *
bn_bin2bn(const uint8_t *data, int len, bignum_t *ret)
{
    if (data == NULL) {
        return bn_new();
    }
    if (ret == NULL) {
        ret = bn_new();
    }

    if (ret == NULL) {
        return NULL;
    }

    return (botan_mp_from_bin(ret->mp, data, len) == 0) ? ret : NULL;
}

/* store in unsigned [big endian] format */
int
bn_bn2bin(const bignum_t *a, unsigned char *b)
{
    if (a == NULL || b == NULL) {
        return -1;
    }

    return botan_mp_to_bin(a->mp, b);
}

bignum_t *
bn_new(void)
{
    bignum_t *a;

    a = calloc(1, sizeof(*a));
    if (a == NULL) {
        return NULL;
    }
    botan_mp_init(&a->mp);
    return a;
}

void
bn_free(bignum_t *a)
{
    if (a != NULL) {
        botan_mp_destroy(a->mp);
        free(a);
    }
}

/* copy, b = a */
int
bn_copy(bignum_t *to, const bignum_t *from)
{
    if (from == NULL || to == NULL) {
        return -1;
    }
    return botan_mp_set_from_mp(to->mp, from->mp);
}

bignum_t *
bn_dup(const bignum_t *a)
{
    bignum_t *ret;

    if (a == NULL) {
        return NULL;
    }
    if ((ret = bn_new()) != NULL) {
        bn_copy(ret, a);
    }
    return ret;
}

void
bn_clear(bignum_t *a)
{
    if (a) {
        botan_mp_clear(a->mp);
    }
}

void
bn_clear_free(bignum_t *a)
{
    /* Same as BN_free in Botan */
    bn_free(a);
}

bool
bn_num_bits(const bignum_t *a, size_t *bits)
{
    if (!a || botan_mp_num_bits(a->mp, bits)) {
        return false;
    }
    return true;
}

bool
bn_num_bytes(const bignum_t *a, size_t *bits)
{
    if (bn_num_bits(a, bits)) {
        *bits = BITS_TO_BYTES(*bits);
        return true;
    }
    return false;
}

int
bn_cmp(bignum_t *a, bignum_t *b)
{
    int cmp_result;

    if (a == NULL || b == NULL) {
        return -1;
    }

    botan_mp_cmp(&cmp_result, a->mp, b->mp);
    return cmp_result;
}

int
bn_print_fp(FILE *fp, const bignum_t *a)
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

char *
bn_bn2hex(const bignum_t *a)
{
    char *       out;
    size_t       out_len;
    int          rc;
    const size_t radix = 16;

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

/* hash a bignum_t, possibly padded - first length, then string itself */
size_t
bn_hash(const bignum_t *bignum_t, pgp_hash_t *hash)
{
    uint8_t *bn;
    size_t   len;
    size_t   padbyte;

    if (!bn_num_bytes(bignum_t, &len) || (len > UINT32_MAX)) {
        RNP_LOG("Wrong input");
        return 0;
    }

    if (len == 0) {
        return pgp_hash_uint32(hash, 0) ? 4 : 0;
    }

    if ((bn = calloc(1, len + 1)) == NULL) {
        RNP_LOG("bad bn alloc");
        return 0;
    }

    bn_bn2bin(bignum_t, bn + 1);
    bn[0] = 0x0;
    padbyte = !!(bn[1] & 0x80);
    len += padbyte;

    bool ret = pgp_hash_uint32(hash, len);
    ret &= !pgp_hash_add(hash, bn + 1 - padbyte, len);

    free(bn);
    return ret ? (4 + len + padbyte) : 0;
}

int
bn_is_zero(const bignum_t *n)
{
    if (n == NULL) {
        return -1;
    }
    return botan_mp_is_zero(n->mp);
}

int
bn_set_word(bignum_t *a, PGPV_BN_ULONG w)
{
    if (a == NULL) {
        return -1;
    }
    /* FIXME: w is treated as signed int here */
    return botan_mp_set_from_int(a->mp, w);
}

int
bn_mod_exp(bignum_t *Y, bignum_t *G, bignum_t *X, bignum_t *P)
{
    if (Y == NULL || G == NULL || X == NULL || P == NULL) {
        return -1;
    }
    return botan_mp_powmod(Y->mp, G->mp, X->mp, P->mp) == 0;
}
