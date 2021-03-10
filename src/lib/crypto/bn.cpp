/*
 * Copyright (c) 2017-2021 Ribose Inc.
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

#include "bn.h"
#include <botan/ffi.h>
#include <stdlib.h>
#include <assert.h>
#include "utils.h"

/* essentiually, these are just wrappers around the botan functions */
/* usually the order of args changes */
/* the bignum_t API tends to have more const poisoning */
/* these wrappers also check the arguments passed for sanity */

bignum_t *
bn_bin2bn(const uint8_t *data, int len, bignum_t *ret)
{
    assert(data);
    if (!data) {
        RNP_LOG("NULL data.");
        return NULL;
    }
    if (!ret) {
        ret = bn_new();
    }
    if (!ret) {
        return NULL;
    }
    return !botan_mp_from_bin(ret->mp, data, len) ? ret : NULL;
}

/* store in unsigned [big endian] format */
int
bn_bn2bin(const bignum_t *a, unsigned char *b)
{
    if (!a || !b) {
        return -1;
    }
    return botan_mp_to_bin(a->mp, b);
}

bignum_t *
bn_new(void)
{
    bignum_t *a = (bignum_t *) calloc(1, sizeof(*a));
    if (!a) {
        return NULL;
    }
    botan_mp_init(&a->mp);
    return a;
}

void
bn_free(bignum_t *a)
{
    if (a) {
        botan_mp_destroy(a->mp);
        free(a);
    }
}

bool
bn_num_bits(const bignum_t *a, size_t *bits)
{
    return a && !botan_mp_num_bits(a->mp, bits);
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
