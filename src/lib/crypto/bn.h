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
#ifndef FAUXBN_H_
#define FAUXBN_H_ 20100108

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>

typedef struct botan_mp_struct *botan_mp_t;
typedef struct pgp_hash_t       pgp_hash_t;
typedef uint32_t                PGPV_BN_ULONG;

/*
 * PGPV_BIGNUM struct
 */
typedef struct PGPV_BIGNUM_st {
    botan_mp_t mp;
} PGPV_BIGNUM;

#define BIGNUM PGPV_BIGNUM

#define MP_LT -1
#define MP_EQ 0
#define MP_GT 1

#define MP_ZPOS 0
#define MP_NEG 1

#define MP_OKAY 0
#define MP_MEM -2
#define MP_VAL -3
#define MP_RANGE MP_VAL

/*********************************/

PGPV_BIGNUM *bn_new(void);
PGPV_BIGNUM *bn_dup(const PGPV_BIGNUM * /*a*/);
int          bn_copy(PGPV_BIGNUM * /*b*/, const PGPV_BIGNUM * /*a*/);
char *bn_bn2hex(const PGPV_BIGNUM *a);
void bn_init(PGPV_BIGNUM * /*a*/);
void bn_free(PGPV_BIGNUM * /*a*/);
void bn_clear(PGPV_BIGNUM * /*a*/);
void bn_clear_free(PGPV_BIGNUM * /*a*/);

int bn_cmp(PGPV_BIGNUM * /*a*/, PGPV_BIGNUM * /*b*/);

PGPV_BIGNUM *bn_bin2bn(const uint8_t * /*buf*/, int /*size*/, PGPV_BIGNUM * /*bn*/);
int          bn_bn2bin(const PGPV_BIGNUM * /*a*/, unsigned char * /*b*/);
int          bn_print_fp(FILE * /*fp*/, const PGPV_BIGNUM * /*a*/);
int bn_is_zero(const PGPV_BIGNUM *n);
int bn_set_word(PGPV_BIGNUM *a, PGPV_BN_ULONG w);
int bn_mod_exp(PGPV_BIGNUM *Y, PGPV_BIGNUM *G, PGPV_BIGNUM *X, PGPV_BIGNUM *P);

/*
 * @param a Initialized PGPV_BIGNUM structure
 * @param bits [out] bitlength of a
 *
 * @returns true on success, otherwise false
 */
bool bn_num_bits(const PGPV_BIGNUM *a, size_t *bits);
/*
 * @param a Initialized PGPV_BIGNUM structure
 * @param bytes [out] byte length of a
 *
 * @returns true on success, otherwise false
 */
bool bn_num_bytes(const PGPV_BIGNUM *a, size_t *bytes);

/*
 * @brief Produces hash of any size bignum.
 *
 * @param bignum: Bignum to be hashed
 * @param hash: Initialized hash context
 *
 * @returns size of hashed data, or 0 on error
 */
size_t bn_hash(const PGPV_BIGNUM *bignum, pgp_hash_t *hash);

#endif
