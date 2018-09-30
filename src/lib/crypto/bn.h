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

/*
 * bignum_t struct
 */
typedef struct bignum_t_st {
    botan_mp_t mp;
} bignum_t;

#define BN_HANDLE(x) ((x).mp)
#define BN_HANDLE_PTR(x) ((x)->mp)

/*********************************/

bignum_t *bn_new(void);

/*
 * @brief Initialize `a' with pointer to `b'. `a' is freed
 *        if it was allocated before. After function returns
 *        `a' and `b' point to same destination.
 *
 * @param a pointer to bn to be initialized
 * @param b pointer to be used as initializer
 *
 */
void bn_init(bignum_t **a, bignum_t *b);
void bn_free(bignum_t * /*a*/);
void bn_clear(bignum_t * /*a*/);
void bn_clear_free(bignum_t * /*a*/);

bignum_t *bn_bin2bn(const uint8_t * /*buf*/, int /*size*/, bignum_t * /*bn*/);
int       bn_bn2bin(const bignum_t * /*a*/, unsigned char * /*b*/);
int       bn_print_fp(FILE * /*fp*/, const bignum_t * /*a*/);
int       bn_set_word(bignum_t *a, uint32_t w);
int       bn_mod_exp(bignum_t *Y, bignum_t *G, bignum_t *X, bignum_t *P);

/*
 * @param a Initialized bignum_t structure
 * @param bits [out] bitlength of a
 *
 * @returns true on success, otherwise false
 */
bool bn_num_bits(const bignum_t *a, size_t *bits);
/*
 * @param a Initialized bignum_t structure
 * @param bytes [out] byte length of a
 *
 * @returns true on success, otherwise false
 */
bool bn_num_bytes(const bignum_t *a, size_t *bytes);

#endif
