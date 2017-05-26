/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef CRYPTO_HASH_H_
#define CRYPTO_HASH_H_

#include <stdlib.h>
#include <stdint.h>

/** Hashing Algorithm Numbers.
 * OpenPGP assigns a unique Algorithm Number to each algorithm that is
 * part of OpenPGP.
 *
 * This lists algorithm numbers for hash algorithms.
 *
 * \see RFC4880 9.4
 */
typedef enum {
	PGP_HASH_UNKNOWN = -1,	/* used to indicate errors */
	PGP_HASH_MD5 = 1,	/* MD5 */
	PGP_HASH_SHA1 = 2,	/* SHA-1 */
	PGP_HASH_RIPEMD = 3,	/* RIPEMD160 */

	PGP_HASH_SHA256 = 8,	/* SHA256 */
	PGP_HASH_SHA384 = 9,	/* SHA384 */
	PGP_HASH_SHA512 = 10,	/* SHA512 */
	PGP_HASH_SHA224 = 11,	/* SHA224 */

	PGP_HASH_SM3    = 105	/* SM3 - temporary allocation in private range */
} pgp_hash_alg_t;

#define	PGP_DEFAULT_HASH_ALGORITHM	PGP_HASH_SHA256

/** pgp_hash_t */
typedef struct pgp_hash_t {
        void                    *handle;        /* hash object */
        size_t                   output_len;
	pgp_hash_alg_t		 alg;		/* algorithm */
} pgp_hash_t;

int pgp_hash_create(pgp_hash_t* hash, pgp_hash_alg_t alg);
void pgp_hash_add(pgp_hash_t* hash, const uint8_t *input, size_t len);
void pgp_hash_add_int(pgp_hash_t* hash, unsigned n, size_t bytes);
size_t pgp_hash_finish(pgp_hash_t* hash, uint8_t *output);

size_t pgp_hash_output_length(pgp_hash_t* hash);

const char* pgp_hash_name(const pgp_hash_t* hash);

#if 0
int pgp_hash_any(pgp_hash_t *, pgp_hash_alg_t);
void pgp_hash_md5(pgp_hash_t *);
void pgp_hash_sha1(pgp_hash_t *);
void pgp_hash_sha256(pgp_hash_t *);
void pgp_hash_sha512(pgp_hash_t *);
void pgp_hash_sha384(pgp_hash_t *);
void pgp_hash_sha224(pgp_hash_t *);
void pgp_hash_sm3(pgp_hash_t *);
#endif

pgp_hash_alg_t pgp_str_to_hash_alg(const char *);
unsigned pgp_hash_size(pgp_hash_alg_t alg);

#endif
