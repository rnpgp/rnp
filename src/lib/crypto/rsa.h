/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RNP_RSA_H_
#define RNP_RSA_H_

#include <rnp/rnp_sdk.h>
#include <repgp/repgp_def.h>
#include "crypto/bn.h"
#include "crypto/rng.h"
#include "crypto/mpi.h"

typedef struct pgp_seckey_t     pgp_seckey_t;
typedef struct pgp_rsa_seckey_t pgp_rsa_seckey_t;

typedef struct pgp_rsa_key_t {
    pgp_mpi_t n;
    pgp_mpi_t e;
    /* secret mpis */
    pgp_mpi_t d;
    pgp_mpi_t p;
    pgp_mpi_t q;
    pgp_mpi_t u;
} pgp_rsa_key_t;

typedef struct pgp_rsa_signature_t {
    pgp_mpi_t s;
} pgp_rsa_signature_t;

typedef struct pgp_rsa_encrypted_t {
    pgp_mpi_t m;
} pgp_rsa_encrypted_t;

/** Structure to hold an RSA public key.
 *
 * \see RFC4880 5.5.2
 */
typedef struct {
    bignum_t *n; /* RSA public modulus n */
    bignum_t *e; /* RSA public encryption exponent e */
} pgp_rsa_pubkey_t;

/** Struct to hold params of an RSA signature */
typedef struct pgp_rsa_sig_t {
    bignum_t *sig; /* the signature value (m^d % n) */
} pgp_rsa_sig_t;

/** Structure to hold data for one RSA secret key
 */
typedef struct pgp_rsa_seckey_t {
    bignum_t *d;
    bignum_t *p;
    bignum_t *q;
    bignum_t *u;
} pgp_rsa_seckey_t;

/*
 * RSA encrypt/decrypt
 */

int pgp_genkey_rsa(rng_t *rng, pgp_seckey_t *seckey, size_t numbits);

int pgp_rsa_encrypt_pkcs1(rng_t *                 rng,
                          uint8_t *               out,
                          size_t                  out_len,
                          const uint8_t *         key,
                          size_t                  key_len,
                          const pgp_rsa_pubkey_t *pubkey);

int pgp_rsa_decrypt_pkcs1(rng_t *                 rng,
                          uint8_t *               out,
                          size_t                  out_len,
                          const uint8_t *         key,
                          size_t                  key_len,
                          const pgp_rsa_seckey_t *privkey,
                          const pgp_rsa_pubkey_t *pubkey);

/*
 * RSA signature generation and verification
 */

/*
 * Returns 1 for valid 0 for invalid/error
 */
bool pgp_rsa_pkcs1_verify_hash(rng_t *                 rng,
                               const uint8_t *         sig_buf,
                               size_t                  sig_buf_size,
                               pgp_hash_alg_t          hash_alg,
                               const uint8_t *         hash,
                               size_t                  hash_len,
                               const pgp_rsa_pubkey_t *pubkey);

/*
 * Returns # bytes written to sig_buf on success, 0 on error
 */
int pgp_rsa_pkcs1_sign_hash(rng_t *        rng,
                            uint8_t *      sig_buf,
                            size_t         sig_buf_size,
                            pgp_hash_alg_t hash_alg,
                            const uint8_t *hash,
                            size_t         hash_len,
                            const pgp_rsa_seckey_t *,
                            const pgp_rsa_pubkey_t *);

#endif
