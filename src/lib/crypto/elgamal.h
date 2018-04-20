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

#ifndef RNP_ELG_H_
#define RNP_ELG_H_

#include <stdint.h>
#include "crypto/bn.h"
#include "crypto/rng.h"
#include "crypto/mpi.h"

typedef struct pgp_eg_key_t {
    pgp_mpi_t p;
    pgp_mpi_t g;
    pgp_mpi_t y;
    /* secret mpi */
    pgp_mpi_t x;
} pgp_eg_key_t;

typedef struct pgp_eg_signature_t {
    /* This is kept only for packet reading. Implementation MUST
     * not create elgamal signatures */
    pgp_mpi_t r;
    pgp_mpi_t s;
} pgp_eg_signature_t;

typedef struct pgp_eg_encrypted_t {
    pgp_mpi_t g;
    pgp_mpi_t m;
} pgp_eg_encrypted_t;

/** Structure to hold an ElGamal public key params.
 *
 * \see RFC4880 5.5.2
 */
typedef struct {
    bignum_t *p; /* ElGamal prime p */
    bignum_t *g; /* ElGamal group generator g */
    bignum_t *y; /* ElGamal public key value y (= g^x mod p
                * with x being the secret) */
} pgp_elgamal_pubkey_t;

/** pgp_elgamal_seckey_t */
typedef struct pgp_elgamal_seckey_t {
    bignum_t *x;
} pgp_elgamal_seckey_t;

/** Struct to hold params of a Elgamal signature */
typedef struct pgp_elgamal_sig_t {
    bignum_t *r;
    bignum_t *s;
} pgp_elgamal_sig_t;

/*
 * Performs ElGamal encryption
 * Result of an encryption is composed of two parts - g2k and encm
 *
 * @param rng initialized rng_t
 * @param g2k [out] buffer stores first part of encryption (g^k % p)
 * @param encm [out] buffer stores second part of encryption (y^k * in % p)
 * @param in plaintext to be encrypted
 * @param pubkey public key to be used for encryption
 *
 * @pre g2k, encm, in: must be valid pointer to correctly initialized buf_t
 * @pre in: len can't be bigger than byte size of `p'
 * @pre g2k, encm: must be capable of storing encrypted data. Usually it is
 *      equal to byte size of `p' (or few bytes less).
 *
 * @return RNP_SUCCESS
 *         RNP_ERROR_BAD_PARAMETERS wrong input provided
 */
rnp_result_t elgamal_encrypt_pkcs1(
    rng_t* rng,
    buf_t* g2k,
    buf_t* encm,
    const buf_t* in,
    const pgp_elgamal_pubkey_t *pubkey);

/*
 * Performs ElGamal decryption
 *
 * @param rng initialized rng_t
 * @param out [out] decrypted plaintext
 * @param g2k buffer stores first part of encryption (g^k % p)
 * @param encm buffer stores second part of encryption (y^k * in % p)
 * @param seckey private part of a key used for decryption
 * @param pubkey public domain parameters (p,g) used for decryption
 *
 * @pre out, g2k, encm: must be valid pointer to correctly initialized buffer
 * @pre out: length must be long enough to store decrypted data. Max size of
 *           decrypted data is equal to bytes size of `p'
 *
 * @return RNP_SUCCESS
 *         RNP_ERROR_BAD_PARAMETERS wrong input provided
 */
rnp_result_t elgamal_decrypt_pkcs1(
    rng_t *                     rng,
    buf_t *                     out,
    const buf_t *               g2k,
    const buf_t *               encm,
    const pgp_elgamal_seckey_t *seckey,
    const pgp_elgamal_pubkey_t *pubkey);

/*
 * Generates ElGamal key
 *
 * @param rng pointer to PRNG
 * @param pubkey[out] generated public key
 * @param seckey[out] generated private key
 * @param keylen key bitlen
 *
 * @pre `keylen' > 1024
 * @pre memory for elgamal key initialized in `seckey' and `'pubkey'
 *
 * @returns RNP_ERROR_BAD_PARAMETERS wrong parameters provided
 *          RNP_ERROR_GENERIC internal error
 *          RNP_SUCCESS key generated and coppied to `seckey'
 */
rnp_result_t elgamal_keygen(
    rng_t *               rng,
    pgp_elgamal_pubkey_t *pubkey,
    pgp_elgamal_seckey_t *seckey,
    size_t                keylen);
#endif
