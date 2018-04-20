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

#ifndef RNP_DSA_H_
#define RNP_DSA_H_

#include <stdint.h>
#include "crypto/bn.h"
#include "crypto/rng.h"
#include "crypto/mpi.h"

#define DSA_MIN_P_BITLEN 1024
#define DSA_MAX_P_BITLEN 3072
#define DSA_DEFAULT_P_BITLEN 2048

typedef struct pgp_dsa_key_t {
    pgp_mpi_t p;
    pgp_mpi_t q;
    pgp_mpi_t g;
    pgp_mpi_t y;
    /* secret mpi */
    pgp_mpi_t x;
} pgp_dsa_key_t;

typedef struct pgp_dsa_signature_t {
    pgp_mpi_t r;
    pgp_mpi_t s;
} pgp_dsa_signature_t;

/** Structure to hold one DSA public key params.
 *
 * \see RFC4880 5.5.2
 */
typedef struct {
    bignum_t *p; /* DSA prime p */
    bignum_t *q; /* DSA group order q */
    bignum_t *g; /* DSA group generator g */
    bignum_t *y; /* DSA public key value y (= g^x mod p
                * with x being the secret) */
} pgp_dsa_pubkey_t;

/** pgp_dsa_seckey_t */
typedef struct pgp_dsa_seckey_t {
    bignum_t *x;
} pgp_dsa_seckey_t;

/** Struct to hold params of a DSA signature */
typedef struct pgp_dsa_sig_t {
    bignum_t *r; /* DSA value r */
    bignum_t *s; /* DSA value s */
} pgp_dsa_sig_t;

/*
 * @brief   Performs DSA sign
 *
 * @param   rng       initialized PRNG
 * @param   sign[out] created signature
 * @param   hash      hash to sign
 * @param   hash_len  length of `hash`
 * @param   seckey    private DSA key
 * @param   pubkey    public DSA key
 *
 * @returns RNP_SUCCESS
 *          RNP_ERROR_BAD_PARAMETERS wrong input provided
 *          RNP_ERROR_SIGNING_FAILED internal error
 */
rnp_result_t dsa_sign(rng_t *                 rng,
                      pgp_dsa_sig_t *         sign,
                      const uint8_t *         hash,
                      size_t                  hash_len,
                      const pgp_dsa_seckey_t *seckey,
                      const pgp_dsa_pubkey_t *pubkey);

/*
 * @brief   Performs DSA verification
 *
 * @param   hash      hash to verify
 * @param   hash_len  length of `hash`
 * @param   sign      hash of the sign to be verified
 * @param   pubkey    public DSA key
 *
 * @returns RNP_SUCCESS
 *          RNP_ERROR_BAD_PARAMETERS wrong input provided
 *          RNP_ERROR_GENERIC internal error
 *          RNP_ERROR_SIGNATURE_INVALID signature is invalid
 */
rnp_result_t dsa_verify(const uint8_t *         hash,
                        size_t                  hash_len,
                        const pgp_dsa_sig_t *   sign,
                        const pgp_dsa_pubkey_t *pubkey);

/*
 * @brief   Performs DSA sign
 *
 * @param   rng             hash to verify
 * @param   keylen          length of the key
 * @param   qbits           subgroup size
 * @param   pubkey[out]     public DSA key
 * @param   seckey[out]     private DSA key
 *
 * @returns RNP_SUCCESS
 *          RNP_ERROR_BAD_PARAMETERS wrong input provided
 *          RNP_ERROR_OUT_OF_MEMORY memory allocation failed
 *          RNP_ERROR_GENERIC internal error
 *          RNP_ERROR_SIGNATURE_INVALID signature is invalid
 */
rnp_result_t dsa_keygen(
  rng_t *rng, pgp_dsa_pubkey_t *pubkey, pgp_dsa_seckey_t *seckey, size_t keylen, size_t qbits);

/*
 * @brief   Returns minimally sized hash which will work
 *          with the DSA subgroup.
 *
 * @param   qsize subgroup order
 *
 * @returns  Either ID of the hash algorithm, or PGP_HASH_UNKNOWN
 *           if not found
 */
pgp_hash_alg_t dsa_get_min_hash(size_t qsize);

/*
 * @brief   Helps to determine subgroup size by size of p
 *          In order not to confuse users, we use less complicated
 *          approach than suggested by FIPS-186, which is:
 *            p=1024  => q=160
 *            p<2048  => q=224
 *            p<=3072 => q=256
 *          So we don't generate (2048, 224) pair
 *
 * @return  Size of `q' or 0 in case `psize' is not in <1024,3072> range
 */
size_t dsa_choose_qsize_by_psize(size_t psize);

#endif
