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
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RNP_DSA_H_
#define RNP_DSA_H_

#include <stdint.h>
#include "crypto/bn.h"
#include "crypto/rng.h"

#define DSA_DEFAULT_P_BITLEN 2048
#define DSA_DEFAULT_Q_BITLEN 256

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
 *          RNP_ERROR_GENERIC internal error
 *          RNP_ERROR_SIGNATURE_INVALID signature is invalid
 */
rnp_result_t dsa_keygen(
  rng_t *rng, pgp_dsa_pubkey_t *pubkey, pgp_dsa_seckey_t *seckey, size_t keylen, size_t qbits);

#endif
