/*
 * Copyright (c) 2021, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>
#include <rnp/rnp_def.h>
#include "dsa.h"
#include "hash.h"
#include "utils.h"

#define DSA_MAX_Q_BITLEN 256

rnp_result_t
dsa_validate_key(rng_t *rng, const pgp_dsa_key_t *key, bool secret)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
dsa_sign(rng_t *              rng,
         pgp_dsa_signature_t *sig,
         const uint8_t *      hash,
         size_t               hash_len,
         const pgp_dsa_key_t *key)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
dsa_verify(const pgp_dsa_signature_t *sig,
           const uint8_t *            hash,
           size_t                     hash_len,
           const pgp_dsa_key_t *      key)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
dsa_generate(rng_t *rng, pgp_dsa_key_t *key, size_t keylen, size_t qbits)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

pgp_hash_alg_t
dsa_get_min_hash(size_t qsize)
{
    /*
     * I'm using _broken_ SHA1 here only because
     * some old implementations may not understand keys created
     * with other hashes. If you're sure we don't have to support
     * such implementations, please be my guest and remove it.
     */
    return (qsize < 160) ? PGP_HASH_UNKNOWN :
                           (qsize == 160) ?
                           PGP_HASH_SHA1 :
                           (qsize <= 224) ?
                           PGP_HASH_SHA224 :
                           (qsize <= 256) ? PGP_HASH_SHA256 :
                                            (qsize <= 384) ? PGP_HASH_SHA384 :
                                                             (qsize <= 512) ? PGP_HASH_SHA512
                                                                              /*(qsize>512)*/ :
                                                                              PGP_HASH_UNKNOWN;
}

size_t
dsa_choose_qsize_by_psize(size_t psize)
{
    return (psize == 1024) ? 160 :
                             (psize <= 2047) ? 224 : (psize <= 3072) ? DSA_MAX_Q_BITLEN : 0;
}
