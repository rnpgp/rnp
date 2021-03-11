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

#include <string.h>
#include "ecdh.h"
#include "hash.h"
#include "symmetric.h"
#include "types.h"
#include "utils.h"

bool
ecdh_set_params(pgp_ec_key_t *key, pgp_curve_t curve_id)
{
    return false;
}

rnp_result_t
ecdh_validate_key(rng_t *rng, const pgp_ec_key_t *key, bool secret)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
ecdh_encrypt_pkcs5(rng_t *                  rng,
                   pgp_ecdh_encrypted_t *   out,
                   const uint8_t *const     in,
                   size_t                   in_len,
                   const pgp_ec_key_t *     key,
                   const pgp_fingerprint_t &fingerprint)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
ecdh_decrypt_pkcs5(uint8_t *                   out,
                   size_t *                    out_len,
                   const pgp_ecdh_encrypted_t *in,
                   const pgp_ec_key_t *        key,
                   const pgp_fingerprint_t &   fingerprint)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}
