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
#include "eddsa.h"
#include "utils.h"

rnp_result_t
eddsa_validate_key(rng_t *rng, const pgp_ec_key_t *key, bool secret)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
eddsa_generate(rng_t *rng, pgp_ec_key_t *key, size_t numbits)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
eddsa_verify(const pgp_ec_signature_t *sig,
             const uint8_t *           hash,
             size_t                    hash_len,
             const pgp_ec_key_t *      key)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
eddsa_sign(rng_t *             rng,
           pgp_ec_signature_t *sig,
           const uint8_t *     hash,
           size_t              hash_len,
           const pgp_ec_key_t *key)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}
