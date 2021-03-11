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
#include "elgamal.h"
#include "utils.h"

// Max supported key byte size
#define ELGAMAL_MAX_P_BYTELEN BITS_TO_BYTES(PGP_MPINT_BITS)

rnp_result_t
elgamal_validate_key(rng_t *rng, const pgp_eg_key_t *key, bool secret)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
elgamal_encrypt_pkcs1(rng_t *             rng,
                      pgp_eg_encrypted_t *out,
                      const uint8_t *     in,
                      size_t              in_len,
                      const pgp_eg_key_t *key)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
elgamal_decrypt_pkcs1(rng_t *                   rng,
                      uint8_t *                 out,
                      size_t *                  out_len,
                      const pgp_eg_encrypted_t *in,
                      const pgp_eg_key_t *      key)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
elgamal_generate(rng_t *rng, pgp_eg_key_t *key, size_t keybits)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}
