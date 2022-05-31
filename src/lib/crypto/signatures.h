/*
 * Copyright (c) 2018-2022, [Ribose Inc](https://www.ribose.com).
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

#ifndef RNP_SIGNATURES_H_
#define RNP_SIGNATURES_H_

#include "crypto/hash.hpp"

/**
 * @brief Initialize a signature computation.
 * @param key the key that will be used to sign or verify
 * @param hash_alg the digest algo to be used
 * @param hash digest object that will be initialized
 */
std::unique_ptr<rnp::Hash> signature_init(const pgp_key_material_t &key,
                                          pgp_hash_alg_t            hash_alg);

/**
 * @brief Calculate signature with pre-populated hash
 * @param sig signature to calculate
 * @param seckey signing secret key material
 * @param hash pre-populated with signed data hash context. It is finalized and destroyed
 *             during the execution. Signature fields and trailer are hashed in this function.
 * @param rng random number generator
 */
void signature_calculate(pgp_signature_t &     sig,
                         pgp_key_material_t &  seckey,
                         rnp::Hash &           hash,
                         rnp::SecurityContext &ctx);

/**
 * @brief Validate a signature with pre-populated hash. This method just checks correspondence
 *        between the hash and signature material. Expiration time and other fields are not
 *        checked for validity.
 * @param sig signature to validate
 * @param key public key material of the verifying key
 * @param hash pre-populated with signed data hash context. It is finalized
 *             during the execution. Signature fields and trailer are hashed in this function.
 * @return RNP_SUCCESS if signature was successfully validated or error code otherwise.
 */
rnp_result_t signature_validate(const pgp_signature_t &     sig,
                                const pgp_key_material_t &  key,
                                rnp::Hash &                 hash,
                                const rnp::SecurityContext &ctx);

#endif
