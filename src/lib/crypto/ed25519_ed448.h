/*
 * Copyright (c) 2023, [MTG AG](https://www.mtg.de).
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

#ifndef ED25519_H_
#define ED25519_H_

#include "config.h"
#include <rnp/rnp_def.h>
#include <vector>
#include <repgp/repgp_def.h>
#include "crypto/rng.h"
#include "crypto/ec.h"

/* implements Ed25519 and Ed448 with native format (V6 and PQC) */

rnp_result_t generate_ed25519_native(rnp::RNG *            rng,
                                     std::vector<uint8_t> &privkey,
                                     std::vector<uint8_t> &pubkey);

rnp_result_t ed25519_sign_native(rnp::RNG *                  rng,
                                 std::vector<uint8_t> &      sig_out,
                                 const std::vector<uint8_t> &key,
                                 const uint8_t *             hash,
                                 size_t                      hash_len);

rnp_result_t ed25519_verify_native(const std::vector<uint8_t> &sig,
                                   const std::vector<uint8_t> &key,
                                   const uint8_t *             hash,
                                   size_t                      hash_len);

rnp_result_t ed25519_validate_key_native(rnp::RNG *               rng,
                                         const pgp_ed25519_key_t *key,
                                         bool                     secret);

rnp_result_t generate_ed448_native(rnp::RNG *            rng,
                                   std::vector<uint8_t> &privkey,
                                   std::vector<uint8_t> &pubkey);
rnp_result_t ed448_sign_native(rnp::RNG *                  rng,
                               std::vector<uint8_t> &      sig_out,
                               const std::vector<uint8_t> &key,
                               const uint8_t *             hash,
                               size_t                      hash_len);
rnp_result_t ed448_verify_native(const std::vector<uint8_t> &sig,
                                 const std::vector<uint8_t> &key,
                                 const uint8_t *             hash,
                                 size_t                      hash_len);
rnp_result_t ed448_validate_key_native(rnp::RNG *rng, const pgp_ed448_key_t *key, bool secret);
#endif
