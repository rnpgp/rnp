/*
 * Copyright (c) 2024, [MTG AG](https://www.mtg.de).
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
#include "config.h"
#include "kem_combiner.hpp"
#if defined(ENABLE_PQC_DBG_LOG)
#include "crypto/mem.h"
#endif
namespace rnp {

std::vector<uint8_t>
PqcKemCombiner::compute(const std::vector<uint8_t> &mlkem_key_share,
                        const std::vector<uint8_t> &ecc_key_share,
                        const std::vector<uint8_t> &ecc_ciphertext,
                        const std::vector<uint8_t> &ecc_pub_key,
                        const std::vector<uint8_t> &mlkem_ciphertext,
                        const std::vector<uint8_t> &mlkem_pub_key,
                        const pgp_pubkey_alg_t      alg_id)
{
    std::vector<uint8_t> out;
#if defined(ENABLE_PQC_DBG_LOG)
    RNP_LOG_NO_POS_INFO("Key Combiner Input: ");
    RNP_LOG_U8VEC(" - mlkemKeyShare: %s", mlkem_key_share);
    RNP_LOG_U8VEC(" - eccKeyShare: %s", ecc_key_share);
    RNP_LOG_U8VEC(" - eccCipherText: %s", ecc_ciphertext);
    RNP_LOG_U8VEC(" - eccPublicKey: %s", ecc_pub_key);
    RNP_LOG_U8VEC(" - mlkemCipherText: %s", mlkem_ciphertext);
    RNP_LOG_U8VEC(" - mlkemPublicKey: %s", mlkem_pub_key);
    RNP_LOG_NO_POS_INFO(" - algID: %d", (uint8_t) alg_id);
    RNP_LOG_NO_POS_INFO("Key Combiner Constants: ");
    RNP_LOG_U8VEC(" - DomSep %s", domSeparation());
#endif

    pgp_hash_alg_t hash_alg = PGP_HASH_SHA3_256;
    auto           hash = rnp::Hash::create(hash_alg);
    hash->add(mlkem_key_share);
    hash->add(ecc_key_share);
    hash->add(ecc_ciphertext);
    hash->add(ecc_pub_key);
    hash->add(mlkem_ciphertext);
    hash->add(mlkem_pub_key);
    hash->add(&alg_id, 1);
    hash->add(domSeparation());

    out.resize(rnp::Hash::size(hash_alg));
    hash->finish(out.data());
#if defined(ENABLE_PQC_DBG_LOG)
    RNP_LOG_U8VEC("PQC KEM Combiner SHA-3 Output: %s", out);
#endif

    return out;
}
} // namespace rnp
