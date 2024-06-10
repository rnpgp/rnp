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

#include "config.h"
#include "kem_combiner.hpp"

#if defined(ENABLE_PQC_DBG_LOG)
#include "crypto/mem.h"
#endif

namespace rnp {
/*
    //   Input:
    //   algID     - the algorithm ID encoded as octet

    fixedInfo = algID || domSeparation
*/
std::vector<uint8_t>
PqcKemCombiner::fixedInfo(pgp_pubkey_alg_t alg_id)
{
    std::vector<uint8_t> result;
    result.push_back(static_cast<uint8_t>(alg_id));
    std::vector<uint8_t> dom_sep = domSeparation();
    result.insert(result.end(), dom_sep.begin(), dom_sep.end());
    return result;
}

void
PqcKemCombiner::hashEncData(std::unique_ptr<rnp::Hash> &hash,
                            const std::vector<uint8_t> &ecc_pub_key,
                            const std::vector<uint8_t> &ecc_key_share,
                            const std::vector<uint8_t> &ecc_ciphertext,
                            const std::vector<uint8_t> &mlkem_pub_key,
                            const std::vector<uint8_t> &mlkem_key_share,
                            const std::vector<uint8_t> &mlkem_ciphertext,
                            pgp_pubkey_alg_t            alg_id)
{
    /*
        ecdhData = ecdhKeyShare || ecdhCipherText || ecdhPublicKey
        mlkemData = mlkemKeyShare || mlkemCipherText || mlkemPublicKey
        return counter || eccKemData || kyberKemData || fixedInfo
    */
#if defined(ENABLE_PQC_DBG_LOG)
    RNP_LOG_NO_POS_INFO("Key Combiner encData: ");
    RNP_LOG_U8VEC(" - counter: %s", counter());
    RNP_LOG_U8VEC(" - eccPublicKey: %s", ecc_pub_key);
    RNP_LOG_U8VEC(" - eccKeyShare: %s", ecc_key_share);
    RNP_LOG_U8VEC(" - eccCipherText: %s", ecc_ciphertext);
    RNP_LOG_U8VEC(" - mlkemPublicKey: %s", mlkem_pub_key);
    RNP_LOG_U8VEC(" - mlkemKeyShare: %s", mlkem_key_share);
    RNP_LOG_U8VEC(" - mlkemCipherText: %s", mlkem_ciphertext);
    RNP_LOG_U8VEC(" - fixedInfo: %s", fixedInfo(alg_id));
#endif

    hash->add(counter());
    hash->add(ecc_key_share);
    hash->add(ecc_ciphertext);
    hash->add(ecc_pub_key);
    hash->add(mlkem_key_share);
    hash->add(mlkem_ciphertext);
    hash->add(mlkem_pub_key);
    hash->add(fixedInfo(alg_id));
}

void
PqcKemCombiner::compute(const std::vector<uint8_t> &ecc_pub_key,
                        const std::vector<uint8_t> &ecc_key_share,
                        const std::vector<uint8_t> &ecc_ciphertext,
                        const std::vector<uint8_t> &mlkem_pub_key,
                        const std::vector<uint8_t> &mlkem_key_share,
                        const std::vector<uint8_t> &mlkem_ciphertext,
                        const pgp_pubkey_alg_t      alg_id,
                        std::vector<uint8_t> &      out)
{
    pgp_hash_alg_t hash_alg = PGP_HASH_SHA3_256;
    auto           hash = rnp::Hash::create(hash_alg);
    hashEncData(hash,
                ecc_pub_key,
                ecc_key_share,
                ecc_ciphertext,
                mlkem_pub_key,
                mlkem_key_share,
                mlkem_ciphertext,
                alg_id);
    out.resize(rnp::Hash::size(hash_alg));
    hash->finish(out.data());

#if defined(ENABLE_PQC_DBG_LOG)
    RNP_LOG_U8VEC("PQC KEM Combiner SHA-3 Output: %s", out);
#endif
}

} // namespace rnp
