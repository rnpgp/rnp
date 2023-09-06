/*
 * Copyright (c) 2022 MTG AG
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


#include "config.h"
#include "kmac.hpp"

#if defined(CRYPTO_BACKEND_BOTAN)
#include "kmac_botan.hpp"
#endif
#if defined(CRYPTO_BACKEND_OPENSSL)
#error KMAC256 not implemented for OpenSSL Backend
#endif

namespace rnp {
std::unique_ptr<KMAC256>
KMAC256::create()
{
#if defined(CRYPTO_BACKEND_OPENSSL)
#error KMAC256 not implemented for OpenSSL
    // return Hash_OpenSSL::create();
#elif defined(CRYPTO_BACKEND_BOTAN)
    return KMAC256_Botan::create();
#else
#error "Crypto backend not specified"
#endif
}

std::vector<uint8_t>
KMAC256::domSeparation() const
{
    return domSeparation_;
}

std::vector<uint8_t>
KMAC256::customizationString() const
{
    return customizationString_;
}

std::vector<uint8_t>
KMAC256::counter() const
{
    return counter_;
}

/* 
    //   Input:
    //   algID - the algorithm ID encoded as octet
    //   publicKey - the recipient's encryption sub-key packet
    //               serialized as octet string

    fixedInfo = algID || SHA3-256(publicKey)
*/
std::vector<uint8_t>
KMAC256::fixedInfo(const std::vector<uint8_t> &subkey_pkt_hash, pgp_pubkey_alg_t alg_id)
{
    std::vector<uint8_t> result(subkey_pkt_hash);
    result.insert(result.begin(), (static_cast<uint8_t>(alg_id)));;
    return result;
}

std::vector<uint8_t>
KMAC256::encData(const std::vector<uint8_t> &ecc_key_share,
                 const std::vector<uint8_t> &ecc_ciphertext,
                 const std::vector<uint8_t> &kyber_key_share,
                 const std::vector<uint8_t> &kyber_ciphertext,
                 const std::vector<uint8_t> &subkey_pkt_hash,
                 pgp_pubkey_alg_t alg_id) 
{
    std::vector<uint8_t> enc_data;
    std::vector<uint8_t> counter_vec = counter();
    std::vector<uint8_t> fixedInfo_vec = fixedInfo(subkey_pkt_hash, alg_id);

    /* draft-wussler-openpgp-pqc-01:

        eccKemData = eccKeyShare || eccCipherText
        kyberKemData = kyberKeyShare || kyberCipherText
        encData = counter || eccKemData || kyberKemData || fixedInfo
    */
    enc_data.insert(enc_data.end(), counter_vec.begin(), counter_vec.end());
    enc_data.insert(enc_data.end(), ecc_key_share.begin(), ecc_key_share.end());
    enc_data.insert(enc_data.end(), ecc_ciphertext.begin(), ecc_ciphertext.end());
    enc_data.insert(enc_data.end(), kyber_key_share.begin(), kyber_key_share.end());
    enc_data.insert(enc_data.end(), kyber_ciphertext.begin(), kyber_ciphertext.end());
    enc_data.insert(enc_data.end(), fixedInfo_vec.begin(), fixedInfo_vec.end());

    return enc_data;
}


KMAC256::~KMAC256()
{
}

} // namespace rnp
