/*
 * Copyright (c) 2026 [Ribose Inc](https://www.ribose.com).
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

#if defined(ENABLE_PQC)

#include "kyber.h"
#include "kyber_common.h"
#include "logging.h"
#include "types.h"
#include "ossl_utils.hpp"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <cassert>

namespace {

const char *
kyber_alg_name(kyber_parameter_e mode)
{
    return mode == kyber_768 ? "ML-KEM-768" : "ML-KEM-1024";
}

rnp::ossl::evp::PKey
load_mlkem_pubkey(const std::vector<uint8_t> &pub, kyber_parameter_e mode)
{
    rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new_from_name(NULL, kyber_alg_name(mode), NULL));
    if (!ctx) {
        return nullptr;
    }
    rnp::ossl::ParamBld bld(OSSL_PARAM_BLD_new());
    if (!bld ||
        !OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pub.data(),
                                          pub.size())) {
        return nullptr;
    }
    rnp::ossl::Param params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params) {
        return nullptr;
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0) {
        return nullptr;
    }
    return rnp::ossl::evp::PKey(pkey);
}

rnp::ossl::evp::PKey
load_mlkem_privkey(const rnp::SecureBytes &seed, kyber_parameter_e mode)
{
    rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new_from_name(NULL, kyber_alg_name(mode), NULL));
    if (!ctx) {
        return nullptr;
    }
    rnp::ossl::ParamBld bld(OSSL_PARAM_BLD_new());
    if (!bld ||
        !OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_ML_KEM_SEED, seed.data(),
                                          seed.size())) {
        return nullptr;
    }
    rnp::ossl::Param params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params) {
        return nullptr;
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_KEYPAIR, params.get()) <= 0) {
        return nullptr;
    }
    return rnp::ossl::evp::PKey(pkey);
}

} // namespace

std::pair<pgp_kyber_public_key_t, pgp_kyber_private_key_t>
kyber_generate_keypair(rnp::RNG *rng, kyber_parameter_e kyber_param)
{
    rnp::ossl::evp::PKeyCtx ctx(
      EVP_PKEY_CTX_new_from_name(NULL, kyber_alg_name(kyber_param), NULL));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        RNP_LOG("failed to init ML-KEM keygen: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    EVP_PKEY *pkey_raw = NULL;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
        RNP_LOG("failed to generate ML-KEM key: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    rnp::ossl::evp::PKey pkey(pkey_raw);

    size_t pub_len = 0;
    EVP_PKEY_get_raw_public_key(pkey.get(), NULL, &pub_len);
    std::vector<uint8_t> pub(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &pub_len) <= 0) {
        RNP_LOG("failed to get ML-KEM public key: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    uint8_t   seed_buf[64];
    OSSL_PARAM sparams[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, seed_buf,
                                          sizeof(seed_buf)),
        OSSL_PARAM_END};
    if (EVP_PKEY_get_params(pkey.get(), sparams) <= 0) {
        RNP_LOG("failed to get ML-KEM seed: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    size_t seed_len = sparams[0].return_size;

    auto result = std::make_pair(pgp_kyber_public_key_t(pub, kyber_param),
                                 pgp_kyber_private_key_t(seed_buf, seed_len, kyber_param));
    rnp::secure_wipe(seed_buf, sizeof(seed_buf));
    return result;
}

kyber_encap_result_t
pgp_kyber_public_key_t::encapsulate(rnp::RNG *rng) const
{
    assert(is_initialized_);
    auto pkey = load_mlkem_pubkey(key_encoded_, kyber_mode_);
    if (!pkey) {
        RNP_LOG("failed to load ML-KEM public key: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(NULL, pkey.get(), NULL));
    if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), NULL) <= 0) {
        RNP_LOG("failed to init ML-KEM encapsulate: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    size_t ct_len = 0, ss_len = 0;
    if (EVP_PKEY_encapsulate(ctx.get(), NULL, &ct_len, NULL, &ss_len) <= 0) {
        RNP_LOG("failed to get ML-KEM encapsulate sizes: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    kyber_encap_result_t result;
    result.ciphertext.resize(ct_len);
    result.symmetric_key.resize(ss_len);
    if (EVP_PKEY_encapsulate(ctx.get(), result.ciphertext.data(), &ct_len,
                             result.symmetric_key.data(), &ss_len) <= 0) {
        RNP_LOG("ML-KEM encapsulate failed: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    return result;
}

std::vector<uint8_t>
pgp_kyber_private_key_t::decapsulate(rnp::RNG *     rng,
                                     const uint8_t *ciphertext,
                                     size_t         ciphertext_len)
{
    assert(is_initialized_);
    auto pkey = load_mlkem_privkey(key_encoded_, kyber_mode_);
    if (!pkey) {
        RNP_LOG("failed to load ML-KEM private key: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(NULL, pkey.get(), NULL));
    if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), NULL) <= 0) {
        RNP_LOG("failed to init ML-KEM decapsulate: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    size_t ss_len = 0;
    if (EVP_PKEY_decapsulate(ctx.get(), NULL, &ss_len, ciphertext, ciphertext_len) <= 0) {
        RNP_LOG("failed to get ML-KEM decapsulate size: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    std::vector<uint8_t> result(ss_len);
    if (EVP_PKEY_decapsulate(ctx.get(), result.data(), &ss_len, ciphertext,
                             ciphertext_len) <= 0) {
        RNP_LOG("ML-KEM decapsulate failed: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    return result;
}

bool
pgp_kyber_public_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    return (bool) load_mlkem_pubkey(key_encoded_, kyber_mode_);
}

bool
pgp_kyber_private_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    return (bool) load_mlkem_privkey(key_encoded_, kyber_mode_);
}

#endif // ENABLE_PQC
