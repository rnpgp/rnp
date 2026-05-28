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

#if defined(ENABLE_PQC) && defined(ENABLE_CRYPTO_REFRESH)

#include "dilithium.h"
#include "logging.h"
#include "types.h"
#include "ossl_utils.hpp"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <cassert>

namespace {

const char *
dilithium_alg_name(dilithium_parameter_e param)
{
    return param == dilithium_L3 ? "ML-DSA-65" : "ML-DSA-87";
}

rnp::ossl::evp::PKey
load_dilithium_pubkey(const std::vector<uint8_t> &pub, dilithium_parameter_e param)
{
    rnp::ossl::evp::PKeyCtx ctx(
      EVP_PKEY_CTX_new_from_name(NULL, dilithium_alg_name(param), NULL));
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
load_dilithium_privkey(const rnp::SecureBytes &seed, dilithium_parameter_e param)
{
    rnp::ossl::evp::PKeyCtx ctx(
      EVP_PKEY_CTX_new_from_name(NULL, dilithium_alg_name(param), NULL));
    if (!ctx) {
        return nullptr;
    }
    rnp::ossl::ParamBld bld(OSSL_PARAM_BLD_new());
    if (!bld ||
        !OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_ML_DSA_SEED, seed.data(),
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

std::pair<pgp_dilithium_public_key_t, pgp_dilithium_private_key_t>
dilithium_generate_keypair(rnp::RNG *rng, dilithium_parameter_e dilithium_param)
{
    rnp::ossl::evp::PKeyCtx ctx(
      EVP_PKEY_CTX_new_from_name(NULL, dilithium_alg_name(dilithium_param), NULL));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        RNP_LOG("failed to init ML-DSA keygen: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    EVP_PKEY *pkey_raw = NULL;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
        RNP_LOG("failed to generate ML-DSA key: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    rnp::ossl::evp::PKey pkey(pkey_raw);

    size_t pub_len = 0;
    EVP_PKEY_get_raw_public_key(pkey.get(), NULL, &pub_len);
    std::vector<uint8_t> pub(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &pub_len) <= 0) {
        RNP_LOG("failed to get ML-DSA public key: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    uint8_t    seed_buf[32];
    OSSL_PARAM sparams[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, seed_buf,
                                          sizeof(seed_buf)),
        OSSL_PARAM_END};
    if (EVP_PKEY_get_params(pkey.get(), sparams) <= 0) {
        RNP_LOG("failed to get ML-DSA seed: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    size_t seed_len = sparams[0].return_size;

    auto result = std::make_pair(pgp_dilithium_public_key_t(pub, dilithium_param),
                                 pgp_dilithium_private_key_t(seed_buf, seed_len, dilithium_param));
    rnp::secure_wipe(seed_buf, sizeof(seed_buf));
    return result;
}

std::vector<uint8_t>
pgp_dilithium_private_key_t::sign(rnp::RNG *rng, const uint8_t *msg, size_t msg_len) const
{
    assert(is_initialized_);
    auto pkey = load_dilithium_privkey(key_encoded_, dilithium_param_);
    if (!pkey) {
        RNP_LOG("failed to load ML-DSA private key: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    rnp::ossl::evp::MDCtx mdctx(EVP_MD_CTX_new());
    if (!mdctx ||
        EVP_DigestSignInit_ex(mdctx.get(), NULL, NULL, NULL, NULL, pkey.get(), NULL) <= 0) {
        RNP_LOG("failed to init ML-DSA sign: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    size_t sig_len = 0;
    if (EVP_DigestSign(mdctx.get(), NULL, &sig_len, msg, msg_len) <= 0) {
        RNP_LOG("failed to get ML-DSA signature size: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(mdctx.get(), sig.data(), &sig_len, msg, msg_len) <= 0) {
        RNP_LOG("ML-DSA sign failed: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    sig.resize(sig_len);
    return sig;
}

bool
pgp_dilithium_public_key_t::verify_signature(const uint8_t *msg,
                                             size_t         msg_len,
                                             const uint8_t *signature,
                                             size_t         signature_len) const
{
    assert(is_initialized_);
    auto pkey = load_dilithium_pubkey(key_encoded_, dilithium_param_);
    if (!pkey) {
        RNP_LOG("failed to load ML-DSA public key: %s", rnp::ossl::latest_err());
        return false;
    }
    rnp::ossl::evp::MDCtx mdctx(EVP_MD_CTX_new());
    if (!mdctx ||
        EVP_DigestVerifyInit_ex(mdctx.get(), NULL, NULL, NULL, NULL, pkey.get(), NULL) <= 0) {
        return false;
    }
    return EVP_DigestVerify(mdctx.get(), signature, signature_len, msg, msg_len) == 1;
}

bool
pgp_dilithium_public_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    return (bool) load_dilithium_pubkey(key_encoded_, dilithium_param_);
}

bool
pgp_dilithium_private_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    return (bool) load_dilithium_privkey(key_encoded_, dilithium_param_);
}

#endif // ENABLE_PQC && ENABLE_CRYPTO_REFRESH
