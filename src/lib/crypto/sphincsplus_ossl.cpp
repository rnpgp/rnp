/*
 * Copyright (c) 2025, [MTG AG](https://www.mtg.de).
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

#include "sphincsplus.h"
#include "logging.h"
#include "types.h"
#include "ossl_utils.hpp"
#include <openssl/evp.h>
#include <cassert>

namespace {

const char *
sphincsplus_alg_name(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_SPHINCSPLUS_SHAKE_128f:
        return "SLH-DSA-SHAKE-128f";
    case PGP_PKA_SPHINCSPLUS_SHAKE_128s:
        return "SLH-DSA-SHAKE-128s";
    case PGP_PKA_SPHINCSPLUS_SHAKE_256s:
        return "SLH-DSA-SHAKE-256s";
    default:
        RNP_LOG("invalid SLH-DSA algorithm identifier");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}

rnp::ossl::evp::PKey
load_slhdsa_pubkey(const std::vector<uint8_t> &pub, pgp_pubkey_alg_t alg)
{
    EVP_PKEY *pkey =
      EVP_PKEY_new_raw_public_key_ex(NULL, sphincsplus_alg_name(alg), NULL, pub.data(),
                                     pub.size());
    return rnp::ossl::evp::PKey(pkey);
}

rnp::ossl::evp::PKey
load_slhdsa_privkey(const rnp::SecureBytes &priv, pgp_pubkey_alg_t alg)
{
    EVP_PKEY *pkey =
      EVP_PKEY_new_raw_private_key_ex(NULL, sphincsplus_alg_name(alg), NULL, priv.data(),
                                      priv.size());
    return rnp::ossl::evp::PKey(pkey);
}

} // namespace

pgp_sphincsplus_public_key_t::pgp_sphincsplus_public_key_t(const uint8_t *  key_encoded,
                                                           size_t           key_encoded_len,
                                                           pgp_pubkey_alg_t alg)
    : key_encoded_(key_encoded, key_encoded + key_encoded_len), pk_alg_(alg),
      is_initialized_(true)
{
}

pgp_sphincsplus_public_key_t::pgp_sphincsplus_public_key_t(
  std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t alg)
    : key_encoded_(key_encoded), pk_alg_(alg), is_initialized_(true)
{
}

pgp_sphincsplus_private_key_t::pgp_sphincsplus_private_key_t(const uint8_t *  key_encoded,
                                                             size_t           key_encoded_len,
                                                             pgp_pubkey_alg_t alg)
    : key_encoded_(key_encoded, key_encoded + key_encoded_len), pk_alg_(alg),
      is_initialized_(true)
{
}

pgp_sphincsplus_private_key_t::pgp_sphincsplus_private_key_t(
  std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t alg)
    : key_encoded_(key_encoded), pk_alg_(alg), is_initialized_(true)
{
}

std::pair<pgp_sphincsplus_public_key_t, pgp_sphincsplus_private_key_t>
sphincsplus_generate_keypair(rnp::RNG *rng, pgp_pubkey_alg_t alg)
{
    rnp::ossl::evp::PKeyCtx ctx(
      EVP_PKEY_CTX_new_from_name(NULL, sphincsplus_alg_name(alg), NULL));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        RNP_LOG("failed to init SLH-DSA keygen: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    EVP_PKEY *pkey_raw = NULL;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
        RNP_LOG("failed to generate SLH-DSA key: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    rnp::ossl::evp::PKey pkey(pkey_raw);

    size_t pub_len = 0, priv_len = 0;
    EVP_PKEY_get_raw_public_key(pkey.get(), NULL, &pub_len);
    EVP_PKEY_get_raw_private_key(pkey.get(), NULL, &priv_len);

    std::vector<uint8_t> pub(pub_len);
    std::vector<uint8_t> priv(priv_len);
    if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &pub_len) <= 0 ||
        EVP_PKEY_get_raw_private_key(pkey.get(), priv.data(), &priv_len) <= 0) {
        RNP_LOG("failed to extract SLH-DSA key material: %s", rnp::ossl::latest_err());
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    auto result = std::make_pair(pgp_sphincsplus_public_key_t(pub, alg),
                                 pgp_sphincsplus_private_key_t(priv, alg));
    rnp::secure_wipe(priv.data(), priv.size());
    return result;
}

rnp_result_t
pgp_sphincsplus_generate(rnp::RNG *rng, pgp_sphincsplus_key_t *material, pgp_pubkey_alg_t alg)
{
    auto keypair = sphincsplus_generate_keypair(rng, alg);
    material->pub = keypair.first;
    material->priv = keypair.second;
    return RNP_SUCCESS;
}

rnp_result_t
pgp_sphincsplus_private_key_t::sign(rnp::RNG *                   rng,
                                    pgp_sphincsplus_signature_t *sig,
                                    const uint8_t *              msg,
                                    size_t                       msg_len) const
{
    assert(is_initialized_);
    auto pkey = load_slhdsa_privkey(key_encoded_, pk_alg_);
    if (!pkey) {
        RNP_LOG("failed to load SLH-DSA private key: %s", rnp::ossl::latest_err());
        return RNP_ERROR_GENERIC;
    }
    rnp::ossl::evp::MDCtx mdctx(EVP_MD_CTX_new());
    if (!mdctx ||
        EVP_DigestSignInit_ex(mdctx.get(), NULL, NULL, NULL, NULL, pkey.get(), NULL) <= 0) {
        RNP_LOG("failed to init SLH-DSA sign: %s", rnp::ossl::latest_err());
        return RNP_ERROR_GENERIC;
    }
    size_t sig_len = 0;
    if (EVP_DigestSign(mdctx.get(), NULL, &sig_len, msg, msg_len) <= 0) {
        RNP_LOG("failed to get SLH-DSA signature size: %s", rnp::ossl::latest_err());
        return RNP_ERROR_GENERIC;
    }
    sig->sig.resize(sig_len);
    if (EVP_DigestSign(mdctx.get(), sig->sig.data(), &sig_len, msg, msg_len) <= 0) {
        RNP_LOG("SLH-DSA sign failed: %s", rnp::ossl::latest_err());
        return RNP_ERROR_GENERIC;
    }
    sig->sig.resize(sig_len);
    return RNP_SUCCESS;
}

rnp_result_t
pgp_sphincsplus_public_key_t::verify(const pgp_sphincsplus_signature_t *sig,
                                     const uint8_t *                    msg,
                                     size_t                             msg_len) const
{
    assert(is_initialized_);
    auto pkey = load_slhdsa_pubkey(key_encoded_, pk_alg_);
    if (!pkey) {
        RNP_LOG("failed to load SLH-DSA public key: %s", rnp::ossl::latest_err());
        return RNP_ERROR_GENERIC;
    }
    rnp::ossl::evp::MDCtx mdctx(EVP_MD_CTX_new());
    if (!mdctx ||
        EVP_DigestVerifyInit_ex(mdctx.get(), NULL, NULL, NULL, NULL, pkey.get(), NULL) <= 0) {
        return RNP_ERROR_GENERIC;
    }
    if (EVP_DigestVerify(mdctx.get(), sig->sig.data(), sig->sig.size(), msg, msg_len) != 1) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    return RNP_SUCCESS;
}

bool
pgp_sphincsplus_public_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    return (bool) load_slhdsa_pubkey(key_encoded_, pk_alg_);
}

bool
pgp_sphincsplus_private_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    return (bool) load_slhdsa_privkey(key_encoded_, pk_alg_);
}

rnp_result_t
sphincsplus_validate_key(rnp::RNG *rng, const pgp_sphincsplus_key_t *key, bool secret)
{
    bool valid = key->pub.is_valid(rng);
    if (secret) {
        valid = valid && key->priv.is_valid(rng);
    }
    return valid ? RNP_SUCCESS : RNP_ERROR_GENERIC;
}

size_t
sphincsplus_privkey_size(pgp_pubkey_alg_t alg)
{
    return 2 * sphincsplus_pubkey_size(alg);
}

size_t
sphincsplus_pubkey_size(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_SPHINCSPLUS_SHAKE_128f:
        return 32;
    case PGP_PKA_SPHINCSPLUS_SHAKE_128s:
        return 32;
    case PGP_PKA_SPHINCSPLUS_SHAKE_256s:
        return 64;
    default:
        RNP_LOG("invalid SLH-DSA algorithm identifier");
        return 0;
    }
}

size_t
sphincsplus_signature_size(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_SPHINCSPLUS_SHAKE_128f:
        return 17088;
    case PGP_PKA_SPHINCSPLUS_SHAKE_128s:
        return 7856;
    case PGP_PKA_SPHINCSPLUS_SHAKE_256s:
        return 29792;
    default:
        RNP_LOG("invalid SLH-DSA algorithm identifier");
        return 0;
    }
}

#endif // ENABLE_PQC && ENABLE_CRYPTO_REFRESH
