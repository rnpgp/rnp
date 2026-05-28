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

#include "ed25519_ed448.h"
#include "logging.h"
#include "utils.h"
#include "ossl_utils.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cassert>

static rnp_result_t
ed_generate_native(rnp::RNG *             rng,
                   std::vector<uint8_t> & privkey,
                   std::vector<uint8_t> & pubkey,
                   int                    nid,
                   size_t                 keylen)
{
    rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new_id(nid, NULL));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        return RNP_ERROR_KEY_GENERATION;
    }
    EVP_PKEY *rawkey = NULL;
    if (EVP_PKEY_keygen(ctx.get(), &rawkey) <= 0) {
        RNP_LOG("keygen failed: %lu", ERR_peek_last_error());
        return RNP_ERROR_KEY_GENERATION;
    }
    rnp::ossl::evp::PKey pkey(rawkey);
    privkey.resize(keylen);
    size_t privlen = keylen;
    if (EVP_PKEY_get_raw_private_key(pkey.get(), privkey.data(), &privlen) <= 0) {
        RNP_LOG("Failed to get private key: %lu", ERR_peek_last_error());
        return RNP_ERROR_KEY_GENERATION;
    }
    pubkey.resize(keylen);
    size_t publen = keylen;
    if (EVP_PKEY_get_raw_public_key(pkey.get(), pubkey.data(), &publen) <= 0) {
        RNP_LOG("Failed to get public key: %lu", ERR_peek_last_error());
        return RNP_ERROR_KEY_GENERATION;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
ed_sign_native(std::vector<uint8_t> &      sig_out,
               const std::vector<uint8_t> &key,
               const uint8_t *             hash,
               size_t                      hash_len,
               int                         nid,
               size_t                      siglen)
{
    rnp::ossl::evp::PKey pkey(
      EVP_PKEY_new_raw_private_key(nid, NULL, key.data(), key.size()));
    if (!pkey) {
        RNP_LOG("Failed to load private key: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    rnp::ossl::evp::MDCtx md(EVP_MD_CTX_new());
    if (!md || EVP_DigestSignInit(md.get(), NULL, NULL, NULL, pkey.get()) <= 0) {
        RNP_LOG("Failed to init signing: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    sig_out.resize(siglen);
    size_t outlen = siglen;
    if (EVP_DigestSign(md.get(), sig_out.data(), &outlen, hash, hash_len) <= 0) {
        RNP_LOG("Signing failed: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    sig_out.resize(outlen);
    return RNP_SUCCESS;
}

static rnp_result_t
ed_verify_native(const std::vector<uint8_t> &sig,
                 const std::vector<uint8_t> &key,
                 const uint8_t *             hash,
                 size_t                      hash_len,
                 int                         nid)
{
    rnp::ossl::evp::PKey pkey(
      EVP_PKEY_new_raw_public_key(nid, NULL, key.data(), key.size()));
    if (!pkey) {
        RNP_LOG("Failed to load public key: %lu", ERR_peek_last_error());
        return RNP_ERROR_VERIFICATION_FAILED;
    }
    rnp::ossl::evp::MDCtx md(EVP_MD_CTX_new());
    if (!md || EVP_DigestVerifyInit(md.get(), NULL, NULL, NULL, pkey.get()) <= 0) {
        RNP_LOG("Failed to init verify: %lu", ERR_peek_last_error());
        return RNP_ERROR_VERIFICATION_FAILED;
    }
    if (EVP_DigestVerify(md.get(), sig.data(), sig.size(), hash, hash_len) < 1) {
        return RNP_ERROR_VERIFICATION_FAILED;
    }
    return RNP_SUCCESS;
}

rnp_result_t
generate_ed25519_native(rnp::RNG *            rng,
                        std::vector<uint8_t> &privkey,
                        std::vector<uint8_t> &pubkey)
{
    return ed_generate_native(rng, privkey, pubkey, EVP_PKEY_ED25519, 32);
}

rnp_result_t
ed25519_sign_native(rnp::RNG *                  rng,
                    std::vector<uint8_t> &      sig_out,
                    const std::vector<uint8_t> &key,
                    const uint8_t *             hash,
                    size_t                      hash_len)
{
    return ed_sign_native(sig_out, key, hash, hash_len, EVP_PKEY_ED25519, 64);
}

rnp_result_t
ed25519_verify_native(const std::vector<uint8_t> &sig,
                      const std::vector<uint8_t> &key,
                      const uint8_t *             hash,
                      size_t                      hash_len)
{
    return ed_verify_native(sig, key, hash, hash_len, EVP_PKEY_ED25519);
}

rnp_result_t
ed25519_validate_key_native(rnp::RNG *rng, const pgp_ed25519_key_t *key, bool secret)
{
    rnp::ossl::evp::PKey pub(
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key->pub.data(), key->pub.size()));
    if (!pub) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (secret) {
        rnp::ossl::evp::PKey priv(EVP_PKEY_new_raw_private_key(
          EVP_PKEY_ED25519, NULL, key->priv.data(), key->priv.size()));
        if (!priv) {
            return RNP_ERROR_SIGNING_FAILED;
        }
    }
    return RNP_SUCCESS;
}

#if defined(ENABLE_CRYPTO_REFRESH)
rnp_result_t
generate_ed448_native(rnp::RNG *            rng,
                      std::vector<uint8_t> &privkey,
                      std::vector<uint8_t> &pubkey)
{
    return ed_generate_native(rng, privkey, pubkey, EVP_PKEY_ED448, 57);
}

rnp_result_t
ed448_sign_native(rnp::RNG *                  rng,
                  std::vector<uint8_t> &      sig_out,
                  const std::vector<uint8_t> &key,
                  const uint8_t *             hash,
                  size_t                      hash_len)
{
    return ed_sign_native(sig_out, key, hash, hash_len, EVP_PKEY_ED448, 114);
}

rnp_result_t
ed448_verify_native(const std::vector<uint8_t> &sig,
                    const std::vector<uint8_t> &key,
                    const uint8_t *             hash,
                    size_t                      hash_len)
{
    return ed_verify_native(sig, key, hash, hash_len, EVP_PKEY_ED448);
}

rnp_result_t
ed448_validate_key_native(rnp::RNG *rng, const pgp_ed448_key_t *key, bool secret)
{
    rnp::ossl::evp::PKey pub(
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, key->pub.data(), key->pub.size()));
    if (!pub) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (secret) {
        rnp::ossl::evp::PKey priv(EVP_PKEY_new_raw_private_key(
          EVP_PKEY_ED448, NULL, key->priv.data(), key->priv.size()));
        if (!priv) {
            return RNP_ERROR_SIGNING_FAILED;
        }
    }
    return RNP_SUCCESS;
}
#endif
