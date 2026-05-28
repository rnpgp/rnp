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

#if defined(ENABLE_CRYPTO_REFRESH) || defined(ENABLE_PQC)

#include "exdsa_ecdhkem.h"
#include "ec_ossl.h"
#include "ed25519_ed448.h"
#include "ec.h"
#include "logging.h"
#include "ossl_utils.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#if defined(CRYPTO_BACKEND_OPENSSL3)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif
#include <cassert>

ec_key_t::~ec_key_t()
{
}

ec_key_t::ec_key_t(pgp_curve_t curve) : curve_(curve)
{
}

ecdh_kem_public_key_t::ecdh_kem_public_key_t(uint8_t *   key_buf,
                                             size_t      key_buf_len,
                                             pgp_curve_t curve)
    : ec_key_t(curve), key_(std::vector<uint8_t>(key_buf, key_buf + key_buf_len))
{
}
ecdh_kem_public_key_t::ecdh_kem_public_key_t(std::vector<uint8_t> key, pgp_curve_t curve)
    : ec_key_t(curve), key_(key)
{
}

ecdh_kem_private_key_t::ecdh_kem_private_key_t(uint8_t *   key_buf,
                                               size_t      key_buf_len,
                                               pgp_curve_t curve)
    : ec_key_t(curve), key_(key_buf, key_buf + key_buf_len)
{
}
ecdh_kem_private_key_t::ecdh_kem_private_key_t(std::vector<uint8_t> key, pgp_curve_t curve)
    : ec_key_t(curve), key_(std::move(key))
{
}

static bool
derive_secret(rnp::ossl::evp::PKey &sec, rnp::ossl::evp::PKey &peer, std::vector<uint8_t> &out)
{
    rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new(sec.get(), NULL));
    if (!ctx) {
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        return false;
    }
    if (EVP_PKEY_derive_init(ctx.get()) <= 0) {
        RNP_LOG("Key derivation init failed: %lu", ERR_peek_last_error());
        return false;
    }
    if (EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) <= 0) {
        RNP_LOG("Peer setting failed: %lu", ERR_peek_last_error());
        return false;
    }
    size_t xlen = 0;
    if (EVP_PKEY_derive(ctx.get(), NULL, &xlen) <= 0) {
        RNP_LOG("Failed to get shared secret size: %lu", ERR_peek_last_error());
        return false;
    }
    out.resize(xlen);
    if (EVP_PKEY_derive(ctx.get(), out.data(), &xlen) <= 0) {
        RNP_LOG("Failed to derive shared secret: %lu", ERR_peek_last_error());
        return false;
    }
    out.resize(xlen);
    return true;
}

static rnp::ossl::evp::PKey
load_nist_pubkey(const std::vector<uint8_t> &key, pgp_curve_t curve)
{
    pgp::mpi pub_mpi;
    pub_mpi.assign(key.data(), key.size());
    return pgp::ec::load_key(pub_mpi, nullptr, curve);
}

#if defined(CRYPTO_BACKEND_OPENSSL3)
static rnp::ossl::evp::PKey
load_nist_privkey(const uint8_t *scalar, size_t scalar_len, pgp_curve_t curve)
{
    auto curv_desc = pgp::ec::Curve::get(curve);
    if (!curv_desc) {
        return nullptr;
    }
    rnp::ossl::ParamBld bld(OSSL_PARAM_BLD_new());
    if (!bld) {
        return nullptr;
    }
    rnp::bn priv(BN_bin2bn(scalar, scalar_len, NULL));
    if (!priv) {
        return nullptr;
    }
    if (!OSSL_PARAM_BLD_push_utf8_string(
          bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, curv_desc->openssl_name, 0) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, priv.get())) {
        return nullptr;
    }
    rnp::ossl::Param params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params) {
        return nullptr;
    }
    rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
    if (!ctx) {
        return nullptr;
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
        EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PRIVATE_KEY, params.get()) != 1) {
        pkey = NULL;
    }
    return rnp::ossl::evp::PKey(pkey);
}
#endif

std::vector<uint8_t>
ecdh_kem_private_key_t::get_pubkey_encoded(rnp::RNG *rng) const
{
    std::vector<uint8_t> pub;
    switch (curve_) {
    case PGP_CURVE_25519: {
        rnp::ossl::evp::PKey pkey(
          EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, key_.data(), key_.size()));
        if (!pkey) {
            RNP_LOG("Failed to load X25519 private key: %lu", ERR_peek_last_error());
            return pub;
        }
        pub.resize(32);
        size_t pub_len = pub.size();
        if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &pub_len) <= 0) {
            RNP_LOG("Failed to get X25519 public key: %lu", ERR_peek_last_error());
            pub.clear();
        }
        break;
    }
#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_CURVE_448: {
        rnp::ossl::evp::PKey pkey(
          EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, NULL, key_.data(), key_.size()));
        if (!pkey) {
            RNP_LOG("Failed to load X448 private key: %lu", ERR_peek_last_error());
            return pub;
        }
        pub.resize(56);
        size_t pub_len = pub.size();
        if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &pub_len) <= 0) {
            RNP_LOG("Failed to get X448 public key: %lu", ERR_peek_last_error());
            pub.clear();
        }
        break;
    }
#endif
    default: {
#if defined(CRYPTO_BACKEND_OPENSSL3)
        auto pkey = load_nist_privkey(key_.data(), key_.size(), curve_);
        if (!pkey) {
            RNP_LOG("Failed to load NIST private key");
            return pub;
        }
        pgp::mpi pub_mpi;
        if (!pgp::ec::write_pubkey(pkey, pub_mpi, curve_)) {
            RNP_LOG("Failed to extract NIST public key");
            return pub;
        }
        pub.assign(pub_mpi.data(), pub_mpi.data() + pub_mpi.size());
#else
        RNP_LOG("NIST ecdh_kem get_pubkey_encoded requires OpenSSL 3.x");
#endif
        break;
    }
    }
    return pub;
}

rnp_result_t
ecdh_kem_public_key_t::encapsulate(rnp::RNG *            rng,
                                   std::vector<uint8_t> &ciphertext,
                                   std::vector<uint8_t> &symmetric_key) const
{
    switch (curve_) {
    case PGP_CURVE_25519: {
        rnp::ossl::evp::PKeyCtx kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL));
        if (!kctx || EVP_PKEY_keygen_init(kctx.get()) <= 0) {
            RNP_LOG("Failed to init X25519 keygen: %lu", ERR_peek_last_error());
            return RNP_ERROR_KEY_GENERATION;
        }
        EVP_PKEY *raw_eph = NULL;
        if (EVP_PKEY_keygen(kctx.get(), &raw_eph) <= 0) {
            RNP_LOG("X25519 keygen failed: %lu", ERR_peek_last_error());
            return RNP_ERROR_KEY_GENERATION;
        }
        rnp::ossl::evp::PKey eph_key(raw_eph);
        ciphertext.resize(32);
        size_t ct_len = ciphertext.size();
        if (EVP_PKEY_get_raw_public_key(eph_key.get(), ciphertext.data(), &ct_len) <= 0) {
            RNP_LOG("Failed to get ephemeral X25519 pubkey: %lu", ERR_peek_last_error());
            return RNP_ERROR_GENERIC;
        }
        rnp::ossl::evp::PKey peer(
          EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, key_.data(), key_.size()));
        if (!peer) {
            RNP_LOG("Failed to load peer X25519 key: %lu", ERR_peek_last_error());
            return RNP_ERROR_GENERIC;
        }
        if (!derive_secret(eph_key, peer, symmetric_key)) {
            return RNP_ERROR_GENERIC;
        }
        break;
    }
#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_CURVE_448: {
        rnp::ossl::evp::PKeyCtx kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X448, NULL));
        if (!kctx || EVP_PKEY_keygen_init(kctx.get()) <= 0) {
            RNP_LOG("Failed to init X448 keygen: %lu", ERR_peek_last_error());
            return RNP_ERROR_KEY_GENERATION;
        }
        EVP_PKEY *raw_eph = NULL;
        if (EVP_PKEY_keygen(kctx.get(), &raw_eph) <= 0) {
            RNP_LOG("X448 keygen failed: %lu", ERR_peek_last_error());
            return RNP_ERROR_KEY_GENERATION;
        }
        rnp::ossl::evp::PKey eph_key(raw_eph);
        ciphertext.resize(56);
        size_t ct_len = ciphertext.size();
        if (EVP_PKEY_get_raw_public_key(eph_key.get(), ciphertext.data(), &ct_len) <= 0) {
            RNP_LOG("Failed to get ephemeral X448 pubkey: %lu", ERR_peek_last_error());
            return RNP_ERROR_GENERIC;
        }
        rnp::ossl::evp::PKey peer(
          EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, NULL, key_.data(), key_.size()));
        if (!peer) {
            RNP_LOG("Failed to load peer X448 key: %lu", ERR_peek_last_error());
            return RNP_ERROR_GENERIC;
        }
        if (!derive_secret(eph_key, peer, symmetric_key)) {
            return RNP_ERROR_GENERIC;
        }
        break;
    }
#endif
    default: {
        auto curve_desc = pgp::ec::Curve::get(curve_);
        if (!curve_desc) {
            RNP_LOG("unknown curve");
            return RNP_ERROR_NOT_SUPPORTED;
        }
        auto eph_key = pgp::ec::generate_pkey(PGP_PKA_ECDH, curve_);
        if (!eph_key) {
            RNP_LOG("Failed to generate ephemeral NIST key");
            return RNP_ERROR_KEY_GENERATION;
        }
        auto peer = load_nist_pubkey(key_, curve_);
        if (!peer) {
            RNP_LOG("Failed to load peer NIST key");
            return RNP_ERROR_GENERIC;
        }
        if (!derive_secret(eph_key, peer, symmetric_key)) {
            return RNP_ERROR_GENERIC;
        }
        pgp::mpi ct_mpi;
        if (!pgp::ec::write_pubkey(eph_key, ct_mpi, curve_)) {
            RNP_LOG("Failed to write ephemeral public key");
            return RNP_ERROR_GENERIC;
        }
        ciphertext.assign(ct_mpi.data(), ct_mpi.data() + ct_mpi.size());
        break;
    }
    }
    return RNP_SUCCESS;
}

rnp_result_t
ecdh_kem_private_key_t::decapsulate(rnp::RNG *                  rng,
                                    const std::vector<uint8_t> &ciphertext,
                                    std::vector<uint8_t> &      plaintext)
{
    switch (curve_) {
    case PGP_CURVE_25519: {
        rnp::ossl::evp::PKey priv(
          EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, key_.data(), key_.size()));
        if (!priv) {
            RNP_LOG("Failed to load X25519 private key: %lu", ERR_peek_last_error());
            return RNP_ERROR_GENERIC;
        }
        rnp::ossl::evp::PKey peer(EVP_PKEY_new_raw_public_key(
          EVP_PKEY_X25519, NULL, ciphertext.data(), ciphertext.size()));
        if (!peer) {
            RNP_LOG("Failed to load X25519 ephemeral key: %lu", ERR_peek_last_error());
            return RNP_ERROR_GENERIC;
        }
        if (!derive_secret(priv, peer, plaintext)) {
            return RNP_ERROR_GENERIC;
        }
        break;
    }
#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_CURVE_448: {
        rnp::ossl::evp::PKey priv(
          EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, NULL, key_.data(), key_.size()));
        if (!priv) {
            RNP_LOG("Failed to load X448 private key: %lu", ERR_peek_last_error());
            return RNP_ERROR_GENERIC;
        }
        rnp::ossl::evp::PKey peer(EVP_PKEY_new_raw_public_key(
          EVP_PKEY_X448, NULL, ciphertext.data(), ciphertext.size()));
        if (!peer) {
            RNP_LOG("Failed to load X448 ephemeral key: %lu", ERR_peek_last_error());
            return RNP_ERROR_GENERIC;
        }
        if (!derive_secret(priv, peer, plaintext)) {
            return RNP_ERROR_GENERIC;
        }
        break;
    }
#endif
    default: {
#if defined(CRYPTO_BACKEND_OPENSSL3)
        auto priv = load_nist_privkey(key_.data(), key_.size(), curve_);
        if (!priv) {
            RNP_LOG("Failed to load NIST private key");
            return RNP_ERROR_GENERIC;
        }
        auto peer = load_nist_pubkey(ciphertext, curve_);
        if (!peer) {
            RNP_LOG("Failed to load NIST ephemeral key");
            return RNP_ERROR_GENERIC;
        }
        if (!derive_secret(priv, peer, plaintext)) {
            return RNP_ERROR_GENERIC;
        }
#else
        RNP_LOG("NIST ecdh_kem decapsulate requires OpenSSL 3.x");
        return RNP_ERROR_NOT_SUPPORTED;
#endif
        break;
    }
    }
    return RNP_SUCCESS;
}

rnp_result_t
ec_key_t::generate_ecdh_kem_key_pair(rnp::RNG *rng, ecdh_kem_key_t *out, pgp_curve_t curve)
{
    std::vector<uint8_t> pub, priv;
    rnp_result_t         result = ec_generate_native(rng, priv, pub, curve);
    if (result != RNP_SUCCESS) {
        RNP_LOG("error when generating EC key pair");
        return result;
    }
    out->priv = ecdh_kem_private_key_t(priv, curve);
    out->pub = ecdh_kem_public_key_t(pub, curve);
    return RNP_SUCCESS;
}

bool
ecdh_kem_public_key_t::is_valid(rnp::RNG *rng) const
{
    switch (curve_) {
    case PGP_CURVE_25519: {
        rnp::ossl::evp::PKey pkey(
          EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, key_.data(), key_.size()));
        return pkey != nullptr;
    }
#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_CURVE_448: {
        rnp::ossl::evp::PKey pkey(
          EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, NULL, key_.data(), key_.size()));
        return pkey != nullptr;
    }
#endif
    default: {
        auto pkey = load_nist_pubkey(key_, curve_);
        if (!pkey) {
            return false;
        }
        rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new(pkey.get(), NULL));
        if (!ctx) {
            return false;
        }
        return EVP_PKEY_public_check(ctx.get()) > 0;
    }
    }
}

bool
ecdh_kem_private_key_t::is_valid(rnp::RNG *rng) const
{
    switch (curve_) {
    case PGP_CURVE_25519: {
        rnp::ossl::evp::PKey pkey(
          EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, key_.data(), key_.size()));
        return pkey != nullptr;
    }
#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_CURVE_448: {
        rnp::ossl::evp::PKey pkey(
          EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, NULL, key_.data(), key_.size()));
        return pkey != nullptr;
    }
#endif
    default: {
#if defined(CRYPTO_BACKEND_OPENSSL3)
        auto pkey = load_nist_privkey(key_.data(), key_.size(), curve_);
        if (!pkey) {
            return false;
        }
        rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new(pkey.get(), NULL));
        if (!ctx) {
            return false;
        }
        return EVP_PKEY_private_check(ctx.get()) > 0;
#else
        return false;
#endif
    }
    }
}

#if defined(ENABLE_CRYPTO_REFRESH)

exdsa_public_key_t::exdsa_public_key_t(uint8_t *key_buf, size_t key_buf_len, pgp_curve_t curve)
    : ec_key_t(curve), key_(key_buf, key_buf + key_buf_len)
{
}
exdsa_public_key_t::exdsa_public_key_t(std::vector<uint8_t> key, pgp_curve_t curve)
    : ec_key_t(curve), key_(key)
{
}

exdsa_private_key_t::exdsa_private_key_t(uint8_t *   key_buf,
                                         size_t      key_buf_len,
                                         pgp_curve_t curve)
    : ec_key_t(curve), key_(key_buf, key_buf + key_buf_len)
{
}
exdsa_private_key_t::exdsa_private_key_t(std::vector<uint8_t> key, pgp_curve_t curve)
    : ec_key_t(curve), key_(std::move(key))
{
}

rnp_result_t
ec_key_t::generate_exdsa_key_pair(rnp::RNG *rng, exdsa_key_t *out, pgp_curve_t curve)
{
    std::vector<uint8_t> pub, priv;
    rnp_result_t         result = ec_generate_native(rng, priv, pub, curve);
    if (result != RNP_SUCCESS) {
        RNP_LOG("error when generating EC key pair");
        return result;
    }
    out->priv = exdsa_private_key_t(priv, curve);
    out->pub = exdsa_public_key_t(pub, curve);
    return RNP_SUCCESS;
}

rnp_result_t
exdsa_private_key_t::sign(rnp::RNG *            rng,
                          std::vector<uint8_t> &sig_out,
                          const uint8_t *       hash,
                          size_t                hash_len,
                          pgp_hash_alg_t        hash_alg) const
{
    (void) hash_alg;
    switch (curve_) {
    case PGP_CURVE_ED25519:
        return ed25519_sign_native(rng, sig_out, key_.unlock(), hash, hash_len);
    case PGP_CURVE_ED448:
        return ed448_sign_native(rng, sig_out, key_.unlock(), hash, hash_len);
    default: {
#if defined(CRYPTO_BACKEND_OPENSSL3)
        auto pkey = load_nist_privkey(key_.data(), key_.size(), curve_);
        if (!pkey) {
            RNP_LOG("Failed to load ECDSA private key");
            return RNP_ERROR_GENERIC;
        }
        rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new(pkey.get(), NULL));
        if (!ctx || EVP_PKEY_sign_init(ctx.get()) <= 0) {
            RNP_LOG("Failed to init ECDSA signing: %lu", ERR_peek_last_error());
            return RNP_ERROR_GENERIC;
        }
        auto curve_desc = pgp::ec::Curve::get(curve_);
        if (!curve_desc) {
            return RNP_ERROR_NOT_SUPPORTED;
        }
        size_t               field_size = curve_desc->bytes();
        std::vector<uint8_t> der_sig(2 * field_size + 16);
        size_t               der_len = der_sig.size();
        if (EVP_PKEY_sign(ctx.get(), der_sig.data(), &der_len, hash, hash_len) <= 0) {
            RNP_LOG("ECDSA signing failed: %lu", ERR_peek_last_error());
            return RNP_ERROR_GENERIC;
        }
        /* decode DER and re-encode as P1363 (raw r || s, zero-padded to field_size) */
        const uint8_t *     p = der_sig.data();
        rnp::ossl::ECDSASig esig(d2i_ECDSA_SIG(NULL, &p, der_len));
        if (!esig) {
            RNP_LOG("Failed to parse DER ECDSA sig: %lu", ERR_peek_last_error());
            return RNP_ERROR_GENERIC;
        }
        rnp::bn r, s;
        ECDSA_SIG_get0(esig.get(), r.cptr(), s.cptr());
        sig_out.resize(2 * field_size, 0);
        if (BN_bn2binpad(r.c_get(), sig_out.data(), field_size) < 0 ||
            BN_bn2binpad(s.c_get(), sig_out.data() + field_size, field_size) < 0) {
            RNP_LOG("Failed to encode P1363 signature");
            return RNP_ERROR_GENERIC;
        }
        return RNP_SUCCESS;
#else
        RNP_LOG("exdsa sign for NIST curves requires OpenSSL 3.x");
        return RNP_ERROR_NOT_SUPPORTED;
#endif
    }
    }
}

rnp_result_t
exdsa_public_key_t::verify(const std::vector<uint8_t> &sig,
                           const uint8_t *             hash,
                           size_t                      hash_len,
                           pgp_hash_alg_t              hash_alg) const
{
    (void) hash_alg;
    switch (curve_) {
    case PGP_CURVE_ED25519:
        return ed25519_verify_native(sig, key_, hash, hash_len);
    case PGP_CURVE_ED448:
        return ed448_verify_native(sig, key_, hash, hash_len);
    default: {
        auto pkey = load_nist_pubkey(key_, curve_);
        if (!pkey) {
            RNP_LOG("Failed to load ECDSA public key");
            return RNP_ERROR_VERIFICATION_FAILED;
        }
        auto curve_desc = pgp::ec::Curve::get(curve_);
        if (!curve_desc) {
            return RNP_ERROR_NOT_SUPPORTED;
        }
        size_t field_size = curve_desc->bytes();
        if (sig.size() != 2 * field_size) {
            RNP_LOG("Invalid P1363 signature size: %zu (expected %zu)", sig.size(),
                    2 * field_size);
            return RNP_ERROR_VERIFICATION_FAILED;
        }
        /* decode P1363 and encode as DER for EVP_PKEY_verify */
        rnp::bn r(BN_bin2bn(sig.data(), field_size, NULL));
        rnp::bn s(BN_bin2bn(sig.data() + field_size, field_size, NULL));
        if (!r || !s) {
            RNP_LOG("Failed to decode P1363 signature");
            return RNP_ERROR_VERIFICATION_FAILED;
        }
        rnp::ossl::ECDSASig ecdsa_sig(ECDSA_SIG_new());
        if (!ecdsa_sig) {
            return RNP_ERROR_VERIFICATION_FAILED;
        }
        ECDSA_SIG_set0(ecdsa_sig.get(), r.own(), s.own());
        int der_len = i2d_ECDSA_SIG(ecdsa_sig.get(), NULL);
        if (der_len <= 0) {
            return RNP_ERROR_VERIFICATION_FAILED;
        }
        std::vector<uint8_t> der_buf(der_len);
        uint8_t *            der_ptr = der_buf.data();
        if (i2d_ECDSA_SIG(ecdsa_sig.get(), &der_ptr) <= 0) {
            return RNP_ERROR_VERIFICATION_FAILED;
        }

        rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new(pkey.get(), NULL));
        if (!ctx || EVP_PKEY_verify_init(ctx.get()) <= 0) {
            RNP_LOG("Failed to init ECDSA verify: %lu", ERR_peek_last_error());
            return RNP_ERROR_VERIFICATION_FAILED;
        }
        if (EVP_PKEY_verify(ctx.get(), der_buf.data(), der_len, hash, hash_len) < 1) {
            return RNP_ERROR_VERIFICATION_FAILED;
        }
        return RNP_SUCCESS;
    }
    }
}

bool
exdsa_public_key_t::is_valid(rnp::RNG *rng) const
{
    switch (curve_) {
    case PGP_CURVE_ED25519: {
        rnp::ossl::evp::PKey pkey(
          EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key_.data(), key_.size()));
        if (!pkey) {
            return false;
        }
        rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new(pkey.get(), NULL));
        return ctx && EVP_PKEY_public_check(ctx.get()) > 0;
    }
    case PGP_CURVE_ED448: {
        rnp::ossl::evp::PKey pkey(
          EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, key_.data(), key_.size()));
        if (!pkey) {
            return false;
        }
        rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new(pkey.get(), NULL));
        return ctx && EVP_PKEY_public_check(ctx.get()) > 0;
    }
    default: {
        auto pkey = load_nist_pubkey(key_, curve_);
        if (!pkey) {
            return false;
        }
        rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new(pkey.get(), NULL));
        return ctx && EVP_PKEY_public_check(ctx.get()) > 0;
    }
    }
}

bool
exdsa_private_key_t::is_valid(rnp::RNG *rng) const
{
    switch (curve_) {
    case PGP_CURVE_ED25519: {
        rnp::ossl::evp::PKey pkey(
          EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, key_.data(), key_.size()));
        if (!pkey) {
            return false;
        }
        rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new(pkey.get(), NULL));
        return ctx && EVP_PKEY_check(ctx.get()) > 0;
    }
    case PGP_CURVE_ED448: {
        rnp::ossl::evp::PKey pkey(
          EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, NULL, key_.data(), key_.size()));
        if (!pkey) {
            return false;
        }
        rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new(pkey.get(), NULL));
        return ctx && EVP_PKEY_check(ctx.get()) > 0;
    }
    default: {
#if defined(CRYPTO_BACKEND_OPENSSL3)
        auto pkey = load_nist_privkey(key_.data(), key_.size(), curve_);
        if (!pkey) {
            return false;
        }
        rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new(pkey.get(), NULL));
        return ctx && EVP_PKEY_private_check(ctx.get()) > 0;
#else
        return false;
#endif
    }
    }
}

#endif /* ENABLE_CRYPTO_REFRESH */

#endif /* ENABLE_CRYPTO_REFRESH || ENABLE_PQC */
