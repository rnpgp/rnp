/*
 * Copyright (c) 2023, [MTG AG](https://www.mtg.de).
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

#include "exdsa_ecdhkem.h"
#include <botan/secmem.h>
#include <botan/pubkey.h>
#include <botan/ecdh.h>
#include <botan/ecdsa.h>
#include <botan/ed25519.h>
#include <botan/x25519.h>
#if defined(ENABLE_CRYPTO_REFRESH)
#include <botan/x448.h>
#include <botan/ed448.h>
#endif
#include "ecdh.h"
#include "ed25519_ed448.h"
#include "ecdsa.h"
#include "ec.h"
#include "types.h"
#include "logging.h"
#include "string.h"
#include "utils.h"
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

static Botan::ECDH_PrivateKey
ecdh_kem_privkey_from_bytes(rnp::RNG *  rng,
                            const uint8_t *key_data,
                            size_t         key_size,
                            pgp_curve_t    curve)
{
    assert(curve >= PGP_CURVE_NIST_P_256 && curve <= PGP_CURVE_P256K1);
    auto ec_desc = pgp::ec::Curve::get(curve);
    return Botan::ECDH_PrivateKey(*(rng->obj()),
                                  Botan::EC_Group::from_name(ec_desc->botan_name),
                                  Botan::BigInt(key_data, key_size));
}

static Botan::ECDH_PublicKey
ecdh_kem_pubkey_from_bytes(rnp::RNG *                   rng,
                           const std::vector<uint8_t> &key,
                           pgp_curve_t                  curve)
{
    assert(curve >= PGP_CURVE_NIST_P_256 && curve <= PGP_CURVE_P256K1);
    auto            ec_desc = pgp::ec::Curve::get(curve);
    Botan::EC_Group group = Botan::EC_Group::from_name(ec_desc->botan_name);
    return Botan::ECDH_PublicKey(group, Botan::EC_AffinePoint(group, key).to_legacy_point());
}

static Botan::X25519_PrivateKey
x25519_privkey_from_bytes(const uint8_t *key_data, size_t key_size)
{
    Botan::secure_vector<uint8_t> sv(key_data, key_data + key_size);
    return Botan::X25519_PrivateKey(sv);
}

static Botan::X25519_PublicKey
x25519_pubkey_from_bytes(const std::vector<uint8_t> &key)
{
    return Botan::X25519_PublicKey(key);
}

#if defined(ENABLE_CRYPTO_REFRESH)
static Botan::X448_PrivateKey
x448_privkey_from_bytes(const uint8_t *key_data, size_t key_size)
{
    Botan::secure_vector<uint8_t> sv(key_data, key_data + key_size);
    return Botan::X448_PrivateKey(sv);
}

static Botan::X448_PublicKey
x448_pubkey_from_bytes(const std::vector<uint8_t> &key)
{
    return Botan::X448_PublicKey(key);
}
#endif

std::vector<uint8_t>
ecdh_kem_private_key_t::get_pubkey_encoded(rnp::RNG *rng) const
{
    switch (curve_) {
    case PGP_CURVE_25519: {
        Botan::X25519_PrivateKey botan_key = x25519_privkey_from_bytes(key_.data(), key_.size());
        return botan_key.public_value();
    }
#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_CURVE_448: {
        Botan::X448_PrivateKey botan_key = x448_privkey_from_bytes(key_.data(), key_.size());
        return botan_key.public_value();
    }
#endif
    default: {
        Botan::ECDH_PrivateKey botan_key = ecdh_kem_privkey_from_bytes(rng, key_.data(), key_.size(), curve_);
        return botan_key.public_value();
    }
    }
}

rnp_result_t
ecdh_kem_public_key_t::encapsulate(rnp::RNG *            rng,
                                   std::vector<uint8_t> &ciphertext,
                                   std::vector<uint8_t> &symmetric_key) const
{
    switch (curve_) {
    case PGP_CURVE_25519: {
        Botan::X25519_PrivateKey eph_prv_key(*(rng->obj()));
        ciphertext = eph_prv_key.public_value();
        Botan::PK_Key_Agreement key_agreement(eph_prv_key, *(rng->obj()), "Raw");
        symmetric_key = Botan::unlock(key_agreement.derive_key(0, key_).bits_of());
        break;
    }
#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_CURVE_448: {
        Botan::X448_PrivateKey eph_prv_key(*(rng->obj()));
        ciphertext = eph_prv_key.public_value();
        Botan::PK_Key_Agreement key_agreement(eph_prv_key, *(rng->obj()), "Raw");
        symmetric_key = Botan::unlock(key_agreement.derive_key(0, key_).bits_of());
        break;
    }
#endif
    default: {
        auto curve_desc = pgp::ec::Curve::get(curve_);
        if (!curve_desc) {
            RNP_LOG("unknown curve");
            return RNP_ERROR_NOT_SUPPORTED;
        }

        Botan::EC_Group         domain = Botan::EC_Group::from_name(curve_desc->botan_name);
        Botan::ECDH_PrivateKey  eph_prv_key(*(rng->obj()), domain);
        Botan::PK_Key_Agreement key_agreement(eph_prv_key, *(rng->obj()), "Raw");
        ciphertext = eph_prv_key.public_value();
        symmetric_key = Botan::unlock(key_agreement.derive_key(0, key_).bits_of());
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
        Botan::X25519_PrivateKey priv_key = x25519_privkey_from_bytes(key_.data(), key_.size());
        Botan::PK_Key_Agreement  key_agreement(priv_key, *(rng->obj()), "Raw");
        plaintext = Botan::unlock(key_agreement.derive_key(0, ciphertext).bits_of());
        break;
    }
#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_CURVE_448: {
        Botan::X448_PrivateKey  priv_key = x448_privkey_from_bytes(key_.data(), key_.size());
        Botan::PK_Key_Agreement key_agreement(priv_key, *(rng->obj()), "Raw");
        plaintext = Botan::unlock(key_agreement.derive_key(0, ciphertext).bits_of());
        break;
    }
#endif
    default: {
        Botan::ECDH_PrivateKey  priv_key = ecdh_kem_privkey_from_bytes(rng, key_.data(), key_.size(), curve_);
        Botan::PK_Key_Agreement key_agreement(priv_key, *(rng->obj()), "Raw");
        plaintext = Botan::unlock(key_agreement.derive_key(0, ciphertext).bits_of());
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

static Botan::ECDSA_PrivateKey
exdsa_privkey_from_bytes(rnp::RNG *     rng,
                         const uint8_t *key_data,
                         size_t         key_size,
                         pgp_curve_t    curve)
{
    auto ec_desc = pgp::ec::Curve::get(curve);
    return Botan::ECDSA_PrivateKey(*(rng->obj()),
                                   Botan::EC_Group::from_name(ec_desc->botan_name),
                                   Botan::BigInt(key_data, key_size));
}

static Botan::ECDSA_PublicKey
exdsa_pubkey_from_bytes(const std::vector<uint8_t> &key, pgp_curve_t curve)
{
    /* format: 04 | X | Y */
    auto            ec_desc = pgp::ec::Curve::get(curve);
    Botan::EC_Group group = Botan::EC_Group::from_name(ec_desc->botan_name);
    return Botan::ECDSA_PublicKey(group, Botan::EC_AffinePoint(group, key).to_legacy_point());
}

/* NOTE hash_alg unused for Ed/X curves */
rnp_result_t
exdsa_private_key_t::sign(rnp::RNG *            rng,
                          std::vector<uint8_t> &sig_out,
                          const uint8_t *       hash,
                          size_t                hash_len,
                          pgp_hash_alg_t        hash_alg) const
{
    switch (curve_) {
    case PGP_CURVE_ED25519: {
        return ed25519_sign_native(rng, sig_out, key_.unlock(), hash, hash_len);
    }
    case PGP_CURVE_ED448: {
        return ed448_sign_native(rng, sig_out, key_.unlock(), hash, hash_len);
    }
    default: {
        Botan::ECDSA_PrivateKey priv_key = exdsa_privkey_from_bytes(rng, key_.data(), key_.size(), curve_);
        auto                    signer =
          Botan::PK_Signer(priv_key, *(rng->obj()), pgp::ecdsa::padding_str_for(hash_alg));
        sig_out = signer.sign_message(hash, hash_len, *(rng->obj()));
        return RNP_SUCCESS;
    }
    }
}

rnp_result_t
exdsa_public_key_t::verify(const std::vector<uint8_t> &sig,
                           const uint8_t *             hash,
                           size_t                      hash_len,
                           pgp_hash_alg_t              hash_alg) const
{
    switch (curve_) {
    case PGP_CURVE_ED25519: {
        return ed25519_verify_native(sig, key_, hash, hash_len);
    }
    case PGP_CURVE_ED448: {
        return ed448_verify_native(sig, key_, hash, hash_len);
    }
    default: {
        Botan::ECDSA_PublicKey pub_key = exdsa_pubkey_from_bytes(key_, curve_);
        auto verifier = Botan::PK_Verifier(pub_key, pgp::ecdsa::padding_str_for(hash_alg));
        if (verifier.verify_message(hash, hash_len, sig.data(), sig.size())) {
            return RNP_SUCCESS;
        }
    }
    }
    return RNP_ERROR_VERIFICATION_FAILED;
}

bool
exdsa_public_key_t::is_valid(rnp::RNG *rng) const
{
    switch (curve_) {
    case PGP_CURVE_ED25519: {
        Botan::Ed25519_PublicKey pub_key(key_);
        return pub_key.check_key(*(rng->obj()), false);
    }
    case PGP_CURVE_ED448: {
        Botan::Ed448_PublicKey pub_key(key_);
        return pub_key.check_key(*(rng->obj()), false);
    }
    default: {
        Botan::ECDSA_PublicKey pub_key = exdsa_pubkey_from_bytes(key_, curve_);
        return pub_key.check_key(*(rng->obj()), false);
    }
    }
}

bool
exdsa_private_key_t::is_valid(rnp::RNG *rng) const
{
    switch (curve_) {
    case PGP_CURVE_ED25519: {
        Botan::secure_vector<uint8_t> sv(key_.begin(), key_.end());
        Botan::Ed25519_PrivateKey     priv_key(sv);
        return priv_key.check_key(*(rng->obj()), false);
    }
    case PGP_CURVE_ED448: {
        Botan::Ed448_PrivateKey priv_key(key_);
        return priv_key.check_key(*(rng->obj()), false);
    }
    default: {
        auto priv_key = exdsa_privkey_from_bytes(rng, key_.data(), key_.size(), curve_);
        return priv_key.check_key(*(rng->obj()), false);
    }
    }
}
#endif

bool
ecdh_kem_public_key_t::is_valid(rnp::RNG *rng) const
{
    switch (curve_) {
    case PGP_CURVE_25519: {
        auto pub_key = x25519_pubkey_from_bytes(key_);
        return pub_key.check_key(*(rng->obj()), false);
    }
#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_CURVE_448: {
        auto pub_key = x448_pubkey_from_bytes(key_);
        return pub_key.check_key(*(rng->obj()), false);
    }
#endif
    default: {
        auto pub_key = ecdh_kem_pubkey_from_bytes(rng, key_, curve_);
        return pub_key.check_key(*(rng->obj()), false);
    }
    }
}

bool
ecdh_kem_private_key_t::is_valid(rnp::RNG *rng) const
{
    switch (curve_) {
    case PGP_CURVE_25519: {
        auto priv_key = x25519_privkey_from_bytes(key_.data(), key_.size());
        return priv_key.check_key(*(rng->obj()), false);
    }
#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_CURVE_448: {
        auto priv_key = x448_privkey_from_bytes(key_.data(), key_.size());
        return priv_key.check_key(*(rng->obj()), false);
    }
#endif
    default: {
        auto priv_key = ecdh_kem_privkey_from_bytes(rng, key_.data(), key_.size(), curve_);
        return priv_key.check_key(*(rng->obj()), false);
    }
    }
}
