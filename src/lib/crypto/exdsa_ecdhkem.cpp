/*
 * Copyright (c) 2023, [MTG AG](https://www.mtg.de).
 * Copyright (c) 2026 [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "exdsa_ecdhkem.h"
#include <botan/ffi.h>
#include "botan_utils.hpp"
#include "ed25519_ed448.h"
#include "ecdsa.h"
#include "ec.h"
#include "types.h"
#include "logging.h"
#include "string.h"
#include "utils.h"
#include <cassert>

namespace {

const char *
curve_botan_name(pgp_curve_t curve)
{
    auto ec_desc = pgp::ec::Curve::get(curve);
    return ec_desc ? ec_desc->botan_name : nullptr;
}

bool
load_ec_privkey(rnp::botan::Privkey &out,
                int (*loader)(botan_privkey_t *, botan_mp_t, const char *),
                const uint8_t *scalar,
                size_t         scalar_len,
                pgp_curve_t    curve)
{
    const char *name = curve_botan_name(curve);
    if (!name) {
        return false;
    }
    rnp::bn s(scalar, scalar_len);
    return s && !loader(&out.get(), s.get(), name);
}

bool
load_ec_pubkey(rnp::botan::Pubkey &out,
               int (*loader)(botan_pubkey_t *, const uint8_t *, size_t, const char *),
               const uint8_t *sec1,
               size_t         sec1_len,
               pgp_curve_t    curve)
{
    const char *name = curve_botan_name(curve);
    if (!name) {
        return false;
    }
    return !loader(&out.get(), sec1, sec1_len, name);
}

bool
export_agreement_public(botan_privkey_t priv, std::vector<uint8_t> &out)
{
    /* The length query returns the size via out_len but signals it via
     * BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE rather than success. */
    size_t len = 0;
    botan_pk_op_key_agreement_export_public(priv, nullptr, &len);
    if (!len) {
        return false;
    }
    out.resize(len);
    if (botan_pk_op_key_agreement_export_public(priv, out.data(), &len)) {
        return false;
    }
    out.resize(len);
    return true;
}

} // namespace

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

std::vector<uint8_t>
ecdh_kem_private_key_t::get_pubkey_encoded(rnp::RNG *rng) const
{
    (void) rng;
    rnp::botan::Privkey priv;
    bool                ok = false;
    switch (curve_) {
    case PGP_CURVE_25519:
        ok = (key_.size() == 32) && !botan_privkey_load_x25519(&priv.get(), key_.data());
        break;
    case PGP_CURVE_448:
        ok = (key_.size() == 56) && !botan_privkey_load_x448(&priv.get(), key_.data());
        break;
    default:
        ok = load_ec_privkey(priv, botan_privkey_load_ecdh, key_.data(), key_.size(), curve_);
        break;
    }
    std::vector<uint8_t> out;
    if (ok) {
        export_agreement_public(priv.get(), out);
    }
    return out;
}

rnp_result_t
ecdh_kem_public_key_t::encapsulate(rnp::RNG *            rng,
                                   std::vector<uint8_t> &ciphertext,
                                   std::vector<uint8_t> &symmetric_key) const
{
    const char *alg = nullptr;
    const char *params = nullptr;
    switch (curve_) {
    case PGP_CURVE_25519:
        alg = "X25519";
        break;
    case PGP_CURVE_448:
        alg = "X448";
        break;
    default:
        alg = "ECDH";
        params = curve_botan_name(curve_);
        break;
    }
    if (!params && curve_ != PGP_CURVE_25519 && curve_ != PGP_CURVE_448) {
        return RNP_ERROR_NOT_SUPPORTED;
    }

    rnp::botan::Privkey eph_prv;
    if (botan_privkey_create(&eph_prv.get(), alg, params ? params : "", rng->handle())) {
        return RNP_ERROR_GENERIC;
    }
    if (!export_agreement_public(eph_prv.get(), ciphertext)) {
        return RNP_ERROR_GENERIC;
    }

    rnp::botan::op::KeyAgreement op;
    if (botan_pk_op_key_agreement_create(&op.get(), eph_prv.get(), "Raw", 0)) {
        return RNP_ERROR_GENERIC;
    }
    size_t slen = 0;
    if (botan_pk_op_key_agreement_size(op.get(), &slen)) {
        return RNP_ERROR_GENERIC;
    }
    symmetric_key.assign(slen, 0);
    if (botan_pk_op_key_agreement(
          op.get(), symmetric_key.data(), &slen, key_.data(), key_.size(), NULL, 0)) {
        return RNP_ERROR_GENERIC;
    }
    symmetric_key.resize(slen);
    return RNP_SUCCESS;
}

rnp_result_t
ecdh_kem_private_key_t::decapsulate(rnp::RNG *                  rng,
                                    const std::vector<uint8_t> &ciphertext,
                                    std::vector<uint8_t> &      plaintext)
{
    (void) rng;
    rnp::botan::Privkey priv;
    bool                ok = false;
    switch (curve_) {
    case PGP_CURVE_25519:
        ok = (key_.size() == 32) && !botan_privkey_load_x25519(&priv.get(), key_.data());
        break;
    case PGP_CURVE_448:
        ok = (key_.size() == 56) && !botan_privkey_load_x448(&priv.get(), key_.data());
        break;
    default:
        ok = load_ec_privkey(priv, botan_privkey_load_ecdh, key_.data(), key_.size(), curve_);
        break;
    }
    if (!ok) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp::botan::op::KeyAgreement op;
    if (botan_pk_op_key_agreement_create(&op.get(), priv.get(), "Raw", 0)) {
        return RNP_ERROR_GENERIC;
    }
    size_t slen = 0;
    if (botan_pk_op_key_agreement_size(op.get(), &slen)) {
        return RNP_ERROR_GENERIC;
    }
    plaintext.assign(slen, 0);
    if (botan_pk_op_key_agreement(
          op.get(), plaintext.data(), &slen, ciphertext.data(), ciphertext.size(), NULL, 0)) {
        return RNP_ERROR_GENERIC;
    }
    plaintext.resize(slen);
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
        rnp::botan::Privkey priv_key;
        if (!load_ec_privkey(
              priv_key, botan_privkey_load_ecdsa, key_.data(), key_.size(), curve_)) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        rnp::botan::op::Sign signer;
        const char *         pad = pgp::ecdsa::padding_str_for(hash_alg);
        if (botan_pk_op_sign_create(&signer.get(), priv_key.get(), pad, 0) ||
            botan_pk_op_sign_update(signer.get(), hash, hash_len)) {
            return RNP_ERROR_SIGNING_FAILED;
        }
        size_t sig_len = 0;
        if (botan_pk_op_sign_output_length(signer.get(), &sig_len) || !sig_len) {
            return RNP_ERROR_SIGNING_FAILED;
        }
        sig_out.assign(sig_len, 0);
        if (botan_pk_op_sign_finish(signer.get(), rng->handle(), sig_out.data(), &sig_len)) {
            return RNP_ERROR_SIGNING_FAILED;
        }
        sig_out.resize(sig_len);
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
        rnp::botan::Pubkey pub_key;
        if (!load_ec_pubkey(
              pub_key, botan_pubkey_load_ecdsa_sec1, key_.data(), key_.size(), curve_)) {
            return RNP_ERROR_SIGNATURE_INVALID;
        }
        rnp::botan::op::Verify verifier;
        const char *           pad = pgp::ecdsa::padding_str_for(hash_alg);
        if (botan_pk_op_verify_create(&verifier.get(), pub_key.get(), pad, 0) ||
            botan_pk_op_verify_update(verifier.get(), hash, hash_len)) {
            return RNP_ERROR_SIGNATURE_INVALID;
        }
        if (botan_pk_op_verify_finish(verifier.get(), sig.data(), sig.size())) {
            return RNP_ERROR_SIGNATURE_INVALID;
        }
        return RNP_SUCCESS;
    }
    }
}

bool
exdsa_public_key_t::is_valid(rnp::RNG *rng) const
{
    rnp::botan::Pubkey pub_key;
    bool               ok = false;
    switch (curve_) {
    case PGP_CURVE_ED25519:
        ok = (key_.size() == 32) && !botan_pubkey_load_ed25519(&pub_key.get(), key_.data());
        break;
    case PGP_CURVE_ED448:
        ok = (key_.size() == 57) && !botan_pubkey_load_ed448(&pub_key.get(), key_.data());
        break;
    default:
        ok = load_ec_pubkey(
          pub_key, botan_pubkey_load_ecdsa_sec1, key_.data(), key_.size(), curve_);
        break;
    }
    return ok && !botan_pubkey_check_key(pub_key.get(), rng->handle(), 0);
}

bool
exdsa_private_key_t::is_valid(rnp::RNG *rng) const
{
    rnp::botan::Privkey priv_key;
    bool                ok = false;
    switch (curve_) {
    case PGP_CURVE_ED25519:
        ok = (key_.size() == 32) && !botan_privkey_load_ed25519(&priv_key.get(), key_.data());
        break;
    case PGP_CURVE_ED448:
        ok = (key_.size() == 57) && !botan_privkey_load_ed448(&priv_key.get(), key_.data());
        break;
    default:
        ok = load_ec_privkey(
          priv_key, botan_privkey_load_ecdsa, key_.data(), key_.size(), curve_);
        break;
    }
    return ok && !botan_privkey_check_key(priv_key.get(), rng->handle(), 0);
}

bool
ecdh_kem_public_key_t::is_valid(rnp::RNG *rng) const
{
    rnp::botan::Pubkey pub_key;
    bool               ok = false;
    switch (curve_) {
    case PGP_CURVE_25519:
        ok = (key_.size() == 32) && !botan_pubkey_load_x25519(&pub_key.get(), key_.data());
        break;
    case PGP_CURVE_448:
        ok = (key_.size() == 56) && !botan_pubkey_load_x448(&pub_key.get(), key_.data());
        break;
    default:
        ok = load_ec_pubkey(
          pub_key, botan_pubkey_load_ecdh_sec1, key_.data(), key_.size(), curve_);
        break;
    }
    return ok && !botan_pubkey_check_key(pub_key.get(), rng->handle(), 0);
}

bool
ecdh_kem_private_key_t::is_valid(rnp::RNG *rng) const
{
    rnp::botan::Privkey priv_key;
    bool                ok = false;
    switch (curve_) {
    case PGP_CURVE_25519:
        ok = (key_.size() == 32) && !botan_privkey_load_x25519(&priv_key.get(), key_.data());
        break;
    case PGP_CURVE_448:
        ok = (key_.size() == 56) && !botan_privkey_load_x448(&priv_key.get(), key_.data());
        break;
    default:
        ok =
          load_ec_privkey(priv_key, botan_privkey_load_ecdh, key_.data(), key_.size(), curve_);
        break;
    }
    return ok && !botan_privkey_check_key(priv_key.get(), rng->handle(), 0);
}
