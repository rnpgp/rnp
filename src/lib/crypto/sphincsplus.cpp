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

#include "sphincsplus.h"
#include <botan/ffi.h>
#include "botan_utils.hpp"
#include <cassert>
#include "logging.h"
#include "types.h"

namespace {

/* SLH-DSA mode string for Botan's FFI (SHAKE variants used by rnp). */
const char *
sphincsplus_mode_str(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_SPHINCSPLUS_SHAKE_128f:
        return "SLH-DSA-SHAKE-128f";
    case PGP_PKA_SPHINCSPLUS_SHAKE_128s:
        return "SLH-DSA-SHAKE-128s";
    case PGP_PKA_SPHINCSPLUS_SHAKE_256s:
        return "SLH-DSA-SHAKE-256s";
    default:
        RNP_LOG("invalid algorithm ID given");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
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
    : key_encoded_(key_encoded.data(), key_encoded.size()), pk_alg_(alg), is_initialized_(true)
{
}

rnp_result_t
pgp_sphincsplus_private_key_t::sign(rnp::RNG *                   rng,
                                    pgp_sphincsplus_signature_t *sig,
                                    const uint8_t *              msg,
                                    size_t                       msg_len) const
{
    assert(is_initialized_);
    rnp::botan::Privkey priv_key;
    if (botan_privkey_load_slh_dsa(&priv_key.get(),
                                   key_encoded_.data(),
                                   key_encoded_.size(),
                                   sphincsplus_mode_str(pk_alg_))) {
        RNP_LOG("Failed to load SLH-DSA private key");
        return RNP_ERROR_GENERIC;
    }

    rnp::botan::op::Sign signer;
    if (botan_pk_op_sign_create(&signer.get(), priv_key.get(), "", 0) ||
        botan_pk_op_sign_update(signer.get(), msg, msg_len)) {
        return RNP_ERROR_SIGNING_FAILED;
    }
    size_t sig_len = 0;
    if (botan_pk_op_sign_output_length(signer.get(), &sig_len) || !sig_len) {
        return RNP_ERROR_SIGNING_FAILED;
    }
    sig->sig.assign(sig_len, 0);
    if (botan_pk_op_sign_finish(signer.get(), rng->handle(), sig->sig.data(), &sig_len)) {
        RNP_LOG("SLH-DSA signing failed");
        return RNP_ERROR_SIGNING_FAILED;
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
    rnp::botan::Pubkey pub_key;
    if (botan_pubkey_load_slh_dsa(&pub_key.get(),
                                  key_encoded_.data(),
                                  key_encoded_.size(),
                                  sphincsplus_mode_str(pk_alg_))) {
        RNP_LOG("Failed to load SLH-DSA public key");
        return RNP_ERROR_SIGNATURE_INVALID;
    }

    rnp::botan::op::Verify verifier;
    if (botan_pk_op_verify_create(&verifier.get(), pub_key.get(), "", 0) ||
        botan_pk_op_verify_update(verifier.get(), msg, msg_len)) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    if (botan_pk_op_verify_finish(verifier.get(), sig->sig.data(), sig->sig.size())) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    return RNP_SUCCESS;
}

std::pair<pgp_sphincsplus_public_key_t, pgp_sphincsplus_private_key_t>
sphincsplus_generate_keypair(rnp::RNG *rng, pgp_pubkey_alg_t alg)
{
    const char *mode = sphincsplus_mode_str(alg);

    rnp::botan::Privkey priv_key;
    if (botan_privkey_create(&priv_key.get(), "SLH-DSA", mode, rng->handle())) {
        RNP_LOG("SLH-DSA key generation failed");
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    std::vector<uint8_t> priv_bits;
    if (botan_privkey_view_raw(priv_key.get(), &priv_bits, rnp_botan_view_bin_vec)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    rnp::botan::Pubkey pub_key;
    if (botan_privkey_export_pubkey(&pub_key.get(), priv_key.get())) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    std::vector<uint8_t> pub_bits;
    if (botan_pubkey_view_raw(pub_key.get(), &pub_bits, rnp_botan_view_bin_vec)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    return std::make_pair(
      pgp_sphincsplus_public_key_t(pub_bits, alg),
      pgp_sphincsplus_private_key_t(priv_bits.data(), priv_bits.size(), alg));
}

rnp_result_t
pgp_sphincsplus_generate(rnp::RNG *rng, pgp_sphincsplus_key_t *material, pgp_pubkey_alg_t alg)
{
    auto keypair = sphincsplus_generate_keypair(rng, alg);
    material->pub = keypair.first;
    material->priv = keypair.second;

    return RNP_SUCCESS;
}

bool
pgp_sphincsplus_public_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    rnp::botan::Pubkey key;
    if (botan_pubkey_load_slh_dsa(&key.get(),
                                  key_encoded_.data(),
                                  key_encoded_.size(),
                                  sphincsplus_mode_str(pk_alg_))) {
        return false;
    }
    return !botan_pubkey_check_key(key.get(), rng->handle(), 0);
}

bool
pgp_sphincsplus_private_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    rnp::botan::Privkey key;
    if (botan_privkey_load_slh_dsa(&key.get(),
                                   key_encoded_.data(),
                                   key_encoded_.size(),
                                   sphincsplus_mode_str(pk_alg_))) {
        return false;
    }
    return !botan_privkey_check_key(key.get(), rng->handle(), 0);
}

rnp_result_t
sphincsplus_validate_key(rnp::RNG *rng, const pgp_sphincsplus_key_t *key, bool secret)
{
    bool valid;

    valid = key->pub.is_valid(rng);
    if (secret) {
        valid = valid && key->priv.is_valid(rng);
    }
    if (!valid) {
        return RNP_ERROR_GENERIC;
    }

    return RNP_SUCCESS;
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
