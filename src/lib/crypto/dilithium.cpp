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

#include "dilithium.h"
#include <botan/ffi.h>
#include "botan_utils.hpp"
#include "logging.h"
#include "types.h"
#include <cassert>

namespace {

const char *
dilithium_mode_str(dilithium_parameter_e mode)
{
    return mode == dilithium_parameter_e::dilithium_L3 ? "ML-DSA-6x5" : "ML-DSA-8x7";
}

} // namespace

std::vector<uint8_t>
pgp_dilithium_private_key_t::sign(rnp::RNG *rng, const uint8_t *msg, size_t msg_len) const
{
    assert(is_initialized_);
    rnp::botan::Privkey priv_key;
    if (botan_privkey_load_ml_dsa(&priv_key.get(),
                                  key_encoded_.data(),
                                  key_encoded_.size(),
                                  dilithium_mode_str(dilithium_param_))) {
        RNP_LOG("Failed to load ML-DSA private key");
        return std::vector<uint8_t>();
    }

    rnp::botan::op::Sign signer;
    if (botan_pk_op_sign_create(&signer.get(), priv_key.get(), "", 0) ||
        botan_pk_op_sign_update(signer.get(), msg, msg_len)) {
        RNP_LOG("ML-DSA signing init failed");
        return std::vector<uint8_t>();
    }

    size_t sig_len = 0;
    if (botan_pk_op_sign_output_length(signer.get(), &sig_len) || !sig_len) {
        return std::vector<uint8_t>();
    }
    std::vector<uint8_t> signature(sig_len);
    if (botan_pk_op_sign_finish(signer.get(), rng->handle(), signature.data(), &sig_len)) {
        RNP_LOG("ML-DSA signing failed");
        return std::vector<uint8_t>();
    }
    signature.resize(sig_len);
    return signature;
}

bool
pgp_dilithium_public_key_t::verify_signature(const uint8_t *msg,
                                             size_t         msg_len,
                                             const uint8_t *signature,
                                             size_t         signature_len) const
{
    assert(is_initialized_);
    rnp::botan::Pubkey pub_key;
    if (botan_pubkey_load_ml_dsa(&pub_key.get(),
                                 key_encoded_.data(),
                                 key_encoded_.size(),
                                 dilithium_mode_str(dilithium_param_))) {
        RNP_LOG("Failed to load ML-DSA public key");
        return false;
    }

    rnp::botan::op::Verify verifier;
    if (botan_pk_op_verify_create(&verifier.get(), pub_key.get(), "", 0) ||
        botan_pk_op_verify_update(verifier.get(), msg, msg_len)) {
        return false;
    }
    return !botan_pk_op_verify_finish(verifier.get(), signature, signature_len);
}

std::pair<pgp_dilithium_public_key_t, pgp_dilithium_private_key_t>
dilithium_generate_keypair(rnp::RNG *rng, dilithium_parameter_e dilithium_param)
{
    const char *mode = dilithium_mode_str(dilithium_param);

    rnp::botan::Privkey priv_key;
    if (botan_privkey_create(&priv_key.get(), "ML-DSA", mode, rng->handle())) {
        RNP_LOG("ML-DSA key generation failed");
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
      pgp_dilithium_public_key_t(pub_bits, dilithium_param),
      pgp_dilithium_private_key_t(priv_bits.data(), priv_bits.size(), dilithium_param));
}

bool
pgp_dilithium_public_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    rnp::botan::Pubkey key;
    if (botan_pubkey_load_ml_dsa(&key.get(),
                                 key_encoded_.data(),
                                 key_encoded_.size(),
                                 dilithium_mode_str(dilithium_param_))) {
        return false;
    }
    return !botan_pubkey_check_key(key.get(), rng->handle(), 0);
}

bool
pgp_dilithium_private_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    rnp::botan::Privkey key;
    if (botan_privkey_load_ml_dsa(&key.get(),
                                  key_encoded_.data(),
                                  key_encoded_.size(),
                                  dilithium_mode_str(dilithium_param_))) {
        return false;
    }
    return !botan_privkey_check_key(key.get(), rng->handle(), 0);
}
