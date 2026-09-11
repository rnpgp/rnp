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

#include "kyber.h"
#include <botan/ffi.h>
#include "botan_utils.hpp"
#include "types.h"
#include "logging.h"
#include <utility>
#include <vector>
#include <cassert>

namespace {

const char *
kyber_mode_str(kyber_parameter_e mode)
{
    return mode == kyber_768 ? "ML-KEM-768" : "ML-KEM-1024";
}

uint32_t
kyber_key_share_size()
{
    return 32;
}

} // namespace

std::pair<pgp_kyber_public_key_t, pgp_kyber_private_key_t>
kyber_generate_keypair(rnp::RNG *rng, kyber_parameter_e kyber_param)
{
    const char *mode = kyber_mode_str(kyber_param);

    rnp::botan::Privkey kyber_priv;
    if (botan_privkey_create(&kyber_priv.get(), "ML-KEM", mode, rng->handle())) {
        RNP_LOG("ML-KEM key generation failed");
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    std::vector<uint8_t> encoded_private_key;
    if (botan_privkey_view_raw(
          kyber_priv.get(), &encoded_private_key, rnp_botan_view_bin_vec)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    rnp::botan::Pubkey kyber_pub;
    if (botan_privkey_export_pubkey(&kyber_pub.get(), kyber_priv.get())) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    std::vector<uint8_t> encoded_public_key;
    if (botan_pubkey_view_raw(kyber_pub.get(), &encoded_public_key, rnp_botan_view_bin_vec)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    return std::make_pair(pgp_kyber_public_key_t(encoded_public_key, kyber_param),
                          pgp_kyber_private_key_t(encoded_private_key.data(),
                                                  encoded_private_key.size(),
                                                  kyber_param));
}

kyber_encap_result_t
pgp_kyber_public_key_t::encapsulate(rnp::RNG *rng) const
{
    assert(is_initialized_);
    rnp::botan::Pubkey pub;
    if (botan_pubkey_load_ml_kem(
          &pub.get(), key_encoded_.data(), key_encoded_.size(), kyber_mode_str(kyber_mode_))) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    rnp::botan::op::KemEncrypt kem_enc;
    if (botan_pk_op_kem_encrypt_create(&kem_enc.get(), pub.get(), "Raw")) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    size_t encap_len = 0;
    size_t shared_len = 0;
    if (botan_pk_op_kem_encrypt_encapsulated_key_length(kem_enc.get(), &encap_len) ||
        botan_pk_op_kem_encrypt_shared_key_length(
          kem_enc.get(), kyber_key_share_size(), &shared_len)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    kyber_encap_result_t result;
    result.ciphertext.assign(encap_len, 0);
    result.symmetric_key.assign(shared_len, 0);
    if (botan_pk_op_kem_encrypt_create_shared_key(kem_enc.get(),
                                                  rng->handle(),
                                                  NULL,
                                                  0,
                                                  kyber_key_share_size(),
                                                  result.symmetric_key.data(),
                                                  &shared_len,
                                                  result.ciphertext.data(),
                                                  &encap_len)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    result.ciphertext.resize(encap_len);
    result.symmetric_key.resize(shared_len);
    return result;
}

std::vector<uint8_t>
pgp_kyber_private_key_t::decapsulate(rnp::RNG *     rng,
                                     const uint8_t *ciphertext,
                                     size_t         ciphertext_len)
{
    (void) rng;
    assert(is_initialized_);
    rnp::botan::Privkey priv;
    if (botan_privkey_load_ml_kem(&priv.get(),
                                  key_encoded_.data(),
                                  key_encoded_.size(),
                                  kyber_mode_str(kyber_mode_))) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    rnp::botan::op::KemDecrypt kem_dec;
    if (botan_pk_op_kem_decrypt_create(&kem_dec.get(), priv.get(), "Raw")) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    size_t shared_len = 0;
    if (botan_pk_op_kem_decrypt_shared_key_length(
          kem_dec.get(), kyber_key_share_size(), &shared_len)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    std::vector<uint8_t> shared(shared_len, 0);
    if (botan_pk_op_kem_decrypt_shared_key(kem_dec.get(),
                                           NULL,
                                           0,
                                           ciphertext,
                                           ciphertext_len,
                                           kyber_key_share_size(),
                                           shared.data(),
                                           &shared_len)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    shared.resize(shared_len);
    return shared;
}

bool
pgp_kyber_public_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    rnp::botan::Pubkey key;
    if (botan_pubkey_load_ml_kem(
          &key.get(), key_encoded_.data(), key_encoded_.size(), kyber_mode_str(kyber_mode_))) {
        return false;
    }
    return !botan_pubkey_check_key(key.get(), rng->handle(), 0);
}

bool
pgp_kyber_private_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }
    rnp::botan::Privkey key;
    if (botan_privkey_load_ml_kem(
          &key.get(), key_encoded_.data(), key_encoded_.size(), kyber_mode_str(kyber_mode_))) {
        return false;
    }
    return !botan_privkey_check_key(key.get(), rng->handle(), 0);
}
