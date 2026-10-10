/*
 * Copyright (c) 2023, [MTG AG](https://www.mtg.de).
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

#include "ed25519_ed448.h"
#include "logging.h"
#include "utils.h"

#include <botan/ffi.h>
#include "botan_utils.hpp"
#include <cassert>
#include <string.h>

rnp_result_t
generate_ed25519_native(rnp::RNG *            rng,
                        std::vector<uint8_t> &privkey,
                        std::vector<uint8_t> &pubkey)
{
    rnp::botan::Privkey private_key;
    if (botan_privkey_create(&private_key.get(), "Ed25519", NULL, rng->handle())) {
        return RNP_ERROR_GENERIC;
    }
    /* botan returns the 32-byte seed followed by the 32-byte public key */
    uint8_t            key_bits[64];
    rnp_botan_view_buf vb{key_bits, sizeof(key_bits)};
    if (botan_privkey_view_raw(private_key.get(), &vb, rnp_botan_view_bin)) {
        return RNP_ERROR_GENERIC;
    }
    const size_t key_len = 32;
    privkey.assign(key_bits, key_bits + key_len);
    pubkey.assign(key_bits + key_len, key_bits + 2 * key_len);
    return RNP_SUCCESS;
}

rnp_result_t
ed25519_sign_native(rnp::RNG *                  rng,
                    std::vector<uint8_t> &      sig_out,
                    const std::vector<uint8_t> &key,
                    const uint8_t *             hash,
                    size_t                      hash_len)
{
    if (key.size() != 32) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::Privkey priv_key;
    if (botan_privkey_load_ed25519(&priv_key.get(), key.data())) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::op::Sign signer;
    if (botan_pk_op_sign_create(&signer.get(), priv_key.get(), "Pure", 0) ||
        botan_pk_op_sign_update(signer.get(), hash, hash_len)) {
        return RNP_ERROR_SIGNING_FAILED;
    }
    uint8_t buf[64];
    size_t  sig_len = sizeof(buf);
    if (botan_pk_op_sign_finish(signer.get(), rng->handle(), buf, &sig_len)) {
        return RNP_ERROR_SIGNING_FAILED;
    }
    sig_out.assign(buf, buf + sig_len);
    return RNP_SUCCESS;
}

rnp_result_t
ed25519_verify_native(const std::vector<uint8_t> &sig,
                      const std::vector<uint8_t> &key,
                      const uint8_t *             hash,
                      size_t                      hash_len)
{
    if (key.size() != 32) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::Pubkey pub_key;
    if (botan_pubkey_load_ed25519(&pub_key.get(), key.data())) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::op::Verify verifier;
    if (botan_pk_op_verify_create(&verifier.get(), pub_key.get(), "Pure", 0) ||
        botan_pk_op_verify_update(verifier.get(), hash, hash_len)) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    if (botan_pk_op_verify_finish(verifier.get(), sig.data(), sig.size())) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    return RNP_SUCCESS;
}

rnp_result_t
ed25519_validate_key_native(rnp::RNG *rng, const pgp_ed25519_key_t *key, bool secret)
{
    if (key->pub.size() != 32) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::Pubkey pub_key;
    if (botan_pubkey_load_ed25519(&pub_key.get(), key->pub.data()) ||
        botan_pubkey_check_key(pub_key.get(), rng->handle(), 0)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (secret) {
        if (key->priv.size() != 32) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        rnp::botan::Privkey priv_key;
        if (botan_privkey_load_ed25519(&priv_key.get(), key->priv.data()) ||
            botan_privkey_check_key(priv_key.get(), rng->handle(), 0)) {
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
    rnp::botan::Privkey private_key;
    if (botan_privkey_create(&private_key.get(), "Ed448", NULL, rng->handle())) {
        return RNP_ERROR_GENERIC;
    }
    uint8_t            priv[57];
    rnp_botan_view_buf priv_vb{priv, sizeof(priv)};
    if (botan_privkey_view_raw(private_key.get(), &priv_vb, rnp_botan_view_bin)) {
        return RNP_ERROR_GENERIC;
    }
    rnp::botan::Pubkey pub_key;
    if (botan_privkey_export_pubkey(&pub_key.get(), private_key.get())) {
        return RNP_ERROR_GENERIC;
    }
    uint8_t            pub[57];
    rnp_botan_view_buf pub_vb{pub, sizeof(pub)};
    if (botan_pubkey_view_raw(pub_key.get(), &pub_vb, rnp_botan_view_bin)) {
        return RNP_ERROR_GENERIC;
    }
    privkey.assign(priv, priv + 57);
    pubkey.assign(pub, pub + 57);
    return RNP_SUCCESS;
}

rnp_result_t
ed448_sign_native(rnp::RNG *                  rng,
                  std::vector<uint8_t> &      sig_out,
                  const std::vector<uint8_t> &key,
                  const uint8_t *             hash,
                  size_t                      hash_len)
{
    if (key.size() != 57) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::Privkey priv_key;
    if (botan_privkey_load_ed448(&priv_key.get(), key.data())) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::op::Sign signer;
    if (botan_pk_op_sign_create(&signer.get(), priv_key.get(), "Pure", 0) ||
        botan_pk_op_sign_update(signer.get(), hash, hash_len)) {
        return RNP_ERROR_SIGNING_FAILED;
    }
    uint8_t buf[114];
    size_t  sig_len = sizeof(buf);
    if (botan_pk_op_sign_finish(signer.get(), rng->handle(), buf, &sig_len)) {
        return RNP_ERROR_SIGNING_FAILED;
    }
    sig_out.assign(buf, buf + sig_len);
    return RNP_SUCCESS;
}

rnp_result_t
ed448_verify_native(const std::vector<uint8_t> &sig,
                    const std::vector<uint8_t> &key,
                    const uint8_t *             hash,
                    size_t                      hash_len)
{
    if (key.size() != 57) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::Pubkey pub_key;
    if (botan_pubkey_load_ed448(&pub_key.get(), key.data())) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::op::Verify verifier;
    if (botan_pk_op_verify_create(&verifier.get(), pub_key.get(), "Pure", 0) ||
        botan_pk_op_verify_update(verifier.get(), hash, hash_len)) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    if (botan_pk_op_verify_finish(verifier.get(), sig.data(), sig.size())) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    return RNP_SUCCESS;
}

rnp_result_t
ed448_validate_key_native(rnp::RNG *rng, const pgp_ed448_key_t *key, bool secret)
{
    if (key->pub.size() != 57) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::Pubkey pub_key;
    if (botan_pubkey_load_ed448(&pub_key.get(), key->pub.data()) ||
        botan_pubkey_check_key(pub_key.get(), rng->handle(), 0)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (secret) {
        if (key->priv.size() != 57) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        rnp::botan::Privkey priv_key;
        if (botan_privkey_load_ed448(&priv_key.get(), key->priv.data()) ||
            botan_privkey_check_key(priv_key.get(), rng->handle(), 0)) {
            return RNP_ERROR_SIGNING_FAILED;
        }
    }
    return RNP_SUCCESS;
}
#endif
