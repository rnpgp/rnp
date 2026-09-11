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

#include "x25519_x448.h"
#include "exdsa_ecdhkem.h"
#include "hkdf.hpp"
#include "utils.h"
#include "botan_utils.hpp"
#include <botan/ffi.h>
#include <cstdio>
#include <string.h>

static const std::vector<uint8_t> hkdf_x25519_info_str = {
  'O', 'p', 'e', 'n', 'P', 'G', 'P', ' ', 'X', '2', '5', '5', '1', '9'};
#if defined(ENABLE_CRYPTO_REFRESH)
static const std::vector<uint8_t> hkdf_x448_info_str = {
  'O', 'p', 'e', 'n', 'P', 'G', 'P', ' ', 'X', '4', '4', '8'};
#endif

static void
x_hkdf(std::vector<uint8_t> &      derived_key,
       const std::vector<uint8_t> &ephemeral_pubkey_material,
       const std::vector<uint8_t> &recipient_pubkey_material,
       const std::vector<uint8_t> &shared_key,
       const std::vector<uint8_t> &info_str)
{
    auto kdf = rnp::Hkdf::create(PGP_HASH_SHA256);
    derived_key.resize(pgp_key_size(PGP_SA_AES_128)); // 128-bit AES key wrap

    std::vector<uint8_t> kdf_input;
    kdf_input.insert(kdf_input.end(),
                     std::begin(ephemeral_pubkey_material),
                     std::end(ephemeral_pubkey_material));
    kdf_input.insert(kdf_input.end(),
                     std::begin(recipient_pubkey_material),
                     std::end(recipient_pubkey_material));
    kdf_input.insert(kdf_input.end(), std::begin(shared_key), std::end(shared_key));

    kdf->extract_expand(NULL,
                        0, // no salt
                        kdf_input.data(),
                        kdf_input.size(),
                        info_str.data(),
                        info_str.size(),
                        derived_key.data(),
                        derived_key.size());
}

/* AES key wrap (RFC 3394) with the KEK length selecting the AES variant. */
static rnp_result_t
aes_kw_enc(const std::vector<uint8_t> &kek,
           const uint8_t *             in,
           size_t                      in_len,
           std::vector<uint8_t> &      out)
{
    char name[16];
    snprintf(name, sizeof(name), "AES-%zu", 8 * kek.size());
    out.resize(in_len + 8);
    size_t out_len = out.size();
    if (botan_nist_kw_enc(name, 0, in, in_len, kek.data(), kek.size(), out.data(), &out_len)) {
        return RNP_ERROR_ENCRYPT_FAILED;
    }
    out.resize(out_len);
    return RNP_SUCCESS;
}

static rnp_result_t
aes_kw_dec(const std::vector<uint8_t> &kek,
           const uint8_t *             in,
           size_t                      in_len,
           std::vector<uint8_t> &      out)
{
    char name[16];
    snprintf(name, sizeof(name), "AES-%zu", 8 * kek.size());
    out.resize(in_len);
    size_t out_len = out.size();
    if (botan_nist_kw_dec(name, 0, in, in_len, kek.data(), kek.size(), out.data(), &out_len)) {
        return RNP_ERROR_DECRYPT_FAILED;
    }
    out.resize(out_len);
    return RNP_SUCCESS;
}

rnp_result_t
x25519_native_encrypt(rnp::RNG *                  rng,
                      const std::vector<uint8_t> &pubkey,
                      const uint8_t *             in,
                      size_t                      in_len,
                      pgp_x25519_encrypted_t *    encrypted)
{
    rnp_result_t         ret;
    std::vector<uint8_t> shared_key;
    std::vector<uint8_t> derived_key;

    if (!in_len || (in_len % 8) != 0) {
        RNP_LOG("incorrect size of in, AES key wrap requires a multiple of 8 bytes");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* encapsulation */
    ecdh_kem_public_key_t ecdhkem_pubkey(pubkey, PGP_CURVE_25519);
    ret = ecdhkem_pubkey.encapsulate(rng, encrypted->eph_key, shared_key);
    if (ret != RNP_SUCCESS) {
        RNP_LOG("encapsulation failed");
        return ret;
    }

    x_hkdf(derived_key, encrypted->eph_key, pubkey, shared_key, hkdf_x25519_info_str);

    return aes_kw_enc(derived_key, in, in_len, encrypted->enc_sess_key);
}

rnp_result_t
x25519_native_decrypt(rnp::RNG *                    rng,
                      const pgp_x25519_key_t &      keypair,
                      const pgp_x25519_encrypted_t *encrypted,
                      uint8_t *                     decbuf,
                      size_t *                      decbuf_len)
{
    rnp_result_t         ret;
    std::vector<uint8_t> shared_key;
    std::vector<uint8_t> derived_key;

    static const size_t x25519_pubkey_size = 32;
    if (encrypted->eph_key.size() != x25519_pubkey_size) {
        RNP_LOG("Wrong ephemeral public key size");
        return RNP_ERROR_BAD_FORMAT;
    }
    if (!encrypted->enc_sess_key.size()) {
        RNP_LOG("No encrypted session key provided");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* decapsulate */
    ecdh_kem_private_key_t ecdhkem_privkey(keypair.priv, PGP_CURVE_25519);
    ret = ecdhkem_privkey.decapsulate(rng, encrypted->eph_key, shared_key);
    if (ret != RNP_SUCCESS) {
        RNP_LOG("decapsulation failed");
        return ret;
    }

    x_hkdf(derived_key, encrypted->eph_key, keypair.pub, shared_key, hkdf_x25519_info_str);

    std::vector<uint8_t> tmp_out;
    ret = aes_kw_dec(
      derived_key, encrypted->enc_sess_key.data(), encrypted->enc_sess_key.size(), tmp_out);
    if (ret != RNP_SUCCESS) {
        return ret;
    }
    if (*decbuf_len < tmp_out.size()) {
        RNP_LOG("buffer for decryption result too small");
        return RNP_ERROR_DECRYPT_FAILED;
    }
    *decbuf_len = tmp_out.size();
    memcpy(decbuf, tmp_out.data(), tmp_out.size());

    return RNP_SUCCESS;
}

rnp_result_t
x25519_validate_key_native(rnp::RNG *rng, const pgp_x25519_key_t *key, bool secret)
{
    if (key->priv.size() != 32) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::Pubkey pub_key;
    if (botan_pubkey_load_x25519(&pub_key.get(), key->priv.data()) ||
        botan_pubkey_check_key(pub_key.get(), rng->handle(), 0)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (secret) {
        rnp::botan::Privkey priv_key;
        if (botan_privkey_load_x25519(&priv_key.get(), key->priv.data()) ||
            botan_privkey_check_key(priv_key.get(), rng->handle(), 0)) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }
    return RNP_SUCCESS;
}

rnp_result_t
generate_x25519_native(rnp::RNG *            rng,
                       std::vector<uint8_t> &privkey,
                       std::vector<uint8_t> &pubkey)
{
    rnp::botan::Privkey priv_key;
    if (botan_privkey_create(&priv_key.get(), "X25519", NULL, rng->handle())) {
        return RNP_ERROR_GENERIC;
    }
    /* public value (32 bytes) */
    pubkey.assign(32, 0);
    size_t publen = pubkey.size();
    if (botan_pk_op_key_agreement_export_public(priv_key.get(), pubkey.data(), &publen)) {
        return RNP_ERROR_GENERIC;
    }
    pubkey.resize(publen);
    /* private scalar (32 bytes) */
    privkey.assign(32, 0);
    rnp_botan_view_buf vb{privkey.data(), privkey.size()};
    if (botan_privkey_view_raw(priv_key.get(), &vb, rnp_botan_view_bin)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

#if defined(ENABLE_CRYPTO_REFRESH)
rnp_result_t
generate_x448_native(rnp::RNG *            rng,
                     std::vector<uint8_t> &privkey,
                     std::vector<uint8_t> &pubkey)
{
    rnp::botan::Privkey priv_key;
    if (botan_privkey_create(&priv_key.get(), "X448", NULL, rng->handle())) {
        return RNP_ERROR_GENERIC;
    }
    pubkey.assign(56, 0);
    size_t publen = pubkey.size();
    if (botan_pk_op_key_agreement_export_public(priv_key.get(), pubkey.data(), &publen)) {
        return RNP_ERROR_GENERIC;
    }
    pubkey.resize(publen);
    privkey.assign(56, 0);
    rnp_botan_view_buf vb{privkey.data(), privkey.size()};
    if (botan_privkey_view_raw(priv_key.get(), &vb, rnp_botan_view_bin)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

rnp_result_t
x448_native_encrypt(rnp::RNG *                  rng,
                    const std::vector<uint8_t> &pubkey,
                    const uint8_t *             in,
                    size_t                      in_len,
                    pgp_x448_encrypted_t *      encrypted)
{
    rnp_result_t         ret;
    std::vector<uint8_t> shared_key;
    std::vector<uint8_t> derived_key;

    if (!in_len || (in_len % 8) != 0) {
        RNP_LOG("incorrect size of in, AES key wrap requires a multiple of 8 bytes");
        return RNP_ERROR_BAD_FORMAT;
    }

    ecdh_kem_public_key_t ecdhkem_pubkey(pubkey, PGP_CURVE_448);
    ret = ecdhkem_pubkey.encapsulate(rng, encrypted->eph_key, shared_key);
    if (ret != RNP_SUCCESS) {
        RNP_LOG("encapsulation failed");
        return ret;
    }

    x_hkdf(derived_key, encrypted->eph_key, pubkey, shared_key, hkdf_x448_info_str);

    return aes_kw_enc(derived_key, in, in_len, encrypted->enc_sess_key);
}

rnp_result_t
x448_native_decrypt(rnp::RNG *                  rng,
                    const pgp_x448_key_t &      keypair,
                    const pgp_x448_encrypted_t *encrypted,
                    uint8_t *                   decbuf,
                    size_t *                    decbuf_len)
{
    rnp_result_t         ret;
    std::vector<uint8_t> shared_key;
    std::vector<uint8_t> derived_key;

    static const size_t x448_pubkey_size = 32;
    if (encrypted->eph_key.size() != x448_pubkey_size) {
        RNP_LOG("Wrong ephemeral public key size");
        return RNP_ERROR_BAD_FORMAT;
    }
    if (!encrypted->enc_sess_key.size()) {
        RNP_LOG("No encrypted session key provided");
        return RNP_ERROR_BAD_FORMAT;
    }

    ecdh_kem_private_key_t ecdhkem_privkey(keypair.priv, PGP_CURVE_448);
    ret = ecdhkem_privkey.decapsulate(rng, encrypted->eph_key, shared_key);
    if (ret != RNP_SUCCESS) {
        RNP_LOG("decapsulation failed");
        return ret;
    }

    x_hkdf(derived_key, encrypted->eph_key, keypair.pub, shared_key, hkdf_x448_info_str);

    std::vector<uint8_t> tmp_out;
    ret = aes_kw_dec(
      derived_key, encrypted->enc_sess_key.data(), encrypted->enc_sess_key.size(), tmp_out);
    if (ret != RNP_SUCCESS) {
        return ret;
    }
    if (*decbuf_len < tmp_out.size()) {
        RNP_LOG("buffer for decryption result too small");
        return RNP_ERROR_DECRYPT_FAILED;
    }
    *decbuf_len = tmp_out.size();
    memcpy(decbuf, tmp_out.data(), tmp_out.size());

    return RNP_SUCCESS;
}

rnp_result_t
x448_validate_key_native(rnp::RNG *rng, const pgp_x448_key_t *key, bool secret)
{
    if (key->priv.size() != 56) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::botan::Pubkey pub_key;
    if (botan_pubkey_load_x448(&pub_key.get(), key->priv.data()) ||
        botan_pubkey_check_key(pub_key.get(), rng->handle(), 0)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (secret) {
        rnp::botan::Privkey priv_key;
        if (botan_privkey_load_x448(&priv_key.get(), key->priv.data()) ||
            botan_privkey_check_key(priv_key.get(), rng->handle(), 0)) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }
    return RNP_SUCCESS;
}
#endif
