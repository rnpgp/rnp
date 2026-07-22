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

#include "x25519_x448.h"
#include "exdsa_ecdhkem.h"
#include "hkdf.hpp"
#include "utils.h"
#include "logging.h"
#include "ossl_utils.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
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

static rnp_result_t
rfc3394_wrap(std::vector<uint8_t> &      out,
             const uint8_t *             in,
             size_t                      in_len,
             const std::vector<uint8_t> &kek)
{
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("aes128-wrap");
    if (!cipher) {
        RNP_LOG("aes128-wrap cipher not available");
        return RNP_ERROR_NOT_SUPPORTED;
    }
    rnp::ossl::evp::CipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_EncryptInit_ex(ctx.get(), cipher, NULL, kek.data(), NULL) <= 0) {
        RNP_LOG("Failed to init wrap: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    out.resize(in_len + 8);
    int outl = (int) out.size();
    if (EVP_EncryptUpdate(ctx.get(), out.data(), &outl, in, (int) in_len) <= 0) {
        RNP_LOG("Failed to wrap: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    out.resize(outl);
    return RNP_SUCCESS;
}

static rnp_result_t
rfc3394_unwrap(std::vector<uint8_t> &      out,
               const std::vector<uint8_t> &in,
               const std::vector<uint8_t> &kek)
{
    if ((in.size() < 16) || (in.size() % 8)) {
        RNP_LOG("Invalid wrapped key size.");
        return RNP_ERROR_GENERIC;
    }
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("aes128-wrap");
    if (!cipher) {
        RNP_LOG("aes128-wrap cipher not available");
        return RNP_ERROR_NOT_SUPPORTED;
    }
    rnp::ossl::evp::CipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_DecryptInit_ex(ctx.get(), cipher, NULL, kek.data(), NULL) <= 0) {
        RNP_LOG("Failed to init unwrap: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    out.resize(in.size() - 8);
    int outl = (int) out.size();
    if (EVP_DecryptUpdate(ctx.get(), out.data(), &outl, in.data(), (int) in.size()) <= 0) {
        RNP_LOG("Failed to unwrap: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    out.resize(outl);
    return RNP_SUCCESS;
}

rnp_result_t
generate_x25519_native(rnp::RNG *            rng,
                       std::vector<uint8_t> &privkey,
                       std::vector<uint8_t> &pubkey)
{
    rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        RNP_LOG("Failed to init X25519 keygen: %lu", ERR_peek_last_error());
        return RNP_ERROR_KEY_GENERATION;
    }
    EVP_PKEY *rawkey = NULL;
    if (EVP_PKEY_keygen(ctx.get(), &rawkey) <= 0) {
        RNP_LOG("X25519 keygen failed: %lu", ERR_peek_last_error());
        return RNP_ERROR_KEY_GENERATION;
    }
    rnp::ossl::evp::PKey pkey(rawkey);
    privkey.resize(32);
    size_t privlen = 32;
    pubkey.resize(32);
    size_t publen = 32;
    if (EVP_PKEY_get_raw_private_key(pkey.get(), privkey.data(), &privlen) <= 0 ||
        EVP_PKEY_get_raw_public_key(pkey.get(), pubkey.data(), &publen) <= 0) {
        RNP_LOG("Failed to extract X25519 key: %lu", ERR_peek_last_error());
        return RNP_ERROR_KEY_GENERATION;
    }
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

    ret = rfc3394_wrap(encrypted->enc_sess_key, in, in_len, derived_key);
    if (ret != RNP_SUCCESS) {
        RNP_LOG("Keywrap failed");
    }
    return ret;
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
    ret = rfc3394_unwrap(tmp_out, encrypted->enc_sess_key, derived_key);
    if (ret != RNP_SUCCESS) {
        RNP_LOG("Keyunwrap failed");
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
    /* mirror Botan version: use priv field for the public key check */
    rnp::ossl::evp::PKey pub(
      EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, key->priv.data(), key->priv.size()));
    if (!pub) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (secret) {
        rnp::ossl::evp::PKey priv(EVP_PKEY_new_raw_private_key(
          EVP_PKEY_X25519, NULL, key->priv.data(), key->priv.size()));
        if (!priv) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }
    return RNP_SUCCESS;
}

#if defined(ENABLE_CRYPTO_REFRESH)
rnp_result_t
generate_x448_native(rnp::RNG *            rng,
                     std::vector<uint8_t> &privkey,
                     std::vector<uint8_t> &pubkey)
{
    rnp::ossl::evp::PKeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X448, NULL));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        RNP_LOG("Failed to init X448 keygen: %lu", ERR_peek_last_error());
        return RNP_ERROR_KEY_GENERATION;
    }
    EVP_PKEY *rawkey = NULL;
    if (EVP_PKEY_keygen(ctx.get(), &rawkey) <= 0) {
        RNP_LOG("X448 keygen failed: %lu", ERR_peek_last_error());
        return RNP_ERROR_KEY_GENERATION;
    }
    rnp::ossl::evp::PKey pkey(rawkey);
    privkey.resize(56);
    size_t privlen = 56;
    pubkey.resize(56);
    size_t publen = 56;
    if (EVP_PKEY_get_raw_private_key(pkey.get(), privkey.data(), &privlen) <= 0 ||
        EVP_PKEY_get_raw_public_key(pkey.get(), pubkey.data(), &publen) <= 0) {
        RNP_LOG("Failed to extract X448 key: %lu", ERR_peek_last_error());
        return RNP_ERROR_KEY_GENERATION;
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

    /* encapsulation */
    ecdh_kem_public_key_t ecdhkem_pubkey(pubkey, PGP_CURVE_448);
    ret = ecdhkem_pubkey.encapsulate(rng, encrypted->eph_key, shared_key);
    if (ret != RNP_SUCCESS) {
        RNP_LOG("encapsulation failed");
        return ret;
    }

    x_hkdf(derived_key, encrypted->eph_key, pubkey, shared_key, hkdf_x448_info_str);

    ret = rfc3394_wrap(encrypted->enc_sess_key, in, in_len, derived_key);
    if (ret != RNP_SUCCESS) {
        RNP_LOG("Keywrap failed");
    }
    return ret;
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

    static const size_t x448_pubkey_size = 56;
    if (encrypted->eph_key.size() != x448_pubkey_size) {
        RNP_LOG("Wrong ephemeral public key size");
        return RNP_ERROR_BAD_FORMAT;
    }
    if (!encrypted->enc_sess_key.size()) {
        RNP_LOG("No encrypted session key provided");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* decapsulate */
    ecdh_kem_private_key_t ecdhkem_privkey(keypair.priv, PGP_CURVE_448);
    ret = ecdhkem_privkey.decapsulate(rng, encrypted->eph_key, shared_key);
    if (ret != RNP_SUCCESS) {
        RNP_LOG("decapsulation failed");
        return ret;
    }

    x_hkdf(derived_key, encrypted->eph_key, keypair.pub, shared_key, hkdf_x448_info_str);

    std::vector<uint8_t> tmp_out;
    ret = rfc3394_unwrap(tmp_out, encrypted->enc_sess_key, derived_key);
    if (ret != RNP_SUCCESS) {
        RNP_LOG("Keyunwrap failed");
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
    /* mirror Botan version: use priv field for the public key check */
    rnp::ossl::evp::PKey pub(
      EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, NULL, key->priv.data(), key->priv.size()));
    if (!pub) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (secret) {
        rnp::ossl::evp::PKey priv(EVP_PKEY_new_raw_private_key(
          EVP_PKEY_X448, NULL, key->priv.data(), key->priv.size()));
        if (!priv) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }
    return RNP_SUCCESS;
}
#endif
