/*-
 * Copyright (c) 2017-2024 Ribose Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <cassert>
#include <botan/ffi.h>
#include "hash_botan.hpp"
#include "botan_utils.hpp"
#include "sm2.h"
#include "utils.h"

static bool
sm2_load_public_key(rnp::botan::Pubkey &pubkey, const pgp::ec::Key &keydata)
{
    auto curve = pgp::ec::Curve::get(keydata.curve);
    if (!curve) {
        return false;
    }

    const size_t sign_half_len = curve->bytes();
    size_t       sz = keydata.p.bytes();
    if (!sz || (sz != (2 * sign_half_len + 1)) || (keydata.p.mpi[0] != 0x04)) {
        return false;
    }

    rnp::bn px(keydata.p.mpi + 1, sign_half_len);
    rnp::bn py(keydata.p.mpi + 1 + sign_half_len, sign_half_len);

    if (!px || !py) {
        return false;
    }
    return !botan_pubkey_load_sm2(&pubkey.get(), px.get(), py.get(), curve->botan_name);
}

static bool
sm2_load_secret_key(rnp::botan::Privkey &seckey, const pgp::ec::Key &keydata)
{
    auto curve = pgp::ec::Curve::get(keydata.curve);
    if (!curve) {
        return false;
    }

    rnp::bn x(keydata.x);
    if (!x) {
        return false;
    }

    return !botan_privkey_load_sm2(&seckey.get(), x.get(), curve->botan_name);
}

rnp_result_t
sm2_compute_za(const pgp::ec::Key &key, rnp::Hash &hash, const char *ident_field)
{
    rnp::botan::Pubkey sm2_key;
    if (!sm2_load_public_key(sm2_key, key)) {
        RNP_LOG("Failed to load SM2 key");
        return RNP_ERROR_GENERIC;
    }

    if (!ident_field) {
        ident_field = "1234567812345678";
    }

    auto                 hash_algo = rnp::Hash_Botan::name_backend(hash.alg());
    size_t               digest_len = hash.size();
    std::vector<uint8_t> digest_buf(digest_len, 0);

    int rc = botan_pubkey_sm2_compute_za(
      digest_buf.data(), &digest_len, ident_field, hash_algo, sm2_key.get());
    if (rc) {
        RNP_LOG("compute_za failed %d", rc);
        return RNP_ERROR_GENERIC;
    }
    hash.add(digest_buf.data(), digest_len);
    return RNP_SUCCESS;
}

rnp_result_t
sm2_validate_key(rnp::RNG &rng, const pgp::ec::Key &key, bool secret)
{
    rnp::botan::Pubkey bpkey;
    if (!sm2_load_public_key(bpkey, key) ||
        botan_pubkey_check_key(bpkey.get(), rng.handle(), 0)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!secret) {
        return RNP_SUCCESS;
    }

    rnp::botan::Privkey bskey;
    if (!sm2_load_secret_key(bskey, key) ||
        botan_privkey_check_key(bskey.get(), rng.handle(), 0)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

rnp_result_t
sm2_sign(rnp::RNG &          rng,
         pgp::ec::Signature &sig,
         pgp_hash_alg_t      hash_alg,
         const uint8_t *     hash,
         size_t              hash_len,
         const pgp::ec::Key &key)
{
    if (botan_ffi_supports_api(20180713)) {
        RNP_LOG("SM2 signatures requires Botan 2.8 or higher");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    if (hash_len != rnp::Hash::size(hash_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    auto curve = pgp::ec::Curve::get(key.curve);
    if (!curve) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp::botan::Privkey b_key;
    if (!sm2_load_secret_key(b_key, key)) {
        RNP_LOG("Can't load private key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp::botan::op::Sign signer;
    if (botan_pk_op_sign_create(&signer.get(), b_key.get(), ",Raw", 0) ||
        botan_pk_op_sign_update(signer.get(), hash, hash_len)) {
        return RNP_ERROR_SIGNING_FAILED;
    }

    size_t               sign_half_len = curve->bytes();
    size_t               sig_len = 2 * sign_half_len;
    std::vector<uint8_t> out_buf(sig_len, 0);
    if (botan_pk_op_sign_finish(signer.get(), rng.handle(), out_buf.data(), &sig_len)) {
        RNP_LOG("Signing failed");
        return RNP_ERROR_SIGNING_FAILED;
    }

    // Allocate memory and copy results
    if (!sig.r.from_mem(out_buf.data(), sign_half_len) ||
        !sig.s.from_mem(out_buf.data() + sign_half_len, sign_half_len)) {
        return RNP_ERROR_SIGNING_FAILED;
    }
    // All good now
    return RNP_SUCCESS;
}

rnp_result_t
sm2_verify(const pgp::ec::Signature &sig,
           pgp_hash_alg_t            hash_alg,
           const uint8_t *           hash,
           size_t                    hash_len,
           const pgp::ec::Key &      key)
{
    if (botan_ffi_supports_api(20180713) != 0) {
        RNP_LOG("SM2 signatures requires Botan 2.8 or higher");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    if (hash_len != rnp::Hash::size(hash_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    auto curve = pgp::ec::Curve::get(key.curve);
    if (!curve) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    size_t r_blen = sig.r.len;
    size_t s_blen = sig.s.len;
    size_t sign_half_len = curve->bytes();

    assert(sign_half_len <= MAX_CURVE_BYTELEN);
    if (!r_blen || (r_blen > sign_half_len) || !s_blen || (s_blen > sign_half_len)) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }

    rnp::botan::Pubkey pub;
    if (!sm2_load_public_key(pub, key)) {
        RNP_LOG("Failed to load public key");
        return RNP_ERROR_SIGNATURE_INVALID;
    }

    rnp::botan::op::Verify verifier;
    if (botan_pk_op_verify_create(&verifier.get(), pub.get(), ",Raw", 0) ||
        botan_pk_op_verify_update(verifier.get(), hash, hash_len)) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }

    std::vector<uint8_t> sign_buf(2 * sign_half_len, 0);
    sig.r.to_mem(sign_buf.data() + sign_half_len - r_blen);
    sig.s.to_mem(sign_buf.data() + 2 * sign_half_len - s_blen);

    if (botan_pk_op_verify_finish(verifier.get(), sign_buf.data(), sign_buf.size())) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    return RNP_SUCCESS;
}

rnp_result_t
sm2_encrypt(rnp::RNG &           rng,
            pgp_sm2_encrypted_t &out,
            const uint8_t *      in,
            size_t               in_len,
            pgp_hash_alg_t       hash_algo,
            const pgp::ec::Key & key)
{
    auto curve = pgp::ec::Curve::get(key.curve);
    if (!curve) {
        return RNP_ERROR_GENERIC;
    }

    size_t hash_alg_len = rnp::Hash::size(hash_algo);
    if (!hash_alg_len) {
        RNP_LOG("Unknown hash algorithm for SM2 encryption");
        return RNP_ERROR_GENERIC;
    }

    /*
     * Format of SM2 ciphertext is a point (2*point_len+1) plus
     * the masked ciphertext (out_len) plus a hash.
     */
    size_t point_len = curve->bytes();
    size_t ctext_len = (2 * point_len + 1) + in_len + hash_alg_len;
    if (ctext_len > PGP_MPINT_SIZE) {
        RNP_LOG("too large output for SM2 encryption");
        return RNP_ERROR_GENERIC;
    }

    rnp::botan::Pubkey sm2_key;
    if (!sm2_load_public_key(sm2_key, key)) {
        RNP_LOG("Failed to load public key");
        return RNP_ERROR_GENERIC;
    }

    /*
    SM2 encryption doesn't have any kind of format specifier because
    it's an all in one scheme, only the hash (used for the integrity
    check) is specified.
    */
    rnp::botan::op::Encrypt enc_op;
    if (botan_pk_op_encrypt_create(
          &enc_op.get(), sm2_key.get(), rnp::Hash_Botan::name_backend(hash_algo), 0)) {
        return RNP_ERROR_GENERIC;
    }

    out.m.len = sizeof(out.m.mpi);
    if (botan_pk_op_encrypt(enc_op.get(), rng.handle(), out.m.mpi, &out.m.len, in, in_len)) {
        return RNP_ERROR_GENERIC;
    }
    out.m.mpi[out.m.len++] = hash_algo;
    return RNP_SUCCESS;
}

rnp_result_t
sm2_decrypt(uint8_t *                  out,
            size_t *                   out_len,
            const pgp_sm2_encrypted_t &in,
            const pgp::ec::Key &       key)
{
    auto   curve = pgp::ec::Curve::get(key.curve);
    size_t in_len = in.m.bytes();
    if (!curve || in_len < 64) {
        return RNP_ERROR_GENERIC;
    }

    uint8_t hash_id = in.m.mpi[in_len - 1];
    auto    hash_name = rnp::Hash_Botan::name_backend((pgp_hash_alg_t) hash_id);
    if (!hash_name) {
        RNP_LOG("Unknown hash used in SM2 ciphertext");
        return RNP_ERROR_GENERIC;
    }

    rnp::botan::Privkey b_key;
    if (!sm2_load_secret_key(b_key, key)) {
        RNP_LOG("Can't load private key");
        return RNP_ERROR_GENERIC;
    }

    rnp::botan::op::Decrypt decrypt_op;
    if (botan_pk_op_decrypt_create(&decrypt_op.get(), b_key.get(), hash_name, 0) ||
        botan_pk_op_decrypt(decrypt_op.get(), out, out_len, in.m.mpi, in_len - 1)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}
