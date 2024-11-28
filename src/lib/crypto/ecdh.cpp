/*-
 * Copyright (c) 2017-2022 Ribose Inc.
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
#include "ecdh.h"
#include "ec.h"
#include "ecdh_utils.h"
#include "symmetric.h"
#include "types.h"
#include "utils.h"
#include "mem.h"

// Produces kek of size kek_len which corresponds to length of wrapping key
static bool
compute_kek(uint8_t *                   kek,
            size_t                      kek_len,
            const std::vector<uint8_t> &other_info,
            const pgp::ec::Curve *      curve_desc,
            const pgp::mpi &            ec_pubkey,
            const rnp::botan::Privkey & ec_prvkey,
            const pgp_hash_alg_t        hash_alg)
{
    const uint8_t *p = ec_pubkey.mpi;
    uint8_t        p_len = ec_pubkey.len;

    if (curve_desc->rnp_curve_id == PGP_CURVE_25519) {
        if ((p_len != 33) || (p[0] != 0x40)) {
            return false;
        }
        p++;
        p_len--;
    }

    rnp::secure_array<uint8_t, MAX_CURVE_BYTELEN * 2 + 1> s;
    size_t                                                s_len = s.size();
    rnp::botan::op::KeyAgreement                          op;
    if (botan_pk_op_key_agreement_create(&op.get(), ec_prvkey.get(), "Raw", 0) ||
        botan_pk_op_key_agreement(op.get(), s.data(), &s_len, p, p_len, NULL, 0)) {
        return false;
    }

    char kdf_name[32] = {0};
    snprintf(
      kdf_name, sizeof(kdf_name), "SP800-56A(%s)", rnp::Hash_Botan::name_backend(hash_alg));
    return !botan_kdf(
      kdf_name, kek, kek_len, s.data(), s_len, NULL, 0, other_info.data(), other_info.size());
}

static bool
ecdh_load_public_key(rnp::botan::Pubkey &pubkey, const pgp::ec::Key &key)
{
    auto curve = pgp::ec::Curve::get(key.curve);
    if (!curve) {
        RNP_LOG("unknown curve");
        return false;
    }

    if (curve->rnp_curve_id == PGP_CURVE_25519) {
        if ((key.p.len != 33) || (key.p.mpi[0] != 0x40)) {
            return false;
        }
        rnp::secure_array<uint8_t, 32> pkey;
        memcpy(pkey.data(), key.p.mpi + 1, 32);
        return !botan_pubkey_load_x25519(&pubkey.get(), pkey.data());
    }

    if (!key.p.bytes() || (key.p.mpi[0] != 0x04)) {
        RNP_LOG("Failed to load public key");
        return false;
    }

    const size_t curve_order = curve->bytes();
    rnp::bn      px(&key.p.mpi[1], curve_order);
    rnp::bn      py(&key.p.mpi[1 + curve_order], curve_order);

    if (!px || !py) {
        return false;
    }

    if (!botan_pubkey_load_ecdh(&pubkey.get(), px.get(), py.get(), curve->botan_name)) {
        return true;
    }
    RNP_LOG("failed to load ecdh public key");
    return false;
}

static bool
ecdh_load_secret_key(rnp::botan::Privkey &seckey, const pgp::ec::Key &key)
{
    auto curve = pgp::ec::Curve::get(key.curve);
    if (!curve) {
        return false;
    }

    if (curve->rnp_curve_id == PGP_CURVE_25519) {
        if (key.x.len != 32) {
            RNP_LOG("wrong x25519 key");
            return false;
        }
        /* need to reverse byte order since in mpi we have big-endian */
        rnp::secure_array<uint8_t, 32> prkey;
        for (int i = 0; i < 32; i++) {
            prkey[i] = key.x.mpi[31 - i];
        }
        return !botan_privkey_load_x25519(&seckey.get(), prkey.data());
    }

    rnp::bn bx(key.x);
    return bx && !botan_privkey_load_ecdh(&seckey.get(), bx.get(), curve->botan_name);
}

rnp_result_t
ecdh_validate_key(rnp::RNG &rng, const pgp::ec::Key &key, bool secret)
{
    auto curve_desc = pgp::ec::Curve::get(key.curve);
    if (!curve_desc) {
        return RNP_ERROR_NOT_SUPPORTED;
    }

    rnp::botan::Pubkey bpkey;
    if (!ecdh_load_public_key(bpkey, key) ||
        botan_pubkey_check_key(bpkey.get(), rng.handle(), 0)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!secret) {
        return RNP_SUCCESS;
    }

    rnp::botan::Privkey bskey;
    if (!ecdh_load_secret_key(bskey, key) ||
        botan_privkey_check_key(bskey.get(), rng.handle(), 0)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

rnp_result_t
ecdh_encrypt_pkcs5(rnp::RNG &               rng,
                   pgp_ecdh_encrypted_t &   out,
                   const uint8_t *const     in,
                   size_t                   in_len,
                   const pgp::ec::Key &     key,
                   const pgp_fingerprint_t &fingerprint)
{
    // 'm' is padded to the 8-byte granularity
    uint8_t m[MAX_SESSION_KEY_SIZE];
    if (!in || (in_len > sizeof(m))) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    const size_t m_padded_len = ((in_len / 8) + 1) * 8;
    // +8 because of AES-wrap adds 8 bytes
    if (ECDH_WRAPPED_KEY_SIZE < (m_padded_len + 8)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

#if !defined(ENABLE_SM2)
    if (key.curve == PGP_CURVE_SM2_P_256) {
        RNP_LOG("SM2 curve support is disabled.");
        return RNP_ERROR_NOT_IMPLEMENTED;
    }
#endif
    auto curve_desc = pgp::ec::Curve::get(key.curve);
    if (!curve_desc) {
        RNP_LOG("unsupported curve");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    // See 13.5 of RFC 4880 for definition of other_info size
    const size_t kek_len = pgp_key_size(key.key_wrap_alg);
    auto         other_info =
      kdf_other_info_serialize(curve_desc, fingerprint, key.kdf_hash_alg, key.key_wrap_alg);
    assert(other_info.size() == curve_desc->OID.size() + 46);

    rnp::botan::Privkey eph_prv_key;
    int                 res = 0;
    if (!strcmp(curve_desc->botan_name, "curve25519")) {
        res = botan_privkey_create(&eph_prv_key.get(), "Curve25519", "", rng.handle());
    } else {
        res = botan_privkey_create(
          &eph_prv_key.get(), "ECDH", curve_desc->botan_name, rng.handle());
    }
    if (res) {
        return RNP_ERROR_GENERIC;
    }

    uint8_t kek[32] = {0}; // Size of SHA-256 or smaller
    if (!compute_kek(
          kek, kek_len, other_info, curve_desc, key.p, eph_prv_key, key.kdf_hash_alg)) {
        RNP_LOG("KEK computation failed");
        return RNP_ERROR_GENERIC;
    }

    memcpy(m, in, in_len);
    if (!pad_pkcs7(m, m_padded_len, in_len)) {
        // Should never happen
        return RNP_ERROR_GENERIC;
    }

    out.mlen = sizeof(out.m);
#if defined(CRYPTO_BACKEND_BOTAN3)
    char name[16];
    snprintf(name, sizeof(name), "AES-%zu", 8 * kek_len);
    if (botan_nist_kw_enc(name, 0, m, m_padded_len, kek, kek_len, out.m, &out.mlen)) {
#else
    if (botan_key_wrap3394(m, m_padded_len, kek, kek_len, out.m, &out.mlen)) {
#endif
        return RNP_ERROR_GENERIC;
    }

    /* we need to prepend 0x40 for the x25519 */
    if (key.curve == PGP_CURVE_25519) {
        out.p.len = sizeof(out.p.mpi) - 1;
        if (botan_pk_op_key_agreement_export_public(
              eph_prv_key.get(), out.p.mpi + 1, &out.p.len)) {
            return RNP_ERROR_GENERIC;
        }
        out.p.mpi[0] = 0x40;
        out.p.len++;
    } else {
        out.p.len = sizeof(out.p.mpi);
        if (botan_pk_op_key_agreement_export_public(
              eph_prv_key.get(), out.p.mpi, &out.p.len)) {
            return RNP_ERROR_GENERIC;
        }
    }
    // All OK
    return RNP_SUCCESS;
}

rnp_result_t
ecdh_decrypt_pkcs5(uint8_t *                   out,
                   size_t *                    out_len,
                   const pgp_ecdh_encrypted_t &in,
                   const pgp::ec::Key &        key,
                   const pgp_fingerprint_t &   fingerprint)
{
    if (!out || !out_len || !key.x.bytes()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    auto curve_desc = pgp::ec::Curve::get(key.curve);
    if (!curve_desc) {
        RNP_LOG("unknown curve");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    auto wrap_alg = key.key_wrap_alg;
    auto kdf_hash = key.kdf_hash_alg;
    /* Ensure that AES is used for wrapping */
    if ((wrap_alg != PGP_SA_AES_128) && (wrap_alg != PGP_SA_AES_192) &&
        (wrap_alg != PGP_SA_AES_256)) {
        RNP_LOG("non-aes wrap algorithm");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    // See 13.5 of RFC 4880 for definition of other_info_size
    auto other_info = kdf_other_info_serialize(curve_desc, fingerprint, kdf_hash, wrap_alg);
    assert(other_info.size() == curve_desc->OID.size() + 46);

    rnp::botan::Privkey prv_key;
    if (!ecdh_load_secret_key(prv_key, key)) {
        RNP_LOG("failed to load ecdh secret key");
        return RNP_ERROR_GENERIC;
    }

    // Size of SHA-256 or smaller
    rnp::secure_array<uint8_t, MAX_SYMM_KEY_SIZE>    kek;
    rnp::secure_array<uint8_t, MAX_SESSION_KEY_SIZE> deckey;

    size_t deckey_len = deckey.size();
    size_t offset = 0;

    /* Security: Always return same error code in case compute_kek,
     *           botan_key_unwrap3394 or unpad_pkcs7 fails
     */
    size_t kek_len = pgp_key_size(wrap_alg);
    if (!compute_kek(kek.data(), kek_len, other_info, curve_desc, in.p, prv_key, kdf_hash)) {
        return RNP_ERROR_GENERIC;
    }

#if defined(CRYPTO_BACKEND_BOTAN3)
    char name[16];
    snprintf(name, sizeof(name), "AES-%zu", 8 * kek_len);
    if (botan_nist_kw_dec(
          name, 0, in.m, in.mlen, kek.data(), kek_len, deckey.data(), &deckey_len)) {
#else
    if (botan_key_unwrap3394(in.m, in.mlen, kek.data(), kek_len, deckey.data(), &deckey_len)) {
#endif
        return RNP_ERROR_GENERIC;
    }

    if (!unpad_pkcs7(deckey.data(), deckey_len, &offset)) {
        return RNP_ERROR_GENERIC;
    }

    if (*out_len < offset) {
        return RNP_ERROR_SHORT_BUFFER;
    }

    *out_len = offset;
    memcpy(out, deckey.data(), *out_len);
    return RNP_SUCCESS;
}

#if defined(ENABLE_CRYPTO_REFRESH) || defined(ENABLE_PQC)
rnp_result_t
ecdh_kem_gen_keypair_native(rnp::RNG *            rng,
                            std::vector<uint8_t> &privkey,
                            std::vector<uint8_t> &pubkey,
                            pgp_curve_t           curve)
{
    return ec_generate_native(rng, privkey, pubkey, curve, PGP_PKA_ECDH);
}

rnp_result_t
exdsa_gen_keypair_native(rnp::RNG *            rng,
                         std::vector<uint8_t> &privkey,
                         std::vector<uint8_t> &pubkey,
                         pgp_curve_t           curve)
{
    pgp_pubkey_alg_t alg;
    switch (curve) {
    case PGP_CURVE_ED25519:
        alg = PGP_PKA_EDDSA;
        break;
    case PGP_CURVE_NIST_P_256:
        FALLTHROUGH_STATEMENT;
    case PGP_CURVE_NIST_P_384:
        FALLTHROUGH_STATEMENT;
    case PGP_CURVE_NIST_P_521:
        FALLTHROUGH_STATEMENT;
    case PGP_CURVE_BP256:
        FALLTHROUGH_STATEMENT;
    case PGP_CURVE_BP384:
        FALLTHROUGH_STATEMENT;
    case PGP_CURVE_BP512:
        FALLTHROUGH_STATEMENT;
    case PGP_CURVE_P256K1:
        alg = PGP_PKA_ECDSA;
        break;
    default:
        RNP_LOG("invalid curve for ECDSA/EDDSA");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return ec_generate_native(rng, privkey, pubkey, curve, alg);
}

#endif
