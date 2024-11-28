/*
 * Copyright (c) 2017-2024, [Ribose Inc](https://www.ribose.com).
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

#include "ecdsa.h"
#include "utils.h"
#include <botan/ffi.h>
#include <string.h>
#include "botan_utils.hpp"

static bool
ecdsa_load_public_key(rnp::botan::Pubkey &pubkey, const pgp::ec::Key &keydata)
{
    auto curve = pgp::ec::Curve::get(keydata.curve);
    if (!curve) {
        RNP_LOG("unknown curve");
        return false;
    }
    if (!keydata.p.bytes() || (keydata.p.mpi[0] != 0x04)) {
        RNP_LOG("Failed to load public key: %02x", keydata.p.mpi[0]);
        return false;
    }

    const size_t curve_order = curve->bytes();
    rnp::bn      px(keydata.p.mpi + 1, curve_order);
    rnp::bn      py(keydata.p.mpi + 1 + curve_order, curve_order);

    if (!px || !py) {
        return false;
    }

    bool res = !botan_pubkey_load_ecdsa(&pubkey.get(), px.get(), py.get(), curve->botan_name);
    if (!res) {
        RNP_LOG("failed to load ecdsa public key");
    }
    return res;
}

static bool
ecdsa_load_secret_key(rnp::botan::Privkey &seckey, const pgp::ec::Key &keydata)
{
    auto curve = pgp::ec::Curve::get(keydata.curve);
    if (!curve) {
        return false;
    }

    rnp::bn x(keydata.x);
    if (!x) {
        return false;
    }

    bool res = !botan_privkey_load_ecdsa(&seckey.get(), x.get(), curve->botan_name);
    if (!res) {
        RNP_LOG("Can't load private key");
    }
    return res;
}

rnp_result_t
ecdsa_validate_key(rnp::RNG &rng, const pgp::ec::Key &key, bool secret)
{
    rnp::botan::Pubkey bpkey;
    if (!ecdsa_load_public_key(bpkey, key) ||
        botan_pubkey_check_key(bpkey.get(), rng.handle(), 0)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!secret) {
        return RNP_SUCCESS;
    }

    rnp::botan::Privkey bskey;
    if (!ecdsa_load_secret_key(bskey, key) ||
        botan_privkey_check_key(bskey.get(), rng.handle(), 0)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

const char *
ecdsa_padding_str_for(pgp_hash_alg_t hash_alg)
{
    switch (hash_alg) {
    case PGP_HASH_MD5:
        return "Raw(MD5)";
    case PGP_HASH_SHA1:
        return "Raw(SHA-1)";
    case PGP_HASH_RIPEMD:
        return "Raw(RIPEMD-160)";

    case PGP_HASH_SHA256:
        return "Raw(SHA-256)";
    case PGP_HASH_SHA384:
        return "Raw(SHA-384)";
    case PGP_HASH_SHA512:
        return "Raw(SHA-512)";
    case PGP_HASH_SHA224:
        return "Raw(SHA-224)";
    case PGP_HASH_SHA3_256:
        return "Raw(SHA-3(256))";
    case PGP_HASH_SHA3_512:
        return "Raw(SHA-3(512))";

    case PGP_HASH_SM3:
        return "Raw(SM3)";
    default:
        return "Raw";
    }
}

rnp_result_t
ecdsa_sign(rnp::RNG &          rng,
           pgp::ec::Signature &sig,
           pgp_hash_alg_t      hash_alg,
           const uint8_t *     hash,
           size_t              hash_len,
           const pgp::ec::Key &key)
{
    auto curve = pgp::ec::Curve::get(key.curve);
    if (!curve) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp::botan::Privkey b_key;
    if (!ecdsa_load_secret_key(b_key, key)) {
        RNP_LOG("Can't load private key");
        return RNP_ERROR_GENERIC;
    }

    rnp::botan::op::Sign signer;
    auto                 pad = ecdsa_padding_str_for(hash_alg);
    if (botan_pk_op_sign_create(&signer.get(), b_key.get(), pad, 0) ||
        botan_pk_op_sign_update(signer.get(), hash, hash_len)) {
        return RNP_ERROR_GENERIC;
    }

    const size_t         curve_order = curve->bytes();
    size_t               sig_len = 2 * curve_order;
    std::vector<uint8_t> out_buf(sig_len);

    if (botan_pk_op_sign_finish(signer.get(), rng.handle(), out_buf.data(), &sig_len)) {
        RNP_LOG("Signing failed");
        return RNP_ERROR_GENERIC;
    }

    // Allocate memory and copy results
    if (!sig.r.from_mem(out_buf.data(), curve_order) ||
        !sig.s.from_mem(out_buf.data() + curve_order, curve_order)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

rnp_result_t
ecdsa_verify(const pgp::ec::Signature &sig,
             pgp_hash_alg_t            hash_alg,
             const uint8_t *           hash,
             size_t                    hash_len,
             const pgp::ec::Key &      key)
{
    auto curve = pgp::ec::Curve::get(key.curve);
    if (!curve) {
        RNP_LOG("unknown curve");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    size_t curve_order = curve->bytes();
    size_t r_blen = sig.r.bytes();
    size_t s_blen = sig.s.bytes();
    if ((r_blen > curve_order) || (s_blen > curve_order) ||
        (curve_order > MAX_CURVE_BYTELEN)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp::botan::Pubkey pub;
    if (!ecdsa_load_public_key(pub, key)) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }

    rnp::botan::op::Verify verifier;
    auto                   pad = ecdsa_padding_str_for(hash_alg);
    if (botan_pk_op_verify_create(&verifier.get(), pub.get(), pad, 0) ||
        botan_pk_op_verify_update(verifier.get(), hash, hash_len)) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }

    std::vector<uint8_t> sign_buf(2 * curve_order, 0);
    // Both can't fail
    sig.r.to_mem(sign_buf.data() + curve_order - r_blen);
    sig.s.to_mem(sign_buf.data() + 2 * curve_order - s_blen);

    if (botan_pk_op_verify_finish(verifier.get(), sign_buf.data(), sign_buf.size())) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    return RNP_SUCCESS;
}
