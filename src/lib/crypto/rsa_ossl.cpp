/*
 * Copyright (c) 2021-2024, [Ribose Inc](https://www.ribose.com).
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

#include <string>
#include <cstring>
#include <cassert>
#include "crypto/rsa.h"
#include "config.h"
#include "utils.h"
#include "ossl_utils.hpp"
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#ifdef CRYPTO_BACKEND_OPENSSL3
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif
#include "hash_ossl.hpp"

namespace pgp {
namespace rsa {

#if !defined(CRYPTO_BACKEND_OPENSSL3)
static rnp::ossl::evp::PKey
load_public_key(const Key &key)
{
    rnp::bn        n(key.n);
    rnp::bn        e(key.e);
    rnp::ossl::RSA rsa;

    if (!n || !e || !rsa.get()) {
        /* LCOV_EXCL_START */
        RNP_LOG("out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }
    /* OpenSSL set0 function transfers ownership of bignums */
    if (RSA_set0_key(rsa.get(), n.own(), e.own(), NULL) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Public key load error: %lu", ERR_peek_last_error());
        return NULL;
        /* LCOV_EXCL_END */
    }

    rnp::ossl::evp::PKey evpkey(EVP_PKEY_new());
    if (!evpkey || (EVP_PKEY_set1_RSA(evpkey.get(), rsa.get()) <= 0)) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set key: %lu", ERR_peek_last_error());
        return NULL;
        /* LCOV_EXCL_END */
    }
    return evpkey;
}

static rnp::ossl::evp::PKey
load_secret_key(const Key &key)
{
    rnp::bn        n(key.n);
    rnp::bn        e(key.e);
    rnp::bn        p(key.p);
    rnp::bn        q(key.q);
    rnp::bn        d(key.d);
    rnp::ossl::RSA rsa;

    if (!n || !p || !q || !e || !d || !rsa.get()) {
        /* LCOV_EXCL_START */
        RNP_LOG("out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }

    /* OpenSSL set0 function transfers ownership of bignums */
    if (RSA_set0_key(rsa.get(), n.own(), e.own(), d.own()) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Secret key load error: %lu", ERR_peek_last_error());
        return NULL;
        /* LCOV_EXCL_END */
    }
    /* OpenSSL has p < q, as we do */
    if (RSA_set0_factors(rsa.get(), p.own(), q.own()) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Factors load error: %lu", ERR_peek_last_error());
        return NULL;
        /* LCOV_EXCL_END */
    }

    rnp::ossl::evp::PKey evpkey(EVP_PKEY_new());
    if (!evpkey || (EVP_PKEY_set1_RSA(evpkey.get(), rsa.get()) <= 0)) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set key: %lu", ERR_peek_last_error());
        return NULL;
        /* LCOV_EXCL_END */
    }
    return evpkey;
}

static rnp::ossl::evp::Ctx
init_context(const Key &key, bool secret)
{
    rnp::ossl::evp::PKey evpkey(secret ? load_secret_key(key) : load_public_key(key));
    if (!evpkey) {
        return rnp::ossl::evp::Ctx(); // LCOV_EXCL_LINE
    }
    rnp::ossl::evp::Ctx ctx(evpkey);
    if (!ctx) {
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error()); // LCOV_EXCL_LINE
    }
    return ctx;
}
#else
static rnp::ossl::Param
bld_params(const Key &key, bool secret)
{
    rnp::ossl::ParamBld bld;
    rnp::bn             n(key.n);
    rnp::bn             e(key.e);

    if (!n || !e || !bld) {
        /* LCOV_EXCL_START */
        RNP_LOG("Out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }

    if (!bld.push(OSSL_PKEY_PARAM_RSA_N, n) || !bld.push(OSSL_PKEY_PARAM_RSA_E, e)) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to push RSA params.");
        return NULL;
        /* LCOV_EXCL_END */
    }

    if (!secret) {
        auto params = bld.to_param();
        if (!params) {
            RNP_LOG("Failed to build RSA pub params: %s.",
                    rnp::ossl::latest_err()); // LCOV_EXCL_LINE
        }
        return params;
    }

    /* Add secret key fields */
    rnp::bn d(key.d);
    /* As we have u = p^-1 mod q, and qInv = q^-1 mod p, we need to replace one with another */
    rnp::bn p(key.q);
    rnp::bn q(key.p);
    rnp::bn u(key.u);

    if (!d || !p || !q || !u) {
        return NULL;
    }
    /* We need to calculate exponents manually */
    rnp::ossl::BNCtx bnctx;
    if (!bnctx.get()) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to allocate BN_CTX.");
        return NULL;
        /* LCOV_EXCL_END */
    }
    auto p1 = bnctx.bn();
    auto q1 = bnctx.bn();
    auto dp = bnctx.bn();
    auto dq = bnctx.bn();
    if (!BN_copy(p1, p.get()) || !BN_sub_word(p1, 1) || !BN_copy(q1, q.get()) ||
        !BN_sub_word(q1, 1) || !BN_mod(dp, d.get(), p1, bnctx.get()) ||
        !BN_mod(dq, d.get(), q1, bnctx.get())) {
        RNP_LOG("Failed to calculate dP or dQ."); // LCOV_EXCL_LINE
    }
    /* Push params */
    if (!bld.push(OSSL_PKEY_PARAM_RSA_D, d) || !bld.push(OSSL_PKEY_PARAM_RSA_FACTOR1, p) ||
        !bld.push(OSSL_PKEY_PARAM_RSA_FACTOR2, q) ||
        !bld.push(OSSL_PKEY_PARAM_RSA_EXPONENT1, dp) ||
        !bld.push(OSSL_PKEY_PARAM_RSA_EXPONENT2, dq) ||
        !bld.push(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, u)) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to push RSA secret params.");
        return NULL;
        /* LCOV_EXCL_END */
    }
    auto params = bld.to_param();
    if (!params) {
        RNP_LOG("Failed to build RSA params: %s.", rnp::ossl::latest_err()); // LCOV_EXCL_LINE
    }
    return params;
}

static rnp::ossl::evp::PKey
load_key(const Key &key, bool secret)
{
    /* Build params */
    auto params = bld_params(key, secret);
    if (!params) {
        return NULL;
    }
    /* Create context for key creation */
    rnp::ossl::evp::Ctx ctx(EVP_PKEY_RSA);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Context allocation failed: %s", rnp::ossl::latest_err());
        return NULL;
        /* LCOV_EXCL_END */
    }
    /* Create key */
    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to initialize key creation: %s", rnp::ossl::latest_err());
        return NULL;
        /* LCOV_EXCL_END */
    }
    rnp::ossl::evp::PKey res;
    if (EVP_PKEY_fromdata(ctx.get(),
                          res.ptr(),
                          secret ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                          params.get()) <= 0) {
        RNP_LOG("Failed to create RSA key: %s", rnp::ossl::latest_err()); // LCOV_EXCL_LINE
    }
    return res;
}

static rnp::ossl::evp::Ctx
init_context(const Key &key, bool secret)
{
    auto pkey = load_key(key, secret);
    if (!pkey) {
        return rnp::ossl::evp::Ctx();
    }
    rnp::ossl::evp::Ctx ctx(pkey);
    if (!ctx) {
        RNP_LOG("Context allocation failed: %s", rnp::ossl::latest_err()); // LCOV_EXCL_LINE
    }
    return ctx;
}
#endif

rnp_result_t
Key::validate(rnp::RNG &rng, bool secret) const noexcept
{
#if defined(CRYPTO_BACKEND_OPENSSL3)
    auto ctx = init_context(*this, secret);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to init context: %s", rnp::ossl::latest_err());
        return RNP_ERROR_GENERIC;
        /* LCOV_EXCL_END */
    }
    int res = secret ? EVP_PKEY_pairwise_check(ctx.get()) : EVP_PKEY_public_check(ctx.get());
    if (res <= 0) {
        RNP_LOG("Key validation error: %s", rnp::ossl::latest_err()); // LCOV_EXCL_LINE
    }
    return res > 0 ? RNP_SUCCESS : RNP_ERROR_GENERIC;
#else
    if (secret) {
        rnp::ossl::evp::Ctx ctx(init_context(*this, secret));
        if (!ctx) {
            /* LCOV_EXCL_START */
            RNP_LOG("Failed to init context: %s", rnp::ossl::latest_err());
            return RNP_ERROR_GENERIC;
            /* LCOV_EXCL_END */
        }
        int res = EVP_PKEY_check(ctx.get());
        if (res <= 0) {
            RNP_LOG("Key validation error: %s", rnp::ossl::latest_err()); // LCOV_EXCL_LINE
        }
        return res > 0 ? RNP_SUCCESS : RNP_ERROR_GENERIC;
    }

    /* OpenSSL 1.1.1 doesn't have RSA public key check function, so let's do some checks */
    rnp::bn on(n);
    rnp::bn oe(e);
    if (!on || !oe) {
        /* LCOV_EXCL_START */
        RNP_LOG("out of memory");
        return RNP_ERROR_OUT_OF_MEMORY;
        /* LCOV_EXCL_END */
    }
    if ((BN_num_bits(on.get()) < 512) || !BN_is_odd(on.get()) || (BN_num_bits(oe.get()) < 2) ||
        !BN_is_odd(oe.get())) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
#endif
}

static bool
setup_context(rnp::ossl::evp::Ctx &ctx)
{
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) <= 0) {
        RNP_LOG("Failed to set padding: %lu", ERR_peek_last_error());
        return false;
    }
    return true;
}

static const uint8_t PKCS1_SHA1_ENCODING[15] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};

static bool
setup_signature_hash(rnp::ossl::evp::Ctx &ctx,
                     pgp_hash_alg_t       hash_alg,
                     const uint8_t *&     enc,
                     size_t &             enc_size)
{
    auto hash_name = rnp::Hash_OpenSSL::name(hash_alg);
    if (!hash_name) {
        RNP_LOG("Unknown hash: %d", (int) hash_alg);
        return false;
    }
    auto hash_tp = EVP_get_digestbyname(hash_name);
    if (!hash_tp) {
        RNP_LOG("Error creating hash object for '%s'", hash_name);
        return false;
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx.get(), hash_tp) <= 0) {
        if ((hash_alg != PGP_HASH_SHA1)) {
            RNP_LOG("Failed to set digest %s: %s", hash_name, rnp::ossl::latest_err());
            return false;
        }
        enc = &PKCS1_SHA1_ENCODING[0];
        enc_size = sizeof(PKCS1_SHA1_ENCODING);
    } else {
        enc = NULL;
        enc_size = 0;
    }
    return true;
}

rnp_result_t
Key::encrypt_pkcs1(rnp::RNG &     rng,
                   Encrypted &    out,
                   const uint8_t *in,
                   size_t         in_len) const noexcept
{
    rnp::ossl::evp::Ctx ctx = init_context(*this, false);
    if (!ctx) {
        return RNP_ERROR_GENERIC;
    }
    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
        RNP_LOG("Failed to initialize encryption: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    if (!setup_context(ctx)) {
        return RNP_ERROR_GENERIC;
    }
    out.m.len = PGP_MPINT_SIZE;
    if (EVP_PKEY_encrypt(ctx.get(), out.m.mpi, &out.m.len, in, in_len) <= 0) {
        RNP_LOG("Encryption failed: %lu", ERR_peek_last_error());
        out.m.len = 0;
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

rnp_result_t
Key::verify_pkcs1(const Signature &sig,
                  pgp_hash_alg_t   hash_alg,
                  const uint8_t *  hash,
                  size_t           hash_len) const noexcept
{
    rnp::ossl::evp::Ctx ctx(init_context(*this, false));
    if (!ctx) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }

    if (EVP_PKEY_verify_init(ctx.get()) <= 0) {
        RNP_LOG("Failed to initialize verification: %lu", ERR_peek_last_error());
        return RNP_ERROR_SIGNATURE_INVALID;
    }

    const uint8_t *hash_enc = NULL;
    size_t         hash_enc_size = 0;
    if (!setup_context(ctx) || !setup_signature_hash(ctx, hash_alg, hash_enc, hash_enc_size)) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    /* Check whether we need to workaround on unsupported SHA1 for RSA signature verification
     */
    std::vector<uint8_t> hash_buf(hash_enc, hash_enc + hash_enc_size);
    if (hash_enc_size) {
        hash_buf.insert(hash_buf.end(), hash, hash + hash_len);
        hash = hash_buf.data();
        hash_len = hash_buf.size();
    }
    int res = 0;
    if (sig.s.len < n.len) {
        /* OpenSSL doesn't like signatures smaller then N */
        std::vector<uint8_t> sn(n.len - sig.s.len, 0);
        sn.insert(sn.end(), sig.s.mpi, sig.s.mpi + sig.s.len);
        res = EVP_PKEY_verify(ctx.get(), sn.data(), sn.size(), hash, hash_len);
    } else {
        res = EVP_PKEY_verify(ctx.get(), sig.s.mpi, sig.s.len, hash, hash_len);
    }
    if (res <= 0) {
        RNP_LOG("RSA verification failure: %s", rnp::ossl::latest_err());
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    return RNP_SUCCESS;
}

rnp_result_t
Key::sign_pkcs1(rnp::RNG &     rng,
                Signature &    sig,
                pgp_hash_alg_t hash_alg,
                const uint8_t *hash,
                size_t         hash_len) const noexcept
{
    if (!q.bytes()) {
        RNP_LOG("private key not set");
        return RNP_ERROR_GENERIC;
    }
    rnp::ossl::evp::Ctx ctx(init_context(*this, true));
    if (!ctx) {
        return RNP_ERROR_GENERIC;
    }

    if (EVP_PKEY_sign_init(ctx.get()) <= 0) {
        RNP_LOG("Failed to initialize signing: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    const uint8_t *hash_enc = NULL;
    size_t         hash_enc_size = 0;
    if (!setup_context(ctx) || !setup_signature_hash(ctx, hash_alg, hash_enc, hash_enc_size)) {
        return RNP_ERROR_GENERIC;
    }
    /* Check whether we need to workaround on unsupported SHA1 for RSA signature verification
     */
    std::vector<uint8_t> hash_buf(hash_enc, hash_enc + hash_enc_size);
    if (hash_enc_size) {
        hash_buf.insert(hash_buf.end(), hash, hash + hash_len);
        hash = hash_buf.data();
        hash_len = hash_buf.size();
    }
    sig.s.len = PGP_MPINT_SIZE;
    if (EVP_PKEY_sign(ctx.get(), sig.s.mpi, &sig.s.len, hash, hash_len) <= 0) {
        RNP_LOG("Signing failed: %lu", ERR_peek_last_error());
        sig.s.len = 0;
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

rnp_result_t
Key::decrypt_pkcs1(rnp::RNG &       rng,
                   uint8_t *        out,
                   size_t &         out_len,
                   const Encrypted &in) const noexcept
{
    if (!q.bytes()) {
        RNP_LOG("private key not set");
        return RNP_ERROR_GENERIC;
    }
    rnp::ossl::evp::Ctx ctx(init_context(*this, true));
    if (!ctx) {
        return RNP_ERROR_GENERIC;
    }
    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
        RNP_LOG("Failed to initialize encryption: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    if (!setup_context(ctx)) {
        return RNP_ERROR_GENERIC;
    }
    out_len = PGP_MPINT_SIZE;
    if (EVP_PKEY_decrypt(ctx.get(), out, &out_len, in.m.mpi, in.m.len) <= 0) {
        RNP_LOG("Encryption failed: %lu", ERR_peek_last_error());
        out_len = 0;
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

static bool
calculate_pqu(const rnp::bn &p, const rnp::bn &q, const rnp::bn &u, Key &key)
{
    /* OpenSSL doesn't care whether p < q */
    if (BN_cmp(p.c_get(), q.c_get()) > 0) {
        /* In this case we have u, as iqmp is inverse of q mod p, and we exchange them */
        return q.mpi(key.p) && p.mpi(key.q) && u.mpi(key.u);
    }

    rnp::ossl::BNCtx bnctx;
    if (!bnctx.get()) {
        return false;
    }

    /* we need to calculate u, since we need inverse of p mod q, while OpenSSL has inverse of q
     * mod p, and doesn't care of p < q */
    auto nu = bnctx.bn();
    auto nq = bnctx.bn();
    if (!nu || !nq) {
        return false;
    }
    BN_with_flags(nq, q.c_get(), BN_FLG_CONSTTIME);
    /* calculate inverse of p mod q */
    if (!BN_mod_inverse(nu, p.c_get(), nq, bnctx.get())) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to calculate u");
        return false;
        /* LCOV_EXCL_END */
    }
    if (!p.mpi(key.p) || !q.mpi(key.q)) {
        return false;
    }
    rnp::bn anu(nu);
    bool    res = anu.mpi(key.u);
    /* internal BIGNUM is owned by the bnctx */
    anu.own();
    return res;
}

static bool
extract_key(rnp::ossl::evp::PKey &pkey, Key &key)
{
#if defined(CRYPTO_BACKEND_OPENSSL3)
    rnp::bn n(pkey.get_bn(OSSL_PKEY_PARAM_RSA_N));
    rnp::bn e(pkey.get_bn(OSSL_PKEY_PARAM_RSA_E));
    rnp::bn d(pkey.get_bn(OSSL_PKEY_PARAM_RSA_D));
    rnp::bn p(pkey.get_bn(OSSL_PKEY_PARAM_RSA_FACTOR1));
    rnp::bn q(pkey.get_bn(OSSL_PKEY_PARAM_RSA_FACTOR2));
    rnp::bn u(pkey.get_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT1));

    return n && e && d && p && q && u && calculate_pqu(p, q, u, key) && n.mpi(key.n) &&
           e.mpi(key.e) && d.mpi(key.d);
#else
    const RSA *rsa = EVP_PKEY_get0_RSA(pkey.get());
    if (!rsa) {
        RNP_LOG("Failed to retrieve RSA key: %lu", ERR_peek_last_error());
        return false;
    }
    if (RSA_check_key(rsa) != 1) {
        RNP_LOG("Key validation error: %lu", ERR_peek_last_error());
        return false;
    }

    rnp::bn n(RSA_get0_n(rsa));
    rnp::bn e(RSA_get0_e(rsa));
    rnp::bn d(RSA_get0_d(rsa));
    rnp::bn p(RSA_get0_p(rsa));
    rnp::bn q(RSA_get0_q(rsa));
    rnp::bn u(RSA_get0_iqmp(rsa));
    if (!n || !e || !d || !p || !q || !u) {
        return false;
    }
    if (!calculate_pqu(p, q, u, key)) {
        return false;
    }
    return n.mpi(key.n) && e.mpi(key.e) && d.mpi(key.d);
#endif
}

rnp_result_t
Key::generate(rnp::RNG &rng, size_t numbits) noexcept
{
    if ((numbits < 1024) || (numbits > PGP_MPINT_BITS)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp::ossl::evp::Ctx ctx(EVP_PKEY_RSA);
    if (!ctx) {
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), numbits) <= 0) {
        RNP_LOG("Failed to set rsa bits: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    rnp::ossl::evp::PKey pkey;
    if (EVP_PKEY_keygen(ctx.get(), pkey.ptr()) <= 0) {
        RNP_LOG("RSA keygen failed: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    if (!extract_key(pkey, *this)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

} // namespace rsa
} // namespace pgp
