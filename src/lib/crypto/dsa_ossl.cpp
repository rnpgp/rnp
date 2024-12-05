/*
 * Copyright (c) 2021-2024 [Ribose Inc](https://www.ribose.com).
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

#include <stdlib.h>
#include <string.h>
#include <rnp/rnp_def.h>
#include "dsa.h"
#include "dl_ossl.h"
#include "utils.h"
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#if defined(CRYPTO_BACKEND_OPENSSL3)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

namespace pgp {
namespace dsa {
static bool
decode_sig(const uint8_t *data, size_t len, Signature &sig)
{
    DSA_SIG *dsig = d2i_DSA_SIG(NULL, &data, len);
    if (!dsig) {
        RNP_LOG("Failed to parse DSA sig: %lu", ERR_peek_last_error());
        return false;
    }
    rnp::bn r, s;
    DSA_SIG_get0(dsig, r.cptr(), s.cptr());
    r.mpi(sig.r);
    s.mpi(sig.s);
    DSA_SIG_free(dsig);
    return true;
}

static bool
encode_sig(uint8_t *data, size_t *len, const Signature &sig)
{
    DSA_SIG *dsig = DSA_SIG_new();
    rnp::bn  r(sig.r);
    rnp::bn  s(sig.s);
    if (!dsig || !r || !s) {
        RNP_LOG("Allocation failed.");
        return false;
    }
    DSA_SIG_set0(dsig, r.own(), s.own());
    auto outlen = i2d_DSA_SIG(dsig, &data);
    DSA_SIG_free(dsig);
    if (outlen < 0) {
        RNP_LOG("Failed to encode signature.");
        return false;
    }
    *len = outlen;
    return true;
}

#if defined(CRYPTO_BACKEND_OPENSSL3)
static rnp::ossl::Param
build_params(rnp::bn &p, rnp::bn &q, rnp::bn &g, rnp::bn &y, rnp::bn &x)
{
    rnp::ossl::ParamBld bld(OSSL_PARAM_BLD_new());
    if (!bld || !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_FFC_P, p.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_FFC_Q, q.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_FFC_G, g.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, y.get()) ||
        (x && !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, x.get()))) {
        return NULL; // LCOV_EXCL_LINE
    }
    return rnp::ossl::Param(OSSL_PARAM_BLD_to_param(bld.get()));
}
#endif

static rnp::ossl::evp::PKey
load_key(const Key &key, bool secret = false)
{
    rnp::bn p(key.p);
    rnp::bn q(key.q);
    rnp::bn g(key.g);
    rnp::bn y(key.y);
    rnp::bn x(secret ? &key.x : NULL);

    if (!p || !q || !g || !y || (secret && !x)) {
        /* LCOV_EXCL_START */
        RNP_LOG("out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }

#if defined(CRYPTO_BACKEND_OPENSSL3)
    rnp::ossl::Param params = build_params(p, q, g, y, x);
    if (!params) {
        /* LCOV_EXCL_START */
        RNP_LOG("failed to build dsa params");
        return NULL;
        /* LCOV_EXCL_END */
    }
    rnp::ossl::evp::Ctx ctx(EVP_PKEY_DSA);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("failed to create dsa context");
        return NULL;
        /* LCOV_EXCL_END */
    }
    rnp::ossl::evp::PKey evpkey;
    if ((EVP_PKEY_fromdata_init(ctx.get()) != 1) ||
        (EVP_PKEY_fromdata(ctx.get(),
                           evpkey.ptr(),
                           secret ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                           params.get()) != 1)) {
        RNP_LOG("failed to create key from data");
        return NULL;
    }
    return evpkey;
#else
    rnp::ossl::DSA dsa;
    if (!dsa.get()) {
        /* LCOV_EXCL_START */
        RNP_LOG("Out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }
    if (DSA_set0_pqg(dsa.get(), p.own(), q.own(), g.own()) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set pqg. Error: %lu", ERR_peek_last_error());
        return NULL;
        /* LCOV_EXCL_END */
    }
    if (DSA_set0_key(dsa.get(), y.own(), x.own()) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Secret key load error: %lu", ERR_peek_last_error());
        return NULL;
        /* LCOV_EXCL_END */
    }

    rnp::ossl::evp::PKey evpkey(EVP_PKEY_new());
    if (!evpkey) {
        /* LCOV_EXCL_START */
        RNP_LOG("allocation failed");
        return NULL;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_set1_DSA(evpkey.get(), dsa.get()) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set key: %lu", ERR_peek_last_error());
        return NULL;
        /* LCOV_EXCL_END */
    }
    return evpkey;
#endif
}

rnp_result_t
Key::validate(rnp::RNG &rng, bool secret) const noexcept
{
    /* OpenSSL doesn't implement key checks for the DSA, however we may use DL via DH */
    rnp::ossl::evp::PKey pkey = dl_load_key(p, &q, g, y, secret ? &x : NULL);
    if (!pkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return dl_validate_key(pkey, secret ? &x : NULL);
}

rnp_result_t
Key::sign(rnp::RNG &rng, Signature &sig, const uint8_t *hash, size_t hash_len) const
{
    if (!x.bytes()) {
        RNP_LOG("private key not set");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* Load secret key to DSA structure*/
    rnp::ossl::evp::PKey evpkey(load_key(*this, true));
    if (!evpkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* init context and sign */
    rnp::ossl::evp::Ctx ctx(evpkey);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_sign_init(ctx.get()) <= 0) {
        RNP_LOG("Failed to initialize signing: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    sig.s.len = PGP_MPINT_SIZE;
    if (EVP_PKEY_sign(ctx.get(), sig.s.mpi, &sig.s.len, hash, hash_len) <= 0) {
        RNP_LOG("Signing failed: %lu", ERR_peek_last_error());
        sig.s.len = 0;
        return RNP_ERROR_GENERIC;
    }
    if (!decode_sig(&sig.s.mpi[0], sig.s.len, sig)) {
        RNP_LOG("Failed to parse DSA sig: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

rnp_result_t
Key::verify(const Signature &sig, const uint8_t *hash, size_t hash_len) const
{
    /* Load secret key to EVP key */
    rnp::ossl::evp::PKey evpkey(load_key(*this, false));
    if (!evpkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* init context and sign */
    rnp::ossl::evp::Ctx ctx(evpkey);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_verify_init(ctx.get()) <= 0) {
        RNP_LOG("Failed to initialize verify: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    pgp::mpi sigbuf;
    if (!encode_sig(sigbuf.mpi, &sigbuf.len, sig)) {
        return RNP_ERROR_GENERIC;
    }
    if (EVP_PKEY_verify(ctx.get(), sigbuf.mpi, sigbuf.len, hash, hash_len) <= 0) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    return RNP_SUCCESS;
}

static bool
extract_key(rnp::ossl::evp::PKey &pkey, Key &key)
{
#if defined(CRYPTO_BACKEND_OPENSSL3)
    return pkey.get_bn(OSSL_PKEY_PARAM_FFC_P, key.p) &&
           pkey.get_bn(OSSL_PKEY_PARAM_FFC_Q, key.q) &&
           pkey.get_bn(OSSL_PKEY_PARAM_FFC_G, key.g) &&
           pkey.get_bn(OSSL_PKEY_PARAM_PUB_KEY, key.y) &&
           pkey.get_bn(OSSL_PKEY_PARAM_PRIV_KEY, key.x);
#else
    const DSA *dsa = EVP_PKEY_get0_DSA(pkey.get());
    if (!dsa) {
        RNP_LOG("Failed to retrieve DSA key: %lu", ERR_peek_last_error());
        return false;
    }

    rnp::bn p(DSA_get0_p(dsa));
    rnp::bn q(DSA_get0_q(dsa));
    rnp::bn g(DSA_get0_g(dsa));
    rnp::bn y(DSA_get0_pub_key(dsa));
    rnp::bn x(DSA_get0_priv_key(dsa));

    if (!p || !q || !g || !y || !x) {
        return false;
    }
    return p.mpi(key.p) && q.mpi(key.q) && g.mpi(key.g) && y.mpi(key.y) && x.mpi(key.x);
#endif
}

rnp_result_t
Key::generate(rnp::RNG &rng, size_t keylen, size_t qbits)
{
    if ((keylen < 1024) || (keylen > 3072) || (qbits < 160) || (qbits > 256)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* Generate DSA params */
    rnp::ossl::evp::Ctx ctx(EVP_PKEY_DSA);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_paramgen_init(ctx.get()) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx.get(), keylen) <= 0) {
        RNP_LOG("Failed to set key bits: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
#if OPENSSL_VERSION_NUMBER < 0x1010105fL
    EVP_PKEY_CTX_ctrl(ctx.get(),
                      EVP_PKEY_DSA,
                      EVP_PKEY_OP_PARAMGEN,
                      EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS,
                      qbits,
                      NULL);
#else
    if (EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx.get(), qbits) <= 0) {
        RNP_LOG("Failed to set key qbits: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
#endif
    rnp::ossl::evp::PKey parmkey;
    if (EVP_PKEY_paramgen(ctx.get(), parmkey.ptr()) <= 0) {
        RNP_LOG("Failed to generate parameters: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    /* Generate DSA key */
    rnp::ossl::evp::Ctx genctx(parmkey);
    if (!genctx) {
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    if (EVP_PKEY_keygen_init(genctx.get()) <= 0) {
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    rnp::ossl::evp::PKey pkey;
    if (EVP_PKEY_keygen(genctx.get(), pkey.ptr()) <= 0) {
        RNP_LOG("DSA keygen failed: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }

    if (!extract_key(pkey, *this)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}
} // namespace dsa
} // namespace pgp
