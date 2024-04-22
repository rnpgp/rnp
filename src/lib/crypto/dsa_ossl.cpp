/*
 * Copyright (c) 2021, 2023 [Ribose Inc](https://www.ribose.com).
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
#include "bn.h"
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

#define DSA_MAX_Q_BITLEN 256

static bool
dsa_decode_sig(const uint8_t *data, size_t len, pgp_dsa_signature_t &sig)
{
    DSA_SIG *dsig = d2i_DSA_SIG(NULL, &data, len);
    if (!dsig) {
        RNP_LOG("Failed to parse DSA sig: %lu", ERR_peek_last_error());
        return false;
    }
    const BIGNUM *r, *s;
    DSA_SIG_get0(dsig, &r, &s);
    bn2mpi(r, &sig.r);
    bn2mpi(s, &sig.s);
    DSA_SIG_free(dsig);
    return true;
}

static bool
dsa_encode_sig(uint8_t *data, size_t *len, const pgp_dsa_signature_t &sig)
{
    bool     res = false;
    DSA_SIG *dsig = DSA_SIG_new();
    BIGNUM * r = mpi2bn(&sig.r);
    BIGNUM * s = mpi2bn(&sig.s);
    if (!dsig || !r || !s) {
        RNP_LOG("Allocation failed.");
        goto done;
    }
    DSA_SIG_set0(dsig, r, s);
    r = NULL;
    s = NULL;
    int outlen;
    outlen = i2d_DSA_SIG(dsig, &data);
    if (outlen < 0) {
        RNP_LOG("Failed to encode signature.");
        goto done;
    }
    *len = outlen;
    res = true;
done:
    DSA_SIG_free(dsig);
    BN_free(r);
    BN_free(s);
    return res;
}

#if defined(CRYPTO_BACKEND_OPENSSL3)
static OSSL_PARAM *
dsa_build_params(bignum_t *p, bignum_t *q, bignum_t *g, bignum_t *y, bignum_t *x)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        return NULL; // LCOV_EXCL_LINE
    }
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, y) ||
        (x && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, x))) {
        /* LCOV_EXCL_START */
        OSSL_PARAM_BLD_free(bld);
        return NULL;
        /* LCOV_EXCL_END */
    }
    OSSL_PARAM *param = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    return param;
}
#endif

static EVP_PKEY *
dsa_load_key(const pgp_dsa_key_t *key, bool secret = false)
{
    EVP_PKEY *evpkey = NULL;
    rnp::bn   p(mpi2bn(&key->p));
    rnp::bn   q(mpi2bn(&key->q));
    rnp::bn   g(mpi2bn(&key->g));
    rnp::bn   y(mpi2bn(&key->y));
    rnp::bn   x(secret ? mpi2bn(&key->x) : NULL);

    if (!p.get() || !q.get() || !g.get() || !y.get() || (secret && !x.get())) {
        /* LCOV_EXCL_START */
        RNP_LOG("out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }

#if defined(CRYPTO_BACKEND_OPENSSL3)
    OSSL_PARAM *params = dsa_build_params(p.get(), q.get(), g.get(), y.get(), x.get());
    if (!params) {
        /* LCOV_EXCL_START */
        RNP_LOG("failed to build dsa params");
        return NULL;
        /* LCOV_EXCL_END */
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("failed to create dsa context");
        OSSL_PARAM_free(params);
        return NULL;
        /* LCOV_EXCL_END */
    }
    if ((EVP_PKEY_fromdata_init(ctx) != 1) ||
        (EVP_PKEY_fromdata(
           ctx, &evpkey, secret ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) != 1)) {
        RNP_LOG("failed to create key from data");
        evpkey = NULL;
    }
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    return evpkey;
#else
    DSA *dsa = DSA_new();
    if (!dsa) {
        /* LCOV_EXCL_START */
        RNP_LOG("Out of memory");
        goto done;
        /* LCOV_EXCL_END */
    }
    if (DSA_set0_pqg(dsa, p.own(), q.own(), g.own()) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set pqg. Error: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (DSA_set0_key(dsa, y.own(), x.own()) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Secret key load error: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }

    evpkey = EVP_PKEY_new();
    if (!evpkey) {
        /* LCOV_EXCL_START */
        RNP_LOG("allocation failed");
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_set1_DSA(evpkey, dsa) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set key: %lu", ERR_peek_last_error());
        EVP_PKEY_free(evpkey);
        evpkey = NULL;
        /* LCOV_EXCL_END */
    }
done:
    DSA_free(dsa);
    return evpkey;
#endif
}

rnp_result_t
dsa_validate_key(rnp::RNG *rng, const pgp_dsa_key_t *key, bool secret)
{
    /* OpenSSL doesn't implement key checks for the DSA, however we may use DL via DH */
    EVP_PKEY *pkey = dl_load_key(key->p, &key->q, key->g, key->y, secret ? &key->x : NULL);
    if (!pkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_result_t ret = dl_validate_key(pkey, secret ? &key->x : NULL);
    EVP_PKEY_free(pkey);
    return ret;
}

rnp_result_t
dsa_sign(rnp::RNG *           rng,
         pgp_dsa_signature_t *sig,
         const uint8_t *      hash,
         size_t               hash_len,
         const pgp_dsa_key_t *key)
{
    if (mpi_bytes(&key->x) == 0) {
        RNP_LOG("private key not set");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* Load secret key to DSA structure*/
    EVP_PKEY *evpkey = dsa_load_key(key, true);
    if (!evpkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t ret = RNP_ERROR_GENERIC;
    /* init context and sign */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize signing: %lu", ERR_peek_last_error());
        goto done;
    }
    sig->s.len = PGP_MPINT_SIZE;
    if (EVP_PKEY_sign(ctx, sig->s.mpi, &sig->s.len, hash, hash_len) <= 0) {
        RNP_LOG("Signing failed: %lu", ERR_peek_last_error());
        sig->s.len = 0;
        goto done;
    }
    if (!dsa_decode_sig(&sig->s.mpi[0], sig->s.len, *sig)) {
        RNP_LOG("Failed to parse DSA sig: %lu", ERR_peek_last_error());
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpkey);
    return ret;
}

rnp_result_t
dsa_verify(const pgp_dsa_signature_t *sig,
           const uint8_t *            hash,
           size_t                     hash_len,
           const pgp_dsa_key_t *      key)
{
    /* Load secret key to DSA structure*/
    EVP_PKEY *evpkey = dsa_load_key(key, false);
    if (!evpkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t ret = RNP_ERROR_GENERIC;
    /* init context and sign */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize verify: %lu", ERR_peek_last_error());
        goto done;
    }
    pgp_mpi_t sigbuf;
    if (!dsa_encode_sig(sigbuf.mpi, &sigbuf.len, *sig)) {
        goto done;
    }
    if (EVP_PKEY_verify(ctx, sigbuf.mpi, sigbuf.len, hash, hash_len) <= 0) {
        ret = RNP_ERROR_SIGNATURE_INVALID;
    } else {
        ret = RNP_SUCCESS;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpkey);
    return ret;
}

static bool
dsa_extract_key(EVP_PKEY *pkey, pgp_dsa_key_t &key)
{
#if defined(CRYPTO_BACKEND_OPENSSL3)
    rnp::bn p;
    rnp::bn q;
    rnp::bn g;
    rnp::bn y;
    rnp::bn x;

    bool res = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, p.ptr()) &&
               EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_Q, q.ptr()) &&
               EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, g.ptr()) &&
               EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, y.ptr()) &&
               EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, x.ptr());
    return res && p.mpi(key.p) && q.mpi(key.q) && g.mpi(key.g) && y.mpi(key.y) && x.mpi(key.x);
#else
    const DSA *dsa = EVP_PKEY_get0_DSA(pkey);
    if (!dsa) {
        RNP_LOG("Failed to retrieve DSA key: %lu", ERR_peek_last_error());
        return false;
    }

    const bignum_t *p = DSA_get0_p(dsa);
    const bignum_t *q = DSA_get0_q(dsa);
    const bignum_t *g = DSA_get0_g(dsa);
    const bignum_t *y = DSA_get0_pub_key(dsa);
    const bignum_t *x = DSA_get0_priv_key(dsa);

    if (!p || !q || !g || !y || !x) {
        return false;
    }
    return bn2mpi(p, &key.p) && bn2mpi(q, &key.q) && bn2mpi(g, &key.g) && bn2mpi(y, &key.y) &&
           bn2mpi(x, &key.x);
#endif
}

rnp_result_t
dsa_generate(rnp::RNG *rng, pgp_dsa_key_t *key, size_t keylen, size_t qbits)
{
    if ((keylen < 1024) || (keylen > 3072) || (qbits < 160) || (qbits > 256)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t  ret = RNP_ERROR_GENERIC;
    EVP_PKEY *    pkey = NULL;
    EVP_PKEY *    parmkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    /* Generate DSA params */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        return ret;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_paramgen_init(ctx) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, keylen) <= 0) {
        RNP_LOG("Failed to set key bits: %lu", ERR_peek_last_error());
        goto done;
    }
#if OPENSSL_VERSION_NUMBER < 0x1010105fL
    EVP_PKEY_CTX_ctrl(
      ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, qbits, NULL);
#else
    if (EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, qbits) <= 0) {
        RNP_LOG("Failed to set key qbits: %lu", ERR_peek_last_error());
        goto done;
    }
#endif
    if (EVP_PKEY_paramgen(ctx, &parmkey) <= 0) {
        RNP_LOG("Failed to generate parameters: %lu", ERR_peek_last_error());
        goto done;
    }
    EVP_PKEY_CTX_free(ctx);
    /* Generate DSA key */
    ctx = EVP_PKEY_CTX_new(parmkey, NULL);
    if (!ctx) {
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        RNP_LOG("DSA keygen failed: %lu", ERR_peek_last_error());
        goto done;
    }

    if (dsa_extract_key(pkey, *key)) {
        ret = RNP_SUCCESS;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(parmkey);
    EVP_PKEY_free(pkey);
    return ret;
}

pgp_hash_alg_t
dsa_get_min_hash(size_t qsize)
{
    /*
     * I'm using _broken_ SHA1 here only because
     * some old implementations may not understand keys created
     * with other hashes. If you're sure we don't have to support
     * such implementations, please be my guest and remove it.
     */
    return (qsize < 160)  ? PGP_HASH_UNKNOWN :
           (qsize == 160) ? PGP_HASH_SHA1 :
           (qsize <= 224) ? PGP_HASH_SHA224 :
           (qsize <= 256) ? PGP_HASH_SHA256 :
           (qsize <= 384) ? PGP_HASH_SHA384 :
           (qsize <= 512) ? PGP_HASH_SHA512
                            /*(qsize>512)*/ :
                            PGP_HASH_UNKNOWN;
}

size_t
dsa_choose_qsize_by_psize(size_t psize)
{
    return (psize == 1024) ? 160 :
           (psize <= 2047) ? 224 :
           (psize <= 3072) ? DSA_MAX_Q_BITLEN :
                             0;
}
