/*
 * Copyright (c) 2021-2023, [Ribose Inc](https://www.ribose.com).
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
#include "bn.h"
#include "ossl_common.h"
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#ifdef CRYPTO_BACKEND_OPENSSL3
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif
#include "hash_ossl.hpp"

#ifndef CRYPTO_BACKEND_OPENSSL3
static RSA *
rsa_load_public_key(const pgp_rsa_key_t *key)
{
    rnp::bn n(key->n);
    rnp::bn e(key->e);

    if (!n.get() || !e.get()) {
        /* LCOV_EXCL_START */
        RNP_LOG("out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }
    RSA *rsa = RSA_new();
    if (!rsa) {
        /* LCOV_EXCL_START */
        RNP_LOG("Out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }
    /* OpenSSL set0 function transfers ownership of bignums */
    if (RSA_set0_key(rsa, n.own(), e.own(), NULL) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Public key load error: %lu", ERR_peek_last_error());
        RSA_free(rsa);
        return NULL;
        /* LCOV_EXCL_END */
    }
    return rsa;
}

static RSA *
rsa_load_secret_key(const pgp_rsa_key_t *key)
{
    rnp::bn n(key->n);
    rnp::bn e(key->e);
    rnp::bn p(key->p);
    rnp::bn q(key->q);
    rnp::bn d(key->d);

    if (!n.get() || !p.get() || !q.get() || !e.get() || !d.get()) {
        /* LCOV_EXCL_START */
        RNP_LOG("out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }

    RSA *rsa = RSA_new();
    if (!rsa) {
        /* LCOV_EXCL_START */
        RNP_LOG("Out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }
    /* OpenSSL set0 function transfers ownership of bignums */
    if (RSA_set0_key(rsa, n.own(), e.own(), d.own()) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Secret key load error: %lu", ERR_peek_last_error());
        RSA_free(rsa);
        return NULL;
        /* LCOV_EXCL_END */
    }
    /* OpenSSL has p < q, as we do */
    if (RSA_set0_factors(rsa, p.own(), q.own()) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Factors load error: %lu", ERR_peek_last_error());
        RSA_free(rsa);
        return NULL;
        /* LCOV_EXCL_END */
    }
    return rsa;
}

static EVP_PKEY_CTX *
rsa_init_context(const pgp_rsa_key_t *key, bool secret)
{
    EVP_PKEY *evpkey = EVP_PKEY_new();
    if (!evpkey) {
        /* LCOV_EXCL_START */
        RNP_LOG("allocation failed");
        return NULL;
        /* LCOV_EXCL_END */
    }
    EVP_PKEY_CTX *ctx = NULL;
    RSA *         rsakey = secret ? rsa_load_secret_key(key) : rsa_load_public_key(key);
    if (!rsakey) {
        goto done;
    }
    if (EVP_PKEY_set1_RSA(evpkey, rsakey) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set key: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (!ctx) {
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error()); // LCOV_EXCL_LINE
    }
done:
    RSA_free(rsakey);
    EVP_PKEY_free(evpkey);
    return ctx;
}
#else
static OSSL_PARAM *
rsa_bld_params(const pgp_rsa_key_t *key, bool secret)
{
    OSSL_PARAM *    params = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    rnp::bn         n(key->n);
    rnp::bn         e(key->e);
    rnp::bn         d;
    rnp::bn         p;
    rnp::bn         q;
    rnp::bn         u;
    BN_CTX *        bnctx = NULL;

    if (!n.get() || !e.get() || !bld) {
        /* LCOV_EXCL_START */
        RNP_LOG("Out of memory");
        goto done;
        /* LCOV_EXCL_END */
    }

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e.get())) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to push RSA params.");
        OSSL_PARAM_BLD_free(bld);
        return NULL;
        /* LCOV_EXCL_END */
    }
    if (secret) {
        d.set(key->d);
        /* As we have u = p^-1 mod q, and qInv = q^-1 mod p, we need to replace one with
         * another */
        p.set(key->q);
        q.set(key->p);
        u.set(key->u);
        if (!d.get() || !p.get() || !q.get() || !u.get()) {
            goto done;
        }
        /* We need to calculate exponents manually */
        bnctx = BN_CTX_new();
        if (!bnctx) {
            /* LCOV_EXCL_START */
            RNP_LOG("Failed to allocate BN_CTX.");
            goto done;
            /* LCOV_EXCL_END */
        }
        bignum_t *p1 = BN_CTX_get(bnctx);
        bignum_t *q1 = BN_CTX_get(bnctx);
        bignum_t *dp = BN_CTX_get(bnctx);
        bignum_t *dq = BN_CTX_get(bnctx);
        if (!BN_copy(p1, p.get()) || !BN_sub_word(p1, 1) || !BN_copy(q1, q.get()) ||
            !BN_sub_word(q1, 1) || !BN_mod(dp, d.get(), p1, bnctx) ||
            !BN_mod(dq, d.get(), q1, bnctx)) {
            RNP_LOG("Failed to calculate dP or dQ."); // LCOV_EXCL_LINE
        }
        /* Push params */
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d.get()) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p.get()) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q.get()) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, u.get())) {
            RNP_LOG("Failed to push RSA secret params."); // LCOV_EXCL_LINE
            goto done;
        }
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) {
        RNP_LOG("Failed to build RSA params: %s.", ossl_latest_err()); // LCOV_EXCL_LINE
    }
done:
    BN_CTX_free(bnctx);
    OSSL_PARAM_BLD_free(bld);
    return params;
}

static EVP_PKEY *
rsa_load_key(const pgp_rsa_key_t *key, bool secret)
{
    /* Build params */
    OSSL_PARAM *params = rsa_bld_params(key, secret);
    if (!params) {
        return NULL;
    }
    /* Create context for key creation */
    EVP_PKEY *    res = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Context allocation failed: %s", ossl_latest_err());
        goto done;
        /* LCOV_EXCL_END */
    }
    /* Create key */
    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to initialize key creation: %s", ossl_latest_err());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_fromdata(
          ctx, &res, secret ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        RNP_LOG("Failed to create RSA key: %s", ossl_latest_err()); // LCOV_EXCL_LINE
    }
done:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    return res;
}

static EVP_PKEY_CTX *
rsa_init_context(const pgp_rsa_key_t *key, bool secret)
{
    EVP_PKEY *pkey = rsa_load_key(key, secret);
    if (!pkey) {
        return NULL;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        RNP_LOG("Context allocation failed: %s", ossl_latest_err()); // LCOV_EXCL_LINE
    }
    EVP_PKEY_free(pkey);
    return ctx;
}
#endif

rnp_result_t
rsa_validate_key(rnp::RNG *rng, const pgp_rsa_key_t *key, bool secret)
{
#ifdef CRYPTO_BACKEND_OPENSSL3
    EVP_PKEY_CTX *ctx = rsa_init_context(key, secret);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to init context: %s", ossl_latest_err());
        return RNP_ERROR_GENERIC;
        /* LCOV_EXCL_END */
    }
    int res = secret ? EVP_PKEY_pairwise_check(ctx) : EVP_PKEY_public_check(ctx);
    if (res <= 0) {
        RNP_LOG("Key validation error: %s", ossl_latest_err()); // LCOV_EXCL_LINE
    }
    EVP_PKEY_CTX_free(ctx);
    return res > 0 ? RNP_SUCCESS : RNP_ERROR_GENERIC;
#else
    if (secret) {
        EVP_PKEY_CTX *ctx = rsa_init_context(key, secret);
        if (!ctx) {
            /* LCOV_EXCL_START */
            RNP_LOG("Failed to init context: %s", ossl_latest_err());
            return RNP_ERROR_GENERIC;
            /* LCOV_EXCL_END */
        }
        int res = EVP_PKEY_check(ctx);
        if (res <= 0) {
            RNP_LOG("Key validation error: %s", ossl_latest_err()); // LCOV_EXCL_LINE
        }
        EVP_PKEY_CTX_free(ctx);
        return res > 0 ? RNP_SUCCESS : RNP_ERROR_GENERIC;
    }

    /* OpenSSL 1.1.1 doesn't have RSA public key check function, so let's do some checks */
    rnp::bn n(key->n);
    rnp::bn e(key->e);
    if (!n.get() || !e.get()) {
        /* LCOV_EXCL_START */
        RNP_LOG("out of memory");
        return RNP_ERROR_OUT_OF_MEMORY;
        /* LCOV_EXCL_END */
    }
    if ((BN_num_bits(n.get()) < 512) || !BN_is_odd(n.get()) || (BN_num_bits(e.get()) < 2) ||
        !BN_is_odd(e.get())) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
#endif
}

static bool
rsa_setup_context(EVP_PKEY_CTX *ctx)
{
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        RNP_LOG("Failed to set padding: %lu", ERR_peek_last_error());
        return false;
    }
    return true;
}

static const uint8_t PKCS1_SHA1_ENCODING[15] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};

static bool
rsa_setup_signature_hash(EVP_PKEY_CTX *  ctx,
                         pgp_hash_alg_t  hash_alg,
                         const uint8_t *&enc,
                         size_t &        enc_size)
{
    const char *hash_name = rnp::Hash_OpenSSL::name(hash_alg);
    if (!hash_name) {
        RNP_LOG("Unknown hash: %d", (int) hash_alg);
        return false;
    }
    const EVP_MD *hash_tp = EVP_get_digestbyname(hash_name);
    if (!hash_tp) {
        RNP_LOG("Error creating hash object for '%s'", hash_name);
        return false;
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, hash_tp) <= 0) {
        if ((hash_alg != PGP_HASH_SHA1)) {
            RNP_LOG("Failed to set digest %s: %s", hash_name, ossl_latest_err());
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
rsa_encrypt_pkcs1(rnp::RNG *           rng,
                  pgp_rsa_encrypted_t *out,
                  const uint8_t *      in,
                  size_t               in_len,
                  const pgp_rsa_key_t *key)
{
    rnp_result_t  ret = RNP_ERROR_GENERIC;
    EVP_PKEY_CTX *ctx = rsa_init_context(key, false);
    if (!ctx) {
        return ret;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize encryption: %lu", ERR_peek_last_error());
        goto done;
    }
    if (!rsa_setup_context(ctx)) {
        goto done;
    }
    out->m.len = sizeof(out->m.mpi);
    if (EVP_PKEY_encrypt(ctx, out->m.mpi, &out->m.len, in, in_len) <= 0) {
        RNP_LOG("Encryption failed: %lu", ERR_peek_last_error());
        out->m.len = 0;
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

rnp_result_t
rsa_verify_pkcs1(const pgp_rsa_signature_t *sig,
                 pgp_hash_alg_t             hash_alg,
                 const uint8_t *            hash,
                 size_t                     hash_len,
                 const pgp_rsa_key_t *      key)
{
    rnp_result_t  ret = RNP_ERROR_SIGNATURE_INVALID;
    EVP_PKEY_CTX *ctx = rsa_init_context(key, false);
    if (!ctx) {
        return ret;
    }
    const uint8_t *hash_enc = NULL;
    size_t         hash_enc_size = 0;
    uint8_t        hash_enc_buf[PGP_MAX_HASH_SIZE + 32] = {0};
    assert(hash_len + hash_enc_size <= sizeof(hash_enc_buf));

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize verification: %lu", ERR_peek_last_error());
        goto done;
    }
    if (!rsa_setup_context(ctx) ||
        !rsa_setup_signature_hash(ctx, hash_alg, hash_enc, hash_enc_size)) {
        goto done;
    }
    /* Check whether we need to workaround on unsupported SHA1 for RSA signature verification
     */
    if (hash_enc_size) {
        memcpy(hash_enc_buf, hash_enc, hash_enc_size);
        memcpy(&hash_enc_buf[hash_enc_size], hash, hash_len);
        hash = hash_enc_buf;
        hash_len += hash_enc_size;
    }
    int res;
    if (sig->s.len < key->n.len) {
        /* OpenSSL doesn't like signatures smaller then N */
        pgp_mpi_t sn;
        sn.len = key->n.len;
        size_t diff = key->n.len - sig->s.len;
        memset(sn.mpi, 0, diff);
        memcpy(&sn.mpi[diff], sig->s.mpi, sig->s.len);
        res = EVP_PKEY_verify(ctx, sn.mpi, sn.len, hash, hash_len);
    } else {
        res = EVP_PKEY_verify(ctx, sig->s.mpi, sig->s.len, hash, hash_len);
    }
    if (res > 0) {
        ret = RNP_SUCCESS;
    } else {
        RNP_LOG("RSA verification failure: %s", ossl_latest_err());
    }
done:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

rnp_result_t
rsa_sign_pkcs1(rnp::RNG *           rng,
               pgp_rsa_signature_t *sig,
               pgp_hash_alg_t       hash_alg,
               const uint8_t *      hash,
               size_t               hash_len,
               const pgp_rsa_key_t *key)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;
    if (mpi_bytes(&key->q) == 0) {
        RNP_LOG("private key not set");
        return ret;
    }
    EVP_PKEY_CTX *ctx = rsa_init_context(key, true);
    if (!ctx) {
        return ret;
    }
    const uint8_t *hash_enc = NULL;
    size_t         hash_enc_size = 0;
    uint8_t        hash_enc_buf[PGP_MAX_HASH_SIZE + 32] = {0};
    assert(hash_len + hash_enc_size <= sizeof(hash_enc_buf));
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize signing: %lu", ERR_peek_last_error());
        goto done;
    }
    if (!rsa_setup_context(ctx) ||
        !rsa_setup_signature_hash(ctx, hash_alg, hash_enc, hash_enc_size)) {
        goto done;
    }
    /* Check whether we need to workaround on unsupported SHA1 for RSA signature verification
     */
    if (hash_enc_size) {
        memcpy(hash_enc_buf, hash_enc, hash_enc_size);
        memcpy(&hash_enc_buf[hash_enc_size], hash, hash_len);
        hash = hash_enc_buf;
        hash_len += hash_enc_size;
    }
    sig->s.len = PGP_MPINT_SIZE;
    if (EVP_PKEY_sign(ctx, sig->s.mpi, &sig->s.len, hash, hash_len) <= 0) {
        RNP_LOG("Encryption failed: %lu", ERR_peek_last_error());
        sig->s.len = 0;
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

rnp_result_t
rsa_decrypt_pkcs1(rnp::RNG *                 rng,
                  uint8_t *                  out,
                  size_t *                   out_len,
                  const pgp_rsa_encrypted_t *in,
                  const pgp_rsa_key_t *      key)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;
    if (mpi_bytes(&key->q) == 0) {
        RNP_LOG("private key not set");
        return ret;
    }
    EVP_PKEY_CTX *ctx = rsa_init_context(key, true);
    if (!ctx) {
        return ret;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize encryption: %lu", ERR_peek_last_error());
        goto done;
    }
    if (!rsa_setup_context(ctx)) {
        goto done;
    }
    *out_len = PGP_MPINT_SIZE;
    if (EVP_PKEY_decrypt(ctx, out, out_len, in->m.mpi, in->m.len) <= 0) {
        RNP_LOG("Encryption failed: %lu", ERR_peek_last_error());
        *out_len = 0;
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static bool
rsa_calculate_pqu(const bignum_t *p, const bignum_t *q, const bignum_t *u, pgp_rsa_key_t &key)
{
    /* OpenSSL doesn't care whether p < q */
    if (BN_cmp(p, q) > 0) {
        /* In this case we have u, as iqmp is inverse of q mod p, and we exchange them */
        bn2mpi(q, &key.p);
        bn2mpi(p, &key.q);
        bn2mpi(u, &key.u);
        return true;
    }

    BN_CTX *bnctx = BN_CTX_new();
    if (!bnctx) {
        return false;
    }

    /* we need to calculate u, since we need inverse of p mod q, while OpenSSL has inverse of q
     * mod p, and doesn't care of p < q */
    BN_CTX_start(bnctx);
    bignum_t *nu = BN_CTX_get(bnctx);
    bignum_t *nq = BN_CTX_get(bnctx);
    if (!nu || !nq) {
        BN_CTX_free(bnctx);
        return false;
    }
    BN_with_flags(nq, q, BN_FLG_CONSTTIME);
    /* calculate inverse of p mod q */
    if (!BN_mod_inverse(nu, p, nq, bnctx)) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to calculate u");
        BN_CTX_free(bnctx);
        return false;
        /* LCOV_EXCL_END */
    }
    bn2mpi(p, &key.p);
    bn2mpi(q, &key.q);
    bn2mpi(nu, &key.u);
    BN_CTX_free(bnctx);
    return true;
}

static bool
rsa_extract_key(EVP_PKEY *pkey, pgp_rsa_key_t &key)
{
#if defined(CRYPTO_BACKEND_OPENSSL3)
    rnp::bn n;
    rnp::bn e;
    rnp::bn d;
    rnp::bn p;
    rnp::bn q;
    rnp::bn u;

    bool res = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, n.ptr()) &&
               EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, e.ptr()) &&
               EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, d.ptr()) &&
               EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, p.ptr()) &&
               EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, q.ptr()) &&
               EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, u.ptr()) &&
               rsa_calculate_pqu(p.get(), q.get(), u.get(), key);
    return res && n.mpi(key.n) && e.mpi(key.e) && d.mpi(key.d);
#else
    const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        RNP_LOG("Failed to retrieve RSA key: %lu", ERR_peek_last_error());
        return false;
    }
    if (RSA_check_key(rsa) != 1) {
        RNP_LOG("Key validation error: %lu", ERR_peek_last_error());
        return false;
    }

    const bignum_t *n = RSA_get0_n(rsa);
    const bignum_t *e = RSA_get0_e(rsa);
    const bignum_t *d = RSA_get0_d(rsa);
    const bignum_t *p = RSA_get0_p(rsa);
    const bignum_t *q = RSA_get0_q(rsa);
    const bignum_t *u = RSA_get0_iqmp(rsa);
    if (!n || !e || !d || !p || !q || !u) {
        return false;
    }
    if (!rsa_calculate_pqu(p, q, u, key)) {
        return false;
    }
    bn2mpi(n, &key.n);
    bn2mpi(e, &key.e);
    bn2mpi(d, &key.d);
    return true;
#endif
}

rnp_result_t
rsa_generate(rnp::RNG *rng, pgp_rsa_key_t *key, size_t numbits)
{
    if ((numbits < 1024) || (numbits > PGP_MPINT_BITS)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t  ret = RNP_ERROR_GENERIC;
    EVP_PKEY *    pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        return ret;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, numbits) <= 0) {
        RNP_LOG("Failed to set rsa bits: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        RNP_LOG("RSA keygen failed: %lu", ERR_peek_last_error());
        goto done;
    }
    if (rsa_extract_key(pkey, *key)) {
        ret = RNP_SUCCESS;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ret;
}
