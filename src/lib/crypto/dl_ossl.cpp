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

#include <cstdlib>
#include <string>
#include <cassert>
#include "bn.h"
#include "dl_ossl.h"
#include "utils.h"
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#if defined(CRYPTO_BACKEND_OPENSSL3)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#if defined(CRYPTO_BACKEND_OPENSSL3)
static OSSL_PARAM *
dl_build_params(bignum_t *p, bignum_t *q, bignum_t *g, bignum_t *y, bignum_t *x)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        return NULL; // LCOV_EXCL_LINE
    }
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p) ||
        (q && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q)) ||
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

EVP_PKEY *
dl_load_key(const pgp_mpi_t &mp,
            const pgp_mpi_t *mq,
            const pgp_mpi_t &mg,
            const pgp_mpi_t &my,
            const pgp_mpi_t *mx)
{
    EVP_PKEY *evpkey = NULL;
    rnp::bn   p(mpi2bn(&mp));
    rnp::bn   q(mq ? mpi2bn(mq) : NULL);
    rnp::bn   g(mpi2bn(&mg));
    rnp::bn   y(mpi2bn(&my));
    rnp::bn   x(mx ? mpi2bn(mx) : NULL);

    if (!p.get() || (mq && !q.get()) || !g.get() || !y.get() || (mx && !x.get())) {
        /* LCOV_EXCL_START */
        RNP_LOG("out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }

#if defined(CRYPTO_BACKEND_OPENSSL3)
    OSSL_PARAM *params = dl_build_params(p.get(), q.get(), g.get(), y.get(), x.get());
    if (!params) {
        /* LCOV_EXCL_START */
        RNP_LOG("failed to build dsa params");
        return NULL;
        /* LCOV_EXCL_END */
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("failed to create dl context");
        OSSL_PARAM_free(params);
        return NULL;
        /* LCOV_EXCL_END */
    }
    if ((EVP_PKEY_fromdata_init(ctx) != 1) ||
        (EVP_PKEY_fromdata(
           ctx, &evpkey, mx ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) != 1)) {
        /* LCOV_EXCL_START */
        RNP_LOG("failed to create key from data");
        evpkey = NULL;
        /* LCOV_EXCL_END */
    }
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    return evpkey;
#else
    DH *dh = DH_new();
    if (!dh) {
        /* LCOV_EXCL_START */
        RNP_LOG("out of memory");
        return NULL;
        /* LCOV_EXCL_END */
    }
    /* line below must not fail */
    int res = DH_set0_pqg(dh, p.own(), q.own(), g.own());
    assert(res == 1);
    if (res < 1) {
        goto done;
    }
    /* line below must not fail */
    res = DH_set0_key(dh, y.own(), x.own());
    assert(res == 1);
    if (res < 1) {
        goto done;
    }

    evpkey = EVP_PKEY_new();
    if (!evpkey) {
        /* LCOV_EXCL_START */
        RNP_LOG("allocation failed");
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_set1_DH(evpkey, dh) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set key: %lu", ERR_peek_last_error());
        EVP_PKEY_free(evpkey);
        evpkey = NULL;
        /* LCOV_EXCL_END */
    }
done:
    DH_free(dh);
    return evpkey;
#endif
}

#if !defined(CRYPTO_BACKEND_OPENSSL3)
static rnp_result_t
dl_validate_secret_key(EVP_PKEY *dlkey, const pgp_mpi_t &mx)
{
    const DH *dh = EVP_PKEY_get0_DH(dlkey);
    assert(dh);
    const bignum_t *p = DH_get0_p(dh);
    const bignum_t *q = DH_get0_q(dh);
    const bignum_t *g = DH_get0_g(dh);
    const bignum_t *y = DH_get0_pub_key(dh);
    assert(p && g && y);
    bignum_t *p1 = NULL;

    rnp_result_t ret = RNP_ERROR_GENERIC;

    BN_CTX *  ctx = BN_CTX_new();
    bignum_t *x = mpi2bn(&mx);
    bignum_t *cy = bn_new();

    if (!x || !cy || !ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Allocation failed");
        goto done;
        /* LCOV_EXCL_END */
    }
    if (!q) {
        /* if q is NULL then group order is (p - 1) / 2 */
        p1 = BN_dup(p);
        if (!p1) {
            /* LCOV_EXCL_START */
            RNP_LOG("Allocation failed");
            goto done;
            /* LCOV_EXCL_END */
        }
        int res;
        res = BN_rshift(p1, p1, 1);
        assert(res == 1);
        if (res < 1) {
            /* LCOV_EXCL_START */
            RNP_LOG("BN_rshift failed.");
            goto done;
            /* LCOV_EXCL_END */
        }
        q = p1;
    }
    if (BN_cmp(x, q) != -1) {
        RNP_LOG("x is too large.");
        goto done;
    }
    if (BN_mod_exp_mont_consttime(cy, g, x, p, ctx, NULL) < 1) {
        RNP_LOG("Exponentiation failed");
        goto done;
    }
    if (BN_cmp(cy, y) == 0) {
        ret = RNP_SUCCESS;
    }
done:
    BN_CTX_free(ctx);
    bn_free(x);
    bn_free(cy);
    bn_free(p1);
    return ret;
}
#endif

rnp_result_t
dl_validate_key(EVP_PKEY *pkey, const pgp_mpi_t *x)
{
    rnp_result_t  ret = RNP_ERROR_GENERIC;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    int res;
    res = EVP_PKEY_param_check(ctx);
    if (res < 0) {
        RNP_LOG("Param validation error: %lu (%s)",
                ERR_peek_last_error(),
                ERR_reason_error_string(ERR_peek_last_error()));
    }
    if (res < 1) {
        /* ElGamal specification doesn't seem to restrict P to the safe prime */
        auto err = ERR_peek_last_error();
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_P_NOT_SAFE_PRIME);
        if ((ERR_GET_REASON(err) == DH_R_CHECK_P_NOT_SAFE_PRIME)) {
            RNP_LOG("Warning! P is not a safe prime.");
        } else {
            goto done;
        }
    }
#if defined(CRYPTO_BACKEND_OPENSSL3)
    res = x ? EVP_PKEY_pairwise_check(ctx) : EVP_PKEY_public_check(ctx);
    if (res == 1) {
        ret = RNP_SUCCESS;
    }
#else
    res = EVP_PKEY_public_check(ctx);
    if (res < 0) {
        RNP_LOG("Key validation error: %lu", ERR_peek_last_error());
    }
    if (res < 1) {
        goto done;
    }
    /* There is no private key check in OpenSSL yet, so need to check x vs y manually */
    if (!x) {
        ret = RNP_SUCCESS;
        goto done;
    }
    ret = dl_validate_secret_key(pkey, *x);
#endif
done:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}
