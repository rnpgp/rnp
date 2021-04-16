/*
 * Copyright (c) 2021, [Ribose Inc](https://www.ribose.com).
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

#include <string.h>
#include "ec.h"
#include "ec_ossl.h"
#include "bn.h"
#include "types.h"
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/ec.h>

rnp_result_t
x25519_generate(rng_t *rng, pgp_ec_key_t *key)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

EVP_PKEY *
ec_generate_pkey(const pgp_pubkey_alg_t alg_id, const pgp_curve_t curve)
{
    if (!alg_allows_curve(alg_id, curve)) {
        return NULL;
    }
    const ec_curve_desc_t *ec_desc = get_curve_desc(curve);
    if (!ec_desc) {
        return NULL;
    }
    int nid = OBJ_sn2nid(ec_desc->openssl_name);
    if (nid == NID_undef) {
        RNP_LOG("Unknown SN: %s", ec_desc->openssl_name);
        return NULL;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        return NULL;
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
        RNP_LOG("Failed to set curve nid: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        RNP_LOG("EC keygen failed: %lu", ERR_peek_last_error());
    }
done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

rnp_result_t
ec_generate(rng_t *                rng,
            pgp_ec_key_t *         key,
            const pgp_pubkey_alg_t alg_id,
            const pgp_curve_t      curve)
{
    EVP_PKEY *pkey = ec_generate_pkey(alg_id, curve);
    if (!pkey) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_result_t ret = RNP_ERROR_GENERIC;
    EC_KEY *     ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) {
        RNP_LOG("Failed to retrieve EC key: %lu", ERR_peek_last_error());
        goto done;
    }
    if (!ec_write_pubkey(pkey, key->p)) {
        RNP_LOG("Failed to write pubkey.");
        goto done;
    }
    const bignum_t *x;
    x = EC_KEY_get0_private_key(ec);
    if (!x) {
        ret = RNP_ERROR_BAD_STATE;
        goto done;
    }
    if (bn2mpi(x, &key->x)) {
        ret = RNP_SUCCESS;
    }
done:
    EVP_PKEY_free(pkey);
    return ret;
}

EVP_PKEY *
ec_load_key(const pgp_mpi_t &keyp, const pgp_mpi_t *keyx, pgp_curve_t curve)
{
    const ec_curve_desc_t *curv_desc = get_curve_desc(curve);
    if (!curv_desc) {
        RNP_LOG("unknown curve");
        return NULL;
    }
    int nid = OBJ_sn2nid(curv_desc->openssl_name);
    if (nid == NID_undef) {
        RNP_LOG("Unknown SN: %s", curv_desc->openssl_name);
        return NULL;
    }
    EC_KEY *ec = EC_KEY_new_by_curve_name(nid);
    if (!ec) {
        RNP_LOG("Failed to create EC key with group %d: %lu", nid, ERR_peek_last_error());
        return NULL;
    }

    bool      res = false;
    bignum_t *x = NULL;
    EVP_PKEY *pkey = NULL;
    EC_POINT *p = EC_POINT_new(EC_KEY_get0_group(ec));
    if (!p) {
        RNP_LOG("Failed to allocate point: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EC_POINT_oct2point(EC_KEY_get0_group(ec), p, keyp.mpi, keyp.len, NULL) <= 0) {
        RNP_LOG("Failed to decode point: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EC_KEY_set_public_key(ec, p) <= 0) {
        RNP_LOG("Failed to set public key: %lu", ERR_peek_last_error());
        goto done;
    }

    pkey = EVP_PKEY_new();
    if (!pkey) {
        RNP_LOG("EVP_PKEY allocation failed: %lu", ERR_peek_last_error());
        goto done;
    }
    if (!keyx) {
        res = true;
        goto done;
    }

    x = mpi2bn(keyx);
    if (!x) {
        RNP_LOG("allocation failed");
        goto done;
    }
    if (EC_KEY_set_private_key(ec, x) <= 0) {
        RNP_LOG("Failed to set secret key: %lu", ERR_peek_last_error());
        goto done;
    }
    res = true;
done:
    if (res) {
        res = EVP_PKEY_set1_EC_KEY(pkey, ec) > 0;
    }
    EC_POINT_free(p);
    BN_free(x);
    EC_KEY_free(ec);
    if (!res) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    return pkey;
}

rnp_result_t
ec_validate_key(const pgp_ec_key_t &key, bool secret)
{
    EVP_PKEY *evpkey = ec_load_key(key.p, secret ? &key.x : NULL, key.curve);
    if (!evpkey) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_result_t  ret = RNP_ERROR_GENERIC;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (!ctx) {
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_check(ctx) > 0) {
        ret = RNP_SUCCESS;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpkey);
    return ret;
}

bool
ec_write_pubkey(EVP_PKEY *pkey, pgp_mpi_t &mpi)
{
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) {
        RNP_LOG("Failed to retrieve EC key: %lu", ERR_peek_last_error());
        return false;
    }
    const EC_POINT *p = EC_KEY_get0_public_key(ec);
    if (!p) {
        RNP_LOG("Null point: %lu", ERR_peek_last_error());
        return false;
    }
    /* call below adds leading zeroes if needed */
    mpi.len = EC_POINT_point2oct(
      EC_KEY_get0_group(ec), p, POINT_CONVERSION_UNCOMPRESSED, mpi.mpi, sizeof(mpi.mpi), NULL);
    if (!mpi.len) {
        RNP_LOG("Failed to encode public key: %lu", ERR_peek_last_error());
    }
    return mpi.len;
}
