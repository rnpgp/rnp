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

#include <string>
#include <cassert>
#include "ec.h"
#include "ec_ossl.h"
#include "bn.h"
#include "types.h"
#include "mem.h"
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#if defined(CRYPTO_BACKEND_OPENSSL3)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

static bool
ec_is_raw_key(const pgp_curve_t curve)
{
    return (curve == PGP_CURVE_ED25519) || (curve == PGP_CURVE_25519);
}

rnp_result_t
x25519_generate(rnp::RNG *rng, pgp_ec_key_t *key)
{
    return ec_generate(rng, key, PGP_PKA_ECDH, PGP_CURVE_25519);
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
        /* LCOV_EXCL_START */
        RNP_LOG("Unknown SN: %s", ec_desc->openssl_name);
        return NULL;
        /* LCOV_EXCL_END */
    }
    bool          raw = ec_is_raw_key(curve);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(raw ? nid : EVP_PKEY_EC, NULL);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        return NULL;
        /* LCOV_EXCL_END */
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (!raw && (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0)) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set curve nid: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        RNP_LOG("EC keygen failed: %lu", ERR_peek_last_error()); // LCOV_EXCL_LINE
    }
done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static bool
ec_write_raw_seckey(EVP_PKEY *pkey, pgp_ec_key_t *key)
{
    /* EdDSA and X25519 keys are saved in a different way */
    static_assert(sizeof(key->x.mpi) > 32, "mpi is too small.");
    key->x.len = sizeof(key->x.mpi);
    if (EVP_PKEY_get_raw_private_key(pkey, key->x.mpi, &key->x.len) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed get raw private key: %lu", ERR_peek_last_error());
        return false;
        /* LCOV_EXCL_END */
    }
    assert(key->x.len == 32);
    if (EVP_PKEY_id(pkey) == EVP_PKEY_X25519) {
        /* in OpenSSL private key is exported as little-endian, while MPI is big-endian */
        for (size_t i = 0; i < 16; i++) {
            std::swap(key->x.mpi[i], key->x.mpi[31 - i]);
        }
    }
    return true;
}

static bool
ec_write_seckey(EVP_PKEY *pkey, pgp_mpi_t &key)
{
#if defined(CRYPTO_BACKEND_OPENSSL3)
    rnp::bn x;
    return EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, x.ptr()) &&
           bn2mpi(x.get(), &key);
#else
    const bignum_t *x = NULL;
    const EC_KEY *  ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to retrieve EC key: %lu", ERR_peek_last_error());
        return false;
        /* LCOV_EXCL_END */
    }
    x = EC_KEY_get0_private_key(ec);
    if (!x) {
        return false;
    }
    return bn2mpi(x, &key);
#endif
}

rnp_result_t
ec_generate(rnp::RNG *             rng,
            pgp_ec_key_t *         key,
            const pgp_pubkey_alg_t alg_id,
            const pgp_curve_t      curve)
{
    EVP_PKEY *pkey = ec_generate_pkey(alg_id, curve);
    if (!pkey) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_result_t ret = RNP_ERROR_GENERIC;
    if (ec_is_raw_key(curve)) {
        if (ec_write_pubkey(pkey, key->p, curve) && ec_write_raw_seckey(pkey, key)) {
            ret = RNP_SUCCESS;
        }
        EVP_PKEY_free(pkey);
        return ret;
    }
    if (!ec_write_pubkey(pkey, key->p, curve)) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to write pubkey.");
        goto done;
        /* LCOV_EXCL_END */
    }
    if (!ec_write_seckey(pkey, key->x)) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to write seckey.");
        goto done;
        /* LCOV_EXCL_END */
    }
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_free(pkey);
    return ret;
}

static EVP_PKEY *
ec_load_raw_key(const pgp_mpi_t &keyp, const pgp_mpi_t *keyx, int nid)
{
    if (!keyx) {
        /* as per RFC, EdDSA & 25519 keys must use 0x40 byte for encoding */
        if ((mpi_bytes(&keyp) != 33) || (keyp.mpi[0] != 0x40)) {
            RNP_LOG("Invalid 25519 public key.");
            return NULL;
        }

        EVP_PKEY *evpkey =
          EVP_PKEY_new_raw_public_key(nid, NULL, &keyp.mpi[1], mpi_bytes(&keyp) - 1);
        if (!evpkey) {
            RNP_LOG("Failed to load public key: %lu", ERR_peek_last_error()); // LCOV_EXCL_LINE
        }
        return evpkey;
    }

    EVP_PKEY *evpkey = NULL;
    if (nid == EVP_PKEY_X25519) {
        if (keyx->len != 32) {
            RNP_LOG("Invalid 25519 secret key");
            return NULL;
        }
        /* need to reverse byte order since in mpi we have big-endian */
        rnp::secure_array<uint8_t, 32> prkey;
        for (int i = 0; i < 32; i++) {
            prkey[i] = keyx->mpi[31 - i];
        }
        evpkey = EVP_PKEY_new_raw_private_key(nid, NULL, prkey.data(), keyx->len);
    } else {
        if (keyx->len > 32) {
            RNP_LOG("Invalid Ed25519 secret key");
            return NULL;
        }
        /* keyx->len may be smaller then 32 as high byte is random and could become 0 */
        rnp::secure_array<uint8_t, 32> prkey{};
        memcpy(prkey.data() + 32 - keyx->len, keyx->mpi, keyx->len);
        evpkey = EVP_PKEY_new_raw_private_key(nid, NULL, prkey.data(), 32);
    }
    if (!evpkey) {
        RNP_LOG("Failed to load private key: %lu", ERR_peek_last_error()); // LCOV_EXCL_LINE
    }
    return evpkey;
}

#if defined(CRYPTO_BACKEND_OPENSSL3)
static OSSL_PARAM *
ec_build_params(const pgp_mpi_t &p, bignum_t *x, const char *curve)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        return NULL;
    }
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve, 0) ||
        !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, p.mpi, p.len) ||
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

static EVP_PKEY *
ec_load_key_openssl3(const pgp_mpi_t &      keyp,
                     const pgp_mpi_t *      keyx,
                     const ec_curve_desc_t *curv_desc)
{
    rnp::bn     x(keyx ? mpi2bn(keyx) : NULL);
    OSSL_PARAM *params = ec_build_params(keyp, x.get(), curv_desc->openssl_name);
    if (!params) {
        /* LCOV_EXCL_START */
        RNP_LOG("failed to build ec params");
        return NULL;
        /* LCOV_EXCL_END */
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("failed to create ec context");
        OSSL_PARAM_free(params);
        return NULL;
        /* LCOV_EXCL_END */
    }
    EVP_PKEY *evpkey = NULL;
    if ((EVP_PKEY_fromdata_init(ctx) != 1) ||
        (EVP_PKEY_fromdata(
           ctx, &evpkey, keyx ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) != 1)) {
        /* LCOV_EXCL_START */
        RNP_LOG("failed to create ec key from data");
        /* Some version of OpenSSL may leave evpkey non-NULL after failure, so let's be safe */
        evpkey = NULL;
        /* LCOV_EXCL_END */
    }
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    return evpkey;
}
#endif

EVP_PKEY *
ec_load_key(const pgp_mpi_t &keyp, const pgp_mpi_t *keyx, pgp_curve_t curve)
{
    const ec_curve_desc_t *curv_desc = get_curve_desc(curve);
    if (!curv_desc) {
        RNP_LOG("unknown curve");
        return NULL;
    }
    if (!curve_supported(curve)) {
        RNP_LOG("Curve %s is not supported.", curv_desc->pgp_name);
        return NULL;
    }
    int nid = OBJ_sn2nid(curv_desc->openssl_name);
    if (nid == NID_undef) {
        /* LCOV_EXCL_START */
        RNP_LOG("Unknown SN: %s", curv_desc->openssl_name);
        return NULL;
        /* LCOV_EXCL_END */
    }
    /* EdDSA and X25519 keys are loaded in a different way */
    if (ec_is_raw_key(curve)) {
        return ec_load_raw_key(keyp, keyx, nid);
    }
#if defined(CRYPTO_BACKEND_OPENSSL3)
    return ec_load_key_openssl3(keyp, keyx, curv_desc);
#else
    EC_KEY *ec = EC_KEY_new_by_curve_name(nid);
    if (!ec) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to create EC key with group %d (%s): %s",
                nid,
                curv_desc->openssl_name,
                ERR_reason_error_string(ERR_peek_last_error()));
        return NULL;
        /* LCOV_EXCL_END */
    }

    bool      res = false;
    bignum_t *x = NULL;
    EVP_PKEY *pkey = NULL;
    EC_POINT *p = EC_POINT_new(EC_KEY_get0_group(ec));
    if (!p) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to allocate point: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EC_POINT_oct2point(EC_KEY_get0_group(ec), p, keyp.mpi, keyp.len, NULL) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to decode point: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EC_KEY_set_public_key(ec, p) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set public key: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }

    pkey = EVP_PKEY_new();
    if (!pkey) {
        /* LCOV_EXCL_START */
        RNP_LOG("EVP_PKEY allocation failed: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (!keyx) {
        res = true;
        goto done;
    }

    x = mpi2bn(keyx);
    if (!x) {
        /* LCOV_EXCL_START */
        RNP_LOG("allocation failed");
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EC_KEY_set_private_key(ec, x) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set secret key: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
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
#endif
}

rnp_result_t
ec_validate_key(const pgp_ec_key_t &key, bool secret)
{
    if (key.curve == PGP_CURVE_25519) {
        /* No key check implementation for x25519 in the OpenSSL yet, so just basic size checks
         */
        if ((mpi_bytes(&key.p) != 33) || (key.p.mpi[0] != 0x40)) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        if (secret && mpi_bytes(&key.x) != 32) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        return RNP_SUCCESS;
    }
    EVP_PKEY *evpkey = ec_load_key(key.p, secret ? &key.x : NULL, key.curve);
    if (!evpkey) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_result_t  ret = RNP_ERROR_GENERIC;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    int res;
    res = secret ? EVP_PKEY_check(ctx) : EVP_PKEY_public_check(ctx);
    if (res < 0) {
        /* LCOV_EXCL_START */
        auto err = ERR_peek_last_error();
        RNP_LOG("EC key check failed: %lu (%s)", err, ERR_reason_error_string(err));
        /* LCOV_EXCL_END */
    }
    if (res > 0) {
        ret = RNP_SUCCESS;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpkey);
    return ret;
}

bool
ec_write_pubkey(EVP_PKEY *pkey, pgp_mpi_t &mpi, pgp_curve_t curve)
{
    if (ec_is_raw_key(curve)) {
        /* EdDSA and X25519 keys are saved in a different way */
        mpi.len = sizeof(mpi.mpi) - 1;
        if (EVP_PKEY_get_raw_public_key(pkey, &mpi.mpi[1], &mpi.len) <= 0) {
            /* LCOV_EXCL_START */
            RNP_LOG("Failed get raw public key: %lu", ERR_peek_last_error());
            return false;
            /* LCOV_EXCL_END */
        }
        assert(mpi.len == 32);
        mpi.mpi[0] = 0x40;
        mpi.len++;
        return true;
    }
#if defined(CRYPTO_BACKEND_OPENSSL3)
    const ec_curve_desc_t *ec_desc = get_curve_desc(curve);
    if (!ec_desc) {
        return false;
    }
    size_t  flen = BITS_TO_BYTES(ec_desc->bitlen);
    rnp::bn qx;
    rnp::bn qy;

    /* OpenSSL before 3.0.9 by default uses compressed point for OSSL_PKEY_PARAM_PUB_KEY so use
     * this approach */
    bool res = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, qx.ptr()) &&
               EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, qy.ptr());
    if (!res) {
        return false;
    }
    /* Compose uncompressed point in mpi */
    size_t xlen = qx.bytes();
    size_t ylen = qy.bytes();
    assert((xlen <= flen) && (ylen <= flen));
    memset(mpi.mpi, 0, sizeof(mpi.mpi));
    mpi.mpi[0] = 0x04;
    mpi.len = 2 * flen + 1;
    return qx.bin(&mpi.mpi[1 + flen - xlen]) && qy.bin(&mpi.mpi[1 + 2 * flen - ylen]);
#else
    const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to retrieve EC key: %lu", ERR_peek_last_error());
        return false;
        /* LCOV_EXCL_END */
    }
    const EC_POINT *p = EC_KEY_get0_public_key(ec);
    if (!p) {
        /* LCOV_EXCL_START */
        RNP_LOG("Null point: %lu", ERR_peek_last_error());
        return false;
        /* LCOV_EXCL_END */
    }
    /* call below adds leading zeroes if needed */
    mpi.len = EC_POINT_point2oct(
      EC_KEY_get0_group(ec), p, POINT_CONVERSION_UNCOMPRESSED, mpi.mpi, sizeof(mpi.mpi), NULL);
    if (!mpi.len) {
        RNP_LOG("Failed to encode public key: %lu", ERR_peek_last_error()); // LCOV_EXCL_LINE
    }
    return mpi.len;
#endif
}
