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
#include <rnp/rnp_def.h>
#include "elgamal.h"
#include "dl_ossl.h"
#include "utils.h"
#include "bn.h"
#include "mem.h"
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#if defined(CRYPTO_BACKEND_OPENSSL3)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

// Max supported key byte size
#define ELGAMAL_MAX_P_BYTELEN BITS_TO_BYTES(PGP_MPINT_BITS)

namespace pgp {
namespace eg {

bool
Key::validate(bool secret) const noexcept
{
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Allocation failed.");
        return false;
        /* LCOV_EXCL_END */
    }
    BN_CTX_start(ctx);
    bool         res = false;
    bignum_t *   op = mpi2bn(p);
    bignum_t *   og = mpi2bn(g);
    bignum_t *   p1 = BN_CTX_get(ctx);
    bignum_t *   r = BN_CTX_get(ctx);
    bignum_t *   oy = NULL;
    bignum_t *   ox = NULL;
    BN_RECP_CTX *rctx = NULL;

    if (!op || !og || !p1 || !r) {
        goto done;
    }

    /* 1 < g < p */
    if ((BN_cmp(og, BN_value_one()) != 1) || (BN_cmp(og, op) != -1)) {
        RNP_LOG("Invalid g value.");
        goto done;
    }
    /* g ^ (p - 1) = 1 mod p */
    if (!BN_copy(p1, op) || !BN_sub_word(p1, 1) || !BN_mod_exp(r, og, p1, op, ctx)) {
        RNP_LOG("g exp failed.");
        goto done;
    }
    if (BN_cmp(r, BN_value_one()) != 0) {
        RNP_LOG("Wrong g exp value.");
        goto done;
    }
    /* check for small order subgroups */
    rctx = BN_RECP_CTX_new();
    if (!rctx || !BN_RECP_CTX_set(rctx, op, ctx) || !BN_copy(r, og)) {
        RNP_LOG("Failed to init RECP context.");
        goto done;
    }
    for (size_t i = 2; i < (1 << 17); i++) {
        if (!BN_mod_mul_reciprocal(r, r, og, rctx, ctx)) {
            /* LCOV_EXCL_START */
            RNP_LOG("Multiplication failed.");
            goto done;
            /* LCOV_EXCL_END */
        }
        if (BN_cmp(r, BN_value_one()) == 0) {
            RNP_LOG("Small subgroup detected. Order %zu", i);
            goto done;
        }
    }
    if (!secret) {
        res = true;
        goto done;
    }
    /* check that g ^ x = y (mod p) */
    ox = mpi2bn(x);
    oy = mpi2bn(y);
    if (!ox || !oy) {
        goto done;
    }
    res = BN_mod_exp(r, og, ox, op, ctx) && !BN_cmp(r, oy);
done:
    BN_CTX_free(ctx);
    BN_RECP_CTX_free(rctx);
    bn_free(op);
    bn_free(og);
    bn_free(oy);
    bn_free(ox);
    return res;
}

static bool
pkcs1v15_pad(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
    assert(out && in);
    if (out_len < in_len + 11) {
        return false;
    }
    out[0] = 0x00;
    out[1] = 0x02;
    size_t rnd = out_len - in_len - 3;
    out[2 + rnd] = 0x00;
    if (RAND_bytes(&out[2], rnd) != 1) {
        return false;
    }
    for (size_t i = 2; i < 2 + rnd; i++) {
        /* we need non-zero bytes */
        size_t cntr = 16;
        while (!out[i] && (cntr--) && (RAND_bytes(&out[i], 1) == 1)) {
        }
        if (!out[i]) {
            /* LCOV_EXCL_START */
            RNP_LOG("Something is wrong with RNG.");
            return false;
            /* LCOV_EXCL_END */
        }
    }
    memcpy(out + rnd + 3, in, in_len);
    return true;
}

static bool
pkcs1v15_unpad(size_t *padlen, const uint8_t *in, size_t in_len, bool skip0)
{
    if (in_len <= (size_t)(11 - skip0)) {
        return false;
    }
    if (!skip0 && in[0]) {
        return false;
    }
    if (in[1 - skip0] != 0x02) {
        return false;
    }
    size_t pad = 2 - skip0;
    while ((pad < in_len) && in[pad]) {
        pad++;
    }
    if (pad >= in_len) {
        return false;
    }
    *padlen = pad + 1;
    return true;
}

rnp_result_t
Key::encrypt_pkcs1(rnp::RNG &rng, Encrypted &out, const uint8_t *in, size_t in_len) const
{
    mpi mm{};
    mm.len = p.len;
    if (!pkcs1v15_pad(mm.mpi, mm.len, in, in_len)) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to add PKCS1 v1.5 padding.");
        return RNP_ERROR_BAD_PARAMETERS;
        /* LCOV_EXCL_END */
    }
    rnp_result_t ret = RNP_ERROR_GENERIC;
    BN_CTX *     ctx = BN_CTX_new();
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Allocation failed.");
        return RNP_ERROR_OUT_OF_MEMORY;
        /* LCOV_EXCL_END */
    }
    BN_CTX_start(ctx);
    BN_MONT_CTX *mctx = BN_MONT_CTX_new();
    bignum_t *   m = mpi2bn(&mm);
    bignum_t *   op = mpi2bn(p);
    bignum_t *   og = mpi2bn(g);
    bignum_t *   oy = mpi2bn(y);
    bignum_t *   c1 = BN_CTX_get(ctx);
    bignum_t *   c2 = BN_CTX_get(ctx);
    bignum_t *   k = BN_secure_new();
    if (!mctx || !m || !op || !og || !oy || !c1 || !c2 || !k) {
        /* LCOV_EXCL_START */
        RNP_LOG("Allocation failed.");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
        /* LCOV_EXCL_END */
    }
    /* initialize Montgomery context */
    if (BN_MONT_CTX_set(mctx, op, ctx) < 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to setup Montgomery context.");
        goto done;
        /* LCOV_EXCL_END */
    }
    int res;
    /* must not fail */
    res = BN_rshift1(c1, op);
    assert(res == 1);
    if (res < 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("BN_rshift1 failed.");
        goto done;
        /* LCOV_EXCL_END */
    }
    /* generate k */
    if (BN_rand_range(k, c1) < 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to generate k.");
        goto done;
        /* LCOV_EXCL_END */
    }
    /* calculate c1 = g ^ k (mod p) */
    if (BN_mod_exp_mont_consttime(c1, og, k, op, ctx, mctx) < 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Exponentiation 1 failed");
        goto done;
        /* LCOV_EXCL_END */
    }
    /* calculate c2 = m * y ^ k (mod p)*/
    if (BN_mod_exp_mont_consttime(c2, oy, k, op, ctx, mctx) < 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Exponentiation 2 failed");
        goto done;
        /* LCOV_EXCL_END */
    }
    if (BN_mod_mul(c2, c2, m, op, ctx) < 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Multiplication failed");
        goto done;
        /* LCOV_EXCL_END */
    }
    res = bn2mpi(c1, &out.g) && bn2mpi(c2, &out.m);
    assert(res == 1);
    ret = RNP_SUCCESS;
done:
    BN_MONT_CTX_free(mctx);
    BN_CTX_free(ctx);
    bn_free(m);
    bn_free(op);
    bn_free(og);
    bn_free(oy);
    bn_free(k);
    return ret;
}

rnp_result_t
Key::decrypt_pkcs1(rnp::RNG &rng, uint8_t *out, size_t *out_len, const Encrypted &in) const
{
    if (!x.bytes()) {
        RNP_LOG("Secret key not set.");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Allocation failed.");
        return RNP_ERROR_OUT_OF_MEMORY;
        /* LCOV_EXCL_END */
    }
    pgp::mpi     mm = {};
    size_t       padlen = 0;
    rnp_result_t ret = RNP_ERROR_GENERIC;
    BN_CTX_start(ctx);
    BN_MONT_CTX *mctx = BN_MONT_CTX_new();
    bignum_t *   op = mpi2bn(p);
    bignum_t *   og = mpi2bn(g);
    bignum_t *   ox = mpi2bn(x);
    bignum_t *   c1 = mpi2bn(in.g);
    bignum_t *   c2 = mpi2bn(in.m);
    bignum_t *   s = BN_CTX_get(ctx);
    bignum_t *   m = BN_secure_new();
    if (!mctx || !op || !og || !ox || !c1 || !c2 || !m) {
        /* LCOV_EXCL_START */
        RNP_LOG("Allocation failed.");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
        /* LCOV_EXCL_END */
    }
    /* initialize Montgomery context */
    if (BN_MONT_CTX_set(mctx, op, ctx) < 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to setup Montgomery context.");
        goto done;
        /* LCOV_EXCL_END */
    }
    /* calculate s = c1 ^ x (mod p) */
    if (BN_mod_exp_mont_consttime(s, c1, ox, op, ctx, mctx) < 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Exponentiation 1 failed");
        goto done;
        /* LCOV_EXCL_END */
    }
    /* calculate s^-1 (mod p) */
    BN_set_flags(s, BN_FLG_CONSTTIME);
    if (!BN_mod_inverse(s, s, op, ctx)) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to calculate inverse.");
        goto done;
        /* LCOV_EXCL_END */
    }
    /* calculate m = c2 * s ^ -1 (mod p)*/
    if (BN_mod_mul(m, c2, s, op, ctx) < 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Multiplication failed");
        goto done;
        /* LCOV_EXCL_END */
    }
    bool res;
    res = bn2mpi(m, &mm);
    assert(res);
    if (!res) {
        /* LCOV_EXCL_START */
        RNP_LOG("bn2mpi failed.");
        goto done;
        /* LCOV_EXCL_END */
    }
    /* unpad, handling skipped leftmost 0 case */
    if (!pkcs1v15_unpad(&padlen, mm.mpi, mm.len, mm.len == p.len - 1)) {
        RNP_LOG("Unpad failed.");
        goto done;
    }
    *out_len = mm.len - padlen;
    memcpy(out, &mm.mpi[padlen], *out_len);
    ret = RNP_SUCCESS;
done:
    secure_clear(mm.mpi, PGP_MPINT_SIZE);
    BN_MONT_CTX_free(mctx);
    BN_CTX_free(ctx);
    bn_free(op);
    bn_free(og);
    bn_free(ox);
    bn_free(c1);
    bn_free(c2);
    bn_free(m);
    return ret;
}

rnp_result_t
Key::generate(rnp::RNG &rng, size_t keybits)
{
    if ((keybits < 1024) || (keybits > PGP_MPINT_BITS)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t ret = RNP_ERROR_GENERIC;
#if !defined(CRYPTO_BACKEND_OPENSSL3)
    const DH *dh = NULL;
#endif
    EVP_PKEY *    pkey = NULL;
    EVP_PKEY *    parmkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    /* Generate DH params, which usable for ElGamal as well */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
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
    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, keybits) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set key bits: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    /* OpenSSL correctly handles case with g = 5, making sure that g is primitive root of
     * q-group */
    if (EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, DH_GENERATOR_5) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set key generator: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_paramgen(ctx, &parmkey) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to generate parameters: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    EVP_PKEY_CTX_free(ctx);
    /* Generate DH (ElGamal) key */
start:
    ctx = EVP_PKEY_CTX_new(parmkey, NULL);
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        /* LCOV_EXCL_START */
        RNP_LOG("ElGamal keygen failed: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
#if defined(CRYPTO_BACKEND_OPENSSL3)
    {
        rnp::bn oy;
        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, oy.ptr())) {
            /* LCOV_EXCL_START */
            RNP_LOG("Failed to retrieve ElGamal public key: %lu", ERR_peek_last_error());
            goto done;
            /* LCOV_EXCL_END */
        }
        if (oy.bytes() != BITS_TO_BYTES(keybits)) {
            /* This code chunk is rarely hit, so ignoring it for the coverage report:
             * LCOV_EXCL_START */
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            EVP_PKEY_free(pkey);
            pkey = NULL;
            goto start;
            /* LCOV_EXCL_END */
        }

        rnp::bn op;
        rnp::bn og;
        rnp::bn ox;
        bool    res = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, op.ptr()) &&
                   EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, og.ptr()) &&
                   EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, ox.ptr());
        if (res && op.mpi(p) && og.mpi(g) && oy.mpi(y) && ox.mpi(x)) {
            ret = RNP_SUCCESS;
        }
    }
#else
    dh = EVP_PKEY_get0_DH(pkey);
    if (!dh) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to retrieve DH key: %lu", ERR_peek_last_error());
        goto done;
        /* LCOV_EXCL_END */
    }
    if (BITS_TO_BYTES(BN_num_bits(DH_get0_pub_key(dh))) != BITS_TO_BYTES(keybits)) {
        /* This code chunk is rarely hit, so ignoring it for the coverage report:
         * LCOV_EXCL_START */
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto start;
        /* LCOV_EXCL_END */
    }

    const bignum_t *op;
    const bignum_t *og;
    const bignum_t *oy;
    const bignum_t *ox;
    op = DH_get0_p(dh);
    og = DH_get0_g(dh);
    oy = DH_get0_pub_key(dh);
    ox = DH_get0_priv_key(dh);
    if (!op || !og || !oy || !ox) {
        /* LCOV_EXCL_START */
        ret = RNP_ERROR_BAD_STATE;
        goto done;
        /* LCOV_EXCL_END */
    }
    bn2mpi(op, p);
    bn2mpi(og, g);
    bn2mpi(oy, y);
    bn2mpi(ox, x);
    ret = RNP_SUCCESS;
#endif
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(parmkey);
    EVP_PKEY_free(pkey);
    return ret;
}

} // namespace eg
} // namespace pgp
