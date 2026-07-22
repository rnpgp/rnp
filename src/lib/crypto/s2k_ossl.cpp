/*-
 * Copyright (c) 2021 Ribose Inc.
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

#include <cstdint>
#include <vector>
#include <algorithm>
#include <openssl/evp.h>
#include "config.h"
#include "hash.hpp"
#include "s2k.h"
#include "mem.h"
#include "logging.h"

/* Argon2 KDFs are available since OpenSSL 3.2 */
#if defined(ENABLE_CRYPTO_REFRESH) && OPENSSL_VERSION_NUMBER >= 0x30200000L
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <cmath>
#include <cstring>
#endif

#if defined(ENABLE_CRYPTO_REFRESH) && OPENSSL_VERSION_NUMBER >= 0x30200000L
int
pgp_s2k_argon2(uint8_t *      out,
               size_t         output_len,
               const char *   password,
               const uint8_t *salt,
               uint8_t        t,
               uint8_t        p,
               uint8_t        encoded_m)
{
    const size_t argon2_salt_size = 16;

    /* check constraints on p and t */
    if (!p || !t) {
        RNP_LOG("Argon2 t and p must be non-zero");
        return -1;
    }
    /* check constraints on m. Floating point calculation is fine due to restricted data range
     * (uint8_t) */
    if (encoded_m < (3 + (uint8_t) std::ceil(std::log2(p))) || encoded_m > 31) {
        RNP_LOG("Argon2 encoded_m must be between 3+ceil(log2(p)) and 31");
        return -1;
    }

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) {
        RNP_LOG("Failed to fetch ARGON2ID KDF");
        return -1;
    }
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) {
        RNP_LOG("Failed to create ARGON2ID KDF context");
        return -1;
    }

    /* memory size in KiB, see RFC 9106 and crypto-refresh */
    uint32_t memcost = ((uint32_t) 1) << encoded_m;
    uint32_t iter = t;
    uint32_t lanes = p;
    /* Thread pool is not available in the default OpenSSL library context, so single-threaded
     * derivation is used. This doesn't affect the derived key, which depends on lanes only. */
    uint32_t   threads = 1;
    /* Argon2 version 1.3 */
    uint32_t   version = 0x13;
    OSSL_PARAM params[8];
    int        n = 0;
    params[n++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_PASSWORD, (void *) password, std::strlen(password));
    params[n++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_SALT, (void *) salt, argon2_salt_size);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version);
    params[n] = OSSL_PARAM_END;

    int rc = EVP_KDF_derive(ctx, out, output_len, params);
    EVP_KDF_CTX_free(ctx);
    if (rc != 1) {
        RNP_LOG("Argon2 derivation failed");
        return -1;
    }
    return 0;
}
#endif

int
pgp_s2k_iterated(pgp_hash_alg_t alg,
                 uint8_t *      out,
                 size_t         output_len,
                 const char *   password,
                 const uint8_t *salt,
                 size_t         iterations)
{
    if ((iterations > 1) && !salt) {
        RNP_LOG("Iterated S2K mus be salted as well.");
        return 1;
    }
    size_t hash_len = rnp::Hash::size(alg);
    if (!hash_len) {
        RNP_LOG("Unknown digest: %d", (int) alg);
        return 1;
    }
    try {
        size_t pswd_len = strlen(password);
        size_t salt_len = salt ? PGP_SALT_SIZE : 0;

        rnp::secure_bytes data(salt_len + pswd_len);
        if (salt_len) {
            memcpy(data.data(), salt, PGP_SALT_SIZE);
        }
        memcpy(data.data() + salt_len, password, pswd_len);
        size_t zeroes = 0;

        while (output_len) {
            /* create hash context */
            auto hash = rnp::Hash::create(alg);
            /* add leading zeroes */
            hash->add(std::vector<uint8_t>(zeroes, 0));
            if (!data.empty()) {
                /* if iteration is 1 then still hash the whole data chunk */
                size_t left = std::max(data.size(), iterations);
                while (left) {
                    size_t to_hash = std::min(left, data.size());
                    hash->add(data.data(), to_hash);
                    left -= to_hash;
                }
            }
            auto   dgst = hash->sec_finish();
            size_t out_copy = std::min(dgst.size(), output_len);
            memcpy(out, dgst.data(), out_copy);
            output_len -= out_copy;
            out += out_copy;
            zeroes++;
        }
        return 0;
    } catch (const std::exception &e) {
        RNP_LOG("s2k failed: %s", e.what());
        return 1;
    }
}
