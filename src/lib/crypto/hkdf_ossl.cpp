/*
 * Copyright (c) 2026 [Ribose Inc](https://www.ribose.com).
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

#include "config.h"

#if defined(ENABLE_CRYPTO_REFRESH) || defined(ENABLE_PQC)

#include "hkdf_ossl.hpp"
#include "hash_ossl.hpp"
#include "logging.h"
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

namespace rnp {

Hkdf_OpenSSL::Hkdf_OpenSSL(pgp_hash_alg_t hash_alg) : Hkdf(hash_alg)
{
}

std::unique_ptr<Hkdf_OpenSSL>
Hkdf_OpenSSL::create(pgp_hash_alg_t alg)
{
    return std::unique_ptr<Hkdf_OpenSSL>(new Hkdf_OpenSSL(alg));
}

void
Hkdf_OpenSSL::extract_expand(const uint8_t *salt,
                              size_t         salt_len,
                              const uint8_t *ikm,
                              size_t         ikm_len,
                              const uint8_t *info,
                              size_t         info_len,
                              uint8_t *      output_buf,
                              size_t         output_length)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        RNP_LOG("Failed to fetch HKDF");
        throw rnp_exception(RNP_ERROR_GENERIC);
    }
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) {
        RNP_LOG("Failed to create HKDF context");
        throw rnp_exception(RNP_ERROR_GENERIC);
    }

    const char *hash_name = Hash_OpenSSL::name_backend(Hkdf::alg());
    OSSL_PARAM  params[5];
    int         n = 0;
    params[n++] = OSSL_PARAM_construct_utf8_string(
      OSSL_KDF_PARAM_DIGEST, const_cast<char *>(hash_name), 0);
    params[n++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_KEY, const_cast<uint8_t *>(ikm), ikm_len);
    if (salt && salt_len) {
        params[n++] = OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_SALT, const_cast<uint8_t *>(salt), salt_len);
    }
    if (info && info_len) {
        params[n++] = OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_INFO, const_cast<uint8_t *>(info), info_len);
    }
    params[n] = OSSL_PARAM_END;

    int rc = EVP_KDF_derive(ctx, output_buf, output_length, params);
    EVP_KDF_CTX_free(ctx);
    if (rc != 1) {
        RNP_LOG("HKDF derivation failed");
        throw rnp_exception(RNP_ERROR_GENERIC);
    }
}

Hkdf_OpenSSL::~Hkdf_OpenSSL()
{
}

} // namespace rnp

#endif
