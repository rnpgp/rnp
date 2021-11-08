/*
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

#include <stdio.h>
#include <memory>
#include <cassert>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "config.h"
#include "hash.h"
#include "types.h"
#include "utils.h"
#include "str-utils.h"
#include "defaults.h"

static const id_str_pair openssl_alg_map[] = {
  {PGP_HASH_MD5, "md5"},
  {PGP_HASH_SHA1, "sha1"},
  {PGP_HASH_RIPEMD, "ripemd160"},
  {PGP_HASH_SHA256, "sha256"},
  {PGP_HASH_SHA384, "sha384"},
  {PGP_HASH_SHA512, "sha512"},
  {PGP_HASH_SHA224, "sha224"},
  {PGP_HASH_SM3, "sm3"},
  {PGP_HASH_SHA3_256, "sha3-256"},
  {PGP_HASH_SHA3_512, "sha3-512"},
  {0, NULL},
};

namespace rnp {
Hash::Hash(pgp_hash_alg_t alg)
{
    const char *hash_name = rnp::Hash::name_backend(alg);
    if (!hash_name) {
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
#if !defined(ENABLE_SM2)
    if (alg == PGP_HASH_SM3) {
        RNP_LOG("SM3 hash is not available.");
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
#endif
    const EVP_MD *hash_tp = EVP_get_digestbyname(hash_name);
    if (!hash_tp) {
        RNP_LOG("Error creating hash object for '%s'", hash_name);
        throw rnp_exception(RNP_ERROR_BAD_STATE);
    }
    EVP_MD_CTX *hash_fn = EVP_MD_CTX_new();
    if (!hash_fn) {
        RNP_LOG("Allocation failure");
        throw rnp_exception(RNP_ERROR_OUT_OF_MEMORY);
    }
    int res = EVP_DigestInit_ex(hash_fn, hash_tp, NULL);
    if (res != 1) {
        RNP_LOG("Digest initializataion error %d : %lu", res, ERR_peek_last_error());
        EVP_MD_CTX_free(hash_fn);
        throw rnp_exception(RNP_ERROR_BAD_STATE);
    }

    alg_ = alg;
    size_ = EVP_MD_size(hash_tp);
    handle_ = hash_fn;
}

void
Hash::add(const void *buf, size_t len)
{
    if (!handle_) {
        throw rnp_exception(RNP_ERROR_NULL_POINTER);
    }
    assert(alg_ != PGP_HASH_UNKNOWN);

    EVP_MD_CTX *hash_fn = static_cast<EVP_MD_CTX *>(handle_);
    int         res = EVP_DigestUpdate(hash_fn, buf, len);
    if (res != 1) {
        RNP_LOG("Digest updating error %d: %lu", res, ERR_peek_last_error());
        throw rnp_exception(RNP_ERROR_GENERIC);
    }
}

size_t
Hash::finish(uint8_t *digest)
{
    if (!handle_) {
        return 0;
    }
    assert(alg_ != PGP_HASH_UNKNOWN);

    EVP_MD_CTX *hash_fn = static_cast<EVP_MD_CTX *>(handle_);
    int         res = digest ? EVP_DigestFinal_ex(hash_fn, digest, NULL) : 1;
    EVP_MD_CTX_free(hash_fn);
    handle_ = NULL;
    if (res != 1) {
        RNP_LOG("Digest finalization error %d: %lu", res, ERR_peek_last_error());
        return 0;
    }

    size_t outsz = size_;
    size_ = 0;
    alg_ = PGP_HASH_UNKNOWN;
    return outsz;
}

void
Hash::clone(Hash &dst) const
{
    if (!handle_) {
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    assert(alg_ != PGP_HASH_UNKNOWN);

    if (dst.handle_) {
        dst.finish();
    }

    EVP_MD_CTX *hash_fn = EVP_MD_CTX_new();
    if (!hash_fn) {
        RNP_LOG("Allocation failure");
        throw rnp_exception(RNP_ERROR_OUT_OF_MEMORY);
    }

    int res = EVP_MD_CTX_copy(hash_fn, static_cast<EVP_MD_CTX *>(handle_));
    if (res != 1) {
        RNP_LOG("Digest copying error %d: %lu", res, ERR_peek_last_error());
        EVP_MD_CTX_free(hash_fn);
        throw rnp_exception(RNP_ERROR_BAD_STATE);
    }

    dst.size_ = size_;
    dst.alg_ = alg_;
    dst.handle_ = hash_fn;
}

Hash::~Hash()
{
    if (handle_) {
        EVP_MD_CTX_free(static_cast<EVP_MD_CTX *>(handle_));
    }
}

const char *
Hash::name_backend(pgp_hash_alg_t alg)
{
    return id_str_pair::lookup(openssl_alg_map, alg);
}
} // namespace rnp
