/*
 * Copyright (c) 2017-2021 Ribose Inc.
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
#include <botan/hash.h>
#include "hash.h"
#include "types.h"
#include "utils.h"
#include "str-utils.h"
#include "defaults.h"
#include "sha1cd/hash_sha1cd.h"

static const id_str_pair botan_alg_map[] = {
  {PGP_HASH_MD5, "MD5"},
  {PGP_HASH_SHA1, "SHA-1"},
  {PGP_HASH_RIPEMD, "RIPEMD-160"},
  {PGP_HASH_SHA256, "SHA-256"},
  {PGP_HASH_SHA384, "SHA-384"},
  {PGP_HASH_SHA512, "SHA-512"},
  {PGP_HASH_SHA224, "SHA-224"},
  {PGP_HASH_SM3, "SM3"},
  {PGP_HASH_SHA3_256, "SHA-3(256)"},
  {PGP_HASH_SHA3_512, "SHA-3(512)"},
  {0, NULL},
};

namespace rnp {

Hash::Hash(pgp_hash_alg_t alg)
{
    if (alg == PGP_HASH_SHA1) {
        /* todo: avoid duplication here and in the OpenSSL backend */
        handle_ = hash_sha1cd_create();
        if (!handle_) {
            throw rnp_exception(RNP_ERROR_OUT_OF_MEMORY);
        }
        alg_ = alg;
        size_ = rnp::Hash::size(alg);
        return;
    }

    const char *name = Hash::name_backend(alg);
    if (!name) {
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    auto hash_fn = Botan::HashFunction::create(name);
    if (!hash_fn) {
        RNP_LOG("Error creating hash object for '%s'", name);
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    size_ = hash_fn->output_length();
    if (!size_) {
        RNP_LOG("output_length() call failed");
        throw rnp_exception(RNP_ERROR_BAD_STATE);
    }
    handle_ = hash_fn.release();
    alg_ = alg;
}

void
Hash::add(const void *buf, size_t len)
{
    if (!handle_) {
        throw rnp_exception(RNP_ERROR_NULL_POINTER);
    }
    if (alg_ == PGP_HASH_SHA1) {
        hash_sha1cd_add(handle_, buf, len);
        return;
    }
    static_cast<Botan::HashFunction *>(handle_)->update(static_cast<const uint8_t *>(buf),
                                                        len);
}

size_t
Hash::finish(uint8_t *digest)
{
    if (!handle_) {
        return 0;
    }
    if (alg_ == PGP_HASH_SHA1) {
        int res = hash_sha1cd_finish(handle_, digest);
        handle_ = NULL;
        size_ = 0;
        if (res) {
            throw rnp_exception(RNP_ERROR_BAD_STATE);
        }
        return 20;
    }

    auto hash_fn =
      std::unique_ptr<Botan::HashFunction>(static_cast<Botan::HashFunction *>(handle_));
    if (!hash_fn) {
        RNP_LOG("Hash finalization failed");
        throw rnp_exception(RNP_ERROR_BAD_STATE);
    }

    size_t outlen = size_;
    handle_ = NULL;
    size_ = 0;

    if (digest) {
        hash_fn->final(digest);
    }
    return outlen;
}

void
Hash::clone(Hash &dst) const
{
    if (!handle_) {
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    if (dst.handle_) {
        dst.finish();
    }

    if (alg_ == PGP_HASH_SHA1) {
        dst.handle_ = hash_sha1cd_clone(handle_);
        if (!dst.handle_) {
            throw rnp_exception(RNP_ERROR_OUT_OF_MEMORY);
        }
        dst.size_ = size_;
        dst.alg_ = alg_;
        return;
    }

    auto hash_fn = static_cast<Botan::HashFunction *>(handle_);
    if (!hash_fn) {
        throw rnp_exception(RNP_ERROR_BAD_STATE);
    }

    auto copy = hash_fn->copy_state();
    if (!copy) {
        RNP_LOG("Failed to clone hash.");
        throw rnp_exception(RNP_ERROR_BAD_STATE);
    }

    dst.size_ = size_;
    dst.alg_ = alg_;
    dst.handle_ = copy.release();
}

Hash::~Hash()
{
    if (!handle_) {
        return;
    }
    if (alg_ == PGP_HASH_SHA1) {
        hash_sha1cd_finish(handle_, NULL);
    } else {
        delete static_cast<Botan::HashFunction *>(handle_);
    }
}

CRC24::CRC24()
{
    auto hash_fn = Botan::HashFunction::create("CRC24");
    if (!hash_fn) {
        RNP_LOG("Error creating hash object for 'CRC24'");
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    size_ = 3;
    alg_ = PGP_HASH_UNKNOWN;
    handle_ = hash_fn.release();
}

const char *
Hash::name_backend(pgp_hash_alg_t alg)
{
    return id_str_pair::lookup(botan_alg_map, alg);
}
} // namespace rnp
