/*-
 * Copyright (c) 2017-2019 Ribose Inc.
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

/*-
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Alistair Crooks (agc@NetBSD.org)
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
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <memory>
#include <botan/hash.h>
#include "hash.h"
#include "types.h"
#include "utils.h"
#include "str-utils.h"
#include "defaults.h"

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
    static_cast<Botan::HashFunction *>(handle_)->update(static_cast<const uint8_t *>(buf),
                                                        len);
}

size_t
Hash::finish(uint8_t *digest)
{
    if (!handle_) {
        return 0;
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

static bool
botan_hash_create(pgp_hash_t *hash, const char *hash_name)
{
    if (!hash_name) {
        return false;
    }

    std::unique_ptr<Botan::HashFunction> hash_fn;
    try {
        hash_fn = Botan::HashFunction::create(hash_name);
    } catch (std::exception &ex) {
        RNP_LOG("Error creating HashFunction ('%s')", ex.what());
    }
    if (!hash_fn) {
        RNP_LOG("Error creating hash object for '%s'", hash_name);
        return false;
    }

    hash->_output_len = hash_fn->output_length();
    if (hash->_output_len == 0) {
        RNP_LOG("In pgp_hash_create, botan_hash_output_length failed");
        return false;
    }

    hash->handle = hash_fn.release();
    return true;
}

/**
\ingroup Core_Hashes
\brief Setup hash for given hash algorithm
\param hash Hash to set up
\param alg Hash algorithm to use
*/
bool
pgp_hash_create(pgp_hash_t *hash, pgp_hash_alg_t alg)
{
    if (!botan_hash_create(hash, rnp::Hash::name_backend(alg))) {
        return false;
    }

    hash->_alg = alg;
    return true;
}

bool
pgp_hash_create_crc24(pgp_hash_t *hash)
{
    if (!botan_hash_create(hash, "CRC24")) {
        return false;
    }

    hash->_alg = PGP_HASH_UNKNOWN;
    return true;
}

bool
pgp_hash_copy(pgp_hash_t *dst, const pgp_hash_t *src)
{
    if (!src || !dst) {
        return false;
    }

    Botan::HashFunction *hash_fn = static_cast<Botan::HashFunction *>(src->handle);
    if (!hash_fn) {
        return false;
    }

    std::unique_ptr<Botan::HashFunction> handle;
    try {
        handle = hash_fn->copy_state();
    } catch (std::exception &ex) {
        RNP_LOG("Error copying HashFunction ('%s')", ex.what());
    }
    if (!handle) {
        return false;
    }

    dst->_output_len = src->_output_len;
    dst->_alg = src->_alg;
    dst->handle = handle.release();
    return true;
}

int
pgp_hash_add(pgp_hash_t *hash, const void *buf, size_t len)
{
    if (!hash->handle) {
        return -1;
    }

    try {
        static_cast<Botan::HashFunction *>(hash->handle)
          ->update(static_cast<const uint8_t *>(buf), len);
    } catch (std::exception &ex) {
        RNP_LOG("Error adding to HashFunction ('%s')", ex.what());
        return -2;
    }
    return 0;
}

size_t
pgp_hash_finish(pgp_hash_t *hash, uint8_t *out)
{
    if (!hash || !hash->handle) {
        return 0;
    }

    Botan::HashFunction *hash_fn = static_cast<Botan::HashFunction *>(hash->handle);
    if (!hash_fn) {
        RNP_LOG("Hash finalization failed");
        return 0;
    }

    size_t outlen = hash->_output_len;
    hash->handle = NULL;
    try {
        if (out) {
            hash_fn->final(out);
        }
        delete hash_fn;
    } catch (std::exception &ex) {
        RNP_LOG("Error finishing HashFunction ('%s')", ex.what());
        outlen = 0;
    }
    hash->_output_len = 0;
    return outlen;
}

pgp_hash_alg_t
pgp_hash_alg_type(const pgp_hash_t *hash)
{
    return hash->_alg;
}

bool
pgp_hash_list_add(std::vector<pgp_hash_t> &hashes, pgp_hash_alg_t alg)
{
    pgp_hash_t hash = {0};
    if (!pgp_hash_list_get(hashes, alg)) {
        if (!pgp_hash_create(&hash, alg)) {
            RNP_LOG("failed to initialize hash algorithm %d", (int) alg);
            return false;
        }
        try {
            hashes.push_back(hash);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            pgp_hash_finish(&hash, NULL);
            return false;
        }
    }
    return true;
}

const pgp_hash_t *
pgp_hash_list_get(std::vector<pgp_hash_t> &hashes, pgp_hash_alg_t alg)
{
    for (auto &hash : hashes) {
        if (pgp_hash_alg_type(&hash) == alg) {
            return &hash;
        }
    }
    return NULL;
}

void
pgp_hash_list_update(std::vector<pgp_hash_t> &hashes, const void *buf, size_t len)
{
    for (auto &hash : hashes) {
        pgp_hash_add(&hash, buf, len);
    }
}

bool
pgp_hash_uint32(pgp_hash_t *hash, uint32_t n)
{
    uint8_t ibuf[4];
    STORE32BE(ibuf, n);
    return !pgp_hash_add(hash, ibuf, sizeof(ibuf));
}
