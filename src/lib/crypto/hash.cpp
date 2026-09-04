/*
 * Copyright (c) 2017-2022 Ribose Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "hash_botan.hpp"
#include "logging.h"
#include <cassert>

static const id_str_pair botan_alg_map[] = {
  {PGP_HASH_MD5, "MD5"},
  {PGP_HASH_SHA1, "SHA-1"},
  {PGP_HASH_RIPEMD, "RIPEMD-160"},
  {PGP_HASH_SHA256, "SHA-256"},
  {PGP_HASH_SHA384, "SHA-384"},
  {PGP_HASH_SHA512, "SHA-512"},
  {PGP_HASH_SHA224, "SHA-224"},
#if defined(ENABLE_SM2)
  {PGP_HASH_SM3, "SM3"},
#endif
  {PGP_HASH_SHA3_256, "SHA-3(256)"},
  {PGP_HASH_SHA3_512, "SHA-3(512)"},
  {0, NULL},
};

namespace rnp {

Hash_Botan::Hash_Botan(pgp_hash_alg_t alg) : Hash(alg)
{
    auto name = Hash_Botan::name_backend(alg);
    if (!name) {
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    if (botan_hash_init(&fn_, name, 0)) {
        RNP_LOG("Error creating hash object for '%s'", name);
        fn_ = nullptr;
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    size_t outlen = 0;
    botan_hash_output_length(fn_, &outlen);
    assert(size_ == outlen);
}

Hash_Botan::Hash_Botan(const Hash_Botan &src) : Hash(src.alg_)
{
    if (!src.fn_) {
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    if (botan_hash_copy_state(&fn_, src.fn_)) {
        throw rnp_exception(RNP_ERROR_GENERIC);
    }
}

Hash_Botan::~Hash_Botan()
{
    if (fn_) {
        botan_hash_destroy(fn_);
    }
}

std::unique_ptr<Hash_Botan>
Hash_Botan::create(pgp_hash_alg_t alg)
{
    return std::unique_ptr<Hash_Botan>(new Hash_Botan(alg));
}

std::unique_ptr<Hash>
Hash_Botan::clone() const
{
    return std::unique_ptr<Hash>(new Hash_Botan(*this));
}

void
Hash_Botan::add(const void *buf, size_t len)
{
    if (!fn_) {
        throw rnp_exception(RNP_ERROR_NULL_POINTER);
    }
    if (botan_hash_update(fn_, static_cast<const uint8_t *>(buf), len)) {
        throw rnp_exception(RNP_ERROR_GENERIC);
    }
}

void
Hash_Botan::finish(uint8_t *digest)
{
    assert(fn_);
    if (!fn_) {
        return;
    }
    if (digest) {
        botan_hash_final(fn_, digest);
    }
    botan_hash_destroy(fn_);
    fn_ = nullptr;
    size_ = 0;
}

const char *
Hash_Botan::name_backend(pgp_hash_alg_t alg)
{
    return id_str_pair::lookup(botan_alg_map, alg);
}

CRC24_Botan::CRC24_Botan()
{
    if (botan_hash_init(&fn_, "CRC24", 0)) {
        RNP_LOG("Error creating CRC24 object");
        fn_ = nullptr;
        throw rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    size_t outlen = 0;
    botan_hash_output_length(fn_, &outlen);
    assert(3 == outlen);
}

CRC24_Botan::~CRC24_Botan()
{
    if (fn_) {
        botan_hash_destroy(fn_);
    }
}

std::unique_ptr<CRC24_Botan>
CRC24_Botan::create()
{
    return std::unique_ptr<CRC24_Botan>(new CRC24_Botan());
}

void
CRC24_Botan::add(const void *buf, size_t len)
{
    if (!fn_) {
        throw rnp_exception(RNP_ERROR_NULL_POINTER);
    }
    if (botan_hash_update(fn_, static_cast<const uint8_t *>(buf), len)) {
        throw rnp_exception(RNP_ERROR_GENERIC);
    }
}

std::array<uint8_t, 3>
CRC24_Botan::finish()
{
    if (!fn_) {
        throw rnp_exception(RNP_ERROR_NULL_POINTER);
    }
    std::array<uint8_t, 3> crc{};
    botan_hash_final(fn_, crc.data());
    botan_hash_destroy(fn_);
    fn_ = nullptr;
    return crc;
}

} // namespace rnp
