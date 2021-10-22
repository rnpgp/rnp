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

#include "hash.h"
#include "types.h"
#include "utils.h"
#include "str-utils.h"

static const struct hash_alg_map_t {
    pgp_hash_alg_t type;
    const char *   name;
    size_t         len;
} hash_alg_map[] = {{PGP_HASH_MD5, "MD5", 16},
                    {PGP_HASH_SHA1, "SHA1", 20},
                    {PGP_HASH_RIPEMD, "RIPEMD160", 20},
                    {PGP_HASH_SHA256, "SHA256", 32},
                    {PGP_HASH_SHA384, "SHA384", 48},
                    {PGP_HASH_SHA512, "SHA512", 64},
                    {PGP_HASH_SHA224, "SHA224", 28},
                    {PGP_HASH_SM3, "SM3", 32},
                    {PGP_HASH_SHA3_256, "SHA3-256", 32},
                    {PGP_HASH_SHA3_512, "SHA3-512", 64}};

namespace rnp {

pgp_hash_alg_t
Hash::alg() const
{
    return alg_;
}

size_t
Hash::size() const
{
    return size_;
}

void
Hash::add(uint32_t val)
{
    uint8_t ibuf[4];
    STORE32BE(ibuf, val);
    add(ibuf, sizeof(ibuf));
}

void
Hash::add(const pgp_mpi_t &val)
{
    size_t len = mpi_bytes(&val);
    size_t idx = 0;
    while ((idx < len) && (!val.mpi[idx])) {
        idx++;
    }

    if (idx >= len) {
        add(0);
        return;
    }

    add(len - idx);
    if (val.mpi[idx] & 0x80) {
        uint8_t padbyte = 0;
        add(&padbyte, 1);
    }
    add(val.mpi + idx, len - idx);
}

pgp_hash_alg_t
Hash::alg(const char *name)
{
    if (!name) {
        return PGP_HASH_UNKNOWN;
    }
    for (size_t i = 0; i < ARRAY_SIZE(hash_alg_map); i++) {
        if (rnp::str_case_eq(name, hash_alg_map[i].name)) {
            return hash_alg_map[i].type;
        }
    }
    return PGP_HASH_UNKNOWN;
}

const char *
Hash::name(pgp_hash_alg_t alg)
{
    const char *ret = NULL;
    ARRAY_LOOKUP_BY_ID(hash_alg_map, type, name, alg, ret);
    return ret;
}

size_t
Hash::size(pgp_hash_alg_t alg)
{
    size_t val = 0;
    ARRAY_LOOKUP_BY_ID(hash_alg_map, type, len, alg, val);
    return val;
}

Hash::Hash(Hash &&src)
{
    handle_ = src.handle_;
    src.handle_ = NULL;
    alg_ = src.alg_;
    src.alg_ = PGP_HASH_UNKNOWN;
    size_ = src.size_;
    src.size_ = 0;
}

Hash &
Hash::operator=(const Hash &src)
{
    src.clone(*this);
    return *this;
}

Hash &
Hash::operator=(Hash &&src)
{
    if (handle_) {
        finish();
    }
    handle_ = src.handle_;
    src.handle_ = NULL;
    alg_ = src.alg_;
    src.alg_ = PGP_HASH_UNKNOWN;
    size_ = src.size_;
    src.size_ = 0;
    return *this;
}

Hash::~Hash()
{
    finish();
}

void
HashList::add_alg(pgp_hash_alg_t alg)
{
    if (!get(alg)) {
        hashes_.emplace_back(alg);
    }
}

const Hash *
HashList::get(pgp_hash_alg_t alg) const
{
    for (auto &hash : hashes_) {
        if (hash.alg() == alg) {
            return &hash;
        }
    }
    return NULL;
}

void
HashList::add(const void *buf, size_t len)
{
    for (auto &hash : hashes_) {
        hash.add(buf, len);
    }
}

bool
HashList::empty() const
{
    return hashes_.empty();
}

std::vector<Hash> &
HashList::hashes()
{
    return hashes_;
}

} // namespace rnp
