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

#ifndef CRYPTO_HASH_H_
#define CRYPTO_HASH_H_

#include <repgp/repgp_def.h>
#include "types.h"
#include "config.h"

/**
 * Output size (in bytes) of biggest supported hash algo
 */
#define PGP_MAX_HASH_SIZE (64)

namespace rnp {
class Hash {
  protected:
    void *         handle_;
    size_t         size_;
    pgp_hash_alg_t alg_;

  public:
    pgp_hash_alg_t alg() const;
    size_t         size() const;

    Hash() : handle_(NULL), size_(0), alg_(PGP_HASH_UNKNOWN){};
    Hash(pgp_hash_alg_t alg);
    Hash(Hash &&src);

    virtual void   add(const void *buf, size_t len);
    virtual void   add(uint32_t val);
    virtual void   add(const pgp_mpi_t &mpi);
    virtual size_t finish(uint8_t *digest = NULL);
    virtual void   clone(Hash &dst) const;

    Hash &operator=(const Hash &src);
    Hash &operator=(Hash &&src);

    virtual ~Hash();

    /* Hash algorithm by string representation from cleartext-signed text */
    static pgp_hash_alg_t alg(const char *name);
    /* Hash algorithm representation for cleartext-signed text */
    static const char *name(pgp_hash_alg_t alg);
    /* Hash algorithm representation for the backend functions */
    static const char *name_backend(pgp_hash_alg_t alg);
    /* Size of the hash algorithm output or 0 if algorithm is unknown */
    static size_t size(pgp_hash_alg_t alg);
};

#if defined(CRYPTO_BACKEND_BOTAN)
class CRC24 : public Hash {
  public:
    CRC24();
};
#endif
#if defined(CRYPTO_BACKEND_OPENSSL)
class CRC24 {
    uint32_t state_;

  public:
    CRC24();

    void   add(const void *buf, size_t len);
    size_t finish(uint8_t *crc);
};
#endif

class HashList {
    std::vector<Hash> hashes_;

  public:
    void               add_alg(pgp_hash_alg_t alg);
    const Hash *       get(pgp_hash_alg_t alg) const;
    void               add(const void *buf, size_t len);
    bool               empty() const;
    std::vector<Hash> &hashes();
};

} // namespace rnp

#endif
