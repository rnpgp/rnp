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

#ifndef CRYPTO_HKDF_OSSL_HPP_
#define CRYPTO_HKDF_OSSL_HPP_

#include "config.h"

#if defined(ENABLE_CRYPTO_REFRESH) || defined(ENABLE_PQC)

#include "hkdf.hpp"

namespace rnp {

class Hkdf_OpenSSL : public Hkdf {
  public:
    Hkdf_OpenSSL(pgp_hash_alg_t alg);
    virtual ~Hkdf_OpenSSL();

    static std::unique_ptr<Hkdf_OpenSSL> create(pgp_hash_alg_t alg);

    void extract_expand(const uint8_t *salt,
                        size_t         salt_len,
                        const uint8_t *ikm,
                        size_t         ikm_len,
                        const uint8_t *info,
                        size_t         info_len,
                        uint8_t *      output_buf,
                        size_t         output_length);
};

} // namespace rnp

#endif

#endif
