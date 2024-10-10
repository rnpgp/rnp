/*
 * Copyright (c) 2024 [Ribose Inc](https://www.ribose.com).
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

#ifndef RNP_KEYGEN_HPP_
#define RNP_KEYGEN_HPP_

#include "repgp/repgp_def.h"
#include "types.h"
#include "sec_profile.hpp"
#include "key_material.hpp"

namespace rnp {

class KeygenParams {
  private:
    pgp_pubkey_alg_t                alg_;
    pgp_hash_alg_t                  hash_;
    pgp_version_t                   version_;
    SecurityContext &               ctx_;
    std::unique_ptr<pgp::KeyParams> key_params_;

  public:
    KeygenParams(pgp_pubkey_alg_t alg, SecurityContext &ctx);

    pgp_pubkey_alg_t
    alg() const noexcept
    {
        return alg_;
    }

    pgp_hash_alg_t
    hash() const noexcept
    {
        return hash_;
    }

    void
    set_hash(pgp_hash_alg_t value) noexcept
    {
        hash_ = value;
    }

    pgp_version_t
    version() const noexcept
    {
        return version_;
    }

    void
    set_version(pgp_version_t value) noexcept
    {
        version_ = value;
    }

    SecurityContext &
    ctx() noexcept
    {
        return ctx_;
    }

    const pgp::KeyParams &
    key_params() const noexcept
    {
        return *key_params_;
    }
};

} // namespace rnp

#endif // RNP_KEYGEN_HPP_