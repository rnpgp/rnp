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
#include "pgp-key.h"

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

    void check_defaults() noexcept;

    bool validate() const noexcept;

    bool validate(const CertParams &cert) const noexcept;

    bool validate(const BindingParams &binding) const noexcept;

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

    pgp::KeyParams &
    key_params() noexcept
    {
        return *key_params_;
    }

    /* Generate secret key packet */
    bool generate(pgp_key_pkt_t &seckey, bool primary);

    /* Generate primary key with self-certification */
    bool generate(CertParams &           cert,
                  pgp_key_t &            primary_sec,
                  pgp_key_t &            primary_pub,
                  pgp_key_store_format_t secformat);

    /* Generate a subkey for already existing primary key*/
    bool generate(BindingParams &                binding,
                  pgp_key_t &                    primary_sec,
                  pgp_key_t &                    primary_pub,
                  pgp_key_t &                    subkey_sec,
                  pgp_key_t &                    subkey_pub,
                  const pgp_password_provider_t &password_provider,
                  pgp_key_store_format_t         secformat);
};

class CertParams {
  public:
    std::string      userid;       /* userid, required */
    uint8_t          flags{};      /* key flags */
    uint32_t         expiration{}; /* key expiration time (sec), 0 = no expiration */
    pgp_user_prefs_t prefs{};      /* user preferences, optional */
    bool             primary;      /* mark this as the primary user id */

    void check_defaults(const KeygenParams &params);

    /**
     * @brief Populate uid and sig packet with data stored in this struct.
     *        At some point we should get rid of it.
     */
    void populate(pgp_userid_pkt_t &uid, pgp_signature_t &sig) const;
    void populate(pgp_signature_t &sig) const;
    void populate(pgp_userid_pkt_t &uid) const;
};

class BindingParams {
  public:
    uint8_t  flags{};
    uint32_t expiration{};

    void check_defaults(const KeygenParams &params);
};

} // namespace rnp

#endif // RNP_KEYGEN_HPP_