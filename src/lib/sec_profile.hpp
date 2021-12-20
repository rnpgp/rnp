/*
 * Copyright (c) 2021 [Ribose Inc](https://www.ribose.com).
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
#ifndef RNP_SEC_PROFILE_H_
#define RNP_SEC_PROFILE_H_

#include <cstdint>
#include <vector>
#include "repgp/repgp_def.h"
#include "crypto/rng.h"

namespace rnp {

enum class FeatureType { Hash, Cipher, PublicKey };
enum class SecurityLevel { Disabled, Insecure, Default };

struct SecurityRule {
    FeatureType   type;
    int           feature;
    SecurityLevel level;
    uint64_t      from;
    bool          override;

    SecurityRule(FeatureType ftype, int fval, SecurityLevel flevel, uint64_t ffrom = 0)
        : type(ftype), feature(fval), level(flevel), from(ffrom), override(false){};

    bool operator==(const SecurityRule &src) const;
    bool operator!=(const SecurityRule &src) const;
};

class SecurityProfile {
  private:
    std::vector<SecurityRule> rules_;

  public:
    size_t        size() const noexcept;
    SecurityRule &add_rule(const SecurityRule &rule);
    SecurityRule &add_rule(SecurityRule &&rule);
    bool          del_rule(const SecurityRule &rule);
    void          clear_rules(FeatureType type, int feature);
    void          clear_rules(FeatureType type);
    void          clear_rules();

    bool                has_rule(FeatureType type, int value, uint64_t time) const noexcept;
    const SecurityRule &get_rule(FeatureType type, int value, uint64_t time) const;
    SecurityLevel       hash_level(pgp_hash_alg_t hash, uint64_t time) const noexcept;
    SecurityLevel       def_level() const;
};

class SecurityContext {
  public:
    SecurityProfile profile;
    RNG             rng;

    SecurityContext();
};
} // namespace rnp

#endif
