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

#include "sec_profile.hpp"
#include "types.h"
#include <algorithm>

namespace rnp {
bool
SecurityRule::operator==(const SecurityRule &src) const
{
    return (type == src.type) && (feature == src.feature) && (from == src.from) &&
           (level == src.level) && (override == src.override);
}

bool
SecurityRule::operator!=(const SecurityRule &src) const
{
    return !(*this == src);
}

size_t
SecurityProfile::size() const
{
    return rules_.size();
}

SecurityRule &
SecurityProfile::add_rule(const SecurityRule &rule)
{
    rules_.push_back(rule);
    return rules_.back();
}

SecurityRule &
SecurityProfile::add_rule(SecurityRule &&rule)
{
    rules_.emplace_back(rule);
    return rules_.back();
}

bool
SecurityProfile::del_rule(const SecurityRule &rule)
{
    size_t old_size = rules_.size();
    rules_.erase(std::remove_if(rules_.begin(),
                                rules_.end(),
                                [rule](const SecurityRule &item) { return item == rule; }),
                 rules_.end());
    return old_size != rules_.size();
}

void
SecurityProfile::clear_rules(FeatureType type, int feature)
{
    rules_.erase(std::remove_if(rules_.begin(),
                                rules_.end(),
                                [type, feature](const SecurityRule &item) {
                                    return (item.type == type) && (item.feature == feature);
                                }),
                 rules_.end());
}

void
SecurityProfile::clear_rules(FeatureType type)
{
    rules_.erase(
      std::remove_if(rules_.begin(),
                     rules_.end(),
                     [type](const SecurityRule &item) { return item.type == type; }),
      rules_.end());
}

void
SecurityProfile::clear_rules()
{
    rules_.clear();
}

bool
SecurityProfile::has_rule(FeatureType type, int value, uint64_t time) const
{
    for (auto &rule : rules_) {
        if ((rule.type == type) && (rule.feature == value) && (rule.from <= time)) {
            return true;
        }
    }
    return false;
}

const SecurityRule &
SecurityProfile::get_rule(FeatureType type, int value, uint64_t time) const
{
    const SecurityRule *res = nullptr;
    for (auto &rule : rules_) {
        if ((rule.type != type) || (rule.feature != value) || (rule.from > time)) {
            continue;
        }
        if (rule.override) {
            return rule;
        }
        if (!res || (res->from < rule.from)) {
            res = &rule;
        }
    }
    if (!res) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    return *res;
}

SecurityLevel
SecurityProfile::hash_level(pgp_hash_alg_t hash, uint64_t time) const
{
    if (has_rule(FeatureType::Hash, hash, time)) {
        return get_rule(FeatureType::Hash, hash, time).level;
    }
    return def_level();
}

SecurityLevel
SecurityProfile::def_level() const
{
    return SecurityLevel::Default;
};

} // namespace rnp