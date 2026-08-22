/*
 * Copyright (c) 2026 [Ribose Inc](https://www.ribose.com).
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

#include "entropy_encoding.hpp"
#include "crypto/hash.hpp"
#include "logging.h"
#include <algorithm>
#include <set>

namespace rnp {

size_t
EntropyEncodingConfig::bits_per_char() const noexcept
{
    size_t n = alphabet.size();
    size_t bits = 0;
    while ((1ULL << bits) < n) {
        bits++;
    }
    return bits;
}

size_t
EntropyEncodingConfig::entropy_bytes() const noexcept
{
    return (entropy_bits + 7) / 8;
}

size_t
EntropyEncodingConfig::entropy_chars() const noexcept
{
    return entropy_bits / bits_per_char();
}

size_t
EntropyEncodingConfig::data_group_count() const noexcept
{
    return entropy_chars() / group_size;
}

size_t
EntropyEncodingConfig::checksum_chars() const noexcept
{
    return checksum_bits / bits_per_char();
}

bool
EntropyEncodingConfig::validate(std::string &error) const
{
    /* Alphabet size must be a power of two, >= 2, <= 256. */
    size_t n = alphabet.size();
    if (n < 2 || n > 256) {
        error = "alphabet size must be 2..256";
        return false;
    }
    size_t bpc = 0;
    while ((1ULL << bpc) < n) {
        bpc++;
    }
    if ((1ULL << bpc) != n) {
        error = "alphabet size must be a power of two";
        return false;
    }
    /* Unique characters. */
    std::set<char> seen;
    for (char c : alphabet) {
        if (!isprint(static_cast<unsigned char>(c))) {
            error = "alphabet must contain only printable characters";
            return false;
        }
        if (!seen.insert(c).second) {
            error = "alphabet must contain unique characters";
            return false;
        }
    }
    if (entropy_bits == 0 || entropy_bits % 8 != 0) {
        error = "entropy_bits must be a positive multiple of 8";
        return false;
    }
    if (entropy_bits % bpc != 0) {
        error = "entropy_bits must be a multiple of bits_per_char";
        return false;
    }
    if (group_size == 0) {
        error = "group_size must be > 0";
        return false;
    }
    if (entropy_chars() % group_size != 0) {
        error = "entropy_chars must divide evenly by group_size";
        return false;
    }
    if (!disable_checksum) {
        if (checksum_bits == 0) {
            error = "checksum_bits must be > 0 when checksum is enabled";
            return false;
        }
        if (checksum_bits % bpc != 0) {
            error = "checksum_bits must be a multiple of bits_per_char";
            return false;
        }
        if (checksum_chars() > group_size) {
            error = "checksum must fit in one group";
            return false;
        }
    }
    if (!disable_group_ids && !disable_checksum) {
        /* checksum_id must NOT be in the alphabet */
        if (checksum_id != 0) {
            if (alphabet.find(checksum_id) != std::string::npos) {
                error = "checksum_id must not be in the alphabet";
                return false;
            }
            if (!isprint(static_cast<unsigned char>(checksum_id))) {
                error = "checksum_id must be printable";
                return false;
            }
        }
    }
    return true;
}

bool
entropy_to_flat_string(const std::vector<uint8_t> & entropy,
                       const EntropyEncodingConfig &cfg,
                       std::string &                out)
{
    size_t bpc = cfg.bits_per_char();
    size_t total_chars = cfg.entropy_chars();
    out.assign(total_chars, cfg.alphabet[0]);
    /* Process bits MSB-first within each byte. */
    size_t bit_pos = 0;
    for (size_t i = 0; i < total_chars; i++) {
        size_t value = 0;
        for (size_t b = 0; b < bpc; b++) {
            size_t bp = bit_pos++;
            size_t byte_idx = bp / 8;
            size_t bit_in_byte = 7 - (bp % 8);
            if (byte_idx < entropy.size() && (entropy[byte_idx] >> bit_in_byte) & 1) {
                value |= (1ULL << (bpc - 1 - b));
            }
        }
        out[i] = cfg.alphabet[value];
    }
    return true;
}

bool
flat_string_to_entropy(const std::string &          flat,
                       const EntropyEncodingConfig &cfg,
                       std::vector<uint8_t> &       out)
{
    size_t bpc = cfg.bits_per_char();
    if (flat.size() != cfg.entropy_chars()) {
        return false;
    }
    out.assign(cfg.entropy_bytes(), 0);
    size_t bit_pos = 0;
    for (size_t i = 0; i < flat.size(); i++) {
        auto pos = cfg.alphabet.find(flat[i]);
        if (pos == std::string::npos) {
            return false;
        }
        size_t value = pos;
        for (size_t b = 0; b < bpc; b++) {
            size_t bp = bit_pos++;
            size_t byte_idx = bp / 8;
            size_t bit_in_byte = 7 - (bp % 8);
            if ((value >> (bpc - 1 - b)) & 1) {
                if (byte_idx < out.size()) {
                    out[byte_idx] |= (1ULL << bit_in_byte);
                }
            }
        }
    }
    return true;
}

bool
compute_checksum(const std::vector<uint8_t> & entropy,
                 const EntropyEncodingConfig &cfg,
                 std::string &                out)
{
    auto hash = rnp::Hash::create(PGP_HASH_SHA256);
    hash->add(entropy);
    std::vector<uint8_t> digest(hash->size());
    hash->finish(digest.data());
    /* Take first checksum_bits bits of the digest, encode as chars. */
    EntropyEncodingConfig cksum_cfg = cfg;
    cksum_cfg.entropy_bits = cfg.checksum_bits;
    /* Pad the digest to entropy_bytes() */
    std::vector<uint8_t> trimmed(digest.begin(), digest.begin() + cksum_cfg.entropy_bytes());
    return entropy_to_flat_string(trimmed, cksum_cfg, out);
}

bool
encode_structured(const std::vector<uint8_t> & entropy,
                  const EntropyEncodingConfig &cfg,
                  std::string &                out)
{
    std::string flat;
    if (!entropy_to_flat_string(entropy, cfg, flat)) {
        return false;
    }
    /* Determine the separator. */
    std::string sep = cfg.separator.empty() ? " " : cfg.separator;

    out.clear();
    /* Checksum line first (for visual recognisability). */
    if (!cfg.disable_checksum) {
        std::string checksum_flat;
        if (!compute_checksum(entropy, cfg, checksum_flat)) {
            return false;
        }
        char id = cfg.checksum_id;
        if (id == 0) {
            /* Auto-pick the first printable ASCII char not in the alphabet. */
            id = '!';
            while (cfg.alphabet.find(id) != std::string::npos && id < '~') {
                id++;
            }
        }
        /* Pad checksum_flat to group_size if shorter. */
        while (checksum_flat.size() < cfg.group_size) {
            checksum_flat += cfg.alphabet[0];
        }
        out += id;
        out += checksum_flat;
    }
    /* Data groups. */
    size_t group_count = cfg.data_group_count();
    for (size_t g = 0; g < group_count; g++) {
        if (!out.empty()) {
            out += sep;
        }
        if (!cfg.disable_group_ids) {
            /* Use alphabet[g % alphabet.size()] as the identifier. */
            out += cfg.alphabet[g % cfg.alphabet.size()];
        }
        out += flat.substr(g * cfg.group_size, cfg.group_size);
    }
    return true;
}

bool
decode_structured(const std::string &          structured,
                  const EntropyEncodingConfig &cfg,
                  std::string &                flat,
                  bool &                       checksum_ok)
{
    checksum_ok = true;
    /* Split by separator. */
    std::string              sep = cfg.separator.empty() ? " " : cfg.separator;
    std::vector<std::string> groups;
    size_t                   start = 0;
    while (start <= structured.size()) {
        size_t pos = structured.find(sep, start);
        if (pos == std::string::npos) {
            groups.push_back(structured.substr(start));
            break;
        }
        groups.push_back(structured.substr(start, pos - start));
        start = pos + sep.size();
    }

    std::string flat_chars;
    flat_chars.reserve(cfg.entropy_chars());
    std::string              checksum_chars;
    size_t                   expected_data_groups = cfg.data_group_count();
    std::vector<bool>        seen_group(expected_data_groups, false);
    std::vector<std::string> group_payloads(expected_data_groups);
    bool   found_checksum = cfg.disable_checksum; /* if disabled, "found" trivially */
    size_t data_group_seq = 0;

    for (auto &grp : groups) {
        if (grp.empty()) {
            continue;
        }
        char first = grp[0];
        /* Check if this is the checksum line. */
        if (!cfg.disable_checksum) {
            char expected_id = cfg.checksum_id;
            if (expected_id == 0) {
                expected_id = '!';
                while (cfg.alphabet.find(expected_id) != std::string::npos &&
                       expected_id < '~') {
                    expected_id++;
                }
            }
            if (first == expected_id) {
                checksum_chars = grp.substr(1);
                found_checksum = true;
                continue;
            }
        }
        /* Data group. */
        std::string payload;
        size_t      idx = data_group_seq;
        if (!cfg.disable_group_ids) {
            payload = grp.substr(1);
            auto id_pos = cfg.alphabet.find(first);
            if (id_pos == std::string::npos) {
                return false;
            }
            idx = id_pos;
            if (idx >= expected_data_groups) {
                return false;
            }
            if (seen_group[idx]) {
                return false;
            }
            seen_group[idx] = true;
            group_payloads[idx] = payload;
        } else {
            payload = grp;
            if (data_group_seq >= expected_data_groups) {
                return false;
            }
            group_payloads[data_group_seq] = payload;
            data_group_seq++;
        }
    }

    if (!found_checksum) {
        return false;
    }
    /* Verify all data groups were present and assemble flat in group order. */
    for (size_t i = 0; i < expected_data_groups; i++) {
        if (!cfg.disable_group_ids && !seen_group[i]) {
            return false;
        }
        flat_chars += group_payloads[i];
    }
    flat = flat_chars;
    /* Verify checksum. */
    if (!cfg.disable_checksum) {
        std::vector<uint8_t> entropy;
        if (!flat_string_to_entropy(flat, cfg, entropy)) {
            return false;
        }
        std::string expected;
        if (!compute_checksum(entropy, cfg, expected)) {
            return false;
        }
        /* Compare up to checksum_chars() length (padding may extend). */
        if (expected.size() > checksum_chars.size()) {
            expected = expected.substr(0, checksum_chars.size());
        }
        checksum_ok = (expected == checksum_chars.substr(0, expected.size()));
    }
    return true;
}

} // namespace rnp
