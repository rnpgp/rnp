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

#ifndef ENTROPY_ENCODING_HPP_
#define ENTROPY_ENCODING_HPP_

#include <cstdint>
#include <string>
#include <vector>
#include "repgp/repgp_def.h"

namespace rnp {

/**
 * Configuration for the human-readable entropy encoding, parsed from
 * the FFI-facing rnp_entropy_encoding_params_t struct.
 */
struct EntropyEncodingConfig {
    std::string alphabet;     /* power-of-two size, unique chars */
    size_t      entropy_bits; /* multiple of bits_per_char * group_size */
    size_t      group_size;   /* payload chars per group */
    bool        disable_group_ids;
    bool        disable_checksum;
    size_t      checksum_bits;
    char        checksum_id;
    std::string separator;

    /* Derived: log2(alphabet.size()) */
    size_t bits_per_char() const noexcept;
    /* Derived: ceil(entropy_bits / 8) */
    size_t entropy_bytes() const noexcept;
    /* Derived: entropy_bits / bits_per_char */
    size_t entropy_chars() const noexcept;
    /* Derived: entropy_chars / group_size */
    size_t data_group_count() const noexcept;
    /* Derived: checksum_bits / bits_per_char */
    size_t checksum_chars() const noexcept;

    /* Validate the config; return false with an error message on failure. */
    bool validate(std::string &error) const;
};

/**
 * Convert raw entropy bytes to a flat string of alphabet characters.
 * Returns false if the config is invalid.
 */
bool entropy_to_flat_string(const std::vector<uint8_t> & entropy,
                            const EntropyEncodingConfig &cfg,
                            std::string &                out);

/**
 * Inverse: decode a flat string of alphabet characters to raw bytes.
 * Returns false if the string contains characters outside the alphabet
 * or the wrong number of characters.
 */
bool flat_string_to_entropy(const std::string &          flat,
                            const EntropyEncodingConfig &cfg,
                            std::vector<uint8_t> &       out);

/**
 * Compute the first `cfg.checksum_bits` bits of SHA-256(entropy),
 * encoded as alphabet characters. Returns false on failure.
 */
bool compute_checksum(const std::vector<uint8_t> & entropy,
                      const EntropyEncodingConfig &cfg,
                      std::string &                out);

/**
 * Encode raw entropy as a structured human-readable string per the
 * config. Returns false on failure.
 */
bool encode_structured(const std::vector<uint8_t> & entropy,
                       const EntropyEncodingConfig &cfg,
                       std::string &                out);

/**
 * Parse a structured human-readable string per the config. Populates
 * `flat` with the entropy characters concatenated (no groups, no IDs,
 * no checksum). Returns false if malformed; sets checksum_ok=false if
 * the checksum does not verify.
 */
bool decode_structured(const std::string &          structured,
                       const EntropyEncodingConfig &cfg,
                       std::string &                flat,
                       bool &                       checksum_ok);

} // namespace rnp

#endif
