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

#ifndef SECURE_BYTES_H_
#define SECURE_BYTES_H_

#include <cstddef>
#include <cstdint>
#include <vector>

namespace rnp {

/* Defined in secure_bytes.cpp as a non-inlineable function so the compiler cannot
   eliminate the zeroing as a dead store. */
void secure_wipe(void *ptr, size_t len);

/* Drop-in replacement for Botan::secure_vector<uint8_t> that carries no Botan dependency
   in its header.  Memory is zeroed on destruction (and before any move-from). */
class SecureBytes {
    std::vector<uint8_t> data_;

  public:
    SecureBytes() = default;

    SecureBytes(const uint8_t *first, const uint8_t *last) : data_(first, last) {}
    SecureBytes(const uint8_t *data, size_t size) : data_(data, data + size) {}

    SecureBytes(const std::vector<uint8_t> &v) : data_(v) {}
    SecureBytes(std::vector<uint8_t> &&v) noexcept : data_(std::move(v)) {}

    ~SecureBytes() { secure_wipe(data_.data(), data_.size()); }

    SecureBytes(const SecureBytes &) = default;
    SecureBytes &operator=(const SecureBytes &) = default;

    SecureBytes(SecureBytes &&o) noexcept : data_(std::move(o.data_)) {}
    SecureBytes &
    operator=(SecureBytes &&o) noexcept
    {
        secure_wipe(data_.data(), data_.size());
        data_ = std::move(o.data_);
        return *this;
    }

    uint8_t *
    data() noexcept
    {
        return data_.data();
    }
    const uint8_t *
    data() const noexcept
    {
        return data_.data();
    }
    size_t
    size() const noexcept
    {
        return data_.size();
    }
    bool
    empty() const noexcept
    {
        return data_.empty();
    }

    std::vector<uint8_t>::iterator
    begin() noexcept
    {
        return data_.begin();
    }
    std::vector<uint8_t>::const_iterator
    begin() const noexcept
    {
        return data_.begin();
    }
    std::vector<uint8_t>::iterator
    end() noexcept
    {
        return data_.end();
    }
    std::vector<uint8_t>::const_iterator
    end() const noexcept
    {
        return data_.end();
    }

    std::vector<uint8_t>
    unlock() const
    {
        return data_;
    }
};

} // namespace rnp

#endif
