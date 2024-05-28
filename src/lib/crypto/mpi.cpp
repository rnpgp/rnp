/*-
 * Copyright (c) 2018, 2024 Ribose Inc.
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

#include <string.h>
#include <stdlib.h>
#include "mpi.h"
#include "mem.h"
#include "utils.h"

namespace pgp {

size_t
mpi::bits() const noexcept
{
    size_t  bits = 0;
    size_t  idx = 0;
    uint8_t bt;

    for (idx = 0; (idx < len) && !mpi[idx]; idx++)
        ;

    if (idx < len) {
        for (bits = (len - idx - 1) << 3, bt = mpi[idx]; bt; bits++, bt = bt >> 1)
            ;
    }

    return bits;
}

size_t
mpi::bytes() const noexcept
{
    return len;
}

bool
mpi::from_mem(const void *mem, size_t mlen) noexcept
{
    if (mlen > sizeof(mpi)) {
        return false;
    }

    memcpy(mpi, mem, mlen);
    len = mlen;
    return true;
}

void
mpi::to_mem(void *mem) const noexcept
{
    memcpy(mem, mpi, len);
}

bool
mpi::operator==(const struct mpi &src) const
{
    size_t idx1 = 0;
    size_t idx2 = 0;

    for (idx1 = 0; (idx1 < this->len) && !this->mpi[idx1]; idx1++)
        ;

    for (idx2 = 0; (idx2 < src.len) && !src.mpi[idx2]; idx2++)
        ;

    return ((this->len - idx1) == (src.len - idx2) &&
            !memcmp(this->mpi + idx1, src.mpi + idx2, this->len - idx1));
}

void
mpi::forget() noexcept
{
    secure_clear(mpi, sizeof(mpi));
    len = 0;
}

} // namespace pgp
