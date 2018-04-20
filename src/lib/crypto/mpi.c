/*-
 * Copyright (c) 2018 Ribose Inc.
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

#include "mpi.h"
#include <string.h>
#include "memory.h"

bool
to_buf(buf_t *b, const uint8_t *in, size_t len)
{
    if (b->len < len) {
        return false;
    }
    memcpy(b->pbuf, in, len);
    b->len = len;
    return true;
}

const buf_t
mpi2buf(pgp_mpi_t *val, bool uselen)
{
    return (buf_t){.pbuf = val->mpi, .len = uselen ? val->len : sizeof(val->mpi)};
}

bignum_t *
mpi2bn(const pgp_mpi_t *val)
{
    return bn_bin2bn(val->mpi, val->len, NULL);
}

bool
bn2mpi(bignum_t *bn, pgp_mpi_t *val)
{
    return bn_num_bytes(bn, &val->len) && (bn_bn2bin(bn, val->mpi) == 0);
}

unsigned
mpi_bits(const pgp_mpi_t *val)
{
    unsigned bits = 0;
    unsigned idx = 0;
    uint8_t  bt;

    while ((idx < val->len) && (val->mpi[idx] == 0)) {
        idx++;
    }

    if (idx < val->len) {
        bt = val->mpi[idx];
        bits = (val->len - idx - 1) << 3;
        while (bt) {
            bits++;
            bt = bt >> 1;
        }
    }

    return bits;
}

void
mpi_forget(pgp_mpi_t *val)
{
    pgp_forget(val, sizeof(*val));
    val->len = 0;
}
