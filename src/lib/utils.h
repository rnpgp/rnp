/*
 * Copyright (c) 2017-2021 [Ribose Inc](https://www.ribose.com).
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
#ifndef RNP_UTILS_H_
#define RNP_UTILS_H_

#include <stdio.h>
#include <limits.h>
#include "logging.h"

/* number of elements in an array */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

/*
 * @params
 * array:       array of the structures to lookup
 * id_field     name of the field to compare against
 * ret_field    filed to return
 * lookup_value lookup value
 * ret          return value
 */
#define ARRAY_LOOKUP_BY_ID(array, id_field, ret_field, lookup_value, ret) \
    do {                                                                  \
        for (size_t i__ = 0; i__ < ARRAY_SIZE(array); i__++) {            \
            if ((array)[i__].id_field == (lookup_value)) {                \
                (ret) = (array)[i__].ret_field;                           \
                break;                                                    \
            }                                                             \
        }                                                                 \
    } while (0)

/* Portable way to convert bits to bytes */

#define BITS_TO_BYTES(b) (((b) + (CHAR_BIT - 1)) / CHAR_BIT)

/* Load little-endian 32-bit from y to x in portable fashion */

inline void
LOAD32LE(uint32_t &x, const uint8_t y[4])
{
    x = (static_cast<uint32_t>(y[3]) << 24) | (static_cast<uint32_t>(y[2]) << 16) |
        (static_cast<uint32_t>(y[1]) << 8) | (static_cast<uint32_t>(y[0]) << 0);
}

/* Store big-endian 32-bit value x in y */
inline void
STORE32BE(uint8_t x[4], uint32_t y)
{
    x[0] = (uint8_t)(y >> 24) & 0xff;
    x[1] = (uint8_t)(y >> 16) & 0xff;
    x[2] = (uint8_t)(y >> 8) & 0xff;
    x[3] = (uint8_t)(y >> 0) & 0xff;
}

/* Store big-endian 64-bit value x in y */
inline void
STORE64BE(uint8_t x[8], uint64_t y)
{
    x[0] = (uint8_t)(y >> 56) & 0xff;
    x[1] = (uint8_t)(y >> 48) & 0xff;
    x[2] = (uint8_t)(y >> 40) & 0xff;
    x[3] = (uint8_t)(y >> 32) & 0xff;
    x[4] = (uint8_t)(y >> 24) & 0xff;
    x[5] = (uint8_t)(y >> 16) & 0xff;
    x[6] = (uint8_t)(y >> 8) & 0xff;
    x[7] = (uint8_t)(y >> 0) & 0xff;
}

inline char *
getenv_logname(void)
{
    char *name = getenv("LOGNAME");
    if (!name) {
        name = getenv("USER");
    }
    return name;
}

#endif
