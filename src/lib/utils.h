/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
#include "types.h"

#define RNP_MSG(msg) (void) fprintf(stdout, msg);
#define RNP_LOG_FD(fd, ...)                                                  \
    do {                                                                     \
        (void) fprintf((fd), "[%s() %s:%d] ", __func__, __FILE__, __LINE__); \
        (void) fprintf((fd), __VA_ARGS__);                                   \
        (void) fprintf((fd), "\n");                                          \
    } while (0)

#define RNP_LOG(...) RNP_LOG_FD(stderr, __VA_ARGS__)

#define CHECK(exp, val, err)                          \
    do {                                              \
        if ((exp) != (val)) {                         \
            RNP_LOG("ERROR: (" #exp ")!=(" #val ")"); \
            ret = (err);                              \
            goto end;                                 \
        }                                             \
    } while (false)

#define CALLBACK(t, cbinfo, pkt)                               \
    do {                                                       \
        (pkt)->tag = (t);                                      \
        if (pgp_callback(pkt, cbinfo) == PGP_RELEASE_MEMORY) { \
            pgp_parser_content_free(pkt);                      \
        }                                                      \
    } while (/* CONSTCOND */ 0)

/* Formating helpers */
#define PRItime "ll"

#ifdef WIN32
#define PRIsize "I"
#else
#define PRIsize "z"
#endif

/* TODO: Review usage of this variable */
#define RNP_BUFSIZ 8192

/* for silencing unused parameter warnings */
#define RNP_USED(x) /*LINTED*/ (void) &(x)

#ifndef RNP_UNCONST
#define RNP_UNCONST(a) ((void *) (unsigned long) (const void *) (a))
#endif

/* Portable way to convert bits to bytes */
#define BITS_TO_BYTES(b) (((b) + (CHAR_BIT - 1)) / CHAR_BIT)

/* number of elements in an array */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

/* debugging helpers*/
int  rnp_set_debug(const char *);
int  rnp_get_debug(const char *);
void hexdump(FILE *, const char *, const uint8_t *, size_t);

const char *pgp_str_from_map(int, pgp_map_t *);
void *      pgp_new(size_t);

#endif