/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
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

#ifndef STREAM_WRITE_H_
#define STREAM_WRITE_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "errors.h"
#include <repgp/repgp.h>

typedef enum {
    PGP_STREAM_FILE,
    PGP_STREAM_MEMORY,
    PGP_STREAM_STDIN,
    PGP_STREAM_STDOUT,
    PGP_STREAM_PACKET,
    PGP_STREAM_PARLEN_PACKET,
    PGP_STREAM_LITERAL,
    PGP_STREAM_COMPRESSED,
    PGP_STREAM_ENCRYPTED,
    PGP_STREAM_SIGNED,
    PGP_STREAM_ARMOURED,
    PGP_STREAM_CLEARTEXT
} pgp_stream_type_t;

typedef struct pgp_dest_t pgp_dest_t;

typedef bool pgp_dest_write_func_t(pgp_dest_t *dst, void *buf, size_t len);
typedef void pgp_dest_close_func_t(pgp_dest_t *dst, bool discard);

typedef struct pgp_dest_t {
    pgp_dest_write_func_t *writefunc;
    pgp_dest_close_func_t *closefunc;
    pgp_stream_type_t      type;

    int64_t             write;  /* number of bytes written */
    void *              param;  /* source-specific additional data */
} pgp_dest_t;

/** @brief write buffer to the destination
 *
 *  @param dst destination structure
 *  @param buf buffer with data
 *  @param len number of bytes to write
 *  @return true on success or false otherwise
 **/
bool dst_write(pgp_dest_t *dst, void *buf, size_t len);

/** @brief close the destination
 *
 *  @param dst destination structure to be closed
 *  @param discard if this is true then all produced output should be discarded
 *  @return void
 **/
void dst_close(pgp_dest_t *dst, bool discard);

/** @brief init file destination
 *  @param dst pre-allocated dest structure
 *  @param path path to the file
 *  @return RNP_SUCCESS or error code
 **/
pgp_errcode_t init_file_dest(pgp_dest_t *dst, const char *path);

/** @brief init stdout destination
 *  @param dst pre-allocated dest structure
 *  @return RNP_SUCCESS or error code
 **/
pgp_errcode_t init_stdout_dest(pgp_dest_t *dst);

/** @brief init memory source
 *  @param dst pre-allocated dest structure
 *  @return RNP_SUCCESS or error code
 **/
pgp_errcode_t init_mem_dest(pgp_dest_t *dst);

#endif
