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

#ifndef STREAM_PARSE_H_
#define STREAM_PARSE_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "errors.h"
#include <repgp/repgp.h>

#define PGP_INPUT_CACHE_SIZE 32768

typedef enum {
    PGP_SOURCE_FILE,
    PGP_SOURCE_MEMORY,
    PGP_SOURCE_STDIN,
    PGP_SOURCE_PACKET,
    PGP_SOURCE_PARLEN_PACKET,
    PGP_SOURCE_LITERAL,
    PGP_SOURCE_COMPRESSED,
    PGP_SOURCE_ENCRYPTED,
    PGP_SOURCE_SIGNED,
    PGP_SOURCE_ARMOURED,
    PGP_SOURCE_CLEARTEXT
} pgp_source_type_t;

typedef enum {
    PGP_ACTION_OK,
    PGP_ACTION_SKIP,
    PGP_ACTION_ABORT,
    PGP_ACTION_MEMORY
} pgp_operation_handler_action_t;

typedef struct pgp_source_t pgp_source_t;
typedef struct pgp_operation_handler_t pgp_operation_handler_t;

typedef ssize_t pgp_source_read_func_t(pgp_source_t *src, void *buf, size_t len);
typedef void pgp_source_close_func_t(pgp_source_t *src);
typedef void pgp_password_needed_func_t(pgp_operation_handler_t *handler, char *pass, int *passlen, pgp_operation_handler_action_t *action);
typedef void pgp_output_funct_t(pgp_operation_handler_t *handler, void *buf, size_t len, pgp_operation_handler_action_t *action);

/* statically preallocated cache for sources. Not used for input filters */
typedef struct pgp_source_cache_t {
    uint8_t buf[PGP_INPUT_CACHE_SIZE];
    unsigned pos;
    unsigned len;
} pgp_source_cache_t;

typedef struct pgp_source_t {
    pgp_source_read_func_t  *readfunc;
    pgp_source_close_func_t *closefunc;
    pgp_source_type_t        type;

    int64_t             size;  /* size of the data if available, 0 otherwise */
    int64_t             read;  /* number of bytes read from the stream via src_read. Do not confuse with number of bytes as returned via the readfunc since data may be cached */
    pgp_source_cache_t *cache; /* cache if used */
    void *              param; /* source-specific additional data */
    
    unsigned            eof : 1;   /* end of data as reported by readfunc and empty cache */
    unsigned            knownsize : 1; /* we know the size of the stream */
} pgp_source_t;

typedef struct pgp_operation_handler_t {
    pgp_passphrase_provider_t *passphrase_provider;
    pgp_output_funct_t *       writefunc;

    void * param;
} pgp_operation_handler_t;

/** @brief read up to len bytes from the source
 *  While this function tries to read as much bytes as possible however it may return
 *  less then len bytes. Then src->eof can be checked if it's end of data.
 *
 *  @param src source structure
 *  @param buf preallocated buffer which can store up to len bytes
 *  @param len number of bytes to read
 *  @return number of bytes read or -1 in case of error. 0 for non-zero read means eof
 **/
ssize_t src_read(pgp_source_t *src, void *buf, size_t len);

/** @brief read up to len bytes and keep them in the cache/do not process
 *  Works only for streams with cache
 *  @param src source structure
 *  @param buf preallocated buffer which can store up to len bytes
 *  @param len number of bytes to read. Must be less then PGP_INPUT_CACHE_SIZE.
 *  @return number of bytes read or -1 in case of error
 **/
ssize_t src_peek(pgp_source_t *src, void *buf, size_t len);

/** @brief skip up to len bytes
 *  @param src source structure
 *  @param len number of bytes to skip
 *  @return number of bytes skipped or -1 in case of error
 **/
ssize_t src_skip(pgp_source_t *src, size_t len);

/** @brief close the source and deallocate all internal resources if any
 **/
void src_close(pgp_source_t *src);

/** @brief init file source
 *  @param src pre-allocate source structure
 *  @param path path to the file
 *  @return RNP_SUCCESS or error code
 **/
pgp_errcode_t init_file_src(pgp_source_t *src, const char *path);

/** @brief init stdin source
 *  @param src pre-allocate source structure
 *  @return RNP_SUCCESS or error code
 **/
pgp_errcode_t init_stdin_src(pgp_source_t *src);

/** @brief init memory source
 *  @param src pre-allocate source structure
 *  @param mem memory to read from
 *  @param len number of bytes in input
 *  @return RNP_SUCCESS or error code
 **/
pgp_errcode_t init_mem_src(pgp_source_t *src, void *mem, size_t len);

/* @brief Process the PGP source: file, memory, stdin
 * Function will parse input data, provided by any source conforming to pgp_source_t, 
 * autodetecting whether it is armoured, cleartext or binary.
 * @param handler handler to respond on stream reader callbacks
 * @param src initialized source with cache
 * @return PGP_E_OK on success or error code otherwise
 **/
pgp_errcode_t process_pgp_source(pgp_operation_handler_t *handler, pgp_source_t *src);

#endif
