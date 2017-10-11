/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#ifndef STREAM_COMMON_H_
#define STREAM_COMMON_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "errors.h"
#include <repgp/repgp.h>

#define PGP_INPUT_CACHE_SIZE 32768
#define PGP_OUTPUT_CACHE_SIZE 32768

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

typedef struct pgp_source_t pgp_source_t;
typedef struct pgp_dest_t   pgp_dest_t;

typedef ssize_t pgp_source_read_func_t(pgp_source_t *src, void *buf, size_t len);
typedef void pgp_source_close_func_t(pgp_source_t *src);

typedef rnp_result_t pgp_dest_write_func_t(pgp_dest_t *dst, const void *buf, size_t len);
typedef void pgp_dest_close_func_t(pgp_dest_t *dst, bool discard);

/* statically preallocated cache for sources. Not used for input filters */
typedef struct pgp_source_cache_t {
    uint8_t  buf[PGP_INPUT_CACHE_SIZE];
    unsigned pos;
    unsigned len;
} pgp_source_cache_t;

typedef struct pgp_source_t {
    pgp_source_read_func_t * read;
    pgp_source_close_func_t *close;
    pgp_stream_type_t        type;

    uint64_t size;  /* size of the data if available, 0 otherwise */
    uint64_t readb; /* number of bytes read from the stream via src_read. Do not confuse with
                       number of bytes as returned via the read since data may be cached */
    pgp_source_cache_t *cache; /* cache if used */
    void *              param; /* source-specific additional data */

    unsigned eof : 1; /* end of data as reported by read and empty cache */
} pgp_source_t;

/** @brief helper function to allocate memory for source's cache and param
 **/
bool init_source_cache(pgp_source_t *src, size_t paramsize);

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
 *  @param buf preallocated buffer which can store up to len bytes, or NULL if data should be
 *  discarded, just making sure that needed input is available in source
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
 *  @param src pre-allocated source structure
 *  @param path path to the file
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t init_file_src(pgp_source_t *src, const char *path);

/** @brief init stdin source
 *  @param src pre-allocated source structure
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t init_stdin_src(pgp_source_t *src);

/** @brief init memory source
 *  @param src pre-allocated source structure
 *  @param mem memory to read from
 *  @param len number of bytes in input
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t init_mem_src(pgp_source_t *src, void *mem, size_t len);

typedef struct pgp_dest_t {
    pgp_dest_write_func_t *write;
    pgp_dest_close_func_t *close;
    pgp_stream_type_t      type;
    rnp_result_t           werr; /* write function may set this to some error code */

    int64_t  writeb; /* number of bytes written */
    void *   param;  /* source-specific additional data */
    uint8_t  cache[PGP_OUTPUT_CACHE_SIZE];
    unsigned clen;
} pgp_dest_t;

/** @brief write buffer to the destination
 *
 *  @param dst destination structure
 *  @param buf buffer with data
 *  @param len number of bytes to write
 *  @return true on success or false otherwise
 **/
void dst_write(pgp_dest_t *dst, const void *buf, size_t len);

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
rnp_result_t init_file_dest(pgp_dest_t *dst, const char *path);

/** @brief init stdout destination
 *  @param dst pre-allocated dest structure
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t init_stdout_dest(pgp_dest_t *dst);

/** @brief init memory source
 *  @param dst pre-allocated dest structure
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t init_mem_dest(pgp_dest_t *dst);

#endif
