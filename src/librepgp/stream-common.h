/*
 * Copyright (c) 2017-2020, [Ribose Inc](https://www.ribose.com).
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
#include "types.h"

#define PGP_INPUT_CACHE_SIZE 32768
#define PGP_OUTPUT_CACHE_SIZE 32768

#define PGP_PARTIAL_PKT_FIRST_PART_MIN_SIZE 512

typedef enum {
    PGP_STREAM_NULL,
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
    PGP_STREAM_ARMORED,
    PGP_STREAM_CLEARTEXT
} pgp_stream_type_t;

typedef struct pgp_source_t pgp_source_t;
typedef struct pgp_dest_t   pgp_dest_t;

typedef bool pgp_source_read_func_t(pgp_source_t *src, void *buf, size_t len, size_t *read);
typedef rnp_result_t pgp_source_finish_func_t(pgp_source_t *src);
typedef void         pgp_source_close_func_t(pgp_source_t *src);

typedef rnp_result_t pgp_dest_write_func_t(pgp_dest_t *dst, const void *buf, size_t len);
typedef rnp_result_t pgp_dest_finish_func_t(pgp_dest_t *src);
typedef void         pgp_dest_close_func_t(pgp_dest_t *dst, bool discard);

/* statically preallocated cache for sources */
typedef struct pgp_source_cache_t {
    uint8_t  buf[PGP_INPUT_CACHE_SIZE];
    unsigned pos;       /* current position in cache */
    unsigned len;       /* number of bytes available in cache */
    bool     readahead; /* whether read-ahead with larger chunks allowed */
} pgp_source_cache_t;

typedef struct pgp_source_t {
    pgp_source_read_func_t *  read;
    pgp_source_finish_func_t *finish;
    pgp_source_close_func_t * close;
    pgp_stream_type_t         type;

    uint64_t size;  /* size of the data if available, see knownsize */
    uint64_t readb; /* number of bytes read from the stream via src_read. Do not confuse with
                       number of bytes as returned via the read since data may be cached */
    pgp_source_cache_t *cache; /* cache if used */
    void *              param; /* source-specific additional data */

    unsigned eof : 1;       /* end of data as reported by read and empty cache */
    unsigned knownsize : 1; /* whether size of the data is known */
    unsigned error : 1;     /* there were reading error */
} pgp_source_t;

/** @brief helper function to allocate memory for source's cache and param
 *         Also fills src and param with zeroes
 *  @param src pointer to the source structure
 *  @param paramsize number of bytes required for src->param
 *  @return true on success or false if memory allocation failed.
 **/
bool init_src_common(pgp_source_t *src, size_t paramsize);

/** @brief read up to len bytes from the source
 *  While this function tries to read as much bytes as possible however it may return
 *  less then len bytes. Then src->eof can be checked if it's end of data.
 *
 *  @param src source structure
 *  @param buf preallocated buffer which can store up to len bytes
 *  @param len number of bytes to read
 *  @param read number of read bytes will be stored here. Cannot be NULL.
 *  @return true on success or false otherwise
 **/
bool src_read(pgp_source_t *src, void *buf, size_t len, size_t *read);

/** @brief shortcut to read exactly len bytes from source. See src_read for parameters.
 *  @return true if len bytes were read or false otherwise (i.e. less then len were read or
 *          read error occurred) */
bool src_read_eq(pgp_source_t *src, void *buf, size_t len);

/** @brief read up to len bytes and keep them in the cache/do not process
 *  Works only for streams with cache
 *  @param src source structure
 *  @param buf preallocated buffer which can store up to len bytes, or NULL if data should be
 *             discarded, just making sure that needed input is available in source
 *  @param len number of bytes to read. Must be less then PGP_INPUT_CACHE_SIZE.
 *  @param read number of bytes read will be stored here. Cannot be NULL.
 *  @return true on success or false otherwise
 **/
bool src_peek(pgp_source_t *src, void *buf, size_t len, size_t *read);

/** @brief shortcut to read exactly len bytes and keep them in the cache/do not process
 *         Works only for streams with cache
 *  @return true if len bytes were read or false otherwise (i.e. less then len were read or
 *          read error occurred) */
bool src_peek_eq(pgp_source_t *src, void *buf, size_t len);

/** @brief skip up to len bytes.
 *         Note: use src_read() if you want to check error condition/get number of bytes
 *skipped.
 *  @param src source structure
 *  @param len number of bytes to skip
 **/
void src_skip(pgp_source_t *src, size_t len);

/** @brief notify source that all reading is done, so final data processing may be started,
 * i.e. signature reading and verification and so on. Do not misuse with src_close.
 *  @param src allocated and initialized source structure
 *  @return RNP_SUCCESS or error code. If source doesn't have finish handler then also
 * RNP_SUCCESS is returned
 */
rnp_result_t src_finish(pgp_source_t *src);

/** @brief check whether there were reading error on source
 *  @param allocated and initialized source structure
 *  @return true if there were reading error or false otherwise
 */
bool src_error(const pgp_source_t *src);

/** @brief check whether there is no more input on source
 *  @param src allocated and initialized source structure
 *  @return true if there is no more input or false otherwise.
 *          On read error false will be returned.
 */
bool src_eof(pgp_source_t *src);

/** @brief close the source and deallocate all internal resources if any
 */
void src_close(pgp_source_t *src);

/** @brief skip end of line on the source (\r\n or \n, depending on input)
 *  @param src allocated and initialized source
 *  @return true if eol was found and skipped or false otherwise
 */
bool src_skip_eol(pgp_source_t *src);

/** @brief peek the line on the source
 *  @param src allocated and initialized source with data
 *  @param buf preallocated buffer to store the result. Result include NULL character and
 *             doesn't include the end of line sequence.
 *  @param len maximum length of data to store in buf, including terminating NULL
 *  @param read on success here will be stored number of bytes in the string, without the NULL
 * character.
 *  @return true on success
 *          false is returned if there were eof, read error or eol was not found within the
 * len. Supported eol sequences are \r\n and \n
 */
bool src_peek_line(pgp_source_t *src, char *buf, size_t len, size_t *read);

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
 *  @param free free the memory pointer on stream close or not
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t init_mem_src(pgp_source_t *src, const void *mem, size_t len, bool free);

/** @brief init NULL source, which doesn't allow to read anything and always returns an error.
 *  @param src pre-allocated source structure
 *  @return always RNP_SUCCESS
 **/
rnp_result_t init_null_src(pgp_source_t *src);

/** @brief init memory source with contents of other source
 *  @param src pre-allocated source structure
 *  @param readsrc opened source with data
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t read_mem_src(pgp_source_t *src, pgp_source_t *readsrc);

/** @brief init memory source with contents of the specified file
 *  @param src pre-allocated source structure
 *  @param filename name of the file
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t file_to_mem_src(pgp_source_t *src, const char *filename);

/** @brief get memory from the memory source
 *  @param src initialized memory source
 *  @return pointer to the memory or NULL if it is not a memory source
 **/
const void *mem_src_get_memory(pgp_source_t *src);

typedef struct pgp_dest_t {
    pgp_dest_write_func_t * write;
    pgp_dest_finish_func_t *finish;
    pgp_dest_close_func_t * close;
    pgp_stream_type_t       type;
    rnp_result_t            werr; /* write function may set this to some error code */

    size_t   writeb;   /* number of bytes written */
    void *   param;    /* source-specific additional data */
    bool     no_cache; /* disable write caching */
    uint8_t  cache[PGP_OUTPUT_CACHE_SIZE];
    unsigned clen;     /* number of bytes in cache */
    bool     finished; /* whether dst_finish was called on dest or not */
} pgp_dest_t;

/** @brief helper function to allocate memory for dest's param.
 *         Initializes dst and param with zeroes as well.
 *  @param dst dest structure
 *  @param paramsize number of bytes required for dst->param
 *  @return true on success, or false if memory allocation failed
 **/
bool init_dst_common(pgp_dest_t *dst, size_t paramsize);

/** @brief write buffer to the destination
 *
 *  @param dst destination structure
 *  @param buf buffer with data
 *  @param len number of bytes to write
 *  @return true on success or false otherwise
 **/
void dst_write(pgp_dest_t *dst, const void *buf, size_t len);

/** @brief printf formatted string to the destination
 *
 *  @param dst destination structure
 *  @param format format string, which is the same as printf() uses
 *  @param ... additional arguments
 */
void dst_printf(pgp_dest_t *dst, const char *format, ...);

/** @brief do all finalization tasks after all writing is done, i.e. calculate and write
 *  mdc, signatures and so on. Do not misuse with dst_close. If was not called then will be
 *  called from the dst_close
 *
 *  @param dst destination structure
 *  @return RNP_SUCCESS or error code if something went wrong
 **/
rnp_result_t dst_finish(pgp_dest_t *dst);

/** @brief close the destination
 *
 *  @param dst destination structure to be closed
 *  @param discard if this is true then all produced output should be discarded
 *  @return void
 **/
void dst_close(pgp_dest_t *dst, bool discard);

/** @brief flush cached data if any. dst_write caches small writes, so data does not
 *         immediately go to stream write function.
 *
 *  @param dst destination structure
 *  @return void
 **/
void dst_flush(pgp_dest_t *dst);

/** @brief init file destination
 *  @param dst pre-allocated dest structure
 *  @param path path to the file
 *  @param overwrite overwrite existing file
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t init_file_dest(pgp_dest_t *dst, const char *path, bool overwrite);

/** @brief init file destination, using the temporary file name, based on path.
 *         Once writing is over, dst_finish() will attempt to rename to the desired name.
 *  @param dst pre-allocated dest structure
 *  @param path path to the file
 *  @param overwrite overwrite existing file on rename
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t init_tmpfile_dest(pgp_dest_t *dst, const char *path, bool overwrite);

/** @brief init stdout destination
 *  @param dst pre-allocated dest structure
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t init_stdout_dest(pgp_dest_t *dst);

/** @brief init memory destination
 *  @param dst pre-allocated dest structure
 *  @param mem pointer to the pre-allocated memory buffer, or NULL if it should be allocated
 *  @param len number of bytes which mem can keep, or maximum amount of memory to allocate if
 *         mem is NULL. If len is zero in later case then allocation is not limited.
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t init_mem_dest(pgp_dest_t *dst, void *mem, unsigned len);

/** @brief set whether to silently discard bytes which overflow memory of the dst.
 *  @param dst pre-allocated and initialized memory dest
 *  @param discard true to discard or false to return an error on overflow.
 **/
void mem_dest_discard_overflow(pgp_dest_t *dst, bool discard);

/** @brief get the pointer to the memory where data is written.
 *  Do not retain the result, it may change between calls due to realloc
 *  @param dst pre-allocated and initialized memory dest
 *  @return pointer to the memory area or NULL if memory was not allocated
 **/
void *mem_dest_get_memory(pgp_dest_t *dst);

/** @brief get ownership on the memory dest's contents. This must be called only before
 *         closing the dest
 *  @param dst pre-allocated and initialized memory dest
 *  @return pointer to the memory area or NULL if memory was not allocated (i.e. nothing was
 *          written to the destination). Also NULL will be returned on possible (re-)allocation
 *          failure, this case can be identified by non-zero dst->writeb.
 **/
void *mem_dest_own_memory(pgp_dest_t *dst);

/** @brief init null destination which silently discards all the output
 *  @param dst pre-allocated dest structure
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t init_null_dest(pgp_dest_t *dst);

/** @brief reads from source and writes to destination
 *  @param src initialized source
 *  @param dst initialized destination
 *  @param limit sets the maximum amount of bytes to be read,
 *         returning an error if the source hasn't come to eof after that amount
 *         if 0, no limit is imposed
 *  @return RNP_SUCCESS or error code
 **/
rnp_result_t dst_write_src(pgp_source_t *src, pgp_dest_t *dst, uint64_t limit = 0);

#endif
