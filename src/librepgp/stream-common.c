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

#include "config.h"
#include "stream-common.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#include <rnp/rnp_def.h>
#include "defs.h"
#include "types.h"
#include "symmetric.h"
#include "crypto/s2k.h"
#include "misc.h"
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

ssize_t
src_read(pgp_source_t *src, void *buf, size_t len)
{
    size_t              left = len;
    ssize_t             read;
    pgp_source_cache_t *cache = src->cache;

    if (src->eof || (len == 0)) {
        return 0;
    }

    // Check whether we have cache and there is data inside
    if (cache && (cache->len > cache->pos)) {
        read = cache->len - cache->pos;
        if (read >= len) {
            memcpy(buf, &cache->buf[cache->pos], len);
            cache->pos += len;
            goto finish;
        } else {
            memcpy(buf, &cache->buf[cache->pos], read);
            cache->pos += read;
            buf = (uint8_t *) buf + read;
            left = len - read;
        }
    }

    // If we got here then we have empty cache or no cache at all
    while (left > 0) {
        if (!cache || (left > sizeof(cache->buf))) {
            // If there is no cache or chunk is larger then read directly
            read = src->read(src, buf, left);
            if (read > 0) {
                left -= read;
                buf = (uint8_t *) buf + read;
            } else if (read == 0) {
                src->eof = 1;
                len = len - left;
                goto finish;
            } else {
                return -1;
            }
        } else {
            // Try to fill the cache to avoid small reads
            read = src->read(src, &cache->buf[0], sizeof(cache->buf));
            if (read == 0) {
                src->eof = 1;
                len = len - left;
                goto finish;
            } else if (read < 0) {
                return -1;
            } else if (read < left) {
                memcpy(buf, &cache->buf[0], read);
                left -= read;
                buf = (uint8_t *) buf + read;
            } else {
                memcpy(buf, &cache->buf[0], left);
                cache->pos = left;
                cache->len = read;
                goto finish;
            }
        }
    }

finish:
    src->readb += len;
    return len;
}

ssize_t
src_peek(pgp_source_t *src, void *buf, size_t len)
{
    ssize_t             read;
    pgp_source_cache_t *cache = src->cache;

    if (!cache || (len > sizeof(cache->buf))) {
        return -1;
    }

    if (src->eof) {
        return 0;
    }

    if (cache->len - cache->pos >= len) {
        memcpy(buf, &cache->buf[cache->pos], len);
        return len;
    }

    if (cache->pos > 0) {
        memmove(&cache->buf[0], &cache->buf[cache->pos], cache->len - cache->pos);
        cache->len -= cache->pos;
        cache->pos = 0;
    }

    while (cache->len < len) {
        read = src->read(src, &cache->buf[cache->len], sizeof(cache->buf) - cache->len);
        if (read == 0) {
            memcpy(buf, &cache->buf[0], cache->len);
            return cache->len;
        } else if (read < 0) {
            return -1;
        } else {
            cache->len += read;
            if (cache->len >= len) {
                memcpy(buf, &cache->buf[0], len);
                return len;
            }
        }
    }

    return -1;
}

ssize_t
src_skip(pgp_source_t *src, size_t len)
{
    ssize_t res;
    void *  buf;
    uint8_t sbuf[16];

    if (len < sizeof(sbuf)) {
        return src_read(src, sbuf, len);
    } else {
        buf = calloc(1, len);

        if (buf == NULL) {
            return -1;
        } else {
            res = src_read(src, buf, len);
            free(buf);
            return res;
        }
    }
}

void
src_close(pgp_source_t *src)
{
    if (src->close) {
        src->close(src);
    }
}

bool
init_source_cache(pgp_source_t *src, size_t paramsize)
{
    if ((src->cache = calloc(1, sizeof(pgp_source_cache_t))) == NULL) {
        return false;
    }

    if (paramsize > 0) {
        if ((src->param = calloc(1, paramsize)) == NULL) {
            free(src->cache);
            src->cache = NULL;
            return false;
        }
    } else {
        src->param = NULL;
    }

    return true;
}

typedef struct pgp_source_file_param_t {
    int fd;
} pgp_source_file_param_t;

ssize_t
file_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_file_param_t *param = src->param;

    if (param == NULL) {
        return -1;
    } else {
        return read(param->fd, buf, len);
    }
}

void
file_src_close(pgp_source_t *src)
{
    pgp_source_file_param_t *param = src->param;
    if (param) {
        if (src->type == PGP_STREAM_FILE) {
            close(param->fd);
        }
        free(src->param);
        src->param = NULL;
    }
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
    }
}

rnp_result_t
init_file_src(pgp_source_t *src, const char *path)
{
    int                      fd;
    struct stat              st;
    pgp_source_file_param_t *param;

    if (stat(path, &st) != 0) {
        (void) fprintf(stderr, "can't stat \"%s\"\n", path);
        return PGP_E_R_READ_FAILED;
    }

#ifdef O_BINARY
    fd = open(path, O_RDONLY | O_BINARY);
#else
    fd = open(path, O_RDONLY);
#endif
    if (fd < 0) {
        (void) fprintf(stderr, "can't open \"%s\"\n", path);
        return RNP_ERROR_READ;
    }

    if (!init_source_cache(src, sizeof(pgp_source_file_param_t))) {
        close(fd);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = src->param;
    param->fd = fd;
    src->read = file_src_read;
    src->close = file_src_close;
    src->type = PGP_STREAM_FILE;
    src->size = st.st_size;
    src->readb = 0;
    src->knownsize = 1;
    src->eof = 0;

    return RNP_SUCCESS;
}

rnp_result_t
init_stdin_src(pgp_source_t *src)
{
    pgp_source_file_param_t *param;

    if (!init_source_cache(src, sizeof(pgp_source_file_param_t))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = src->param;
    param->fd = 0;
    src->read = file_src_read;
    src->close = file_src_close;
    src->type = PGP_STREAM_STDIN;
    src->size = 0;
    src->readb = 0;
    src->knownsize = 0;
    src->eof = 0;

    return RNP_SUCCESS;
}

rnp_result_t
init_mem_src(pgp_source_t *src, void *mem, size_t len)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

void
dst_write(pgp_dest_t *dst, void *buf, size_t len)
{
    if ((len > 0) && (dst->write)) {
        dst->write(dst, buf, len);
        dst->writeb += len;
    }
}

void
dst_close(pgp_dest_t *dst, bool discard)
{
    if (dst->close) {
        dst->close(dst, discard);
    }
}

typedef struct pgp_dest_file_param_t {
    int  fd;
    int  errcode;
    char path[PATH_MAX];
} pgp_dest_file_param_t;

void
file_dst_write(pgp_dest_t *dst, void *buf, size_t len)
{
    ssize_t                ret;
    pgp_dest_file_param_t *param = dst->param;

    if (!param) {
        (void) fprintf(stderr, "file_dst_write: wrong param\n");
        dst->werr = RNP_ERROR_BAD_PARAMETERS;
        return;
    }

    /* we assyme that blocking I/O is used so everything is written or error received */
    ret = write(param->fd, buf, len);
    if (ret < 0) {
        dst->werr = RNP_ERROR_WRITE;
        param->errcode = errno;
        (void) fprintf(stderr, "file_dst_write: write failed, error %d\n", param->errcode);
    } else {
        dst->werr = RNP_SUCCESS;
        param->errcode = 0;
    }
}

void
file_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_file_param_t *param = dst->param;

    if (!param) {
        return;
    }

    close(param->fd);

    if (discard && (dst->type == PGP_STREAM_FILE)) {
        unlink(param->path);
    }
}

rnp_result_t
init_file_dest(pgp_dest_t *dst, const char *path)
{
    int                    fd;
    int                    flags;
    struct stat            st;
    pgp_dest_file_param_t *param;

    if (strlen(path) > sizeof(param->path)) {
        (void) fprintf(stderr, "init_file_dest: path too long\n");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if ((param = calloc(1, sizeof(*param))) == NULL) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (stat(path, &st) == 0) {
        (void) fprintf(stderr, "init_file_dest: file already exists: \"%s\"\n", path);
        return RNP_ERROR_WRITE;
    }

    flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_BINARY
    flags |= O_BINARY;
#endif
    fd = open(path, flags, 0600);
    if (fd < 0) {
        (void) fprintf(stderr, "init_file_dest: failed to create file '%s'\n", path);
        return false;
    }

    dst->param = param;
    param->fd = fd;
    strcpy(param->path, path);
    dst->write = file_dst_write;
    dst->close = file_dst_close;
    dst->type = PGP_STREAM_FILE;
    dst->writeb = 0;

    return RNP_SUCCESS;
}

rnp_result_t
init_stdout_dest(pgp_dest_t *dst)
{
    pgp_dest_file_param_t *param;

    if ((param = calloc(1, sizeof(*param))) == NULL) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    dst->param = param;
    param->fd = STDOUT_FILENO;
    dst->write = file_dst_write;
    dst->close = file_dst_close;
    dst->type = PGP_STREAM_STDOUT;
    dst->writeb = 0;

    return RNP_SUCCESS;
}

rnp_result_t
init_mem_dest(pgp_dest_t *dst)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}
