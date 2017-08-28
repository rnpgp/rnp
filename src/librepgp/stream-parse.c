/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#include "stream-parse.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

ssize_t src_read(pgp_source_t *src, void *buf, size_t len)
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
            read += len;
            return len;
        } else {
            memcpy(buf, &cache->buf[cache->pos], read);
            cache->pos += read;
            buf = (uint8_t*)buf + read;
            left = len - read;
        }
    }

    // If we got here then we have empty cache or no cache at all
    while (left > 0) {
        if (!cache || (left > sizeof(cache->buf))) {
            // If there is no cache or chunk large then read directly
            read = src->readfunc(src, buf, left);
            if (read > 0) {
                left -= read;
                buf = (uint8_t*)buf + read;
            } else if (read == 0) {
                src->eof = 1;
                src->read += len - left;
                return len - left;
            } else {
                return -1;
            }
        } else {
            // Try to fill the cache to avoid small reads
            read = src->readfunc(src, &cache->buf[0], sizeof(cache->buf));
            if (read == 0) {
                src->eof = 1;
                src->read += len - left;
                return len - left;
            } else if (read < 0) {
                return -1;
            } else if (read < left) {
                memcpy(buf, &cache->buf[0], read);
                left -= read;
                buf = (uint8_t*)buf + read;
            } else {
                memcpy(buf, &cache->buf[0], left);
                cache->pos = left;
                cache->len = read;
                src->read += len;
                return len;
            }
        }
    }
    
    src->read += len;
    return len;
}

ssize_t src_peek(pgp_source_t *src, void *buf, size_t len)
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
        read = src->readfunc(src, &cache->buf[0], sizeof(cache->buf) - cache->len);
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

ssize_t src_skip(pgp_source_t *src, size_t len)
{
    ssize_t res;
    void *  buf;
     
    buf = calloc(1, len);

    if (buf == NULL) {
        return -1;
    } else {
        res = src_read(src, buf, len);
        free(buf);
        return res;
    }
}

typedef struct pgp_source_file_param_t {
    int fd;
} pgp_source_file_param_t;

ssize_t file_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_file_param_t *param = src->param;

    if (param == NULL) {
        return -1;
    } else {
        return read(param->fd, buf, len);
    }
}

void file_src_close(pgp_source_t *src)
{
    pgp_source_file_param_t *param = src->param;
    if (param) {
        if (src->type == PGP_SOURCE_FILE) {
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

pgp_errcode_t init_file_src(pgp_source_t *src, char *path)
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
        return PGP_E_R_READ_FAILED;
    }

    if ((src->cache = calloc(1, sizeof(pgp_source_cache_t))) == NULL) {
        close(fd);
        return PGP_E_OUT_OF_MEMORY;
    }

    if ((param = calloc(1, sizeof(pgp_source_file_param_t))) == NULL) {
        close(fd);
        free(src->cache);
        src->cache = NULL;
        return PGP_E_OUT_OF_MEMORY;
    }

    src->readfunc = file_src_read;
    src->closefunc = file_src_close;
    param->fd = fd;
    src->param = param;
    src->type = PGP_SOURCE_FILE;
    src->size = st.st_size;
    src->read = 0;
    src->knownsize = 1;
    src->eof = 0;

    return PGP_E_OK;
}

pgp_errcode_t init_stdin_src(pgp_source_t *src)
{
    pgp_source_file_param_t *param;

    if ((src->cache = calloc(1, sizeof(pgp_source_cache_t))) == NULL) {
        return PGP_E_OUT_OF_MEMORY;
    }

    if ((param = calloc(1, sizeof(pgp_source_file_param_t))) == NULL) {
        free(src->cache);
        src->cache = NULL;
        return PGP_E_OUT_OF_MEMORY;
    }

    src->readfunc = file_src_read;
    src->closefunc = file_src_close;
    param->fd = 0;
    src->param = param;
    src->type = PGP_SOURCE_STDIN;
    src->size = 0;
    src->read = 0;
    src->knownsize = 0;
    src->eof = 0;

    return PGP_E_OK;
}

pgp_errcode_t init_mem_src(pgp_source_t *src, void *mem, size_t len)
{
    return PGP_E_FAIL;
}

pgp_errcode_t process_pgp_source(pgp_source_t *src)
{
    return PGP_E_FAIL;
}
