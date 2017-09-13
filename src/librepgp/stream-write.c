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

#include "config.h"
#include "stream-parse.h"
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

bool dst_write(pgp_dest_t *dst, void *buf, size_t len)
{
    return dst->writefunc(dst, buf, len);
}

void dst_close(pgp_dest_t *dst, bool discard)
{
    if (dst->closefunc) {
        dst->closefunc(dst, discard);
    }
}

typedef struct pgp_dest_file_param_t {
    int  fd;
    char path[PATH_MAX];
} pgp_dest_file_param_t;

bool file_dst_write(pgp_dest_t *dst, void *buf, size_t len)
{
    ssize_t                ret;
    pgp_dest_file_param_t *param = dst->param;

    if (!param) {
        return false;
    }

    ret = write(param->fd, buf, len);
    if (ret != len) {
        (void) fprintf(stderr, "file_dst_write: write failed\n");
        return false;
    }

    return true;
}

void file_dst_close(pgp_dest_t *dst, bool discard)
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

pgp_errcode_t init_file_dest(pgp_dest_t *dst, const char *path)
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
    dst->writefunc = file_dst_write;
    dst->closefunc = file_dst_close;
    dst->type = PGP_STREAM_FILE;
    dst->write = 0;

    return RNP_SUCCESS;
}

pgp_errcode_t init_stdout_dest(pgp_dest_t *dst)
{
    pgp_dest_file_param_t *param;

    if ((param = calloc(1, sizeof(*param))) == NULL) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    dst->param = param;
    param->fd = STDOUT_FILENO;
    dst->writefunc = file_dst_write;
    dst->closefunc = file_dst_close;
    dst->type = PGP_STREAM_STDOUT;
    dst->write = 0;

    return RNP_SUCCESS;
}

pgp_errcode_t init_mem_dest(pgp_dest_t *dst)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}
