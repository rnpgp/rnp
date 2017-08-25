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
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** \file
 */
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#include <stdlib.h>

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: compress.c,v 1.23 2012/03/05 02:20:18 christos Exp $");
#endif

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

#include <string.h>
#include <stdlib.h>

#include <rnp/rnp_def.h>
#include <repgp/repgp.h>
#include "errors.h"
#include "utils.h"
#include "crypto.h"
#include "memory.h"
#include "writer.h"

#define DECOMPRESS_BUFFER (1024)

typedef struct {
    pgp_compression_type_t type;
    pgp_region_t *         region;
    uint8_t                in[DECOMPRESS_BUFFER];
    uint8_t                out[DECOMPRESS_BUFFER];
    z_stream               zstream; /* ZIP and ZLIB */
    size_t                 offset;
    int                    inflate_ret;
} z_decompress_t;

#ifdef HAVE_BZLIB_H
typedef struct {
    pgp_compression_type_t type;
    pgp_region_t *         region;
    char                   in[DECOMPRESS_BUFFER];
    char                   out[DECOMPRESS_BUFFER];
    bz_stream              bzstream; /* BZIP2 */
    size_t                 offset;
    int                    inflate_ret;
} bz_decompress_t;
#endif

/*
 * \todo remove code duplication between this and
 * bzip2_compressed_data_reader
 */
static int
zlib_compressed_data_reader(pgp_stream_t *stream,
                            void *        dest,
                            size_t        length,
                            pgp_error_t **errors,
                            pgp_reader_t *readinfo,
                            pgp_cbdata_t *cbinfo)
{
    z_decompress_t *z = pgp_reader_get_arg(readinfo);
    size_t          len;
    size_t          cc;
    char *          cdest = dest;

    if (z->type != PGP_C_ZIP && z->type != PGP_C_ZLIB) {
        RNP_LOG("weird type %d\n", z->type);
        return 0;
    }

    if (z->inflate_ret == Z_STREAM_END && z->zstream.next_out == &z->out[z->offset]) {
        return 0;
    }
    if (rnp_get_debug(__FILE__)) {
        RNP_LOG("length %" PRIsize "d", length);
    }
    for (cc = 0; cc < length; cc += len) {
        if (&z->out[z->offset] == z->zstream.next_out) {
            int ret;

            z->zstream.next_out = z->out;
            z->zstream.avail_out = sizeof(z->out);
            z->offset = 0;
            if (z->zstream.avail_in == 0) {
                unsigned n = z->region->length;

                if (!z->region->indeterminate) {
                    n -= z->region->readc;
                    if (n > sizeof(z->in)) {
                        n = sizeof(z->in);
                    }
                } else {
                    n = sizeof(z->in);
                }
                if (!pgp_stacked_limited_read(
                      stream, z->in, n, z->region, errors, readinfo, cbinfo)) {
                    return -1;
                }

                z->zstream.next_in = z->in;
                z->zstream.avail_in = (z->region->indeterminate) ? z->region->last_read : n;
            }
            ret = inflate(&z->zstream, Z_SYNC_FLUSH);
            if (ret == Z_STREAM_END) {
                if (!z->region->indeterminate && z->region->readc != z->region->length) {
                    PGP_ERROR_1(cbinfo->errors,
                                PGP_E_P_DECOMPRESSION_ERROR,
                                "%s",
                                "Compressed stream ended before packet end.");
                }
            } else if (ret != Z_OK) {
                (void) fprintf(stderr, "zlib error %d\n", ret);
                PGP_ERROR_1(cbinfo->errors, PGP_E_P_DECOMPRESSION_ERROR, "%s", z->zstream.msg);
                return 0;
            }
            z->inflate_ret = ret;
        }
        if (z->zstream.next_out < &z->out[z->offset]) {
            RNP_LOG("Out of memory in buffer");
            return 0;
        }
        len = (size_t)(z->zstream.next_out - &z->out[z->offset]);
        if (len + cc > length) {
            len = length - cc;
        }
        (void) memcpy(&cdest[cc], &z->out[z->offset], len);
        z->offset += len;
    }

    return (int) length;
}

#ifdef HAVE_BZLIB_H
/* \todo remove code duplication between this and zlib_compressed_data_reader */
static int
bzip2_compressed_data_reader(pgp_stream_t *stream,
                             void *        dest,
                             size_t        length,
                             pgp_error_t **errors,
                             pgp_reader_t *readinfo,
                             pgp_cbdata_t *cbinfo)
{
    bz_decompress_t *bz = pgp_reader_get_arg(readinfo);
    size_t           len;
    size_t           cc;
    char *           cdest = dest;

    if (bz->type != PGP_C_BZIP2) {
        (void) fprintf(stderr, "Weird type %d\n", bz->type);
        return 0;
    }
    if (bz->inflate_ret == BZ_STREAM_END && bz->bzstream.next_out == &bz->out[bz->offset]) {
        return 0;
    }
    for (cc = 0; cc < length; cc += len) {
        if (&bz->out[bz->offset] == bz->bzstream.next_out) {
            int ret;
            bz->bzstream.next_out = (char *) bz->out;
            bz->bzstream.avail_out = sizeof(bz->out);
            bz->offset = 0;
            if (bz->bzstream.avail_in == 0) {
                unsigned n = bz->region->length;

                if (!bz->region->indeterminate) {
                    n -= bz->region->readc;
                    if (n > sizeof(bz->in))
                        n = sizeof(bz->in);
                } else
                    n = sizeof(bz->in);

                if (!pgp_stacked_limited_read(
                      stream, (uint8_t *) bz->in, n, bz->region, errors, readinfo, cbinfo))
                    return -1;

                bz->bzstream.next_in = bz->in;
                bz->bzstream.avail_in =
                  (bz->region->indeterminate) ? bz->region->last_read : n;
            }
            ret = BZ2_bzDecompress(&bz->bzstream);
            if (ret == BZ_STREAM_END) {
                if (!bz->region->indeterminate && bz->region->readc != bz->region->length)
                    PGP_ERROR_1(cbinfo->errors,
                                PGP_E_P_DECOMPRESSION_ERROR,
                                "%s",
                                "Compressed stream ended before packet end.");
            } else if (ret != BZ_OK) {
                PGP_ERROR_1(cbinfo->errors,
                            PGP_E_P_DECOMPRESSION_ERROR,
                            "Invalid return %d from BZ2_bzDecompress",
                            ret);
            }
            bz->inflate_ret = ret;
        }

        if (bz->bzstream.next_out < &bz->out[bz->offset]) {
            (void) fprintf(stderr, "Out of bz memory\n");
            return 0;
        }
        len = (size_t)(bz->bzstream.next_out - &bz->out[bz->offset]);

        if ((len == 0) && (bz->inflate_ret == BZ_STREAM_END)) {
            return cc;
        }

        if (len + cc > length) {
            len = length - cc;
        }
        (void) memcpy(&cdest[cc], &bz->out[bz->offset], len);
        bz->offset += len;
    }
    return (int) length;
}
#endif

bool
pgp_decompress(pgp_region_t *region, pgp_stream_t *stream, pgp_compression_type_t type)
{
    z_decompress_t z;
#ifdef HAVE_BZLIB_H
    bz_decompress_t bz;
#endif
    const int printerrors = 1;
    bool      res = false;

    if (!region || !stream) {
        return false;
    }

    switch (type) {
    case PGP_C_ZIP:
    case PGP_C_ZLIB:
        (void) memset(&z, 0x0, sizeof(z));

        z.region = region;
        z.offset = 0;
        z.type = type;

        z.zstream.next_in = Z_NULL;
        z.zstream.avail_in = 0;
        z.zstream.next_out = z.out;
        z.zstream.zalloc = Z_NULL;
        z.zstream.zfree = Z_NULL;
        z.zstream.opaque = Z_NULL;

        break;

#ifdef HAVE_BZLIB_H
    case PGP_C_BZIP2:
        (void) memset(&bz, 0x0, sizeof(bz));

        bz.region = region;
        bz.offset = 0;
        bz.type = type;

        bz.bzstream.next_in = NULL;
        bz.bzstream.avail_in = 0;
        bz.bzstream.next_out = bz.out;
        bz.bzstream.bzalloc = NULL;
        bz.bzstream.bzfree = NULL;
        bz.bzstream.opaque = NULL;
#endif

        break;

    default:
        PGP_ERROR_1(&stream->errors,
                    PGP_E_ALG_UNSUPPORTED_COMPRESS_ALG,
                    "Compression algorithm %d is not yet supported",
                    type);
        goto end;
    }

    int ret;
    switch (type) {
    case PGP_C_ZIP:
        /* LINTED */ /* this is a lint problem in zlib.h header */
        ret = (int) inflateInit2(&z.zstream, -15);
        break;

    case PGP_C_ZLIB:
        /* LINTED */ /* this is a lint problem in zlib.h header */
        ret = (int) inflateInit(&z.zstream);
        break;

#ifdef HAVE_BZLIB_H
    case PGP_C_BZIP2:
        ret = BZ2_bzDecompressInit(&bz.bzstream, 0, 0);
        break;
#endif

    default:
        PGP_ERROR_1(&stream->errors,
                    PGP_E_ALG_UNSUPPORTED_COMPRESS_ALG,
                    "Compression algorithm %d is not yet supported",
                    type);
        goto end;
    }

    switch (type) {
    case PGP_C_ZIP:
    case PGP_C_ZLIB:
        if (ret != Z_OK) {
            PGP_ERROR_1(&stream->errors,
                        PGP_E_P_DECOMPRESSION_ERROR,
                        "Cannot initialise ZIP or ZLIB stream for decompression: error=%d",
                        ret);
            goto end;
        }
        pgp_reader_push(stream, zlib_compressed_data_reader, NULL, &z);
        break;

#ifdef HAVE_BZLIB_H
    case PGP_C_BZIP2:
        if (ret != BZ_OK) {
            PGP_ERROR_1(&stream->errors,
                        PGP_E_P_DECOMPRESSION_ERROR,
                        "Cannot initialise BZIP2 stream for decompression: error=%d",
                        ret);
            goto end;
        }
        pgp_reader_push(stream, bzip2_compressed_data_reader, NULL, &bz);
        break;
#endif

    default:
        PGP_ERROR_1(&stream->errors,
                    PGP_E_ALG_UNSUPPORTED_COMPRESS_ALG,
                    "Compression algorithm %d is not yet supported",
                    type);
        goto end;
    }

    res = pgp_parse(stream, !printerrors);
    pgp_reader_pop(stream);

end:
#ifdef HAVE_BZLIB_H
    if (type == PGP_C_BZIP2) {
        BZ2_bzDecompressEnd(&bz.bzstream);
    } else
#endif
    {
        inflateEnd(&z.zstream);
    }

    return res;
}

static size_t
estimate_output_sz(pgp_compression_type_t type, size_t input_len)
{
    if (type == PGP_C_BZIP2) {
        /*
        Despite claims on the bzip2 website, it has worst-case expansion
        much worse than .5% even after accounting for the ~50 byte constant
        overhead. Eg compressing 4096 random bytes results in a 4591 byte
        compression, hundreds of bytes more than the docs would imply.
        It is up to 3x higher for very small inputs.

        These estimates are still guesswork and might fail for certain inputs.
        */
        if (input_len <= 128)
            return (4 * input_len);
        else if (input_len <= 4096)
            return (3 * input_len);
        else if (input_len <= 8192)
            return (2 * input_len);
        else {
            // trust the docs...
            return (105 * input_len) / 100 + 64;
        }
    } else {
        return (105 * input_len) / 100 + 64;
    }
}

bool
pgp_writez(pgp_output_t *         out_stream,
           const uint8_t *        input,
           size_t                 input_len,
           pgp_compression_type_t type,
           int                    level)
{
    uint8_t *    output = NULL;
    bool         ret = false;
    const size_t output_len = estimate_output_sz(type, input_len);
    unsigned int output_produced = 0;

    if (!out_stream || !input) {
        return false;
    }

    output = calloc(1, output_len);
    if (!output) {
        goto end;
    }

    if (type == PGP_C_BZIP2) {
#if defined(HAVE_BZLIB_H)
        bz_stream stream;
        memset(&stream, 0, sizeof(stream));

        if (BZ2_bzCompressInit(&stream, level, 0, 0) != BZ_OK) {
            RNP_LOG("can't initialise bzlib");
            goto end;
        }

        stream.next_in = (char *) input;
        stream.avail_in = (unsigned) input_len;
        stream.next_out = (char *) output;
        stream.avail_out = (unsigned) output_len;

        int r;
        do {
            r = BZ2_bzCompress(&stream, BZ_FINISH);
        } while (r != BZ_STREAM_END);

        BZ2_bzCompressEnd(&stream);
        output_produced = stream.total_out_lo32;
#else
        RNP_LOG("bzip2 support missing");
        goto end;
#endif
    } else if (type == PGP_C_ZLIB || type == PGP_C_ZIP) {
#if defined(HAVE_ZLIB_H)
        z_stream stream;
        memset(&stream, 0, sizeof(stream));

        if (type == PGP_C_ZIP) {
            if (deflateInit2(&stream, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
                RNP_LOG("can't initialise zlib");
                goto end;
            }

        } else {
            if (deflateInit(&stream, level) != Z_OK) {
                RNP_LOG("can't initialise zlib");
                goto end;
            }
        }

        stream.next_in = (uint8_t *) input;
        stream.avail_in = (unsigned) input_len;
        stream.next_out = output;
        stream.avail_out = (unsigned) output_len;

        int r;
        do {
            r = deflate(&stream, Z_FINISH);
        } while (r != Z_STREAM_END);

        output_produced = stream.total_out;
        deflateEnd(&stream);
#else
        RNP_LOG("zlib support missing");
        goto end;
#endif
    }

    /* setup stream */

    /* write it out */
    ret = pgp_write_ptag(out_stream, PGP_PTAG_CT_COMPRESSED) &&
          pgp_write_length(out_stream, (unsigned) (output_produced + 1)) &&
          pgp_write_scalar(out_stream, type, 1) &&
          pgp_write(out_stream, output, output_produced);

end:
    free(output);
    return ret;
}
