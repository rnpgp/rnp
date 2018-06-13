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
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: reader.c,v 1.49 2012/03/05 02:20:18 christos Exp $");
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <repgp/repgp.h>

#include <rnp/rnp_sdk.h>
#include "crypto.h"
#include "packet-print.h"
#include "packet-parse.h"
#include "utils.h"

/**
 * \ingroup Internal_Readers_Generic
 * \brief Starts reader stack
 * \param stream Parse settings
 * \param reader Reader to use
 * \param destroyer Destroyer to use
 * \param vp Reader-specific arg
 */
void
pgp_reader_set(pgp_stream_t *          stream,
               pgp_reader_func_t *     reader,
               pgp_reader_destroyer_t *destroyer,
               void *                  vp)
{
    stream->readinfo.reader = reader;
    stream->readinfo.destroyer = destroyer;
    stream->readinfo.arg = vp;
}

/**
 * \ingroup Internal_Readers_Generic
 * \brief Gets arg from reader
 * \param readinfo Reader info
 * \return Pointer to reader info's arg
 */
void *
pgp_reader_get_arg(pgp_reader_t *readinfo)
{
    return readinfo->arg;
}

/** Arguments for reader_fd
 */
typedef struct mmap_reader_t {
    void *   mem;    /* memory mapped file */
    uint64_t size;   /* size of file */
    uint64_t offset; /* current offset in file */
    int      fd;     /* file descriptor */
} mmap_reader_t;

typedef struct {
    const uint8_t *buffer;
    size_t         length;
    size_t         offset;
} reader_mem_t;

static int
mem_reader(pgp_stream_t *stream,
           void *        dest,
           size_t        length,
           pgp_error_t **errors,
           pgp_reader_t *readinfo,
           pgp_cbdata_t *cbinfo)
{
    reader_mem_t *reader = (reader_mem_t *) pgp_reader_get_arg(readinfo);
    unsigned      n;

    RNP_USED(cbinfo);
    RNP_USED(errors);
    if (reader->offset + length > reader->length) {
        n = (unsigned) (reader->length - reader->offset);
    } else {
        n = (unsigned) length;
    }
    if (n == (unsigned) 0) {
        return 0;
    }
    memcpy(dest, reader->buffer + reader->offset, n);
    reader->offset += n;
    return n;
}

static void
mem_destroyer(pgp_reader_t *readinfo)
{
    free(pgp_reader_get_arg(readinfo));
}

/**
   \ingroup Core_Readers_First
   \brief Starts stack with memory reader
*/

bool
pgp_reader_set_memory(pgp_stream_t *stream, const void *buffer, size_t length)
{
    reader_mem_t *mem;

    if ((mem = (reader_mem_t *) calloc(1, sizeof(*mem))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_set_memory: bad alloc\n");
        return false;
    } else {
        mem->buffer = (uint8_t *) buffer;
        mem->length = length;
        mem->offset = 0;
        pgp_reader_set(stream, mem_reader, mem_destroyer, mem);
        return true;
    }
}

/**************************************************************************/

int
pgp_setup_memory_read(pgp_io_t *     io,
                      pgp_stream_t **stream,
                      pgp_memory_t * mem,
                      void *         vp,
                      pgp_cb_ret_t   callback(const pgp_packet_t *, pgp_cbdata_t *),
                      unsigned       accumulate)
{
    *stream = (pgp_stream_t *) pgp_new(sizeof(**stream));
    if (*stream == NULL) {
        return false;
    }
    (*stream)->io = (*stream)->cbinfo.io = io;
    pgp_set_callback(*stream, callback, vp);
    pgp_reader_set_memory(*stream, pgp_mem_data(mem), pgp_mem_len(mem));
    if (accumulate) {
        (*stream)->readinfo.accumulate = 1;
    }

    return true;
}

/**
   \ingroup Core_Readers
   \brief Frees stream and mem
   \param stream
   \param mem
   \sa pgp_setup_memory_read()
*/
void
pgp_teardown_memory_read(pgp_stream_t *stream, pgp_memory_t *mem)
{
    pgp_stream_delete(stream);
    pgp_memory_free(mem);
}

unsigned
pgp_reader_set_accumulate(pgp_stream_t *stream, unsigned state)
{
    return stream->readinfo.accumulate = state;
}
