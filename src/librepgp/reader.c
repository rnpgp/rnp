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

/* data from partial blocks is queued up in virtual block in stream */
static int
read_partial_data(pgp_stream_t *stream, void *dest, size_t length)
{
    unsigned n;

    if (rnp_get_debug(__FILE__)) {
        (void) fprintf(stderr, "fd_reader: coalesced data, off %d\n", stream->virtualoff);
    }
    n = MIN(stream->virtualc - stream->virtualoff, (unsigned) length);
    (void) memcpy(dest, &stream->virtualpkt[stream->virtualoff], n);
    stream->virtualoff += n;
    if (stream->virtualoff == stream->virtualc) {
        free(stream->virtualpkt);
        stream->virtualpkt = NULL;
        stream->virtualc = stream->virtualoff = 0;
    }
    return (int) n;
}

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
 * \brief Adds to reader stack
 * \param stream Parse settings
 * \param reader Reader to use
 * \param destroyer Reader's destroyer
 * \param vp Reader-specific arg
 */
bool
pgp_reader_push(pgp_stream_t *          stream,
                pgp_reader_func_t *     reader,
                pgp_reader_destroyer_t *destroyer,
                void *                  vp)
{
    pgp_reader_t *readinfo;

    if ((readinfo = calloc(1, sizeof(*readinfo))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_push: bad alloc\n");
        return false;
    }

    *readinfo = stream->readinfo;
    (void) memset(&stream->readinfo, 0x0, sizeof(stream->readinfo));
    stream->readinfo.next = readinfo;
    stream->readinfo.parent = stream;

    /* should copy accumulate flags from other reader? RW */
    stream->readinfo.accumulate = readinfo->accumulate;

    pgp_reader_set(stream, reader, destroyer, vp);
    return true;
}

/**
 * \ingroup Internal_Readers_Generic
 * \brief Removes from reader stack
 * \param stream Parse settings
 */
void
pgp_reader_pop(pgp_stream_t *stream)
{
    pgp_reader_t *next = stream->readinfo.next;

    free(stream->readinfo.accumulated);
    stream->readinfo = *next;
    free(next);
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

#define CRC24_POLY 0x1864cfbL

/** Arguments for reader_fd
 */
typedef struct mmap_reader_t {
    void *   mem;    /* memory mapped file */
    uint64_t size;   /* size of file */
    uint64_t offset; /* current offset in file */
    int      fd;     /* file descriptor */
} mmap_reader_t;

/**
 * \ingroup Core_Readers
 *
 * pgp_reader_fd() attempts to read up to "plength" bytes from the file
 * descriptor in "parse_info" into the buffer starting at "dest" using the
 * rules contained in "flags"
 *
 * \param    dest    Pointer to previously allocated buffer
 * \param    plength Number of bytes to try to read
 * \param    flags    Rules about reading to use
 * \param    readinfo    Reader info
 * \param    cbinfo    Callback info
 *
 * \return    n    Number of bytes read
 *
 * PGP_R_EARLY_EOF and PGP_R_ERROR push errors on the stack
 */
static int
fd_reader(pgp_stream_t *stream,
          void *        dest,
          size_t        length,
          pgp_error_t **errors,
          pgp_reader_t *readinfo,
          pgp_cbdata_t *cbinfo)
{
    mmap_reader_t *reader;
    int            n;

    RNP_USED(cbinfo);
    reader = pgp_reader_get_arg(readinfo);
    if (!stream->coalescing && stream->virtualc && stream->virtualoff < stream->virtualc) {
        n = read_partial_data(stream, dest, length);
    } else {
        n = (int) read(reader->fd, dest, length);
    }
    if (n == 0) {
        return 0;
    }
    if (n < 0) {
        PGP_SYSTEM_ERROR_1(
          errors, PGP_E_R_READ_FAILED, "read", "file descriptor %d", reader->fd);
        return -1;
    }
    return n;
}

static void
reader_fd_destroyer(pgp_reader_t *readinfo)
{
    free(pgp_reader_get_arg(readinfo));
}

/**
   \ingroup Core_Readers_First
   \brief Starts stack with file reader
*/

void
pgp_reader_set_fd(pgp_stream_t *stream, int fd)
{
    mmap_reader_t *reader;

    if ((reader = calloc(1, sizeof(*reader))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_set_fd: bad alloc\n");
    } else {
        reader->fd = fd;
        pgp_reader_set(stream, fd_reader, reader_fd_destroyer, reader);
    }
}

unsigned
pgp_crc24(unsigned checksum, uint8_t c)
{
    unsigned i;

    checksum ^= c << 16;
    for (i = 0; i < 8; i++) {
        checksum <<= 1;
        if (checksum & 0x1000000)
            checksum ^= CRC24_POLY;
    }
    return (unsigned) (checksum & 0xffffffL);
}

/**************************************************************************/

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
    reader_mem_t *reader = pgp_reader_get_arg(readinfo);
    unsigned      n;

    RNP_USED(cbinfo);
    RNP_USED(errors);
    if (!stream->coalescing && stream->virtualc && stream->virtualoff < stream->virtualc) {
        n = read_partial_data(stream, dest, length);
    } else {
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
    }
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

    if ((mem = calloc(1, sizeof(*mem))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_set_memory: bad alloc\n");
        return false;
    } else {
        mem->buffer = buffer;
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
    *stream = pgp_new(sizeof(**stream));
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

/**
   \ingroup Core_Readers
   \brief Creates parse_info, opens file, and sets to read from file
   \param stream Address where new parse_info will be set
   \param filename Name of file to read
   \param vp Reader-specific arg
   \param callback Callback to use when reading
   \param accumulate Set if we need to accumulate as we read. (Usually 0 unless doing signature
   verification)
   \note It is the caller's responsiblity to free parse_info and to close fd
   \sa pgp_teardown_file_read()
*/
int
pgp_setup_file_read(pgp_io_t *     io,
                    pgp_stream_t **stream,
                    const char *   filename,
                    void *         vp,
                    pgp_cb_ret_t   callback(const pgp_packet_t *, pgp_cbdata_t *),
                    unsigned       accumulate)
{
    int fd;

#ifdef O_BINARY
    fd = open(filename, O_RDONLY | O_BINARY);
#else
    fd = open(filename, O_RDONLY);
#endif
    if (fd < 0) {
        (void) fprintf(io->errs, "can't open \"%s\"\n", filename);
        return fd;
    }
    *stream = pgp_new(sizeof(**stream));
    (*stream)->io = (*stream)->cbinfo.io = io;
    pgp_set_callback(*stream, callback, vp);
#ifdef USE_MMAP_FOR_FILES
    pgp_reader_set_mmap(*stream, fd);
#else
    pgp_reader_set_fd(*stream, fd);
#endif
    if (accumulate) {
        (*stream)->readinfo.accumulate = 1;
    }
    return fd;
}

/**
   \ingroup Core_Readers
   \brief Frees stream and closes fd
   \param stream
   \param fd
   \sa pgp_setup_file_read()
*/
void
pgp_teardown_file_read(pgp_stream_t *stream, int fd)
{
    close(fd);
    pgp_stream_delete(stream);
}

unsigned
pgp_reader_set_accumulate(pgp_stream_t *stream, unsigned state)
{
    return stream->readinfo.accumulate = state;
}

/**************************************************************************/

/* read memory from the previously mmap-ed file */
static int
mmap_reader(pgp_stream_t *stream,
            void *        dest,
            size_t        length,
            pgp_error_t **errors,
            pgp_reader_t *readinfo,
            pgp_cbdata_t *cbinfo)
{
    mmap_reader_t *mem = pgp_reader_get_arg(readinfo);
    unsigned       n;
    char *         cmem = mem->mem;

    RNP_USED(errors);
    RNP_USED(cbinfo);
    if (!stream->coalescing && stream->virtualc && stream->virtualoff < stream->virtualc) {
        n = read_partial_data(stream, dest, length);
    } else {
        n = (unsigned) MIN(length, (unsigned) (mem->size - mem->offset));
        if (n > 0) {
            (void) memcpy(dest, &cmem[(int) mem->offset], (unsigned) n);
            mem->offset += n;
        }
    }
    return (int) n;
}

/* tear down the mmap, close the fd */
static void
mmap_destroyer(pgp_reader_t *readinfo)
{
    mmap_reader_t *mem = pgp_reader_get_arg(readinfo);

    (void) munmap(mem->mem, (unsigned) mem->size);
    (void) close(mem->fd);
    free(pgp_reader_get_arg(readinfo));
}

/* set up the file to use mmap-ed memory if available, file IO otherwise */
void
pgp_reader_set_mmap(pgp_stream_t *stream, int fd)
{
    mmap_reader_t *mem;
    struct stat    st;

    if (fstat(fd, &st) != 0) {
        (void) fprintf(stderr, "pgp_reader_set_mmap: can't fstat\n");
    } else if ((mem = calloc(1, sizeof(*mem))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_set_mmap: bad alloc\n");
    } else {
        mem->size = (uint64_t) st.st_size;
        mem->offset = 0;
        mem->fd = fd;
        mem->mem = mmap(NULL, (size_t) st.st_size, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
        if (mem->mem == MAP_FAILED) {
            pgp_reader_set(stream, fd_reader, reader_fd_destroyer, mem);
        } else {
            pgp_reader_set(stream, mmap_reader, mmap_destroyer, mem);
        }
    }
}
