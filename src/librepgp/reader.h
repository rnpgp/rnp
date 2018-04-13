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

#ifndef READER_H_
#define READER_H_

#include "packet-create.h"

/* if this is defined, we'll use mmap in preference to file ops */
#define USE_MMAP_FOR_FILES 1

/*
   A reader MUST read at least one byte if it can, and should read up
   to the number asked for. Whether it reads more for efficiency is
   its own decision, but if it is a stacked reader it should never
   read more than the length of the region it operates in (which it
   would have to be given when it is stacked).

   If a read is short because of EOF, then it should return the short
   read (obviously this will be zero on the second attempt, if not the
   first). Because a reader is not obliged to do a full read, only a
   zero return can be taken as an indication of EOF.

   If there is an error, then the callback should be notified, the
   error stacked, and -1 should be returned.

   Note that although length is a size_t, a reader will never be asked
   to read more than INT_MAX in one go.

 */
typedef int pgp_reader_func_t(
  pgp_stream_t *, void *, size_t, pgp_error_t **, pgp_reader_t *, pgp_cbdata_t *);

typedef void pgp_reader_destroyer_t(pgp_reader_t *);

pgp_reader_func_t pgp_stacked_read;

#define CRC24_INIT 0xb704ceL
unsigned pgp_crc24(unsigned, uint8_t);

void  pgp_reader_set(pgp_stream_t *, pgp_reader_func_t *, pgp_reader_destroyer_t *, void *);
bool  pgp_reader_push(pgp_stream_t *, pgp_reader_func_t *, pgp_reader_destroyer_t *, void *);
void  pgp_reader_pop(pgp_stream_t *);
void *pgp_reader_get_arg(pgp_reader_t *);

void pgp_reader_set_fd(pgp_stream_t *, int);
void pgp_reader_set_mmap(pgp_stream_t *, int);
bool pgp_reader_set_memory(pgp_stream_t *, const void *, size_t);

/* Do a sum mod 65536 of all bytes read (as needed for secret keys) */
void     pgp_reader_push_sum16(pgp_stream_t *);
uint16_t pgp_reader_pop_sum16(pgp_stream_t *);

unsigned pgp_reader_set_accumulate(pgp_stream_t *, unsigned);

/* file reading */
int pgp_setup_file_read(pgp_io_t *,
                        pgp_stream_t **,
                        const char *,
                        void *,
                        pgp_cb_ret_t callback(const pgp_packet_t *, pgp_cbdata_t *),
                        unsigned);
void pgp_teardown_file_read(pgp_stream_t *, int);

/* memory reading */
int pgp_setup_memory_read(pgp_io_t *,
                          pgp_stream_t **,
                          pgp_memory_t *,
                          void *,
                          pgp_cb_ret_t callback(const pgp_packet_t *, pgp_cbdata_t *),
                          unsigned);
void pgp_teardown_memory_read(pgp_stream_t *, pgp_memory_t *);

void pgp_reader_push_dearmor(pgp_stream_t *);
void pgp_reader_pop_dearmor(pgp_stream_t *);

#endif /* READER_H_ */
