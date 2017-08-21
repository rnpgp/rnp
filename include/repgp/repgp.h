#ifndef REPGP_H_
#define REPGP_H_

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
 * Parser for OpenPGP packets - headers.
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <rekey/rnp_key_store.h>

#include "repgp_def.h"
#include "packet.h"

/** pgp_region_t */
typedef struct pgp_region_t {
    struct pgp_region_t *parent;
    unsigned             length;
    unsigned             readc; /* length read */
    unsigned             last_read;
    /* length of last read, only valid in deepest child */
    unsigned indeterminate : 1;
} pgp_region_t;

void pgp_init_subregion(pgp_region_t *, pgp_region_t *);

/** pgp_cb_ret_t */
typedef enum { PGP_RELEASE_MEMORY, PGP_KEEP_MEMORY, PGP_FINISHED } pgp_cb_ret_t;

typedef struct pgp_cbdata_t pgp_cbdata_t;
typedef pgp_cb_ret_t        pgp_cbfunc_t(const pgp_packet_t *, pgp_cbdata_t *);

typedef struct pgp_stream_t    pgp_stream_t;
typedef struct pgp_reader_t    pgp_reader_t;
typedef struct pgp_cryptinfo_t pgp_cryptinfo_t;

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

void         pgp_stream_delete(pgp_stream_t *);
pgp_error_t *pgp_stream_get_errors(pgp_stream_t *);

void  pgp_set_callback(pgp_stream_t *, pgp_cbfunc_t *, void *);
void  pgp_callback_push(pgp_stream_t *, pgp_cbfunc_t *, void *);
void *pgp_callback_arg(pgp_cbdata_t *);
void *pgp_callback_errors(pgp_cbdata_t *);
void  pgp_reader_set(pgp_stream_t *, pgp_reader_func_t *, pgp_reader_destroyer_t *, void *);
bool  pgp_reader_push(pgp_stream_t *, pgp_reader_func_t *, pgp_reader_destroyer_t *, void *);
void  pgp_reader_pop(pgp_stream_t *);

void *pgp_reader_get_arg(pgp_reader_t *);

pgp_cb_ret_t  pgp_callback(const pgp_packet_t *, pgp_cbdata_t *);
pgp_cb_ret_t  pgp_stacked_callback(const pgp_packet_t *, pgp_cbdata_t *);
pgp_reader_t *pgp_readinfo(pgp_stream_t *);

bool pgp_parse(pgp_stream_t *, const bool show_erros);

/** Used to specify whether subpackets should be returned raw, parsed
 * or ignored.  */
typedef enum {
    PGP_PARSE_RAW,    /* Callback Raw */
    PGP_PARSE_PARSED, /* Callback Parsed */
    PGP_PARSE_IGNORE  /* Don't callback */
} pgp_parse_type_t;

/**
 * @brief Specifies whether one or more signature subpacket types
 *        should be returned parsed; or raw; or ignored.
 *
 * @param    stream   Pointer to previously allocated structure
 * @param    tag      Packet tag. PGP_PTAG_SS_ALL for all SS tags; or one individual
 *                    signature subpacket tag
 * @param    type     Parse type
 *
 * @todo Make all packet types optional, not just subpackets
 */
void pgp_parse_options(pgp_stream_t *stream, pgp_content_enum tag, pgp_parse_type_t type);

bool pgp_limited_read(pgp_stream_t *,
                      uint8_t *,
                      size_t,
                      pgp_region_t *,
                      pgp_error_t **,
                      pgp_reader_t *,
                      pgp_cbdata_t *);
bool pgp_stacked_limited_read(pgp_stream_t *,
                              uint8_t *,
                              unsigned,
                              pgp_region_t *,
                              pgp_error_t **,
                              pgp_reader_t *,
                              pgp_cbdata_t *);

void pgp_parser_content_free(pgp_packet_t *);

pgp_reader_func_t pgp_stacked_read;

/* ----------------------------- printing -----------------------------*/
void repgp_print_key(pgp_io_t *,
                     const rnp_key_store_t *,
                     const pgp_key_t *,
                     const char *,
                     const pgp_pubkey_t *,
                     const int);

int repgp_sprint_json(pgp_io_t *,
                      const rnp_key_store_t *,
                      const pgp_key_t *,
                      json_object *,
                      const char *,
                      const pgp_pubkey_t *,
                      const int);

#endif /* REPGP_H_ */
