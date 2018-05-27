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

#ifndef PACKET_PARSE_H_
#define PACKET_PARSE_H_

#include <repgp/repgp.h>
#include "types.h"

typedef struct pgp_cbdata_t pgp_cbdata_t;
typedef struct pgp_reader_t pgp_reader_t;

/** pgp_region_t */
typedef struct pgp_region_t {
    struct pgp_region_t *parent;
    unsigned             length;
    unsigned             readc; /* length read */
    unsigned             last_read;
    /* length of last read, only valid in deepest child */
    unsigned indeterminate : 1;
} pgp_region_t;

/** pgp_cb_ret_t */
typedef enum { PGP_RELEASE_MEMORY, PGP_KEEP_MEMORY, PGP_FINISHED } pgp_cb_ret_t;

typedef pgp_cb_ret_t pgp_cbfunc_t(const pgp_packet_t *, pgp_cbdata_t *);

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
void repgp_parse_options(pgp_stream_t *stream, pgp_content_enum tag, repgp_parse_type_t type);

bool repgp_parse(pgp_stream_t *, const bool show_erros);

void repgp_parser_content_free(pgp_packet_t *);

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

void pgp_init_subregion(pgp_region_t *, pgp_region_t *);

void pgp_userid_free(uint8_t **);

void pgp_data_free(pgp_data_t *);

void pgp_sig_free(pgp_sig_info_t *);

void pgp_rawpacket_free(pgp_rawpacket_t *);

void  pgp_set_callback(pgp_stream_t *, pgp_cbfunc_t *, void *);
void  pgp_callback_push(pgp_stream_t *, pgp_cbfunc_t *, void *);
void *pgp_callback_arg(pgp_cbdata_t *);
void *pgp_callback_errors(pgp_cbdata_t *);

void         pgp_stream_delete(pgp_stream_t *);
pgp_error_t *pgp_stream_get_errors(pgp_stream_t *);

pgp_cb_ret_t  pgp_callback(const pgp_packet_t *, pgp_cbdata_t *);
pgp_cb_ret_t  pgp_stacked_callback(const pgp_packet_t *, pgp_cbdata_t *);
pgp_reader_t *pgp_readinfo(pgp_stream_t *);

#endif
