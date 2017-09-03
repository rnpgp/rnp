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

/** \file
 * Parser for OpenPGP packets - headers.
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <json.h>

#include "repgp_def.h"

typedef struct pgp_packet_t pgp_packet_t;
typedef struct pgp_stream_t pgp_stream_t;
typedef void *              repgp_stream_t;
typedef void *              repgp_io_t;

/* New interfaces */

#define REPGP_HANDLE_NULL ((void *) 0)

// OZAPTF
typedef uint32_t rnp_result;

/** Used to specify whether subpackets should be returned raw, parsed
 * or ignored.  */
typedef enum {
    REPGP_PARSE_RAW,    /* Callback Raw */
    REPGP_PARSE_PARSED, /* Callback Parsed */
    REPGP_PARSE_IGNORE  /* Don't callback */
} repgp_parse_type_t;

repgp_stream_t create_filepath_stream(const char *filename, size_t filename_len);

// it will do realloc
repgp_stream_t create_stdin_stream(void);

repgp_stream_t create_buffer_stream(const size_t buffer_size);

void repgp_destroy_stream(repgp_stream_t stream);

repgp_io_t repgp_create_io(void);
void repgp_destroy_io(repgp_io_t io);

void repgp_set_input(repgp_io_t io, /*const?*/ repgp_stream_t stream);
void repgp_set_output(repgp_io_t io, /*const?*/ repgp_stream_t stream);

rnp_result repgp_verify(const void *ctx, repgp_io_t io);
rnp_result repgp_decrypt(const void *ctx, repgp_io_t io);
rnp_result repgp_list_packets(const void *ctx, repgp_stream_t input);
rnp_result repgp_validate_pubkeys_signatures(const void *ctx);
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

/* Old interfaces */

void repgp_parser_content_free(pgp_packet_t *);

bool repgp_parse(pgp_stream_t *, const bool show_erros);

#endif /* REPGP_H_ */
