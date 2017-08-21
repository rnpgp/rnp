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
#ifndef CREATE_H_
#define CREATE_H_

#include <stdbool.h>
#include "types.h"
#include "packet.h"
#include "crypto.h"
#include "errors.h"
#include <rekey/rnp_key_store.h>
#include "writer.h"
#include "memory.h"

/**
 * \ingroup Create
 * This struct contains the required information about how to write this stream
 */
struct pgp_output_t {
    pgp_writer_t writer;
    pgp_error_t *errors; /* error stack */
    rnp_ctx_t *  ctx;    /* current operation context */
};

pgp_output_t *pgp_output_new(void);
void          pgp_output_delete(pgp_output_t *);

int pgp_filewrite(const char *, const char *, const size_t, const unsigned);

void pgp_build_pubkey(pgp_memory_t *, const pgp_pubkey_t *, unsigned);

unsigned pgp_calc_sesskey_checksum(pgp_pk_sesskey_t *, uint8_t *);
unsigned pgp_write_struct_userid(pgp_output_t *, const uint8_t *);
unsigned pgp_write_ss_header(pgp_output_t *, unsigned, pgp_content_enum);

bool     pgp_write_struct_pubkey(pgp_output_t *, pgp_content_enum, const pgp_pubkey_t *);
unsigned pgp_write_struct_seckey(pgp_content_enum,
                                 const pgp_seckey_t *,
                                 const char *,
                                 pgp_output_t *);
unsigned pgp_write_one_pass_sig(pgp_output_t *,
                                const pgp_seckey_t *,
                                const pgp_hash_alg_t,
                                const pgp_sig_type_t);
unsigned pgp_write_litdata(pgp_output_t *, const uint8_t *, const int, const pgp_litdata_enum);
pgp_pk_sesskey_t *pgp_create_pk_sesskey(const pgp_pubkey_t *, pgp_symm_alg_t);
bool              pgp_write_pk_sesskey(pgp_output_t *, pgp_pk_sesskey_t *);
unsigned          pgp_write_xfer_pubkey(pgp_output_t *,
                               const pgp_key_t *,
                               const rnp_key_store_t *,
                               const unsigned);
bool pgp_write_xfer_seckey(pgp_output_t *,
                           const pgp_key_t *,
                           const rnp_key_store_t *,
                           const unsigned);

unsigned pgp_write_userid(const uint8_t *, pgp_output_t *);
unsigned pgp_fileread_litdata(const char *, const pgp_litdata_enum, pgp_output_t *);

bool pgp_write_selfsig_cert(pgp_output_t *               output,
                            const pgp_seckey_t *         seckey,
                            const pgp_hash_alg_t         hash_alg,
                            const rnp_selfsig_cert_info *cert);
bool pgp_write_selfsig_binding(pgp_output_t *                  output,
                               const pgp_seckey_t *            primary_sec,
                               const pgp_hash_alg_t            hash_alg,
                               const pgp_pubkey_t *            subkey,
                               const rnp_selfsig_binding_info *binding);

#endif /* CREATE_H_ */
