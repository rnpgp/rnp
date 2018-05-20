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
#ifndef VALIDATE_H_
#define VALIDATE_H_ 1

#include "crypto/hash.h"

typedef struct pgp_validation_t {
    unsigned        validc;
    pgp_sig_info_t *valid_sigs;
    unsigned        invalidc;
    pgp_sig_info_t *invalid_sigs;
    unsigned        unknownc;
    pgp_sig_info_t *unknown_sigs;
    time_t          creation;
    time_t          expiration;
    rnp_ctx_t *     rnp_ctx;
} pgp_validation_t;

typedef struct {
    const pgp_key_t *key;
    unsigned         packet;
    unsigned         offset;
} validate_reader_t;

/** Struct used with the validate_key_cb callback */
typedef struct {
    pgp_key_pkt_t pubkey;
    pgp_key_pkt_t subkey;
    pgp_key_pkt_t seckey;
    bool          loaded_pubkey;
    enum { ATTRIBUTE = 1, ID } last_seen;
    uint8_t *              userid;
    pgp_data_t             userattr;
    uint8_t                hash[PGP_MAX_HASH_SIZE];
    const rnp_key_store_t *keyring;
    validate_reader_t *    reader;
    pgp_validation_t *     result;
} validate_key_cb_t;

void pgp_validate_result_free(pgp_validation_t *);

bool pgp_key_reader_set(pgp_stream_t *, const pgp_key_t *);

pgp_cb_ret_t pgp_validate_key_cb(const pgp_packet_t *, pgp_cbdata_t *);

/**
 * \ingroup HighLevel_Verify
 * \brief Validate all signatures on a single key against the given keyring
 * \param result Where to put the result
 * \param key Key to validate
 * \param keyring Keyring to use for validation
 * \return 1 if all signatures OK; else 0
 * \note It is the caller's responsiblity to free result after use.
 * \sa pgp_validate_result_free()
 */
bool pgp_validate_key_sigs(pgp_validation_t *     result,
                           const pgp_key_t *      key,
                           const rnp_key_store_t *keyring);

/**
 * \ingroup HighLevel_Verify
 * \brief Indicicates whether any errors were found
 * \param result Validation result to check
 * \return 0 if any invalid signatures or unknown signers
        or no valid signatures; else 1
 */
bool validate_result_status(const char *f, pgp_validation_t *val);

#endif /* !VALIDATE_H_ */
