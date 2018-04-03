/*
 * Copyright (c) 2018, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef STREAM_KEY_H_
#define STREAM_KEY_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "errors.h"
#include <repgp/repgp.h>
#include <rnp/rnp.h>
#include "stream-common.h"

/* userid/userattr with all the corresponding signatures */
typedef struct pgp_transferable_userid_t {
    pgp_userid_pkt_t uid;
    list             signatures;
} pgp_transferable_userid_t;

/* subkey with all corresponding signatures */
typedef struct pgp_transferable_subkey_t {
    pgp_key_pkt_t subkey;
    list          signatures;
} pgp_transferable_subkey_t;

/* transferable key with userids, subkeys and revocation signatures */
typedef struct pgp_transferable_key_t {
    pgp_key_pkt_t key; /* main key packet */
    list          userids;
    list          subkeys;
    list          signatures;
} pgp_transferable_key_t;

/* sequence of OpenPGP transferable keys */
typedef struct pgp_key_sequence_t {
    list keys; /* list of pgp_transferable_key_t records */
} pgp_key_sequence_t;

void transferable_key_destroy(pgp_transferable_key_t *key);

void key_sequence_destroy(pgp_key_sequence_t *keys);

rnp_result_t process_pgp_keys(pgp_source_t *src, pgp_key_sequence_t *keys);

rnp_result_t write_pgp_keys(pgp_key_sequence_t *keys, pgp_dest_t *dst, bool armor);

rnp_result_t decrypt_secret_key(pgp_key_pkt_t *key, const char *password);

void forget_secret_key_fields(pgp_key_pkt_t *key);

#endif
