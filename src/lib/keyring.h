/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef KEYRING_H_
#define KEYRING_H_

#include <rnp.h>
#include <json.h>

#include <stdint.h>

#include "packet.h"

typedef struct keyring_t {
    DYNARRAY(pgp_key_t,	key);
    pgp_hash_alg_t	hashtype;
} keyring_t;

void keyring_format_key(char *buffer, uint8_t *sigid, int len);
int keyring_get_first_ring(keyring_t *ring, char *id, size_t len, int last);

void keyring_free(keyring_t *);

int keyring_list(pgp_io_t *, const keyring_t *, const int);
int keyring_json(pgp_io_t *, const keyring_t *, json_object *, const int);

int keyring_append_keyring(keyring_t *, keyring_t *);
int keyring_add_key(pgp_io_t *, keyring_t *, pgp_keydata_key_t *, pgp_content_enum tag);

const pgp_key_t *keyring_get_key_by_id(pgp_io_t *, const keyring_t *, const unsigned char *, unsigned *, pgp_pubkey_t **);
const pgp_key_t *keyring_get_key_by_name(pgp_io_t *, const keyring_t *, const char *);
const pgp_key_t *keyring_get_next_key_by_name(pgp_io_t *, const keyring_t *, const char *, unsigned *);

#endif /* KEYRING_H_ */
