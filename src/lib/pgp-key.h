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

#ifndef RNP_PACKET_KEY_H
#define RNP_PACKET_KEY_H

#include <stdbool.h>
#include <stdio.h>
#include "pass-provider.h"
#include <repgp/repgp.h>
#include <rekey/rnp_key_store.h>
#include "memory.h"
#include "types.h"
#include "defs.h"
#include "symmetric.h"

/* describes a user's key */
struct pgp_key_t {
    DYNARRAY(uint8_t *, uid);          /* array of user ids */
    DYNARRAY(pgp_rawpacket_t, packet); /* array of raw packets */
    DYNARRAY(pgp_subsig_t, subsig);    /* array of signature subkeys */
    DYNARRAY(pgp_revoke_t, revoke);    /* array of signature revocations */
    DYNARRAY(struct pgp_key_t *, subkey);
    pgp_content_enum   type;      /* type of key */
    pgp_keydata_key_t  key;       /* pubkey/seckey data */
    uint8_t            key_flags; /* key flags */
    uint8_t            keyid[PGP_KEY_ID_SIZE];
    pgp_fingerprint_t  fingerprint;
    uint8_t            grip[PGP_FINGERPRINT_SIZE];
    uint32_t           uid0;         /* primary uid index in uids array */
    unsigned           uid0_set : 1; /* flag for the above */
    uint8_t            revoked;      /* key has been revoked */
    pgp_revoke_t       revocation;   /* revocation reason */
    key_store_format_t format;       /* the format of the key in packets[0] */

    bool is_protected; /* whether the key in packets[0] is encrypted (for secret keys) */
};

struct pgp_key_t *pgp_key_new(void);

/** free the internal data of a key *and* the key structure itself
 *
 *  @param key the key
 **/
void pgp_key_free(pgp_key_t *);

/** free the internal data of a key
 *
 *  This does *not* free the key structure itself.
 *
 *  @param key the key
 **/
void pgp_key_free_data(pgp_key_t *);

void pgp_free_user_prefs(pgp_user_prefs_t *prefs);

const pgp_pubkey_t *pgp_get_pubkey(const pgp_key_t *);

bool pgp_is_key_public(const pgp_key_t *);

bool pgp_is_key_secret(const pgp_key_t *);

bool pgp_key_can_sign(const pgp_key_t *key);
bool pgp_key_can_certify(const pgp_key_t *key);
bool pgp_key_can_encrypt(const pgp_key_t *key);

bool pgp_is_primary_key_tag(pgp_content_enum tag);
bool pgp_is_subkey_tag(pgp_content_enum tag);
bool pgp_is_secret_key_tag(pgp_content_enum tag);
bool pgp_is_public_key_tag(pgp_content_enum tag);

bool pgp_key_is_primary_key(const pgp_key_t *key);
bool pgp_key_is_subkey(const pgp_key_t *key);

const struct pgp_seckey_t *pgp_get_seckey(const pgp_key_t *);

pgp_seckey_t *pgp_get_writable_seckey(pgp_key_t *);

pgp_seckey_t *pgp_decrypt_seckey_pgp(const uint8_t *,
                                     size_t,
                                     const pgp_pubkey_t *,
                                     const char *);

pgp_seckey_t *pgp_decrypt_seckey(const pgp_key_t *,
                                 const pgp_passphrase_provider_t *,
                                 const pgp_passphrase_ctx_t *);

void pgp_set_seckey(pgp_contents_t *, const pgp_key_t *);

const unsigned char *pgp_get_key_id(const pgp_key_t *);

unsigned pgp_get_userid_count(const pgp_key_t *);

const unsigned char *pgp_get_userid(const pgp_key_t *, unsigned);

unsigned char *pgp_add_userid(pgp_key_t *, const unsigned char *);

struct pgp_rawpacket_t *pgp_add_rawpacket(pgp_key_t *, const pgp_rawpacket_t *);

void pgp_key_init(pgp_key_t *, const pgp_content_enum);

pgp_key_flags_t pgp_pk_alg_capabilities(pgp_pubkey_alg_t alg);

char *pgp_export_key(pgp_io_t *, const pgp_key_t *, const pgp_passphrase_provider_t *);

/** check if a key is currently locked
 *
 *  Note: Key locking does not apply to unprotected keys.
 *
 *  @param key the key
 *  @return true if the key is locked, false otherwise
 **/
bool pgp_key_is_locked(const pgp_key_t *key);

/** unlock a key
 *
 *  Note: Key locking does not apply to unprotected keys.
 *
 *  @param key the key
 *  @param pass_provider the passphrase provider that may be used
 *         to unlock the key, if necessary
 *  @return true if the key was unlocked, false otherwise
 **/
bool pgp_key_unlock(pgp_key_t *key, const pgp_passphrase_provider_t *provider);

/** lock a key
 *
 *  Note: Key locking does not apply to unprotected keys.
 *
 *  @param key the key
 *  @return true if the key was unlocked, false otherwise
 **/
bool pgp_key_lock(pgp_key_t *key);

/** add protection to a key
 *
 *  @param key
 *  @param format
 *  @param passphrase_provider
 *  @return true if key was successfully protected, false otherwise
 **/
bool pgp_key_protect(pgp_key_t *                      key,
                     key_store_format_t               format,
                     rnp_key_protection_params_t *    protection,
                     const pgp_passphrase_provider_t *passphrase_provider);

/** add protection to a key
 *
 *  @param key
 *  @param format
 *  @param protection
 *  @param passphrase
 *  @return true if key was successfully protected, false otherwise
 **/
bool pgp_key_protect_passphrase(pgp_key_t *                  key,
                                key_store_format_t           format,
                                rnp_key_protection_params_t *protection,
                                const char *                 passphrase);

/** remove protection from a key
 *
 *  @param key
 *  @param passphrase_provider
 *  @return true if protection was successfully removed, false otherwise
 **/
bool pgp_key_unprotect(pgp_key_t *key, const pgp_passphrase_provider_t *passphrase_provider);

/** check if a key is currently protected
 *
 *  @param key
 *  @return true if the key is protected, false otherwise
 **/
bool pgp_key_is_protected(const pgp_key_t *key);

bool pgp_key_add_userid(pgp_key_t *            key,
                        const pgp_seckey_t *   seckey,
                        pgp_hash_alg_t         hash_alg,
                        rnp_selfsig_cert_info *cert);

#endif // RNP_PACKET_KEY_H
