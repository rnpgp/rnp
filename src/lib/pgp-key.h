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
#include "crypto/symmetric.h"
#include "types.h"

/* describes a user's key */
struct pgp_key_t {
    list          uids;         /* list of user ids as (char*) */
    list          packets;      /* list of raw packets as pgp_rawpacket_t */
    list          subsigs;      /* list of signatures as pgp_subsig_t */
    list          revokes;      /* list of signature revocations pgp_revoke_t */
    list          subkey_grips; /* list of subkey grips (for primary keys) as uint8_t[20] */
    uint8_t *     primary_grip; /* grip of primary key (for subkeys) */
    time_t        expiration;   /* key expiration time, if available */
    pgp_key_pkt_t pkt;          /* pubkey/seckey data packet */
    uint8_t       key_flags;    /* key flags */
    uint8_t       keyid[PGP_KEY_ID_SIZE];
    pgp_fingerprint_t  fingerprint;
    uint8_t            grip[PGP_KEY_GRIP_SIZE];
    uint32_t           uid0;         /* primary uid index in uids array */
    unsigned           uid0_set : 1; /* flag for the above */
    uint8_t            revoked;      /* key has been revoked */
    pgp_revoke_t       revocation;   /* revocation reason */
    key_store_format_t format;       /* the format of the key in packets[0] */
    bool               valid;        /* this key is valid and usable */
};

struct pgp_key_t *pgp_key_new(void);

/** create a key from the key pkt
 *
 *  This sets up basic properties of the key like keyid/fpr/grip, type, etc.
 *  It does not set primary_grip or subkey_grips (the key store does this).
 */
bool pgp_key_from_pkt(pgp_key_t *key, const pgp_key_pkt_t *pkt, const pgp_content_enum tag);

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

/**
 * @brief Copy key, optionally copying only the public key part.
 *
 * @param dst destination of copying
 * @param src source key
 * @param public if true then only public key fields will be copied, i.e. key converted from
 *               secret to public
 * @return RNP_SUCCESS if operation succeeded or error code otherwise
 */
rnp_result_t pgp_key_copy(pgp_key_t *dst, const pgp_key_t *src, bool pubonly);

/**
 * @brief Copy calculated key fields (grip, userid list, etc). Does not copy key packet/raw
 *        packets. Zeroes dst so should not be used with pre-filled objects.
 *
 * @param dst destination of copying
 * @param src source key
 * @return RNP_SUCCESS if operation succeeded or error code otherwise
 */
rnp_result_t pgp_key_copy_fields(pgp_key_t *dst, const pgp_key_t *src);

void pgp_free_user_prefs(pgp_user_prefs_t *prefs);

bool pgp_user_prefs_set_symm_algs(pgp_user_prefs_t *prefs, const uint8_t *algs, size_t len);

bool pgp_user_prefs_add_symm_alg(pgp_user_prefs_t *prefs, pgp_symm_alg_t alg);

bool pgp_user_prefs_set_hash_algs(pgp_user_prefs_t *prefs, const uint8_t *algs, size_t len);

bool pgp_user_prefs_add_hash_alg(pgp_user_prefs_t *prefs, pgp_hash_alg_t alg);

bool pgp_user_prefs_set_z_algs(pgp_user_prefs_t *prefs, const uint8_t *algs, size_t len);

bool pgp_user_prefs_add_z_alg(pgp_user_prefs_t *prefs, pgp_compression_type_t alg);

bool pgp_user_prefs_set_ks_prefs(pgp_user_prefs_t *prefs, const uint8_t *vals, size_t len);

bool pgp_user_prefs_add_ks_pref(pgp_user_prefs_t *prefs, pgp_key_server_prefs_t val);

const pgp_key_pkt_t *pgp_key_get_pkt(const pgp_key_t *);

const pgp_key_material_t *pgp_key_get_material(const pgp_key_t *key);

pgp_pubkey_alg_t pgp_key_get_alg(const pgp_key_t *key);

int pgp_key_get_type(const pgp_key_t *key);

bool pgp_key_is_encrypted(const pgp_key_t *);

bool pgp_key_can_sign(const pgp_key_t *key);
bool pgp_key_can_certify(const pgp_key_t *key);
bool pgp_key_can_encrypt(const pgp_key_t *key);

bool pgp_key_is_public(const pgp_key_t *);
bool pgp_key_is_secret(const pgp_key_t *);
bool pgp_key_is_primary_key(const pgp_key_t *key);
bool pgp_key_is_subkey(const pgp_key_t *key);

pgp_key_pkt_t *pgp_decrypt_seckey_pgp(const uint8_t *,
                                      size_t,
                                      const pgp_key_pkt_t *,
                                      const char *);

pgp_key_pkt_t *pgp_decrypt_seckey(const pgp_key_t *,
                                  const pgp_password_provider_t *,
                                  const pgp_password_ctx_t *);

/**
 * @brief Get key's keyid
 *
 * @param key populated key, should not be NULL
 * @return pointer to the 8-byte buffer with keyid
 */
const uint8_t *pgp_key_get_keyid(const pgp_key_t *key);

/**
 * @brief Get key's fingerprint
 *
 * @param key populated key, should not be NULL
 * @return pointer to the fingerprint structure
 */
const pgp_fingerprint_t *pgp_key_get_fp(const pgp_key_t *key);

/**
 * @brief Get key's grip
 *
 * @param key populated key, should not be NULL
 * @return pointer to buffer with the grip
 */
const uint8_t *pgp_key_get_grip(const pgp_key_t *key);

/**
 * @brief Get primary key's grip for the subkey, if available.
 *
 * @param key subkey, which primary key's grip should be returned
 * @return pointer to the array with grip or NULL if it is not available
 */
const uint8_t *pgp_key_get_primary_grip(const pgp_key_t *key);

/**
 * @brief Set primary key's grip for the subkey
 *
 * @param key subkey
 * @param grip buffer with grip, should not be NULL
 * @return true on success or false otherwise (key is not subkey, or allocation failed)
 */
bool pgp_key_set_primary_grip(pgp_key_t *key, const uint8_t *grip);

/**
 * @brief Link key with subkey via primary_grip and subkey_grips list
 *
 * @param key primary key
 * @param subkey subkey of the primary key
 * @return true on success or false otherwise (allocation failed, wrong key types)
 */
bool pgp_key_link_subkey_grip(pgp_key_t *key, pgp_key_t *subkey);

size_t pgp_key_get_userid_count(const pgp_key_t *);

const char *pgp_key_get_userid(const pgp_key_t *, size_t);

const char *pgp_key_get_primary_userid(const pgp_key_t *);

bool pgp_key_has_userid(const pgp_key_t *, const char *);

unsigned char *pgp_key_add_userid(pgp_key_t *, const unsigned char *);

pgp_revoke_t *pgp_key_add_revoke(pgp_key_t *);

size_t pgp_key_get_revoke_count(const pgp_key_t *);

pgp_revoke_t *pgp_key_get_revoke(const pgp_key_t *, size_t);

pgp_subsig_t *pgp_key_add_subsig(pgp_key_t *);

size_t pgp_key_get_subsig_count(const pgp_key_t *);

pgp_subsig_t *pgp_key_get_subsig(const pgp_key_t *, size_t);

pgp_rawpacket_t *pgp_key_add_rawpacket(pgp_key_t *, void *, size_t, pgp_content_enum);

size_t pgp_key_get_rawpacket_count(const pgp_key_t *);

pgp_rawpacket_t *pgp_key_get_rawpacket(const pgp_key_t *, size_t);

/**
 * @brief Get the number of pgp key's subkeys.
 *
 * @param key pointer to the primary key
 * @return number of the subkeys
 */
size_t pgp_key_get_subkey_count(const pgp_key_t *key);

/**
 * @brief Get the pgp key's subkey grip
 *
 * @param key key pointer to the primary key
 * @param idx index of the subkey
 * @return pointer to the grip data or NULL if subkey not found
 */
uint8_t *pgp_key_get_subkey_grip(const pgp_key_t *key, size_t idx);

/**
 * @brief Get the key's subkey by it's index
 *
 * @param key primary key
 * @param store key store wich will be searched for subkeys
 * @param idx index of the subkey
 * @return pointer to the subkey or NULL if subkey not found
 */
pgp_key_t *pgp_key_get_subkey(const pgp_key_t *key, const rnp_key_store_t *store, size_t idx);

pgp_key_flags_t pgp_pk_alg_capabilities(pgp_pubkey_alg_t alg);

/**
 * @brief Export and armor OpenPGP key, writing it to the NULL-terminated string.
 *
 * @param keyring where key belongs to. Needed to fetch all subkeys as well, not NULL.
 * @param key pointer to the key, cannot be NULL.
 * @return allocated string with armored key, or NULL on failure. Resulting string must be
 *         released by caller.
 */
char *pgp_export_key(const rnp_key_store_t *keyring, const pgp_key_t *key);

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
 *  @param pass_provider the password provider that may be used
 *         to unlock the key, if necessary
 *  @return true if the key was unlocked, false otherwise
 **/
bool pgp_key_unlock(pgp_key_t *key, const pgp_password_provider_t *provider);

/** lock a key
 *
 *  Note: Key locking does not apply to unprotected keys.
 *
 *  @param key the key
 *  @return true if the key was unlocked, false otherwise
 **/
bool pgp_key_lock(pgp_key_t *key);

/** add protection to an unlocked key
 *
 *  @param key the key, which must be unlocked
 *  @param format
 *  @param protection
 *  @param password_provider the password provider, which is used to retrieve
 *         the new password for the key.
 *  @return true if key was successfully protected, false otherwise
 **/
bool rnp_key_add_protection(pgp_key_t *                    key,
                            key_store_format_t             format,
                            rnp_key_protection_params_t *  protection,
                            const pgp_password_provider_t *password_provider);

/** add protection to a key
 *
 *  @param key
 *  @param decrypted_seckey
 *  @param format
 *  @param protection
 *  @param new_password
 *  @return true if key was successfully protected, false otherwise
 **/
bool pgp_key_protect(pgp_key_t *                  key,
                     pgp_key_pkt_t *              decrypted_seckey,
                     key_store_format_t           format,
                     rnp_key_protection_params_t *protection,
                     const char *                 new_password);

/** remove protection from a key
 *
 *  @param key
 *  @param password_provider
 *  @return true if protection was successfully removed, false otherwise
 **/
bool pgp_key_unprotect(pgp_key_t *key, const pgp_password_provider_t *password_provider);

/** check if a key is currently protected
 *
 *  @param key
 *  @return true if the key is protected, false otherwise
 **/
bool pgp_key_is_protected(const pgp_key_t *key);

/** add a new userid to a key
 *
 *  @param key
 *  @param seckey the decrypted seckey for signing
 *  @param hash_alg the hash algorithm to be used for the signature
 *  @param cert the self-signature information
 *  @return true if the userid was added, false otherwise
 */
bool pgp_key_add_userid(pgp_key_t *              key,
                        const pgp_key_pkt_t *    seckey,
                        pgp_hash_alg_t           hash_alg,
                        rnp_selfsig_cert_info_t *cert);

bool pgp_key_write_packets(const pgp_key_t *key, pgp_dest_t *dst);

/** find a key suitable for a particular operation
 *
 *  If the key passed is suitable, it will be returned.
 *  Otherwise, its subkeys (if it is a primary w/subs)
 *  will be checked. NULL will be returned if no suitable
 *  key is found.
 *
 *  @param op the operation for which the key should be suitable
 *  @param key the key
 *  @param desired_usage
 *  @param key_provider the key provider. This will be used
 *         if/when subkeys are checked.
 *
 *  @returns key or last created subkey with desired usage flag
 *           set or NULL if not found
 */
pgp_key_t *find_suitable_key(pgp_op_t            op,
                             pgp_key_t *         key,
                             pgp_key_provider_t *key_provider,
                             uint8_t             desired_usage);

pgp_key_t *pgp_get_primary_key_for(const pgp_key_t *         subkey,
                                   const rnp_key_store_t *   store,
                                   const pgp_key_provider_t *key_provider);

/*
 *  Picks up hash algorithm according to domain parameters set
 *  in `pubkey' and user provided hash. That's mostly because DSA
 *  and ECDSA needs special treatment.
 *
 *  @param hash set by the caller
 *  @param pubkey initialized public key
 *
 *  @returns hash algorithm that must be use for operation (mostly
             signing with secure key which corresponds to 'pubkey')
 */
pgp_hash_alg_t pgp_hash_adjust_alg_to_key(pgp_hash_alg_t hash, const pgp_key_pkt_t *pubkey);

#endif // RNP_PACKET_KEY_H
