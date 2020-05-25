/*
 * Copyright (c) 2017-2020 [Ribose Inc](https://www.ribose.com).
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
#include <vector>
#include "pass-provider.h"
#include <rekey/rnp_key_store.h>
#include "crypto/symmetric.h"
#include "types.h"

/* describes a user's key */
struct pgp_key_t {
    std::vector<pgp_userid_t>   uids;         /* array of user ids */
    std::vector<pgp_subsig_t>   subsigs;      /* array of key signatures */
    std::vector<pgp_revoke_t>   revokes;      /* array of revocations */
    std::vector<pgp_key_grip_t> subkey_grips; /* array of subkey grips (for primary keys) */
    pgp_key_grip_t              primary_grip; /* grip of primary key (for subkeys) */
    bool                        primary_grip_set;
    time_t                      expiration; /* key expiration time, if available */
    pgp_key_pkt_t               pkt;        /* pubkey/seckey data packet */
    pgp_rawpacket_t             rawpkt;     /* key raw packet */
    uint8_t                     key_flags;  /* key flags */
    uint8_t                     keyid[PGP_KEY_ID_SIZE];
    pgp_fingerprint_t           fingerprint;
    pgp_key_grip_t              grip;
    uint32_t                    uid0;         /* primary uid index in uids array */
    unsigned                    uid0_set : 1; /* flag for the above */
    uint8_t                     revoked;      /* key has been revoked */
    pgp_revoke_t                revocation;   /* revocation reason */
    pgp_key_store_format_t      format;       /* the format of the key in packets[0] */
    bool                        valid;        /* this key is valid and usable */
    bool                        validated;    /* this key was validated */

    ~pgp_key_t();
    pgp_key_t() = default;
    pgp_key_t &operator=(pgp_key_t &&);
    /* make sure we use only empty constructor/move operator */
    pgp_key_t(const pgp_key_t &src) = delete;
    pgp_key_t(pgp_key_t &&src) = delete;
    pgp_key_t &operator=(const pgp_key_t &) = delete;
};

/**
 * @brief Create pgp_key_t object from the OpenPGP key packet.
 *
 * @param key pointer to the key object, cannot be NULL.
 * @param pkt pointer to the key packet, cannot be NULL.
 * @return true if operation succeeded or false otherwise.
 */
bool pgp_key_from_pkt(pgp_key_t *key, const pgp_key_pkt_t *pkt);

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

size_t pgp_key_get_dsa_qbits(const pgp_key_t *key);

size_t pgp_key_get_bits(const pgp_key_t *key);

pgp_curve_t pgp_key_get_curve(const pgp_key_t *key);

pgp_version_t pgp_key_get_version(const pgp_key_t *key);

pgp_pkt_type_t pgp_key_get_type(const pgp_key_t *key);

bool pgp_key_is_encrypted(const pgp_key_t *);

uint8_t pgp_key_get_flags(const pgp_key_t *key);
bool    pgp_key_can_sign(const pgp_key_t *key);
bool    pgp_key_can_certify(const pgp_key_t *key);
bool    pgp_key_can_encrypt(const pgp_key_t *key);

/**
 * @brief Get key's expiration time in seconds. If 0 then it doesn't expire.
 *
 * @param key populated key, could not be NULL
 * @return key expiration time
 */
uint32_t pgp_key_get_expiration(const pgp_key_t *key);

/**
 * @brief Get key's creation time in seconds since Jan, 1 1980.
 *
 * @param key populated key, could not be NULL
 * @return key creation time
 */
uint32_t pgp_key_get_creation(const pgp_key_t *key);

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
 * @return key's grip
 */
const pgp_key_grip_t &pgp_key_get_grip(const pgp_key_t *key);

/**
 * @brief Get primary key's grip for the subkey, if available.
 *
 * @param key subkey, which primary key's grip should be returned
 * @return pointer to the array with grip or NULL if it is not available
 */
const pgp_key_grip_t &pgp_key_get_primary_grip(const pgp_key_t *key);

bool pgp_key_has_primary_grip(const pgp_key_t *key);

/**
 * @brief Set primary key's grip for the subkey
 *
 * @param key subkey
 * @param grip buffer with grip
 * @return void
 */
void pgp_key_set_primary_grip(pgp_key_t *key, const pgp_key_grip_t &grip);

/**
 * @brief Link key with subkey via primary_grip and subkey_grips list
 *
 * @param key primary key
 * @param subkey subkey of the primary key
 * @return true on success or false otherwise (allocation failed, wrong key types)
 */
bool pgp_key_link_subkey_grip(pgp_key_t *key, pgp_key_t *subkey);

size_t pgp_key_get_userid_count(const pgp_key_t *);

const pgp_userid_t *pgp_key_get_userid(const pgp_key_t *, size_t);

pgp_userid_t *pgp_key_get_userid(pgp_key_t *, size_t);

const pgp_revoke_t *pgp_key_get_userid_revoke(const pgp_key_t *, size_t userid);

bool pgp_key_has_userid(const pgp_key_t *, const char *);

pgp_userid_t *pgp_key_add_userid(pgp_key_t *);

pgp_revoke_t *pgp_key_add_revoke(pgp_key_t *);

size_t pgp_key_get_revoke_count(const pgp_key_t *);

const pgp_revoke_t *pgp_key_get_revoke(const pgp_key_t *, size_t);

pgp_revoke_t *pgp_key_get_revoke(pgp_key_t *key, size_t idx);

void revoke_free(pgp_revoke_t *revoke);

pgp_subsig_t *pgp_key_add_subsig(pgp_key_t *);

size_t pgp_key_get_subsig_count(const pgp_key_t *);

const pgp_subsig_t *pgp_key_get_subsig(const pgp_key_t *, size_t);
pgp_subsig_t *      pgp_key_get_subsig(pgp_key_t *, size_t);

bool pgp_subsig_from_signature(pgp_subsig_t *subsig, const pgp_signature_t *sig);

bool pgp_key_has_signature(const pgp_key_t *key, const pgp_signature_t *sig);

pgp_subsig_t *pgp_key_replace_signature(pgp_key_t *      key,
                                        pgp_signature_t *oldsig,
                                        pgp_signature_t *newsig);

/**
 * @brief Get the latest valid self-signature with information about the primary key,
 * containing the specified subpacket. It could be userid certification or direct-key
 * signature.
 *
 * @param key key which should be searched for signature.
 * @param subpkt subpacket type. Pass 0 to return just latest signature.
 * @return pointer to signature object or NULL if failed/not found.
 */
pgp_subsig_t *pgp_key_latest_selfsig(pgp_key_t *key, pgp_sig_subpacket_type_t subpkt);

/**
 * @brief Get the latest valid subkey binding.
 *
 * @param subkey subkey which should be searched for signature.
 * @param validated set to true whether binding signature must be validated
 * @return pointer to signature object or NULL if failed/not found.
 */
pgp_subsig_t *pgp_key_latest_binding(pgp_key_t *subkey, bool validated);

bool pgp_key_refresh_data(pgp_key_t *key);

bool pgp_subkey_refresh_data(pgp_key_t *sub, pgp_key_t *key);

size_t pgp_key_get_rawpacket_count(const pgp_key_t *);

pgp_rawpacket_t &      pgp_key_get_rawpacket(pgp_key_t *);
const pgp_rawpacket_t &pgp_key_get_rawpacket(const pgp_key_t *);

/**
 * @brief Get the number of pgp key's subkeys.
 *
 * @param key pointer to the primary key
 * @return number of the subkeys
 */
size_t pgp_key_get_subkey_count(const pgp_key_t *key);

/**
 * @brief Add subkey grip to key's list.
 *        Note: this function will check for duplicates.
 *
 * @param key key pointer to the primary key
 * @param grip subkey's grip.
 * @return true if succeeded (grip already exists in list or added), or false otherwise.
 */
bool pgp_key_add_subkey_grip(pgp_key_t *key, const pgp_key_grip_t &grip);

/**
 * @brief Get the pgp key's subkey grip
 *
 * @param key key pointer to the primary key
 * @param idx index of the subkey
 * @return grip or throws std::out_of_range exception
 */
const pgp_key_grip_t &pgp_key_get_subkey_grip(const pgp_key_t *key, size_t idx);

/**
 * @brief Get the key's subkey by it's index
 *
 * @param key primary key
 * @param store key store wich will be searched for subkeys
 * @param idx index of the subkey
 * @return pointer to the subkey or NULL if subkey not found
 */
pgp_key_t *pgp_key_get_subkey(const pgp_key_t *key, rnp_key_store_t *store, size_t idx);

pgp_key_flags_t pgp_pk_alg_capabilities(pgp_pubkey_alg_t alg);

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
                            pgp_key_store_format_t         format,
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
                     pgp_key_store_format_t       format,
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

/** add a new certified userid to a key
 *
 *  @param key
 *  @param seckey the decrypted seckey for signing
 *  @param hash_alg the hash algorithm to be used for the signature
 *  @param cert the self-signature information
 *  @return true if the userid was added, false otherwise
 */
bool pgp_key_add_userid_certified(pgp_key_t *              key,
                                  const pgp_key_pkt_t *    seckey,
                                  pgp_hash_alg_t           hash_alg,
                                  rnp_selfsig_cert_info_t *cert);

bool pgp_key_set_expiration(pgp_key_t *key, pgp_key_t *signer, uint32_t expiry);

bool pgp_subkey_set_expiration(pgp_key_t *sub,
                               pgp_key_t *primsec,
                               pgp_key_t *secsub,
                               uint32_t   expiry);

bool pgp_key_write_packets(const pgp_key_t *key, pgp_dest_t *dst);

/**
 * @brief Write OpenPGP key packets (including subkeys) to the specified stream
 *
 * @param dst stream to write packets
 * @param key key
 * @param keyring keyring, which will be searched for subkeys
 * @return true on success or false otherwise
 */
bool pgp_key_write_xfer(pgp_dest_t *dst, const pgp_key_t *key, const rnp_key_store_t *keyring);

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

void pgp_key_validate_subkey(pgp_key_t *subkey, pgp_key_t *key);

void pgp_key_validate(pgp_key_t *key, rnp_key_store_t *keyring);

void pgp_key_revalidate_updated(pgp_key_t *key, rnp_key_store_t *keyring);

#endif // RNP_PACKET_KEY_H
