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

#ifndef STREAM_SIG_H_
#define STREAM_SIG_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "rnp.h"
#include "stream-common.h"

/* information about the validated signature */
typedef struct pgp_signature_info_t {
    pgp_signature_t *sig;       /* signature, or NULL if there were parsing error */
    pgp_key_t *      signer;    /* signer's public key if found */
    bool             valid;     /* signature is cryptographically valid (but may be expired) */
    bool             unknown;   /* signature is unknown - parsing error, wrong version, etc */
    bool             no_signer; /* no signer's public key available */
    bool             expired;   /* signature is expired */
    bool             signer_valid;  /* assume that signing key is valid */
    bool             ignore_expiry; /* ignore signer's key expiration time */
} pgp_signature_info_t;

typedef std::vector<pgp_signature_t> pgp_signature_list_t;

/**
 * @brief Get the signature's expiration time
 * @param sig populated or loaded signature
 * @return expiration time in seconds since the creation time. 0 if signature never expires.
 */
uint32_t signature_get_expiration(const pgp_signature_t *sig);

/**
 * @brief Set the signature's expiration time
 * @param sig signature being populated
 * @param etime expiration time
 * @return true on success or false otherwise
 */
bool signature_set_expiration(pgp_signature_t *sig, uint32_t etime);

/**
 * @brief Get the key expiration time
 * @param sig populated or loaded signature
 * @return expiration time in seconds since the creation time. 0 if key never expires.
 */
uint32_t signature_get_key_expiration(const pgp_signature_t *sig);

/**
 * @brief Set the key expiration time
 * @param sig signature being populated
 * @param etime expiration time
 * @return true on success or false otherwise
 */
bool signature_set_key_expiration(pgp_signature_t *sig, uint32_t etime);

/**
 * @brief Get the key flags
 * @param sig populated or loaded signature
 * @return byte of key flags. If there is no corresponding subpackets then 0 is returned.
 */
uint8_t signature_get_key_flags(const pgp_signature_t *sig);

/**
 * @brief Set the key flags
 * @param sig signature being populated
 * @param flags byte of key flags
 * @return true on success or false otherwise
 */
bool signature_set_key_flags(pgp_signature_t *sig, uint8_t flags);

/**
 * @brief Get the primary user id flag
 * @param sig populated or loaded signature
 * @return true if user id is marked as primary or false otherwise
 */
bool signature_get_primary_uid(pgp_signature_t *sig);

/**
 * @brief Set the primary user id flag
 * @param sig signature being populated
 * @param primary true if user id should be marked as primary
 * @return true on success or false otherwise
 */
bool signature_set_primary_uid(pgp_signature_t *sig, bool primary);

bool signature_get_preferred_symm_algs(const pgp_signature_t *sig,
                                       uint8_t **             algs,
                                       size_t *               count);

bool signature_set_preferred_symm_algs(pgp_signature_t *sig, uint8_t algs[], size_t len);

bool signature_get_preferred_hash_algs(const pgp_signature_t *sig,
                                       uint8_t **             algs,
                                       size_t *               count);

bool signature_set_preferred_hash_algs(pgp_signature_t *sig, uint8_t algs[], size_t len);

bool signature_get_preferred_z_algs(const pgp_signature_t *sig, uint8_t **algs, size_t *count);

bool signature_set_preferred_z_algs(pgp_signature_t *sig, uint8_t algs[], size_t len);

uint8_t signature_get_key_server_prefs(const pgp_signature_t *sig);

bool signature_set_key_server_prefs(pgp_signature_t *sig, uint8_t prefs);

bool signature_set_preferred_key_server(pgp_signature_t *sig, const char *uri);

bool signature_get_trust(const pgp_signature_t *sig, uint8_t *level, uint8_t *amount);

bool signature_set_trust(pgp_signature_t *sig, uint8_t level, uint8_t amount);

bool signature_get_revocable(const pgp_signature_t *sig);

bool signature_set_revocable(pgp_signature_t *sig, bool revocable);

bool signature_set_features(pgp_signature_t *sig, uint8_t features);

bool signature_set_signer_uid(pgp_signature_t *sig, uint8_t *uid, size_t len);

bool signature_set_embedded_sig(pgp_signature_t *sig, pgp_signature_t *esig);

bool signature_add_notation_data(pgp_signature_t *sig,
                                 bool             readable,
                                 const char *     name,
                                 const char *     value);

char *signature_get_key_server(const pgp_signature_t *sig);

bool signature_get_revocation_reason(const pgp_signature_t *sig,
                                     pgp_revocation_type_t *code,
                                     char **                reason);

bool signature_set_revocation_reason(pgp_signature_t *     sig,
                                     pgp_revocation_type_t code,
                                     const char *          reason);

/**
 * @brief Fill signature's hashed data. This includes all the fields from signature which are
 *        hashed after the previous document or key fields.
 * @param sig Signature being populated
 * @return true if sig->hashed_data is filled up correctly or false otherwise
 */
bool signature_fill_hashed_data(pgp_signature_t *sig);

/**
 * @brief Hash key packet. Used in signatures and v4 fingerprint calculation.
 * @param key key packet, must be populated
 * @param hash pointer to initialized hash context
 * @return true if sig->hashed_data is filled up correctly or false otherwise
 */
bool signature_hash_key(const pgp_key_pkt_t *key, pgp_hash_t *hash);

bool signature_hash_userid(const pgp_userid_pkt_t *uid,
                           pgp_hash_t *            hash,
                           pgp_version_t           sigver);

bool signature_hash_signature(pgp_signature_t *sig, pgp_hash_t *hash);

bool signature_hash_certification(const pgp_signature_t * sig,
                                  const pgp_key_pkt_t *   key,
                                  const pgp_userid_pkt_t *userid,
                                  pgp_hash_t *            hash);

bool signature_hash_binding(const pgp_signature_t *sig,
                            const pgp_key_pkt_t *  key,
                            const pgp_key_pkt_t *  subkey,
                            pgp_hash_t *           hash);

bool signature_hash_direct(const pgp_signature_t *sig,
                           const pgp_key_pkt_t *  key,
                           pgp_hash_t *           hash);

/**
 * @brief Check signature, including the expiration time, key validity and so on.
 *
 * @param sinfo populated signature info structure. Method will set flags valid, no_signer,
 *              expired.
 * @param hash populated hash
 * @return RNP_SUCCESS if all checks were passed, RNP_ERROR_SIGNATURE_INVALID for invalid sig,
 *         RNP_ERROR_SIGNATURE_EXPIRED for expired signature. Other error code means problems
 *         during the signature validation (out of memory, wrong parameters, etc).
 */
rnp_result_t signature_check(pgp_signature_info_t *sinfo, pgp_hash_t *hash);

rnp_result_t signature_check_certification(pgp_signature_info_t *  sinfo,
                                           const pgp_key_pkt_t *   key,
                                           const pgp_userid_pkt_t *uid);

rnp_result_t signature_check_binding(pgp_signature_info_t *sinfo,
                                     const pgp_key_pkt_t * key,
                                     pgp_key_t *           subkey);

rnp_result_t signature_check_direct(pgp_signature_info_t *sinfo, const pgp_key_pkt_t *key);

rnp_result_t signature_check_subkey_revocation(pgp_signature_info_t *sinfo,
                                               const pgp_key_pkt_t * key,
                                               const pgp_key_pkt_t * subkey);

/**
 * @brief Parse stream with signatures to the signatures list.
 *        Can handle binary or armored stream with signatures, including stream with multiple
 * armored signatures.
 *
 * @param src signatures stream, cannot be NULL.
 * @param sigs on success parsed signature structures will be put here.
 * @return RNP_SUCCESS or error code otherwise.
 */
rnp_result_t process_pgp_signatures(pgp_source_t *src, pgp_signature_list_t &sigs);

#endif
