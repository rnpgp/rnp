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
#include "errors.h"
#include <repgp/repgp.h>
#include <rnp/rnp.h>
#include "stream-common.h"

/**
 * @brief Check whether signature packet matches one-pass signature packet.
 * @param sig pointer to the read signature packet
 * @param onepass pointer to the read one-pass signature packet
 * @return true if sig corresponds to onepass or false otherwise
 */
bool signature_matches_onepass(pgp_signature_t *sig, pgp_one_pass_sig_t *onepass);

/**
 * @brief Get v4 signature's subpacket of the specified type
 * @param sig loaded or populated signature, could not be NULL
 * @param type type of the subpacket to lookup for
 * @return pointer to the subpacket structure or NULL if it was not found or error occurred
 */
pgp_sig_subpkt_t *signature_get_subpkt(const pgp_signature_t *  sig,
                                       pgp_sig_subpacket_type_t type);

/**
 * @brief Add subpacket of the specified type to v4 signature
 * @param sig loaded or populated signature, could not be NULL
 * @param type type of the subpacket
 * @param datalen length of the subpacket body
 * @param reuse replace already existing subpacket of the specified type if any
 * @return pointer to the subpacket structure or NULL if error occurred
 */
pgp_sig_subpkt_t *signature_add_subpkt(pgp_signature_t *        sig,
                                       pgp_sig_subpacket_type_t type,
                                       size_t                   datalen,
                                       bool                     reuse);

/**
 * @brief Check whether signature has signing key fingerprint
 * @param sig loaded or populated v4 signature, could not be NULL
 * @return true if fingerprint is available or false otherwise
 */
bool signature_has_keyfp(const pgp_signature_t *sig);

/**
 * @brief Get signing key's fingerprint if it is available
 * @param sig loaded or populated v4 signature, could not be NULL
 * @param fp pointer to the buffer of at least PGP_FINGERPRINT_SIZE bytes
 * @param len number of bytes in buffer
 * @param outlen pointer to the number of bytes written to fp (if succeeded). Could not be 0.
 * @return true if fingerprint is available and returned or false otherwise
 */
bool signature_get_keyfp(const pgp_signature_t *sig, pgp_fingerprint_t *fp);

/**
 * @brief Set signing key fingerprint
 * @param sig v4 signature being populated
 * @param fp fingerprint structure
 * @return true on success or false otherwise;
 */
bool signature_set_keyfp(pgp_signature_t *sig, const pgp_fingerprint_t *fp);

/**
 * @brief Check whether signature has signing key id
 * @param sig populated or loaded signature
 * @return true if key id available (via v3 field, or v4 key id/key fp subpacket)
 */
bool signature_has_keyid(const pgp_signature_t *sig);

/**
 * @brief Get signature's signing key id
 * @param sig populated or loaded signature
 * @param id buffer to return key identifier, must be capable of storing PGP_KEY_ID_SIZE bytes
 * @return true on success or false otherwise
 */
bool signature_get_keyid(const pgp_signature_t *sig, uint8_t *id);

/**
 * @brief Set the signature's key id
 * @param sig signature being populated. Version should be set prior of setting key id.
 * @param id pointer to buffer with PGP_KEY_ID_SIZE bytes of key id.
 * @return true on success or false otherwise
 */
bool signature_set_keyid(pgp_signature_t *sig, uint8_t *id);

/**
 * @brief Get signature's creation time
 * @param sig pointer to the loaded or populated signature.
 * @return time in seconds since the Jan 1, 1970 UTC. 0 is the default value and returned even
 *         if creation time is not available
 */
uint32_t signature_get_creation(const pgp_signature_t *sig);

/**
 * @brief Set signature's creation time
 * @param sig signature being populated
 * @param ctime creation time in seconds since the Jan 1, 1970 UTC.
 * @return true on success or false otherwise
 */
bool signature_set_creation(pgp_signature_t *sig, uint32_t ctime);

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
 * @brief Check whether signature has key expiration
 * @param sig populated or loaded signature
 * @return true if signature has key expiration time or false otherwise
 */
bool signature_has_key_expiration(const pgp_signature_t *sig);

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
 * @brief Check whether signature has key flags
 * @param sig populated or loaded signature
 * @return true if key flags are available or false otherwise
 */
bool signature_has_key_flags(const pgp_signature_t *sig);

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

bool signature_has_preferred_symm_algs(const pgp_signature_t *sig);

bool signature_get_preferred_symm_algs(const pgp_signature_t *sig,
                                       uint8_t **             algs,
                                       size_t *               count);

bool signature_set_preferred_symm_algs(pgp_signature_t *sig, uint8_t algs[], size_t len);

bool signature_has_preferred_hash_algs(const pgp_signature_t *sig);

bool signature_get_preferred_hash_algs(const pgp_signature_t *sig,
                                       uint8_t **             algs,
                                       size_t *               count);

bool signature_set_preferred_hash_algs(pgp_signature_t *sig, uint8_t algs[], size_t len);

bool signature_has_preferred_z_algs(const pgp_signature_t *sig);

bool signature_get_preferred_z_algs(const pgp_signature_t *sig, uint8_t **algs, size_t *count);

bool signature_set_preferred_z_algs(pgp_signature_t *sig, uint8_t algs[], size_t len);

bool signature_has_key_server_prefs(const pgp_signature_t *sig);

uint8_t signature_get_key_server_prefs(const pgp_signature_t *sig);

bool signature_set_key_server_prefs(pgp_signature_t *sig, uint8_t prefs);

bool signature_set_preferred_key_server(pgp_signature_t *sig, const char *uri);

bool signature_has_trust(const pgp_signature_t *sig);

bool signature_get_trust(const pgp_signature_t *sig, uint8_t *level, uint8_t *amount);

bool signature_set_trust(pgp_signature_t *sig, uint8_t level, uint8_t amount);

bool signature_get_revocable(const pgp_signature_t *sig);

bool signature_set_revocable(pgp_signature_t *sig, bool revocable);

bool signature_set_features(pgp_signature_t *sig, uint8_t features);

bool signature_set_signer_uid(pgp_signature_t *sig, uint8_t *uid, size_t len);

bool signature_set_embedded_sig(pgp_signature_t *sig, uint8_t *esig, size_t len);

bool signature_add_notation_data(pgp_signature_t *sig,
                                 bool             readable,
                                 const char *     name,
                                 const char *     value);

bool signature_has_key_server(const pgp_signature_t *sig);

char *signature_get_key_server(const pgp_signature_t *sig);

bool signature_has_revocation_reason(const pgp_signature_t *sig);

bool signature_get_revocation_reason(const pgp_signature_t *sig, uint8_t *code, char **reason);

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
 * @brief Add signature fields to the hash context and finish it.
 * @param hash initialized hash context feeded with signed data (document, key, etc).
 *             It is finalized in this function.
 * @param sig populated or loaded signature
 * @param hbuf buffer to store the resulting hash. Must be large enough for hash output.
 * @param hlen on success will be filled with the hash size, otherwise zeroed
 * @return true on success or false otherwise
 */
bool signature_hash_finish(const pgp_signature_t *sig,
                           pgp_hash_t *           hash,
                           uint8_t *              hbuf,
                           size_t *               hlen);

/**
 * @brief Validate a signature with pre-populated hash. This method just checks correspondence
 *        between the hash and signature material. Expiration time and other fields are not
 *        checked for validity.
 * @param sig signature to validate
 * @param key public key material of the verifying key
 * @param hash pre-populated with signed data hash context. It is finalized and destroyed
 *             during the execution. Signature fields and trailer are hashed in this function.
 * @param rng random number generator
 * @return RNP_SUCCESS if signature was successfully validated or error code otherwise.
 */
rnp_result_t signature_validate(const pgp_signature_t *   sig,
                                const pgp_key_material_t *key,
                                pgp_hash_t *              hash,
                                rng_t *                   rng);

rnp_result_t signature_validate_certification(const pgp_signature_t *   sig,
                                              const pgp_key_pkt_t *     key,
                                              const pgp_userid_pkt_t *  uid,
                                              const pgp_key_material_t *signer,
                                              rng_t *                   rng);

rnp_result_t signature_validate_binding(const pgp_signature_t *sig,
                                        const pgp_key_pkt_t *  key,
                                        const pgp_key_pkt_t *  subkey,
                                        rng_t *                rng);

rnp_result_t signature_validate_direct(const pgp_signature_t *   sig,
                                       const pgp_key_pkt_t *     key,
                                       const pgp_key_material_t *signer,
                                       rng_t *                   rng);

/**
 * @brief Calculate signature with pre-populated hash
 * @param sig signature to calculate
 * @param seckey signing secret key material
 * @param hash pre-populated with signed data hash context. It is finalized and destroyed
 *             during the execution. Signature fields and trailer are hashed in this function.
 * @param rng random number generator
 * @return RNP_SUCCESS if signature was successfully calculated or error code otherwise
 */
rnp_result_t signature_calculate(pgp_signature_t *         sig,
                                 const pgp_key_material_t *seckey,
                                 pgp_hash_t *              hash,
                                 rng_t *                   rng);

#endif
