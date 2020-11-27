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
#include "rnp.h"
#include "stream-common.h"
#include "stream-sig.h"
#include "stream-packet.h"

/** Struct to hold a key packet. May contain public or private key/subkey */
typedef struct pgp_key_pkt_t {
    pgp_pkt_type_t   tag;           /* packet tag: public key/subkey or private key/subkey */
    pgp_version_t    version;       /* Key packet version */
    uint32_t         creation_time; /* Key creation time */
    pgp_pubkey_alg_t alg;
    uint16_t         v3_days; /* v2/v3 validity time */

    uint8_t *hashed_data; /* key's hashed data used for signature calculation */
    size_t   hashed_len;

    pgp_key_material_t material;

    /* secret key data, if available. sec_len == 0, sec_data == NULL for public key/subkey */
    pgp_key_protection_t sec_protection;
    uint8_t *            sec_data;
    size_t               sec_len;

    pgp_key_pkt_t()
        : tag(PGP_PKT_RESERVED), version(PGP_VUNKNOWN), creation_time(0), alg(PGP_PKA_NOTHING),
          v3_days(0), hashed_data(NULL), hashed_len(0), material({}), sec_protection({}),
          sec_data(NULL), sec_len(0){};
    pgp_key_pkt_t(const pgp_key_pkt_t &src, bool pubonly = false);
    pgp_key_pkt_t(pgp_key_pkt_t &&src);
    pgp_key_pkt_t &operator=(pgp_key_pkt_t &&src);
    pgp_key_pkt_t &operator=(const pgp_key_pkt_t &src);
    ~pgp_key_pkt_t();

    void         write(pgp_dest_t &dst);
    rnp_result_t parse(pgp_source_t &src);
    /** @brief Fills the hashed (signed) data part of the key packet. Must be called before
     *         pgp_key_pkt_t::write() on the newly generated key */
    void fill_hashed_data();
    bool equals(const pgp_key_pkt_t &key, bool pubonly = false) const noexcept;
} pgp_key_pkt_t;

/* userid/userattr with all the corresponding signatures */
typedef struct pgp_transferable_userid_t {
    pgp_userid_pkt_t     uid;
    pgp_signature_list_t signatures;
} pgp_transferable_userid_t;

/* subkey with all corresponding signatures */
typedef struct pgp_transferable_subkey_t {
    pgp_key_pkt_t        subkey;
    pgp_signature_list_t signatures;

    pgp_transferable_subkey_t() = default;
    pgp_transferable_subkey_t(const pgp_transferable_subkey_t &src, bool pubonly = false);
    pgp_transferable_subkey_t &operator=(const pgp_transferable_subkey_t &) = default;
} pgp_transferable_subkey_t;

/* transferable key with userids, subkeys and revocation signatures */
typedef struct pgp_transferable_key_t {
    pgp_key_pkt_t                          key; /* main key packet */
    std::vector<pgp_transferable_userid_t> userids;
    std::vector<pgp_transferable_subkey_t> subkeys;
    pgp_signature_list_t                   signatures;

    pgp_transferable_key_t() = default;
    pgp_transferable_key_t(const pgp_transferable_key_t &src, bool pubonly = false);
    pgp_transferable_key_t &operator=(const pgp_transferable_key_t &) = default;
} pgp_transferable_key_t;

/* sequence of OpenPGP transferable keys */
typedef struct pgp_key_sequence_t {
    std::vector<pgp_transferable_key_t> keys;
} pgp_key_sequence_t;

rnp_result_t transferable_key_from_key(pgp_transferable_key_t &dst, const pgp_key_t &key);

rnp_result_t transferable_key_merge(pgp_transferable_key_t &      dst,
                                    const pgp_transferable_key_t &src);

rnp_result_t transferable_subkey_from_key(pgp_transferable_subkey_t &dst,
                                          const pgp_key_t &          key);

rnp_result_t transferable_subkey_merge(pgp_transferable_subkey_t &      dst,
                                       const pgp_transferable_subkey_t &src);

pgp_transferable_userid_t *transferable_key_add_userid(pgp_transferable_key_t &key,
                                                       const char *            userid);

pgp_signature_t *transferable_userid_certify(const pgp_key_pkt_t &          key,
                                             pgp_transferable_userid_t &    userid,
                                             const pgp_key_pkt_t &          signer,
                                             pgp_hash_alg_t                 hash_alg,
                                             const rnp_selfsig_cert_info_t &cert);

pgp_signature_t *transferable_subkey_bind(const pgp_key_pkt_t &             primary_key,
                                          pgp_transferable_subkey_t &       subkey,
                                          pgp_hash_alg_t                    hash_alg,
                                          const rnp_selfsig_binding_info_t &binding);

pgp_signature_t *transferable_key_revoke(const pgp_key_pkt_t &key,
                                         const pgp_key_pkt_t &signer,
                                         pgp_hash_alg_t       hash_alg,
                                         const pgp_revoke_t & revoke);

/* Process single primary key or subkey, skipping all key-related packets on error.
   If key.key.tag is zero, then (on success) result is subkey and it is stored in
   key.subkeys[0].
   If returns RNP_ERROR_BAD_FORMAT then some packets failed parsing, but still key may contain
   successfully read key or subkey.
*/
rnp_result_t process_pgp_key_auto(pgp_source_t &          src,
                                  pgp_transferable_key_t &key,
                                  bool                    allowsub,
                                  bool                    skiperrors);

rnp_result_t process_pgp_keys(pgp_source_t *src, pgp_key_sequence_t &keys, bool skiperrors);

rnp_result_t process_pgp_key(pgp_source_t *src, pgp_transferable_key_t &key, bool skiperrors);

rnp_result_t process_pgp_subkey(pgp_source_t &             src,
                                pgp_transferable_subkey_t &subkey,
                                bool                       skiperrors);

rnp_result_t write_pgp_key(pgp_transferable_key_t &key, pgp_dest_t *dst, bool armor);

rnp_result_t write_pgp_keys(pgp_key_sequence_t &keys, pgp_dest_t *dst, bool armor);

rnp_result_t decrypt_secret_key(pgp_key_pkt_t *key, const char *password);

rnp_result_t encrypt_secret_key(pgp_key_pkt_t *key, const char *password, rng_t *rng);

void forget_secret_key_fields(pgp_key_material_t *key);

bool signature_calculate_certification(const pgp_key_pkt_t *   key,
                                       const pgp_userid_pkt_t *uid,
                                       pgp_signature_t *       sig,
                                       const pgp_key_pkt_t *   signer);

bool signature_calculate_direct(const pgp_key_pkt_t *key,
                                pgp_signature_t *    sig,
                                const pgp_key_pkt_t *signer);

bool signature_calculate_binding(const pgp_key_pkt_t *key,
                                 const pgp_key_pkt_t *sub,
                                 pgp_signature_t *    sig,
                                 bool                 subsign);

#endif
