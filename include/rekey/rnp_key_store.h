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

#ifndef KEY_STORE_H_
#define KEY_STORE_H_

#include <stdint.h>
#include <stdbool.h>
#include "rnp.h"
#include "librepgp/stream-common.h"
#include "pgp-key.h"
#include <string>
#include <list>
#include <map>
#include <unordered_map>

typedef enum {
    KBX_EMPTY_BLOB = 0,
    KBX_HEADER_BLOB = 1,
    KBX_PGP_BLOB = 2,
    KBX_X509_BLOB = 3
} kbx_blob_type;

typedef struct {
    uint32_t      length;
    kbx_blob_type type;

    uint8_t *image;
} kbx_blob_t;

typedef struct {
    kbx_blob_t blob;
    uint8_t    version;
    uint16_t   flags;
    uint32_t   file_created_at;
    uint32_t   last_maintenance_run;
} kbx_header_blob_t;

typedef struct {
    uint8_t  fp[PGP_FINGERPRINT_SIZE];
    uint32_t keyid_offset;
    uint16_t flags;
} kbx_pgp_key_t;

typedef struct {
    uint32_t offset;
    uint32_t length;
    uint16_t flags;
    uint8_t  validity;
} kbx_pgp_uid_t;

typedef struct {
    uint32_t expired;
} kbx_pgp_sig_t;

typedef struct {
    kbx_blob_t blob;
    uint8_t    version;
    uint16_t   flags;
    uint32_t   keyblock_offset;
    uint32_t   keyblock_length;

    uint16_t nkeys;
    uint16_t keys_len;
    list     keys; // list of kbx_pgp_key_t

    uint16_t sn_size;
    uint8_t *sn;

    uint16_t nuids;
    uint16_t uids_len;
    list     uids; // list of kbx_pgp_uid_t

    uint16_t nsigs;
    uint16_t sigs_len;
    list     sigs; // list of kbx_pgp_sig_t

    uint8_t ownertrust;
    uint8_t all_Validity;

    uint32_t recheck_after;
    uint32_t latest_timestamp;
    uint32_t blob_created_at;
} kbx_pgp_blob_t;

/* Key import status. Order of elements is important. */
typedef enum pgp_key_import_status_t {
    PGP_KEY_IMPORT_STATUS_UNKNOWN = 0,
    PGP_KEY_IMPORT_STATUS_UNCHANGED,
    PGP_KEY_IMPORT_STATUS_UPDATED,
    PGP_KEY_IMPORT_STATUS_NEW,
} pgp_key_import_status_t;

typedef enum pgp_sig_import_status_t {
    PGP_SIG_IMPORT_STATUS_UNKNOWN = 0,
    PGP_SIG_IMPORT_STATUS_UNKNOWN_KEY,
    PGP_SIG_IMPORT_STATUS_UNCHANGED,
    PGP_SIG_IMPORT_STATUS_NEW
} pgp_sig_import_status_t;

typedef std::unordered_map<pgp_fingerprint_t, std::list<pgp_key_t>::iterator> pgp_key_fp_map_t;

typedef struct rnp_key_store_t {
    std::string            path;
    pgp_key_store_format_t format;
    bool                   disable_validation =
      false; /* do not automatically validate keys, added to this key store */

    std::list<pgp_key_t> keys;
    pgp_key_fp_map_t     keybyfp;

    list blobs = NULL; // list of kbx_blob_t

    ~rnp_key_store_t();
    rnp_key_store_t() : path(""), format(PGP_KEY_STORE_UNKNOWN){};
    rnp_key_store_t(pgp_key_store_format_t format, const std::string &path);
    /* make sure we use only empty constructor */
    rnp_key_store_t(rnp_key_store_t &&src) = delete;
    rnp_key_store_t &operator=(rnp_key_store_t &&) = delete;
    rnp_key_store_t(const rnp_key_store_t &src) = delete;
    rnp_key_store_t &operator=(const rnp_key_store_t &) = delete;
} rnp_key_store_t;

bool rnp_key_store_load_from_path(rnp_key_store_t *, const pgp_key_provider_t *key_provider);
bool rnp_key_store_load_from_src(rnp_key_store_t *,
                                 pgp_source_t *,
                                 const pgp_key_provider_t *key_provider);

bool rnp_key_store_write_to_path(rnp_key_store_t *);
bool rnp_key_store_write_to_dst(rnp_key_store_t *, pgp_dest_t *);

void rnp_key_store_clear(rnp_key_store_t *);

size_t rnp_key_store_get_key_count(const rnp_key_store_t *);

/**
 * @brief Add key to the keystore, copying it.
 *
 * @param keyring allocated keyring, cannot be NULL.
 * @param key key to be added, cannot be NULL.
 * @return pointer to the added key or NULL if failed.
 */
pgp_key_t *rnp_key_store_add_key(rnp_key_store_t *keyring, pgp_key_t *key);

pgp_key_t *rnp_key_store_import_key(rnp_key_store_t *,
                                    pgp_key_t *,
                                    bool,
                                    pgp_key_import_status_t *);

/**
 * @brief Get signer's key from key store.
 *
 * @param store populated key store, cannot be NULL.
 * @param sig signature, cannot be NULL.
 * @return pointer to pgp_key_t structure if key was found or NULL otherwise.
 */
pgp_key_t *rnp_key_store_get_signer_key(rnp_key_store_t *store, const pgp_signature_t *sig);

pgp_sig_import_status_t rnp_key_store_import_key_signature(rnp_key_store_t *      keyring,
                                                           pgp_key_t *            key,
                                                           const pgp_signature_t *sig);

/**
 * @brief Import revocation or direct-key signature to the keyring.
 *
 * @param keyring populated keyring, cannot be NULL.
 * @param sig signature to import.
 * @param status signature import status will be put here, if not NULL.
 * @return pointer to the key to which this signature belongs (or NULL if key was not found)
 */
pgp_key_t *rnp_key_store_import_signature(rnp_key_store_t *        keyring,
                                          const pgp_signature_t *  sig,
                                          pgp_sig_import_status_t *status);

bool rnp_key_store_remove_key(rnp_key_store_t *, const pgp_key_t *, bool);

pgp_key_t *rnp_key_store_get_key_by_id(rnp_key_store_t *   keyring,
                                       const pgp_key_id_t &keyid,
                                       pgp_key_t *         key);

bool rnp_key_store_get_key_grip(const pgp_key_material_t *, pgp_key_grip_t &grip);

const pgp_key_t *rnp_key_store_get_key_by_grip(const rnp_key_store_t *,
                                               const pgp_key_grip_t &);
pgp_key_t *      rnp_key_store_get_key_by_grip(rnp_key_store_t *, const pgp_key_grip_t &);
const pgp_key_t *rnp_key_store_get_key_by_fpr(const rnp_key_store_t *,
                                              const pgp_fingerprint_t &fpr);
pgp_key_t *      rnp_key_store_get_key_by_fpr(rnp_key_store_t *, const pgp_fingerprint_t &fpr);
pgp_key_t *      rnp_key_store_get_primary_key(rnp_key_store_t *, const pgp_key_t *);
pgp_key_t *rnp_key_store_search(rnp_key_store_t *, const pgp_key_search_t *, pgp_key_t *);

#endif /* KEY_STORE_H_ */
