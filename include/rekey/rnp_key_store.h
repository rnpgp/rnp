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
#include <memory>
#include "librekey/kbx_blob.hpp"
#include "sec_profile.hpp"

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

class rnp_key_store_t {
  private:
    pgp_key_t *             add_subkey(pgp_key_t &srckey, pgp_key_t *oldkey);
    pgp_sig_import_status_t import_subkey_signature(pgp_key_t &            key,
                                                    const pgp_signature_t &sig);

  public:
    std::string            path;
    pgp_key_store_format_t format;
    rnp::SecurityContext & secctx;
    bool                   disable_validation =
      false; /* do not automatically validate keys, added to this key store */

    std::list<pgp_key_t>                     keys;
    pgp_key_fp_map_t                         keybyfp;
    std::vector<std::unique_ptr<kbx_blob_t>> blobs;

    ~rnp_key_store_t();
    rnp_key_store_t(rnp::SecurityContext &ctx)
        : path(""), format(PGP_KEY_STORE_UNKNOWN), secctx(ctx){};
    rnp_key_store_t(pgp_key_store_format_t format,
                    const std::string &    path,
                    rnp::SecurityContext & ctx);
    /* make sure we use only empty constructor */
    rnp_key_store_t(rnp_key_store_t &&src) = delete;
    rnp_key_store_t &operator=(rnp_key_store_t &&) = delete;
    rnp_key_store_t(const rnp_key_store_t &src) = delete;
    rnp_key_store_t &operator=(const rnp_key_store_t &) = delete;

    /**
     * @brief Try to load key store from path.
     */
    bool load(const pgp_key_provider_t *key_provider = nullptr);

    /**
     * @brief Try to load key store from source.
     */
    bool load(pgp_source_t &src, const pgp_key_provider_t *key_provider = nullptr);

    /**
     * @brief Write key store to the path.
     */
    bool write();

    /**
     * @brief Write key store to the dest.
     */
    bool write(pgp_dest_t &dst);

    void clear();

    size_t key_count() const;

    pgp_key_t *      get_key(const pgp_fingerprint_t &fpr);
    const pgp_key_t *get_key(const pgp_fingerprint_t &fpr) const;

    /**
     * @brief Get the signer's key for signature
     *
     * @param sig signature
     * @param prov key provider to request needed key.
     * @return pointer to the key or nullptr if signer's key was not found.
     */
    pgp_key_t *get_signer(const pgp_signature_t &sig, pgp_key_provider_t *prov = nullptr);

    /**
     * @brief Add key to the keystore, copying it.
     * @return pointer to the added key or nullptr if failed.
     */
    pgp_key_t *add_key(pgp_key_t &key);

    /**
     * @brief Import key to the keystore.
     *
     * @param srckey source key.
     * @param pubkey import just public key part.
     * @param status if not nullptr then import status will be stored here.
     * @return pgp_key_t*
     */
    pgp_key_t *import_key(pgp_key_t &              srckey,
                          bool                     pubkey,
                          pgp_key_import_status_t *status = nullptr);

    /**
     * @brief Import signature for the specified key.
     */
    pgp_sig_import_status_t import_signature(pgp_key_t &key, const pgp_signature_t &sig);

    /**
     * @brief Import revocation or direct-key signature to the keystore.
     *
     * @param sig signature to import.
     * @param status signature import status will be put here, if not nullptr.
     * @return pointer to the key to which this signature belongs (or nullptr if key was not
     * found)
     */
    pgp_key_t *import_signature(const pgp_signature_t &sig, pgp_sig_import_status_t *status);
};

bool rnp_key_store_remove_key(rnp_key_store_t *, const pgp_key_t *, bool);

bool rnp_key_store_get_key_grip(const pgp_key_material_t *, pgp_key_grip_t &grip);

pgp_key_t *rnp_key_store_get_primary_key(rnp_key_store_t *, const pgp_key_t *);
pgp_key_t *rnp_key_store_search(rnp_key_store_t *, const pgp_key_search_t *, pgp_key_t *);

#endif /* KEY_STORE_H_ */
