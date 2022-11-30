/*
 * Copyright (c) 2017-2022 [Ribose Inc](https://www.ribose.com).
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

#include "config.h"
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#else
#include "uniwin.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <algorithm>
#include <stdexcept>

#include <rekey/rnp_key_store.h>
#include <librepgp/stream-packet.h>

#include "key_store_pgp.h"
#include "key_store_kbx.h"
#include "key_store_g10.h"
#include "kbx_blob.hpp"

#include "pgp-key.h"
#include "fingerprint.h"
#include "crypto/hash.hpp"
#include "crypto/mem.h"
#include "file-utils.h"
#ifdef _WIN32
#include "str-utils.h"
#endif

bool
rnp_key_store_load_from_path(rnp_key_store_t *         key_store,
                             const pgp_key_provider_t *key_provider)
{
    pgp_source_t src = {};

    if (key_store->format == PGP_KEY_STORE_G10) {
        auto dir = rnp_opendir(key_store->path.c_str());
        if (!dir) {
            RNP_LOG(
              "Can't open G10 directory %s: %s", key_store->path.c_str(), strerror(errno));
            return false;
        }

        std::string dirname;
        while (!((dirname = rnp_readdir_name(dir)).empty())) {
            std::string path = rnp::path::append(key_store->path, dirname);

            if (init_file_src(&src, path.c_str())) {
                RNP_LOG("failed to read file %s", path.c_str());
                continue;
            }
            // G10 may fail to read one file, so ignore it!
            if (!rnp_key_store_g10_from_src(key_store, &src, key_provider)) {
                RNP_LOG("Can't parse file: %s", path.c_str()); // TODO: %S ?
            }
            src_close(&src);
        }
        rnp_closedir(dir);
        return true;
    }

    /* init file source and load from it */
    if (init_file_src(&src, key_store->path.c_str())) {
        RNP_LOG("failed to read file %s", key_store->path.c_str());
        return false;
    }

    bool rc = rnp_key_store_load_from_src(key_store, &src, key_provider);
    src_close(&src);
    return rc;
}

bool
rnp_key_store_load_from_src(rnp_key_store_t *         key_store,
                            pgp_source_t *            src,
                            const pgp_key_provider_t *key_provider)
{
    switch (key_store->format) {
    case PGP_KEY_STORE_GPG:
        return rnp_key_store_pgp_read_from_src(key_store, src) == RNP_SUCCESS;
    case PGP_KEY_STORE_KBX:
        return rnp_key_store_kbx_from_src(key_store, src, key_provider);
    case PGP_KEY_STORE_G10:
        return rnp_key_store_g10_from_src(key_store, src, key_provider);
    default:
        RNP_LOG("Unsupported load from memory for key-store format: %d", key_store->format);
    }

    return false;
}

bool
rnp_key_store_write_to_path(rnp_key_store_t *key_store)
{
    bool       rc;
    pgp_dest_t keydst = {};

    /* write g10 key store to the directory */
    if (key_store->format == PGP_KEY_STORE_G10) {
        char path[MAXPATHLEN];

        struct stat path_stat;
        if (rnp_stat(key_store->path.c_str(), &path_stat) != -1) {
            if (!S_ISDIR(path_stat.st_mode)) {
                RNP_LOG("G10 keystore should be a directory: %s", key_store->path.c_str());
                return false;
            }
        } else {
            if (errno != ENOENT) {
                RNP_LOG("stat(%s): %s", key_store->path.c_str(), strerror(errno));
                return false;
            }
            if (RNP_MKDIR(key_store->path.c_str(), S_IRWXU) != 0) {
                RNP_LOG("mkdir(%s, S_IRWXU): %s", key_store->path.c_str(), strerror(errno));
                return false;
            }
        }

        for (auto &key : key_store->keys) {
            char grip[PGP_FINGERPRINT_HEX_SIZE] = {0};
            rnp::hex_encode(key.grip().data(), key.grip().size(), grip, sizeof(grip));
            snprintf(path, sizeof(path), "%s/%s.key", key_store->path.c_str(), grip);

            if (init_tmpfile_dest(&keydst, path, true)) {
                RNP_LOG("failed to create file");
                return false;
            }

            if (!rnp_key_store_gnupg_sexp_to_dst(&key, &keydst)) {
                RNP_LOG("failed to write key to file");
                dst_close(&keydst, true);
                return false;
            }

            rc = dst_finish(&keydst) == RNP_SUCCESS;
            dst_close(&keydst, !rc);

            if (!rc) {
                return false;
            }
        }

        return true;
    }

    /* write kbx/gpg store to the single file */
    if (init_tmpfile_dest(&keydst, key_store->path.c_str(), true)) {
        RNP_LOG("failed to create keystore file");
        return false;
    }

    if (!rnp_key_store_write_to_dst(key_store, &keydst)) {
        RNP_LOG("failed to write keys to file");
        dst_close(&keydst, true);
        return false;
    }

    rc = dst_finish(&keydst) == RNP_SUCCESS;
    dst_close(&keydst, !rc);
    return rc;
}

bool
rnp_key_store_write_to_dst(rnp_key_store_t *key_store, pgp_dest_t *dst)
{
    switch (key_store->format) {
    case PGP_KEY_STORE_GPG:
        return rnp_key_store_pgp_write_to_dst(key_store, dst);
    case PGP_KEY_STORE_KBX:
        return rnp_key_store_kbx_to_dst(key_store, dst);
    default:
        RNP_LOG("Unsupported write to memory for key-store format: %d", key_store->format);
    }

    return false;
}

void
rnp_key_store_clear(rnp_key_store_t *keyring)
{
    keyring->keybyfp.clear();
    keyring->keys.clear();
    keyring->blobs.clear();
}

size_t
rnp_key_store_get_key_count(const rnp_key_store_t *keyring)
{
    return keyring->keys.size();
}

static bool
rnp_key_store_refresh_subkey_grips(rnp_key_store_t *keyring, pgp_key_t *key)
{
    if (key->is_subkey()) {
        RNP_LOG("wrong argument");
        return false;
    }

    for (auto &skey : keyring->keys) {
        bool found = false;

        /* if we have primary_grip then we also added to subkey_grips */
        if (!skey.is_subkey() || skey.has_primary_fp()) {
            continue;
        }

        for (size_t i = 0; i < skey.sig_count(); i++) {
            const pgp_subsig_t &subsig = skey.get_sig(i);

            if (subsig.sig.type() != PGP_SIG_SUBKEY) {
                continue;
            }
            if (subsig.sig.has_keyfp() && (key->fp() == subsig.sig.keyfp())) {
                found = true;
                break;
            }
            if (subsig.sig.has_keyid() && (key->keyid() == subsig.sig.keyid())) {
                found = true;
                break;
            }
        }

        if (found) {
            try {
                key->link_subkey_fp(skey);
            } catch (const std::exception &e) {
                RNP_LOG("%s", e.what());
                return false;
            }
        }
    }

    return true;
}

static pgp_key_t *
rnp_key_store_add_subkey(rnp_key_store_t *keyring, pgp_key_t *srckey, pgp_key_t *oldkey)
{
    pgp_key_t *primary = NULL;
    if (oldkey) {
        primary = rnp_key_store_get_primary_key(keyring, oldkey);
    }
    if (!primary) {
        primary = rnp_key_store_get_primary_key(keyring, srckey);
    }

    if (oldkey) {
        /* check for the weird case when same subkey has different primary keys */
        if (srckey->has_primary_fp() && oldkey->has_primary_fp() &&
            (srckey->primary_fp() != oldkey->primary_fp())) {
            RNP_LOG_KEY("Warning: different primary keys for subkey %s", srckey);
            pgp_key_t *srcprim = rnp_key_store_get_key_by_fpr(keyring, srckey->primary_fp());
            if (srcprim && (srcprim != primary)) {
                srcprim->remove_subkey_fp(srckey->fp());
            }
        }
        /* in case we already have key let's merge it in */
        if (!oldkey->merge(*srckey, primary)) {
            RNP_LOG_KEY("failed to merge subkey %s", srckey);
            RNP_LOG_KEY("primary key is %s", primary);
            return NULL;
        }
    } else {
        try {
            keyring->keys.emplace_back();
            oldkey = &keyring->keys.back();
            keyring->keybyfp[srckey->fp()] = std::prev(keyring->keys.end());
            *oldkey = pgp_key_t(*srckey);
            if (primary) {
                primary->link_subkey_fp(*oldkey);
            }
        } catch (const std::exception &e) {
            RNP_LOG_KEY("key %s copying failed", srckey);
            RNP_LOG_KEY("primary key is %s", primary);
            RNP_LOG("%s", e.what());
            if (oldkey) {
                keyring->keys.pop_back();
                keyring->keybyfp.erase(srckey->fp());
            }
            return NULL;
        }
    }

    /* validate all added keys if not disabled */
    if (!keyring->disable_validation && !oldkey->validated()) {
        oldkey->validate_subkey(primary, keyring->secctx);
    }
    if (!oldkey->refresh_data(primary, keyring->secctx)) {
        RNP_LOG_KEY("Failed to refresh subkey %s data", srckey);
        RNP_LOG_KEY("primary key is %s", primary);
    }
    return oldkey;
}

/* add a key to keyring */
pgp_key_t *
rnp_key_store_add_key(rnp_key_store_t *keyring, pgp_key_t *srckey)
{
    assert(srckey->type() && srckey->version());
    pgp_key_t *added_key = rnp_key_store_get_key_by_fpr(keyring, srckey->fp());
    /* we cannot merge G10 keys - so just return it */
    if (added_key && (srckey->format == PGP_KEY_STORE_G10)) {
        return added_key;
    }
    /* different processing for subkeys */
    if (srckey->is_subkey()) {
        return rnp_key_store_add_subkey(keyring, srckey, added_key);
    }

    if (added_key) {
        if (!added_key->merge(*srckey)) {
            RNP_LOG_KEY("failed to merge key %s", srckey);
            return NULL;
        }
    } else {
        try {
            keyring->keys.emplace_back();
            added_key = &keyring->keys.back();
            keyring->keybyfp[srckey->fp()] = std::prev(keyring->keys.end());
            *added_key = pgp_key_t(*srckey);
            /* primary key may be added after subkeys, so let's handle this case correctly */
            if (!rnp_key_store_refresh_subkey_grips(keyring, added_key)) {
                RNP_LOG_KEY("failed to refresh subkey grips for %s", added_key);
            }
        } catch (const std::exception &e) {
            RNP_LOG_KEY("key %s copying failed", srckey);
            RNP_LOG("%s", e.what());
            if (added_key) {
                keyring->keys.pop_back();
                keyring->keybyfp.erase(srckey->fp());
            }
            return NULL;
        }
    }

    /* validate all added keys if not disabled or already validated */
    if (!keyring->disable_validation && !added_key->validated()) {
        added_key->revalidate(*keyring);
    } else if (!added_key->refresh_data(keyring->secctx)) {
        RNP_LOG_KEY("Failed to refresh key %s data", srckey);
    }
    return added_key;
}

pgp_key_t *
rnp_key_store_import_key(rnp_key_store_t *        keyring,
                         pgp_key_t *              srckey,
                         bool                     pubkey,
                         pgp_key_import_status_t *status)
{
    /* add public key */
    pgp_key_t *exkey = rnp_key_store_get_key_by_fpr(keyring, srckey->fp());
    size_t     expackets = exkey ? exkey->rawpkt_count() : 0;
    try {
        pgp_key_t keycp(*srckey, pubkey);
        keyring->disable_validation = true;
        exkey = rnp_key_store_add_key(keyring, &keycp);
        keyring->disable_validation = false;
        if (!exkey) {
            RNP_LOG("failed to add key to the keyring");
            return NULL;
        }
        bool changed = exkey->rawpkt_count() > expackets;
        if (changed || !exkey->validated()) {
            /* this will revalidated primary key with all subkeys */
            exkey->revalidate(*keyring);
        }
        if (status) {
            *status = changed ? (expackets ? PGP_KEY_IMPORT_STATUS_UPDATED :
                                             PGP_KEY_IMPORT_STATUS_NEW) :
                                PGP_KEY_IMPORT_STATUS_UNCHANGED;
        }
        return exkey;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        keyring->disable_validation = false;
        return NULL;
    }
}

pgp_key_t *
rnp_key_store_get_signer_key(rnp_key_store_t *store, const pgp_signature_t *sig)
{
    pgp_key_search_t search;
    // prefer using the issuer fingerprint when available
    if (sig->has_keyfp()) {
        search.by.fingerprint = sig->keyfp();
        search.type = PGP_KEY_SEARCH_FINGERPRINT;
        return rnp_key_store_search(store, &search, NULL);
    }
    // fall back to key id search
    if (sig->has_keyid()) {
        search.by.keyid = sig->keyid();
        search.type = PGP_KEY_SEARCH_KEYID;
        return rnp_key_store_search(store, &search, NULL);
    }
    return NULL;
}

static pgp_sig_import_status_t
rnp_key_store_import_subkey_signature(rnp_key_store_t *      keyring,
                                      pgp_key_t *            key,
                                      const pgp_signature_t *sig)
{
    if ((sig->type() != PGP_SIG_SUBKEY) && (sig->type() != PGP_SIG_REV_SUBKEY)) {
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }
    pgp_key_t *primary = rnp_key_store_get_signer_key(keyring, sig);
    if (!primary || !key->has_primary_fp()) {
        RNP_LOG("No primary grip or primary key");
        return PGP_SIG_IMPORT_STATUS_UNKNOWN_KEY;
    }
    if (primary->fp() != key->primary_fp()) {
        RNP_LOG("Wrong subkey signature's signer.");
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }

    try {
        pgp_key_t tmpkey(key->pkt());
        tmpkey.add_sig(*sig);
        if (!tmpkey.refresh_data(primary, keyring->secctx)) {
            RNP_LOG("Failed to add signature to the key.");
            return PGP_SIG_IMPORT_STATUS_UNKNOWN;
        }

        size_t expackets = key->rawpkt_count();
        key = rnp_key_store_add_key(keyring, &tmpkey);
        if (!key) {
            RNP_LOG("Failed to add key with imported sig to the keyring");
            return PGP_SIG_IMPORT_STATUS_UNKNOWN;
        }
        return (key->rawpkt_count() > expackets) ? PGP_SIG_IMPORT_STATUS_NEW :
                                                   PGP_SIG_IMPORT_STATUS_UNCHANGED;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }
}

pgp_sig_import_status_t
rnp_key_store_import_key_signature(rnp_key_store_t *      keyring,
                                   pgp_key_t *            key,
                                   const pgp_signature_t *sig)
{
    if (key->is_subkey()) {
        return rnp_key_store_import_subkey_signature(keyring, key, sig);
    }
    if ((sig->type() != PGP_SIG_DIRECT) && (sig->type() != PGP_SIG_REV_KEY)) {
        RNP_LOG("Wrong signature type: %d", (int) sig->type());
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }

    try {
        pgp_key_t tmpkey(key->pkt());
        tmpkey.add_sig(*sig);
        if (!tmpkey.refresh_data(keyring->secctx)) {
            RNP_LOG("Failed to add signature to the key.");
            return PGP_SIG_IMPORT_STATUS_UNKNOWN;
        }

        size_t expackets = key->rawpkt_count();
        key = rnp_key_store_add_key(keyring, &tmpkey);
        if (!key) {
            RNP_LOG("Failed to add key with imported sig to the keyring");
            return PGP_SIG_IMPORT_STATUS_UNKNOWN;
        }
        return (key->rawpkt_count() > expackets) ? PGP_SIG_IMPORT_STATUS_NEW :
                                                   PGP_SIG_IMPORT_STATUS_UNCHANGED;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }
}

pgp_key_t *
rnp_key_store_import_signature(rnp_key_store_t *        keyring,
                               const pgp_signature_t *  sig,
                               pgp_sig_import_status_t *status)
{
    pgp_sig_import_status_t tmp_status = PGP_SIG_IMPORT_STATUS_UNKNOWN;
    if (!status) {
        status = &tmp_status;
    }
    *status = PGP_SIG_IMPORT_STATUS_UNKNOWN;

    /* we support only direct-key and key revocation signatures here */
    if ((sig->type() != PGP_SIG_DIRECT) && (sig->type() != PGP_SIG_REV_KEY)) {
        return NULL;
    }

    pgp_key_t *res_key = rnp_key_store_get_signer_key(keyring, sig);
    if (!res_key || !res_key->is_primary()) {
        *status = PGP_SIG_IMPORT_STATUS_UNKNOWN_KEY;
        return NULL;
    }
    *status = rnp_key_store_import_key_signature(keyring, res_key, sig);
    return res_key;
}

bool
rnp_key_store_remove_key(rnp_key_store_t *keyring, const pgp_key_t *key, bool subkeys)
{
    auto it = keyring->keybyfp.find(key->fp());
    if (it == keyring->keybyfp.end()) {
        return false;
    }

    /* cleanup primary_grip (or subkey)/subkey_grips */
    if (key->is_primary() && key->subkey_count()) {
        for (size_t i = 0; i < key->subkey_count(); i++) {
            auto it = keyring->keybyfp.find(key->get_subkey_fp(i));
            if (it == keyring->keybyfp.end()) {
                continue;
            }
            /* if subkeys are deleted then no need to update grips */
            if (subkeys) {
                keyring->keys.erase(it->second);
                keyring->keybyfp.erase(it);
                continue;
            }
            it->second->unset_primary_fp();
        }
    }
    if (key->is_subkey() && key->has_primary_fp()) {
        pgp_key_t *primary = rnp_key_store_get_primary_key(keyring, key);
        if (primary) {
            primary->remove_subkey_fp(key->fp());
        }
    }

    keyring->keys.erase(it->second);
    keyring->keybyfp.erase(it);
    return true;
}

const pgp_key_t *
rnp_key_store_get_key_by_fpr(const rnp_key_store_t *keyring, const pgp_fingerprint_t &fpr)
{
    auto it = keyring->keybyfp.find(fpr);
    if (it == keyring->keybyfp.end()) {
        return NULL;
    }
    return &*it->second;
}

pgp_key_t *
rnp_key_store_get_key_by_fpr(rnp_key_store_t *keyring, const pgp_fingerprint_t &fpr)
{
    auto it = keyring->keybyfp.find(fpr);
    if (it == keyring->keybyfp.end()) {
        return NULL;
    }
    return &*it->second;
}

pgp_key_t *
rnp_key_store_get_primary_key(rnp_key_store_t *keyring, const pgp_key_t *subkey)
{
    if (!subkey->is_subkey()) {
        return NULL;
    }

    if (subkey->has_primary_fp()) {
        pgp_key_t *primary = rnp_key_store_get_key_by_fpr(keyring, subkey->primary_fp());
        return primary && primary->is_primary() ? primary : NULL;
    }

    for (size_t i = 0; i < subkey->sig_count(); i++) {
        const pgp_subsig_t &subsig = subkey->get_sig(i);
        if (subsig.sig.type() != PGP_SIG_SUBKEY) {
            continue;
        }

        pgp_key_t *primary = rnp_key_store_get_signer_key(keyring, &subsig.sig);
        if (primary && primary->is_primary()) {
            return primary;
        }
    }
    return NULL;
}

static void
grip_hash_mpi(rnp::Hash &hash, const pgp_mpi_t &val, const char name, bool lzero = true)
{
    size_t len = mpi_bytes(&val);
    size_t idx = 0;
    for (idx = 0; (idx < len) && !val.mpi[idx]; idx++)
        ;

    if (name) {
        size_t hlen = idx >= len ? 0 : len - idx;
        if ((len > idx) && lzero && (val.mpi[idx] & 0x80)) {
            hlen++;
        }

        char buf[20] = {0};
        snprintf(buf, sizeof(buf), "(1:%c%zu:", name, hlen);
        hash.add(buf, strlen(buf));
    }

    if (idx < len) {
        /* gcrypt prepends mpis with zero if higher bit is set */
        if (lzero && (val.mpi[idx] & 0x80)) {
            uint8_t zero = 0;
            hash.add(&zero, 1);
        }
        hash.add(val.mpi + idx, len - idx);
    }
    if (name) {
        hash.add(")", 1);
    }
}

static void
grip_hash_ecc_hex(rnp::Hash &hash, const char *hex, char name)
{
    pgp_mpi_t mpi = {};
    mpi.len = rnp::hex_decode(hex, mpi.mpi, sizeof(mpi.mpi));
    if (!mpi.len) {
        RNP_LOG("wrong hex mpi");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    /* libgcrypt doesn't add leading zero when hashes ecc mpis */
    return grip_hash_mpi(hash, mpi, name, false);
}

static void
grip_hash_ec(rnp::Hash &hash, const pgp_ec_key_t &key)
{
    const ec_curve_desc_t *desc = get_curve_desc(key.curve);
    if (!desc) {
        RNP_LOG("unknown curve %d", (int) key.curve);
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    /* build uncompressed point from gx and gy */
    pgp_mpi_t g = {};
    g.mpi[0] = 0x04;
    g.len = 1;
    size_t len = rnp::hex_decode(desc->gx, g.mpi + g.len, sizeof(g.mpi) - g.len);
    if (!len) {
        RNP_LOG("wrong x mpi");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    g.len += len;
    len = rnp::hex_decode(desc->gy, g.mpi + g.len, sizeof(g.mpi) - g.len);
    if (!len) {
        RNP_LOG("wrong y mpi");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    g.len += len;

    /* p, a, b, g, n, q */
    grip_hash_ecc_hex(hash, desc->p, 'p');
    grip_hash_ecc_hex(hash, desc->a, 'a');
    grip_hash_ecc_hex(hash, desc->b, 'b');
    grip_hash_mpi(hash, g, 'g', false);
    grip_hash_ecc_hex(hash, desc->n, 'n');

    if ((key.curve == PGP_CURVE_ED25519) || (key.curve == PGP_CURVE_25519)) {
        if (g.len < 1) {
            RNP_LOG("wrong 25519 p");
            throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
        }
        g.len = key.p.len - 1;
        memcpy(g.mpi, key.p.mpi + 1, g.len);
        grip_hash_mpi(hash, g, 'q', false);
    } else {
        grip_hash_mpi(hash, key.p, 'q', false);
    }
}

/* keygrip is subjectKeyHash from pkcs#15 for RSA. */
bool
rnp_key_store_get_key_grip(const pgp_key_material_t *key, pgp_key_grip_t &grip)
{
    try {
        auto hash = rnp::Hash::create(PGP_HASH_SHA1);
        switch (key->alg) {
        case PGP_PKA_RSA:
        case PGP_PKA_RSA_SIGN_ONLY:
        case PGP_PKA_RSA_ENCRYPT_ONLY:
            grip_hash_mpi(*hash, key->rsa.n, '\0');
            break;
        case PGP_PKA_DSA:
            grip_hash_mpi(*hash, key->dsa.p, 'p');
            grip_hash_mpi(*hash, key->dsa.q, 'q');
            grip_hash_mpi(*hash, key->dsa.g, 'g');
            grip_hash_mpi(*hash, key->dsa.y, 'y');
            break;
        case PGP_PKA_ELGAMAL:
        case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
            grip_hash_mpi(*hash, key->eg.p, 'p');
            grip_hash_mpi(*hash, key->eg.g, 'g');
            grip_hash_mpi(*hash, key->eg.y, 'y');
            break;
        case PGP_PKA_ECDH:
        case PGP_PKA_ECDSA:
        case PGP_PKA_EDDSA:
        case PGP_PKA_SM2:
            grip_hash_ec(*hash, key->ec);
            break;
        default:
            RNP_LOG("unsupported public-key algorithm %d", (int) key->alg);
            return false;
        }
        return hash->finish(grip.data()) == grip.size();
    } catch (const std::exception &e) {
        RNP_LOG("Grip calculation failed: %s", e.what());
        return false;
    }
}

pgp_key_t *
rnp_key_store_search(rnp_key_store_t *       keyring,
                     const pgp_key_search_t *search,
                     pgp_key_t *             after)
{
    // since keys are distinguished by fingerprint then just do map lookup
    if (search->type == PGP_KEY_SEARCH_FINGERPRINT) {
        pgp_key_t *key = rnp_key_store_get_key_by_fpr(keyring, search->by.fingerprint);
        if (after && (after != key)) {
            RNP_LOG("searching with invalid after param");
            return NULL;
        }
        // return NULL if after is specified
        return after ? NULL : key;
    }

    // if after is provided, make sure it is a member of the appropriate list
    auto it =
      std::find_if(keyring->keys.begin(), keyring->keys.end(), [after](const pgp_key_t &key) {
          return !after || (after == &key);
      });
    if (after && (it == keyring->keys.end())) {
        RNP_LOG("searching with non-keyrings after param");
        return NULL;
    }
    if (after) {
        it = std::next(it);
    }
    it = std::find_if(it, keyring->keys.end(), [search](const pgp_key_t &key) {
        return rnp_key_matches_search(&key, search);
    });
    return (it == keyring->keys.end()) ? NULL : &(*it);
}

rnp_key_store_t::rnp_key_store_t(pgp_key_store_format_t _format,
                                 const std::string &    _path,
                                 rnp::SecurityContext & ctx)
    : secctx(ctx)
{
    if (_format == PGP_KEY_STORE_UNKNOWN) {
        RNP_LOG("Invalid key store format");
        throw std::invalid_argument("format");
    }
    format = _format;
    path = _path;
}

rnp_key_store_t::~rnp_key_store_t()
{
    rnp_key_store_clear(this);
}
