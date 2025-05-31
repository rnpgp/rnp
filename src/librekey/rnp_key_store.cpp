/*
 * Copyright (c) 2017-2023 [Ribose Inc](https://www.ribose.com).
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

namespace rnp {
bool
KeyStore::load(const pgp_key_provider_t *key_provider)
{
    pgp_source_t src = {};

    if (format == PGP_KEY_STORE_G10) {
        auto dir = rnp_opendir(path.c_str());
        if (!dir) {
            RNP_LOG("Can't open G10 directory %s: %s", path.c_str(), strerror(errno));
            return false;
        }

        std::string dirname;
        while (!((dirname = rnp_readdir_name(dir)).empty())) {
            std::string apath = rnp::path::append(path, dirname);

            if (init_file_src(&src, apath.c_str())) {
                RNP_LOG("failed to read file %s", apath.c_str());
                continue;
            }
            // G10 may fail to read one file, so ignore it!
            if (!load_g10(src, key_provider)) {
                RNP_LOG("Can't parse file: %s", apath.c_str()); // TODO: %S ?
            }
            src_close(&src);
        }
        rnp_closedir(dir);
        return true;
    }

    /* init file source and load from it */
    if (init_file_src(&src, path.c_str())) {
        RNP_LOG("failed to read file %s", path.c_str());
        return false;
    }

    bool rc = load(src, key_provider);
    src_close(&src);
    return rc;
}

bool
KeyStore::load(pgp_source_t &src, const pgp_key_provider_t *key_provider)
{
    switch (format) {
    case PGP_KEY_STORE_GPG:
        return !load_pgp(src);
    case PGP_KEY_STORE_KBX:
        return load_kbx(src, key_provider);
    case PGP_KEY_STORE_G10:
        return load_g10(src, key_provider);
    default:
        RNP_LOG("Unsupported load from memory for key-store format: %d", format);
    }

    return false;
}

bool
KeyStore::write()
{
    bool       rc;
    pgp_dest_t keydst = {};

    /* write g10 key store to the directory */
    if (format == PGP_KEY_STORE_G10) {
        char chpath[MAXPATHLEN];

        struct stat path_stat;
        if (rnp_stat(path.c_str(), &path_stat) != -1) {
            if (!S_ISDIR(path_stat.st_mode)) {
                RNP_LOG("G10 keystore should be a directory: %s", path.c_str());
                return false;
            }
        } else {
            if (errno != ENOENT) {
                RNP_LOG("stat(%s): %s", path.c_str(), strerror(errno));
                return false;
            }
            if (RNP_MKDIR(path.c_str(), S_IRWXU) != 0) {
                RNP_LOG("mkdir(%s, S_IRWXU): %s", path.c_str(), strerror(errno));
                return false;
            }
        }

        for (auto &key : keys) {
            char grip[PGP_MAX_FINGERPRINT_HEX_SIZE] = {0};
            rnp::hex_encode(key.grip().data(), key.grip().size(), grip, sizeof(grip));
            snprintf(chpath, sizeof(chpath), "%s/%s.key", path.c_str(), grip);

            if (init_tmpfile_dest(&keydst, chpath, true)) {
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
    if (init_tmpfile_dest(&keydst, path.c_str(), true)) {
        RNP_LOG("failed to create keystore file");
        return false;
    }

    if (!write(keydst)) {
        RNP_LOG("failed to write keys to file");
        dst_close(&keydst, true);
        return false;
    }

    rc = dst_finish(&keydst) == RNP_SUCCESS;
    dst_close(&keydst, !rc);
    return rc;
}

bool
KeyStore::write(pgp_dest_t &dst)
{
    switch (format) {
    case PGP_KEY_STORE_GPG:
        return write_pgp(dst);
    case PGP_KEY_STORE_KBX:
        return write_kbx(dst);
    default:
        RNP_LOG("Unsupported write to memory for key-store format: %d", format);
    }

    return false;
}

void
KeyStore::clear()
{
    keybyfp.clear();
    keys.clear();
    blobs.clear();
}

size_t
KeyStore::key_count() const
{
    return keys.size();
}

namespace {
bool
rnp_key_store_refresh_subkey_grips(KeyStore *keyring, pgp_key_t *key)
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
} // namespace

pgp_key_t *
KeyStore::add_subkey(pgp_key_t &srckey, pgp_key_t *oldkey)
{
    pgp_key_t *primary = NULL;
    if (oldkey) {
        primary = primary_key(*oldkey);
    }
    if (!primary) {
        primary = primary_key(srckey);
    }

    if (oldkey) {
        /* check for the weird case when same subkey has different primary keys */
        if (srckey.has_primary_fp() && oldkey->has_primary_fp() &&
            (srckey.primary_fp() != oldkey->primary_fp())) {
            RNP_LOG_KEY("Warning: different primary keys for subkey %s", &srckey);
            pgp_key_t *srcprim = get_key(srckey.primary_fp());
            if (srcprim && (srcprim != primary)) {
                srcprim->remove_subkey_fp(srckey.fp());
            }
        }
        /* in case we already have key let's merge it in */
        if (!oldkey->merge(srckey, primary)) {
            RNP_LOG_KEY("failed to merge subkey %s", &srckey);
            RNP_LOG_KEY("primary key is %s", primary);
            return NULL;
        }
    } else {
        try {
            keys.emplace_back();
            oldkey = &keys.back();
            keybyfp[srckey.fp()] = std::prev(keys.end());
            *oldkey = pgp_key_t(srckey);
            if (primary) {
                primary->link_subkey_fp(*oldkey);
            }
        } catch (const std::exception &e) {
            RNP_LOG_KEY("key %s copying failed", &srckey);
            RNP_LOG_KEY("primary key is %s", primary);
            RNP_LOG("%s", e.what());
            if (oldkey) {
                keys.pop_back();
                keybyfp.erase(srckey.fp());
            }
            return nullptr;
        }
    }

    /* validate all added keys if not disabled */
    if (!disable_validation && !oldkey->validated()) {
        oldkey->validate_subkey(primary, secctx);
    }
    if (!oldkey->refresh_data(primary, secctx)) {
        RNP_LOG_KEY("Failed to refresh subkey %s data", &srckey);
        RNP_LOG_KEY("primary key is %s", primary);
    }
    return oldkey;
}

/* add a key to keyring */
pgp_key_t *
KeyStore::add_key(pgp_key_t &srckey)
{
    assert(srckey.type() && srckey.version());
    pgp_key_t *added_key = get_key(srckey.fp());
    /* we cannot merge G10 keys - so just return it */
    if (added_key && (srckey.format == PGP_KEY_STORE_G10)) {
        return added_key;
    }
    /* different processing for subkeys */
    if (srckey.is_subkey()) {
        return add_subkey(srckey, added_key);
    }

    if (added_key) {
        if (!added_key->merge(srckey)) {
            RNP_LOG_KEY("failed to merge key %s", &srckey);
            return NULL;
        }
    } else {
        try {
            keys.emplace_back();
            added_key = &keys.back();
            keybyfp[srckey.fp()] = std::prev(keys.end());
            *added_key = pgp_key_t(srckey);
            /* primary key may be added after subkeys, so let's handle this case correctly */
            if (!rnp_key_store_refresh_subkey_grips(this, added_key)) {
                RNP_LOG_KEY("failed to refresh subkey grips for %s", added_key);
            }
        } catch (const std::exception &e) {
            RNP_LOG_KEY("key %s copying failed", &srckey);
            RNP_LOG("%s", e.what());
            if (added_key) {
                keys.pop_back();
                keybyfp.erase(srckey.fp());
            }
            return NULL;
        }
    }

    /* validate all added keys if not disabled or already validated */
    if (!disable_validation && !added_key->validated()) {
        added_key->revalidate(*this);
    } else if (!added_key->refresh_data(secctx)) {
        RNP_LOG_KEY("Failed to refresh key %s data", &srckey);
    }
    return added_key;
}

pgp_key_t *
KeyStore::import_key(pgp_key_t &srckey, bool pubkey, pgp_key_import_status_t *status)
{
    /* add public key */
    pgp_key_t *exkey = get_key(srckey.fp());
    size_t     expackets = exkey ? exkey->rawpkt_count() : 0;
    try {
        pgp_key_t keycp(srckey, pubkey);
        disable_validation = true;
        exkey = add_key(keycp);
        disable_validation = false;
        if (!exkey) {
            RNP_LOG("failed to add key to the keyring");
            return nullptr;
        }
        bool changed = exkey->rawpkt_count() > expackets;
        if (changed || !exkey->validated()) {
            /* this will revalidated primary key with all subkeys */
            exkey->revalidate(*this);
        }
        if (status) {
            *status = changed ? (expackets ? PGP_KEY_IMPORT_STATUS_UPDATED :
                                             PGP_KEY_IMPORT_STATUS_NEW) :
                                PGP_KEY_IMPORT_STATUS_UNCHANGED;
        }
        return exkey;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        disable_validation = false;
        return nullptr;
    }
}

pgp_sig_import_status_t
KeyStore::import_subkey_signature(pgp_key_t &key, const pgp_signature_t &sig)
{
    if ((sig.type() != PGP_SIG_SUBKEY) && (sig.type() != PGP_SIG_REV_SUBKEY)) {
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }
    pgp_key_t *primary = get_signer(sig);
    if (!primary || !key.has_primary_fp()) {
        RNP_LOG("No primary grip or primary key");
        return PGP_SIG_IMPORT_STATUS_UNKNOWN_KEY;
    }
    if (primary->fp() != key.primary_fp()) {
        RNP_LOG("Wrong subkey signature's signer.");
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }

    try {
        pgp_key_t tmpkey(key.pkt());
        tmpkey.add_sig(sig);
        if (!tmpkey.refresh_data(primary, secctx)) {
            RNP_LOG("Failed to add signature to the key.");
            return PGP_SIG_IMPORT_STATUS_UNKNOWN;
        }

        size_t expackets = key.rawpkt_count();
        auto   nkey = add_key(tmpkey);
        if (!nkey) {
            RNP_LOG("Failed to add key with imported sig to the keyring");
            return PGP_SIG_IMPORT_STATUS_UNKNOWN;
        }
        return (nkey->rawpkt_count() > expackets) ? PGP_SIG_IMPORT_STATUS_NEW :
                                                    PGP_SIG_IMPORT_STATUS_UNCHANGED;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }
}

pgp_sig_import_status_t
KeyStore::import_signature(pgp_key_t &key, const pgp_signature_t &sig)
{
    if (key.is_subkey()) {
        return import_subkey_signature(key, sig);
    }
    if ((sig.type() != PGP_SIG_DIRECT) && (sig.type() != PGP_SIG_REV_KEY)) {
        RNP_LOG("Wrong signature type: %d", (int) sig.type());
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }

    try {
        pgp_key_t tmpkey(key.pkt());
        tmpkey.add_sig(sig);
        if (!tmpkey.refresh_data(secctx)) {
            RNP_LOG("Failed to add signature to the key.");
            return PGP_SIG_IMPORT_STATUS_UNKNOWN;
        }

        size_t expackets = key.rawpkt_count();
        auto   nkey = add_key(tmpkey);
        if (!nkey) {
            RNP_LOG("Failed to add key with imported sig to the keyring");
            return PGP_SIG_IMPORT_STATUS_UNKNOWN;
        }
        return (nkey->rawpkt_count() > expackets) ? PGP_SIG_IMPORT_STATUS_NEW :
                                                    PGP_SIG_IMPORT_STATUS_UNCHANGED;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }
}

pgp_key_t *
KeyStore::import_signature(const pgp_signature_t &sig, pgp_sig_import_status_t *status)
{
    pgp_sig_import_status_t tmp_status = PGP_SIG_IMPORT_STATUS_UNKNOWN;
    if (!status) {
        status = &tmp_status;
    }
    *status = PGP_SIG_IMPORT_STATUS_UNKNOWN;

    /* we support only direct-key and key revocation signatures here */
    if ((sig.type() != PGP_SIG_DIRECT) && (sig.type() != PGP_SIG_REV_KEY)) {
        return nullptr;
    }

    pgp_key_t *res_key = get_signer(sig);
    if (!res_key || !res_key->is_primary()) {
        *status = PGP_SIG_IMPORT_STATUS_UNKNOWN_KEY;
        return nullptr;
    }
    *status = import_signature(*res_key, sig);
    return res_key;
}

bool
KeyStore::remove_key(const pgp_key_t &key, bool subkeys)
{
    auto it = keybyfp.find(key.fp());
    if (it == keybyfp.end()) {
        return false;
    }

    /* cleanup primary_grip (or subkey)/subkey_grips */
    if (key.is_primary() && key.subkey_count()) {
        for (size_t i = 0; i < key.subkey_count(); i++) {
            auto its = keybyfp.find(key.get_subkey_fp(i));
            if (its == keybyfp.end()) {
                continue;
            }
            /* if subkeys are deleted then no need to update grips */
            if (subkeys) {
                keys.erase(its->second);
                keybyfp.erase(its);
                continue;
            }
            its->second->unset_primary_fp();
        }
    }
    if (key.is_subkey() && key.has_primary_fp()) {
        pgp_key_t *primary = primary_key(key);
        if (primary) {
            primary->remove_subkey_fp(key.fp());
        }
    }

    keys.erase(it->second);
    keybyfp.erase(it);
    return true;
}

const pgp_key_t *
KeyStore::get_key(const pgp_fingerprint_t &fpr) const
{
    auto it = keybyfp.find(fpr);
    if (it == keybyfp.end()) {
        return nullptr;
    }
    return &*it->second;
}

pgp_key_t *
KeyStore::get_key(const pgp_fingerprint_t &fpr)
{
    auto it = keybyfp.find(fpr);
    if (it == keybyfp.end()) {
        return nullptr;
    }
    return &*it->second;
}

pgp_key_t *
KeyStore::get_subkey(const pgp_key_t &key, size_t idx)
{
    if (idx >= key.subkey_count()) {
        return nullptr;
    }
    return get_key(key.get_subkey_fp(idx));
}

pgp_key_t *
KeyStore::primary_key(const pgp_key_t &subkey)
{
    if (!subkey.is_subkey()) {
        return nullptr;
    }

    if (subkey.has_primary_fp()) {
        pgp_key_t *primary = get_key(subkey.primary_fp());
        return primary && primary->is_primary() ? primary : nullptr;
    }

    for (size_t i = 0; i < subkey.sig_count(); i++) {
        auto &subsig = subkey.get_sig(i);
        if (subsig.sig.type() != PGP_SIG_SUBKEY) {
            continue;
        }

        pgp_key_t *primary = get_signer(subsig.sig);
        if (primary && primary->is_primary()) {
            return primary;
        }
    }
    return nullptr;
}

pgp_key_t *
KeyStore::search(const pgp_key_search_t &search, pgp_key_t *after)
{
    // since keys are distinguished by fingerprint then just do map lookup
    if (search.type == PGP_KEY_SEARCH_FINGERPRINT) {
        pgp_key_t *key = get_key(search.by.fingerprint);
        if (after && (after != key)) {
            RNP_LOG("searching with invalid after param");
            return nullptr;
        }
        // return NULL if after is specified
        return after ? nullptr : key;
    }

    // if after is provided, make sure it is a member of the appropriate list
    auto it = std::find_if(keys.begin(), keys.end(), [after](const pgp_key_t &key) {
        return !after || (after == &key);
    });
    if (after && (it == keys.end())) {
        RNP_LOG("searching with non-keyrings after param");
        return nullptr;
    }
    if (after) {
        it = std::next(it);
    }
    it = std::find_if(it, keys.end(), [search](const pgp_key_t &key) {
        return rnp_key_matches_search(&key, &search);
    });
    return (it == keys.end()) ? nullptr : &(*it);
}

pgp_key_t *
KeyStore::get_signer(const pgp_signature_t &sig, pgp_key_provider_t *prov)
{
    pgp_key_request_ctx_t ctx(PGP_OP_VERIFY, false, PGP_KEY_SEARCH_UNKNOWN);
    /* if we have fingerprint let's check it */
    if (sig.has_keyfp()) {
        ctx.search.by.fingerprint = sig.keyfp();
        ctx.search.type = PGP_KEY_SEARCH_FINGERPRINT;
    } else if (sig.has_keyid()) {
        ctx.search.by.keyid = sig.keyid();
        ctx.search.type = PGP_KEY_SEARCH_KEYID;
    } else {
        RNP_LOG("No way to search for the signer.");
        return nullptr;
    }

    pgp_key_t *key = search(ctx.search);
    if (key || !prov) {
        return key;
    }
    return prov->request_key(ctx);
}

KeyStore::KeyStore(pgp_key_store_format_t _format,
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

KeyStore::~KeyStore()
{
    clear();
}
} // namespace rnp
