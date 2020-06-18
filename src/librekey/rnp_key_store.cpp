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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <algorithm>
#include <stdexcept>

#include <rnp/rnp_sdk.h>
#include <rekey/rnp_key_store.h>
#include <librepgp/stream-packet.h>

#include "key_store_pgp.h"
#include "key_store_kbx.h"
#include "key_store_g10.h"

#include "pgp-key.h"
#include "fingerprint.h"
#include "crypto/hash.h"

// must be placed after include "utils.h"
#ifndef RNP_USE_STD_REGEX
#include <regex.h>
#else
#include <regex>
#endif

bool
rnp_key_store_load_from_path(rnp_key_store_t *         key_store,
                             const pgp_key_provider_t *key_provider)
{
    DIR *          dir;
    bool           rc;
    pgp_source_t   src = {};
    struct dirent *ent;
    char           path[MAXPATHLEN];

    if (key_store->format == PGP_KEY_STORE_G10) {
        dir = opendir(key_store->path.c_str());
        if (dir == NULL) {
            RNP_LOG(
              "Can't open G10 directory %s: %s", key_store->path.c_str(), strerror(errno));
            return false;
        }

        while ((ent = readdir(dir)) != NULL) {
            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
                continue;
            }

            snprintf(path, sizeof(path), "%s/%s", key_store->path.c_str(), ent->d_name);
            RNP_DLOG("Loading G10 key from file '%s'", path);

            if (init_file_src(&src, path)) {
                RNP_LOG("failed to read file %s", path);
                continue;
            }

            // G10 may don't read one file, so, ignore it!
            if (!rnp_key_store_g10_from_src(key_store, &src, key_provider)) {
                RNP_LOG("Can't parse file: %s", path);
            }
            src_close(&src);
        }
        closedir(dir);
        return true;
    }

    /* init file source and load from it */
    if (init_file_src(&src, key_store->path.c_str())) {
        RNP_LOG("failed to read file %s", key_store->path.c_str());
        return false;
    }

    rc = rnp_key_store_load_from_src(key_store, &src, key_provider);
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
        char grips[PGP_FINGERPRINT_HEX_SIZE];

        struct stat path_stat;
        if (stat(key_store->path.c_str(), &path_stat) != -1) {
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
            const pgp_key_grip_t &grip = pgp_key_get_grip(&key);
            snprintf(path,
                     sizeof(path),
                     "%s/%s.key",
                     key_store->path.c_str(),
                     rnp_strhexdump_upper(grips, grip.data(), grip.size(), ""));

            if (init_tmpfile_dest(&keydst, path, true)) {
                RNP_LOG("failed to create file");
                return false;
            }

            if (!rnp_key_store_g10_key_to_dst(&key, &keydst)) {
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
    keyring->keybygrip.clear();
    keyring->keys.clear();
    for (list_item *item = list_front(keyring->blobs); item; item = list_next(item)) {
        kbx_blob_t *blob = *((kbx_blob_t **) item);
        if (blob->type == KBX_PGP_BLOB) {
            kbx_pgp_blob_t *pgpblob = (kbx_pgp_blob_t *) blob;
            free_kbx_pgp_blob(pgpblob);
        }
        free(blob);
    }
    list_destroy(&keyring->blobs);
}

size_t
rnp_key_store_get_key_count(const rnp_key_store_t *keyring)
{
    return keyring->keys.size();
}

static bool
rnp_key_store_merge_subkey(pgp_key_t *dst, const pgp_key_t *src, pgp_key_t *primary)
{
    pgp_transferable_subkey_t dstkey = {};
    pgp_transferable_subkey_t srckey = {};
    pgp_key_t                 tmpkey = {};
    bool                      res = false;

    if (!pgp_key_is_subkey(dst) || !pgp_key_is_subkey(src)) {
        RNP_LOG("wrong subkey merge call");
        return false;
    }

    if (transferable_subkey_from_key(&dstkey, dst)) {
        RNP_LOG("failed to get transferable key from dstkey");
        return false;
    }

    if (transferable_subkey_from_key(&srckey, src)) {
        RNP_LOG("failed to get transferable key from srckey");
        transferable_subkey_destroy(&dstkey);
        return false;
    }

    /* if src is secret key then merged key will become secret as well. */
    if (is_secret_key_pkt(srckey.subkey.tag) && !is_secret_key_pkt(dstkey.subkey.tag)) {
        pgp_key_pkt_t tmp = dstkey.subkey;
        dstkey.subkey = srckey.subkey;
        srckey.subkey = tmp;
    }

    if (transferable_subkey_merge(&dstkey, &srckey)) {
        RNP_LOG("failed to merge transferable subkeys");
        goto done;
    }

    if (!rnp_key_from_transferable_subkey(&tmpkey, &dstkey, primary)) {
        RNP_LOG("failed to process subkey");
        goto done;
    }

    /* check whether key was unlocked and assign secret key data */
    if (pgp_key_is_secret(dst) && !pgp_key_is_locked(dst)) {
        /* we may do thing below only because key material is opaque structure without
         * pointers! */
        tmpkey.pkt.material = dst->pkt.material;
    } else if (pgp_key_is_secret(src) && !pgp_key_is_locked(src)) {
        tmpkey.pkt.material = src->pkt.material;
    }
    /* copy validity status */
    tmpkey.valid = dst->valid && src->valid;
    /* we may safely leave validated status only if both merged subkeys are valid && validated.
     * Otherwise we'll need to revalidate. For instance, one validated but invalid subkey may
     * add revocation signature, or valid subkey may add binding to the invalid one. */
    tmpkey.validated = dst->validated && src->validated && tmpkey.valid;

    *dst = std::move(tmpkey);
    res = true;
done:
    transferable_subkey_destroy(&dstkey);
    transferable_subkey_destroy(&srckey);
    return res;
}

static bool
rnp_key_store_merge_key(pgp_key_t *dst, const pgp_key_t *src)
{
    pgp_transferable_key_t dstkey = {};
    pgp_transferable_key_t srckey = {};
    pgp_key_t              tmpkey = {};
    bool                   res = false;

    if (pgp_key_is_subkey(dst) || pgp_key_is_subkey(src)) {
        RNP_LOG("wrong key merge call");
        return false;
    }

    if (transferable_key_from_key(&dstkey, dst)) {
        RNP_LOG("failed to get transferable key from dstkey");
        return false;
    }

    if (transferable_key_from_key(&srckey, src)) {
        RNP_LOG("failed to get transferable key from srckey");
        transferable_key_destroy(&dstkey);
        return false;
    }

    /* if src is secret key then merged key will become secret as well. */
    if (is_secret_key_pkt(srckey.key.tag) && !is_secret_key_pkt(dstkey.key.tag)) {
        pgp_key_pkt_t tmp = dstkey.key;
        dstkey.key = srckey.key;
        srckey.key = tmp;
        /* no subkey processing here - they are separated from the main key */
    }

    if (transferable_key_merge(&dstkey, &srckey)) {
        RNP_LOG("failed to merge transferable keys");
        goto done;
    }

    if (!rnp_key_from_transferable_key(&tmpkey, &dstkey)) {
        RNP_LOG("failed to process key");
        goto done;
    }

    /* move existing subkey grips since they are not present in transferable key */
    tmpkey.subkey_grips = std::move(dst->subkey_grips);
    for (auto &grip : src->subkey_grips) {
        if (!pgp_key_add_subkey_grip(&tmpkey, grip)) {
            RNP_LOG("failed to add subkey grip");
        }
    }
    /* check whether key was unlocked and assign secret key data */
    if (pgp_key_is_secret(dst) && !pgp_key_is_locked(dst)) {
        /* we may do thing below only because key material is opaque structure without
         * pointers! */
        tmpkey.pkt.material = dst->pkt.material;
    } else if (pgp_key_is_secret(src) && !pgp_key_is_locked(src)) {
        tmpkey.pkt.material = src->pkt.material;
    }
    /* copy validity status */
    tmpkey.valid = dst->valid && src->valid;
    /* We may safely leave validated status only if both merged keys are valid && validated.
     * Otherwise we'll need to revalidate. For instance, one validated but invalid key may add
     * revocation signature, or valid key may add certification to the invalid one. */
    tmpkey.validated = dst->validated && src->validated && tmpkey.valid;

    *dst = std::move(tmpkey);
    res = true;
done:
    transferable_key_destroy(&dstkey);
    transferable_key_destroy(&srckey);
    return res;
}

static bool
rnp_key_store_refresh_subkey_grips(rnp_key_store_t *keyring, pgp_key_t *key)
{
    uint8_t           keyid[PGP_KEY_ID_SIZE] = {0};
    pgp_fingerprint_t keyfp = {};

    if (pgp_key_is_subkey(key)) {
        RNP_LOG("wrong argument");
        return false;
    }

    for (auto &skey : keyring->keys) {
        bool found = false;

        /* if we have primary_grip then we also added to subkey_grips */
        if (!pgp_key_is_subkey(&skey) || pgp_key_has_primary_grip(&skey)) {
            continue;
        }

        for (unsigned i = 0; i < pgp_key_get_subsig_count(&skey); i++) {
            const pgp_subsig_t *subsig = pgp_key_get_subsig(&skey, i);

            if (subsig->sig.type != PGP_SIG_SUBKEY) {
                continue;
            }

            if (signature_get_keyfp(&subsig->sig, &keyfp) &&
                fingerprint_equal(pgp_key_get_fp(key), &keyfp)) {
                found = true;
                break;
            }

            if (signature_get_keyid(&subsig->sig, keyid) &&
                !memcmp(pgp_key_get_keyid(key), keyid, PGP_KEY_ID_SIZE)) {
                found = true;
                break;
            }
        }

        if (found && !pgp_key_link_subkey_grip(key, &skey)) {
            return false;
        }
    }

    return true;
}

static pgp_key_t *
rnp_key_store_add_subkey(rnp_key_store_t *keyring, pgp_key_t *srckey, pgp_key_t *oldkey)
{
    pgp_key_t *primary = rnp_key_store_get_primary_key(keyring, srckey);
    if (!primary && oldkey) {
        primary = rnp_key_store_get_primary_key(keyring, oldkey);
    }

    if (oldkey) {
        /* in case we already have key let's merge it in */
        if (!rnp_key_store_merge_subkey(oldkey, srckey, primary)) {
            RNP_LOG_KEY("failed to merge subkey %s", srckey);
            RNP_LOG_KEY("primary key is %s", primary);
            return NULL;
        }
    } else {
        try {
            keyring->keys.emplace_back();
            oldkey = &keyring->keys.back();
            keyring->keybygrip[pgp_key_get_grip(srckey)] = std::prev(keyring->keys.end());
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return NULL;
        }
        if (pgp_key_copy(oldkey, srckey, false)) {
            RNP_LOG_KEY("key %s copying failed", srckey);
            RNP_LOG_KEY("primary key is %s", primary);
            keyring->keys.pop_back();
            keyring->keybygrip.erase(pgp_key_get_grip(srckey));
            return NULL;
        }
        if (primary && !pgp_key_link_subkey_grip(primary, oldkey)) {
            RNP_LOG_KEY("failed to link subkey %s grip", oldkey);
            RNP_LOG_KEY("primary key is %s", primary);
        }
    }

    RNP_DLOG("keyc %lu", (long unsigned) rnp_key_store_get_key_count(keyring));
    /* validate all added keys if not disabled */
    if (!keyring->disable_validation && !oldkey->validated) {
        pgp_key_validate_subkey(oldkey, primary);
    }
    if (!pgp_subkey_refresh_data(oldkey, primary)) {
        RNP_LOG_KEY("Failed to refresh subkey %s data", srckey);
        RNP_LOG_KEY("primary key is %s", primary);
    }
    return oldkey;
}

/* add a key to keyring */
pgp_key_t *
rnp_key_store_add_key(rnp_key_store_t *keyring, pgp_key_t *srckey)
{
    assert(pgp_key_get_type(srckey) && pgp_key_get_version(srckey));
    pgp_key_t *added_key = rnp_key_store_get_key_by_grip(keyring, pgp_key_get_grip(srckey));
    /* we cannot merge G10 keys - so just return it */
    if (added_key && (srckey->format == PGP_KEY_STORE_G10)) {
        return added_key;
    }
    /* different processing for subkeys */
    if (pgp_key_is_subkey(srckey)) {
        return rnp_key_store_add_subkey(keyring, srckey, added_key);
    }

    if (added_key) {
        if (!rnp_key_store_merge_key(added_key, srckey)) {
            RNP_LOG_KEY("failed to merge key %s", srckey);
            return NULL;
        }
    } else {
        try {
            keyring->keys.emplace_back();
            added_key = &keyring->keys.back();
            keyring->keybygrip[pgp_key_get_grip(srckey)] = std::prev(keyring->keys.end());
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return NULL;
        }
        if (pgp_key_copy(added_key, srckey, false)) {
            RNP_LOG_KEY("key %s copying failed", srckey);
            keyring->keys.pop_back();
            keyring->keybygrip.erase(pgp_key_get_grip(srckey));
            return NULL;
        }
        /* primary key may be added after subkeys, so let's handle this case correctly */
        if (!rnp_key_store_refresh_subkey_grips(keyring, added_key)) {
            RNP_LOG_KEY("failed to refresh subkey grips for %s", added_key);
        }
    }

    RNP_DLOG("keyc %lu", (long unsigned) rnp_key_store_get_key_count(keyring));
    /* validate all added keys if not disabled or already validated */
    if (!keyring->disable_validation && !added_key->validated) {
        pgp_key_revalidate_updated(added_key, keyring);
    } else if (!pgp_key_refresh_data(added_key)) {
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
    pgp_key_t  keycp = {};
    pgp_key_t *exkey = NULL;
    size_t     expackets = 0;
    bool       changed = false;

    /* add public key */
    if (pgp_key_copy(&keycp, srckey, pubkey)) {
        RNP_LOG_KEY("failed to create key %s copy", srckey);
        return NULL;
    }
    exkey = rnp_key_store_get_key_by_grip(keyring, pgp_key_get_grip(srckey));
    expackets = exkey ? pgp_key_get_rawpacket_count(exkey) : 0;
    keyring->disable_validation = true;
    exkey = rnp_key_store_add_key(keyring, &keycp);
    keyring->disable_validation = false;
    if (!exkey) {
        RNP_LOG("failed to add key to the keyring");
        return NULL;
    }
    changed = pgp_key_get_rawpacket_count(exkey) > expackets;
    if (changed) {
        /* this will revalidated primary key with all subkeys */
        pgp_key_revalidate_updated(exkey, keyring);
    }
    if (status) {
        *status = changed ?
                    (expackets ? PGP_KEY_IMPORT_STATUS_UPDATED : PGP_KEY_IMPORT_STATUS_NEW) :
                    PGP_KEY_IMPORT_STATUS_UNCHANGED;
    }

    return exkey;
}

pgp_key_t *
rnp_key_store_get_signer_key(rnp_key_store_t *store, const pgp_signature_t *sig)
{
    pgp_key_search_t search = {};
    // prefer using the issuer fingerprint when available
    if (signature_has_keyfp(sig) && signature_get_keyfp(sig, &search.by.fingerprint)) {
        search.type = PGP_KEY_SEARCH_FINGERPRINT;
        return rnp_key_store_search(store, &search, NULL);
    }
    // fall back to key id search
    if (signature_get_keyid(sig, search.by.keyid)) {
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
    pgp_sig_type_t sigtype = signature_get_type(sig);
    if ((sigtype != PGP_SIG_SUBKEY) && (sigtype != PGP_SIG_REV_SUBKEY)) {
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }
    pgp_key_t *primary = rnp_key_store_get_signer_key(keyring, sig);
    if (!primary || !pgp_key_has_primary_grip(key)) {
        RNP_LOG("No primary grip or primary key");
        return PGP_SIG_IMPORT_STATUS_UNKNOWN_KEY;
    }
    if (pgp_key_get_grip(primary) != pgp_key_get_primary_grip(key)) {
        RNP_LOG("Wrong subkey signature's signer.");
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }

    pgp_key_t tmpkey = {};
    if (!pgp_key_from_pkt(&tmpkey, &key->pkt) || !rnp_key_add_signature(&tmpkey, sig) ||
        !pgp_subkey_refresh_data(&tmpkey, primary)) {
        RNP_LOG("Failed to add signature to the key.");
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }

    size_t expackets = pgp_key_get_rawpacket_count(key);
    key = rnp_key_store_add_key(keyring, &tmpkey);
    if (!key) {
        RNP_LOG("Failed to add key with imported sig to the keyring");
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }
    return (pgp_key_get_rawpacket_count(key) > expackets) ? PGP_SIG_IMPORT_STATUS_NEW :
                                                            PGP_SIG_IMPORT_STATUS_UNCHANGED;
}

pgp_sig_import_status_t
rnp_key_store_import_key_signature(rnp_key_store_t *      keyring,
                                   pgp_key_t *            key,
                                   const pgp_signature_t *sig)
{
    if (pgp_key_is_subkey(key)) {
        return rnp_key_store_import_subkey_signature(keyring, key, sig);
    }
    pgp_sig_type_t sigtype = signature_get_type(sig);
    if ((sigtype != PGP_SIG_DIRECT) && (sigtype != PGP_SIG_REV_KEY)) {
        RNP_LOG("Wrong signature type: %d", (int) sigtype);
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }

    pgp_key_t tmpkey = {};
    if (!pgp_key_from_pkt(&tmpkey, &key->pkt) || !rnp_key_add_signature(&tmpkey, sig) ||
        !pgp_key_refresh_data(&tmpkey)) {
        RNP_LOG("Failed to add signature to the key.");
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }

    size_t expackets = pgp_key_get_rawpacket_count(key);
    key = rnp_key_store_add_key(keyring, &tmpkey);
    if (!key) {
        RNP_LOG("Failed to add key with imported sig to the keyring");
        return PGP_SIG_IMPORT_STATUS_UNKNOWN;
    }
    return (pgp_key_get_rawpacket_count(key) > expackets) ? PGP_SIG_IMPORT_STATUS_NEW :
                                                            PGP_SIG_IMPORT_STATUS_UNCHANGED;
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

    pgp_sig_type_t sigtype = signature_get_type(sig);
    /* we support only direct-key and key revocation signatures here */
    if ((sigtype != PGP_SIG_DIRECT) && (sigtype != PGP_SIG_REV_KEY)) {
        return NULL;
    }

    pgp_key_t *res_key = rnp_key_store_get_signer_key(keyring, sig);
    if (!res_key || !pgp_key_is_primary_key(res_key)) {
        *status = PGP_SIG_IMPORT_STATUS_UNKNOWN_KEY;
        return NULL;
    }
    *status = rnp_key_store_import_key_signature(keyring, res_key, sig);
    return res_key;
}

bool
rnp_key_store_remove_key(rnp_key_store_t *keyring, const pgp_key_t *key, bool subkeys)
{
    auto it = keyring->keybygrip.find(pgp_key_get_grip(key));
    if (it == keyring->keybygrip.end()) {
        return false;
    }

    /* cleanup primary_grip (or subkey)/subkey_grips */
    if (pgp_key_is_primary_key(key) && pgp_key_get_subkey_count(key)) {
        for (size_t i = 0; i < pgp_key_get_subkey_count(key); i++) {
            auto it = keyring->keybygrip.find(pgp_key_get_subkey_grip(key, i));
            if (it == keyring->keybygrip.end()) {
                continue;
            }
            /* if subkeys are deleted then no need to update grips */
            if (subkeys) {
                keyring->keys.erase(it->second);
                keyring->keybygrip.erase(it);
                continue;
            }
            it->second->primary_grip = {};
            it->second->primary_grip_set = false;
        }
    }
    if (pgp_key_is_subkey(key) && pgp_key_has_primary_grip(key)) {
        pgp_key_t *primary = rnp_key_store_get_primary_key(keyring, key);
        if (primary) {
            pgp_key_remove_subkey_grip(primary, pgp_key_get_grip(key));
        }
    }

    keyring->keys.erase(it->second);
    keyring->keybygrip.erase(it);
    return true;
}

/**
   \ingroup HighLevel_KeyringFind

   \brief Finds key in keyring from its Key ID

   \param keyring Keyring to be searched
   \param keyid ID of required key

   \return Pointer to key, if found; NULL, if not found

   \note This returns a pointer to the key inside the given keyring,
   not a copy.  Do not free it after use.

*/
pgp_key_t *
rnp_key_store_get_key_by_id(rnp_key_store_t *keyring, const uint8_t *keyid, pgp_key_t *after)
{
    RNP_DLOG("searching keyring %p", keyring);
    if (!keyring) {
        return NULL;
    }

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
    it = std::find_if(it, keyring->keys.end(), [keyid](const pgp_key_t &key) {
        return !memcmp(pgp_key_get_keyid(&key), keyid, PGP_KEY_ID_SIZE) ||
               !memcmp(
                 pgp_key_get_keyid(&key) + PGP_KEY_ID_SIZE / 2, keyid, PGP_KEY_ID_SIZE / 2);
    });
    return (it == keyring->keys.end()) ? NULL : &(*it);
}

const pgp_key_t *
rnp_key_store_get_key_by_grip(const rnp_key_store_t *keyring, const pgp_key_grip_t &grip)
{
    auto it = keyring->keybygrip.find(grip);
    if (it == keyring->keybygrip.end()) {
        return NULL;
    }
    return &*it->second;
}

pgp_key_t *
rnp_key_store_get_key_by_grip(rnp_key_store_t *keyring, const pgp_key_grip_t &grip)
{
    auto it = keyring->keybygrip.find(grip);
    if (it == keyring->keybygrip.end()) {
        return NULL;
    }
    return &*it->second;
}

pgp_key_t *
rnp_key_store_get_key_by_fpr(rnp_key_store_t *keyring, const pgp_fingerprint_t *fpr)
{
    auto it =
      std::find_if(keyring->keys.begin(), keyring->keys.end(), [fpr](const pgp_key_t &key) {
          return fingerprint_equal(pgp_key_get_fp(&key), fpr);
      });
    return (it == keyring->keys.end()) ? NULL : &(*it);
}

pgp_key_t *
rnp_key_store_get_primary_key(rnp_key_store_t *keyring, const pgp_key_t *subkey)
{
    uint8_t           keyid[PGP_KEY_ID_SIZE] = {0};
    pgp_fingerprint_t keyfp = {};

    if (!pgp_key_is_subkey(subkey)) {
        return NULL;
    }

    if (pgp_key_has_primary_grip(subkey)) {
        return rnp_key_store_get_key_by_grip(keyring, pgp_key_get_primary_grip(subkey));
    }

    for (unsigned i = 0; i < pgp_key_get_subsig_count(subkey); i++) {
        const pgp_subsig_t *subsig = pgp_key_get_subsig(subkey, i);
        if (subsig->sig.type != PGP_SIG_SUBKEY) {
            continue;
        }

        if (signature_get_keyfp(&subsig->sig, &keyfp)) {
            return rnp_key_store_get_key_by_fpr(keyring, &keyfp);
        }

        if (signature_get_keyid(&subsig->sig, keyid)) {
            return rnp_key_store_get_key_by_id(keyring, keyid, NULL);
        }
    }

    return NULL;
}

static bool
grip_hash_mpi(pgp_hash_t *hash, const pgp_mpi_t *val, const char name, bool lzero)
{
    size_t len;
    size_t idx;
    char   buf[20] = {0};

    len = mpi_bytes(val);
    for (idx = 0; (idx < len) && (val->mpi[idx] == 0); idx++)
        ;

    if (name) {
        size_t hlen = idx >= len ? 0 : len - idx;
        if ((len > idx) && lzero && (val->mpi[idx] & 0x80)) {
            hlen++;
        }

        snprintf(buf, sizeof(buf), "(1:%c%zu:", name, hlen);
        pgp_hash_add(hash, buf, strlen(buf));
    }

    if (idx < len) {
        /* gcrypt prepends mpis with zero if hihger bit is set */
        if (lzero && (val->mpi[idx] & 0x80)) {
            buf[0] = '\0';
            pgp_hash_add(hash, buf, 1);
        }
        pgp_hash_add(hash, val->mpi + idx, len - idx);
    }

    if (name) {
        pgp_hash_add(hash, ")", 1);
    }

    return true;
}

static bool
grip_hash_ecc_hex(pgp_hash_t *hash, const char *hex, char name)
{
    pgp_mpi_t mpi = {};

    if (!hex2bin(hex, strlen(hex), mpi.mpi, sizeof(mpi.mpi), &mpi.len)) {
        RNP_LOG("wrong hex mpi");
        return false;
    }

    /* libgcrypt doesn't add leading zero when hashes ecc mpis */
    return grip_hash_mpi(hash, &mpi, name, false);
}

static bool
grip_hash_ec(pgp_hash_t *hash, const pgp_ec_key_t *key)
{
    const ec_curve_desc_t *desc = get_curve_desc(key->curve);
    pgp_mpi_t              g = {};
    size_t                 len = 0;
    bool                   res = false;

    if (!desc) {
        RNP_LOG("unknown curve %d", (int) key->curve);
        return false;
    }

    /* build uncompressed point from gx and gy */
    g.mpi[0] = 0x04;
    g.len = 1;
    if (!hex2bin(desc->gx, strlen(desc->gx), g.mpi + g.len, sizeof(g.mpi) - g.len, &len)) {
        RNP_LOG("wrong x mpi");
        return false;
    }
    g.len += len;
    if (!hex2bin(desc->gy, strlen(desc->gy), g.mpi + g.len, sizeof(g.mpi) - g.len, &len)) {
        RNP_LOG("wrong y mpi");
        return false;
    }
    g.len += len;

    /* p, a, b, g, n, q */
    res = grip_hash_ecc_hex(hash, desc->p, 'p') && grip_hash_ecc_hex(hash, desc->a, 'a') &&
          grip_hash_ecc_hex(hash, desc->b, 'b') && grip_hash_mpi(hash, &g, 'g', false) &&
          grip_hash_ecc_hex(hash, desc->n, 'n');

    if ((key->curve == PGP_CURVE_ED25519) || (key->curve == PGP_CURVE_25519)) {
        if (g.len < 1) {
            RNP_LOG("wrong 25519 p");
            return false;
        }
        g.len = key->p.len - 1;
        memcpy(g.mpi, key->p.mpi + 1, g.len);
        res &= grip_hash_mpi(hash, &g, 'q', false);
    } else {
        res &= grip_hash_mpi(hash, &key->p, 'q', false);
    }
    return res;
}

/* keygrip is subjectKeyHash from pkcs#15 for RSA. */
bool
rnp_key_store_get_key_grip(const pgp_key_material_t *key, pgp_key_grip_t &grip)
{
    pgp_hash_t hash = {0};

    if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
        RNP_LOG("bad sha1 alloc");
        return false;
    }

    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_SIGN_ONLY:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
        grip_hash_mpi(&hash, &key->rsa.n, '\0', true);
        break;

    case PGP_PKA_DSA:
        grip_hash_mpi(&hash, &key->dsa.p, 'p', true);
        grip_hash_mpi(&hash, &key->dsa.q, 'q', true);
        grip_hash_mpi(&hash, &key->dsa.g, 'g', true);
        grip_hash_mpi(&hash, &key->dsa.y, 'y', true);
        break;

    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        grip_hash_mpi(&hash, &key->eg.p, 'p', true);
        grip_hash_mpi(&hash, &key->eg.g, 'g', true);
        grip_hash_mpi(&hash, &key->eg.y, 'y', true);
        break;

    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        if (!grip_hash_ec(&hash, &key->ec)) {
            pgp_hash_finish(&hash, grip.data());
            return false;
        }
        break;

    default:
        RNP_LOG("unsupported public-key algorithm %d", (int) key->alg);
        pgp_hash_finish(&hash, grip.data());
        return false;
    }

    return pgp_hash_finish(&hash, grip.data()) == grip.size();
}

pgp_key_t *
rnp_key_store_search(rnp_key_store_t *       keyring,
                     const pgp_key_search_t *search,
                     pgp_key_t *             after)
{
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

rnp_key_store_t::rnp_key_store_t(pgp_key_store_format_t _format, const std::string &_path)
{
    if (_format == PGP_KEY_STORE_UNKNOWN) {
        RNP_LOG("Invalid key store format");
        throw std::invalid_argument("format");
    }
    format = _format;
    path = _path;
    disable_validation = false;
    skip_parsing_errors = false;
    blobs = NULL;
}

rnp_key_store_t::~rnp_key_store_t()
{
    rnp_key_store_clear(this);
}
