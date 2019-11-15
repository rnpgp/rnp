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

#include <rnp/rnp_sdk.h>
#include <rekey/rnp_key_store.h>
#include <librepgp/stream-packet.h>

#include "key_store_internal.h"
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

static bool
parse_ks_format(enum key_store_format_t *key_store_format, const char *format)
{
    if (strcmp(format, RNP_KEYSTORE_GPG) == 0) {
        *key_store_format = GPG_KEY_STORE;
    } else if (strcmp(format, RNP_KEYSTORE_KBX) == 0) {
        *key_store_format = KBX_KEY_STORE;
    } else if (strcmp(format, RNP_KEYSTORE_G10) == 0) {
        *key_store_format = G10_KEY_STORE;
    } else {
        RNP_LOG("unsupported keystore format: \"%s\"", format);
        return false;
    }
    return true;
}

rnp_key_store_t *
rnp_key_store_new(const char *format, const char *path)
{
    rnp_key_store_t *       key_store = NULL;
    enum key_store_format_t key_store_format = UNKNOW_KEY_STORE;

    if (!parse_ks_format(&key_store_format, format)) {
        return NULL;
    }

    key_store = (rnp_key_store_t *) calloc(1, sizeof(*key_store));
    if (key_store == NULL) {
        RNP_LOG("Can't allocate memory");
        return NULL;
    }

    key_store->format = key_store_format;
    key_store->format_label = strdup(format);
    key_store->path = strdup(path);

    return key_store;
}

bool
rnp_key_store_load_from_path(rnp_key_store_t *         key_store,
                             const pgp_key_provider_t *key_provider)
{
    DIR *          dir;
    bool           rc;
    pgp_source_t   src = {};
    struct dirent *ent;
    char           path[MAXPATHLEN];

    if (key_store->format == G10_KEY_STORE) {
        dir = opendir(key_store->path);
        if (dir == NULL) {
            RNP_LOG("Can't open G10 directory %s: %s", key_store->path, strerror(errno));
            return false;
        }

        while ((ent = readdir(dir)) != NULL) {
            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
                continue;
            }

            snprintf(path, sizeof(path), "%s/%s", key_store->path, ent->d_name);
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
    if (init_file_src(&src, key_store->path)) {
        RNP_LOG("failed to read file %s", key_store->path);
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
    case GPG_KEY_STORE:
        return rnp_key_store_pgp_read_from_src(key_store, src) == RNP_SUCCESS;
    case KBX_KEY_STORE:
        return rnp_key_store_kbx_from_src(key_store, src, key_provider);
    case G10_KEY_STORE:
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
    if (key_store->format == G10_KEY_STORE) {
        char path[MAXPATHLEN];
        char grips[PGP_FINGERPRINT_HEX_SIZE];

        struct stat path_stat;
        if (stat(key_store->path, &path_stat) != -1) {
            if (!S_ISDIR(path_stat.st_mode)) {
                RNP_LOG("G10 keystore should be a directory: %s", key_store->path);
                return false;
            }
        } else {
            if (errno != ENOENT) {
                RNP_LOG("stat(%s): %s", key_store->path, strerror(errno));
                return false;
            }
            if (RNP_MKDIR(key_store->path, S_IRWXU) != 0) {
                RNP_LOG("mkdir(%s, S_IRWXU): %s", key_store->path, strerror(errno));
                return false;
            }
        }

        for (list_item *key_item = list_front(rnp_key_store_get_keys(key_store)); key_item;
             key_item = list_next(key_item)) {
            pgp_key_t *key = (pgp_key_t *) key_item;
            snprintf(
              path,
              sizeof(path),
              "%s/%s.key",
              key_store->path,
              rnp_strhexdump_upper(grips, pgp_key_get_grip(key), PGP_KEY_GRIP_SIZE, ""));

            if (init_tmpfile_dest(&keydst, path, true)) {
                RNP_LOG("failed to create file");
                return false;
            }

            if (!rnp_key_store_g10_key_to_dst(key, &keydst)) {
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
    if (init_tmpfile_dest(&keydst, key_store->path, true)) {
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
    case GPG_KEY_STORE:
        return rnp_key_store_pgp_write_to_dst(key_store, false, dst);
    case KBX_KEY_STORE:
        return rnp_key_store_kbx_to_dst(key_store, dst);
    default:
        RNP_LOG("Unsupported write to memory for key-store format: %d", key_store->format);
    }

    return false;
}

/* Format a PGP key to a readable hexadecimal string in a user supplied
 * buffer.
 *
 * buffer: the buffer to write into
 * keyid:  the PGP key ID to format
 * len:    the length of buffer, including the null terminator
 *
 * TODO: There is no error checking here.
 * TODO: Make this function more general or use an existing one.
 */

void
rnp_key_store_format_key(char *buffer, const uint8_t *keyid, int len)
{
    unsigned int i;
    unsigned int n;

    /* Chunks of two bytes are processed at a time because we can
     * always be reasonably sure that PGP_KEY_ID_SIZE will be
     * divisible by two. However, if the RFCs specify a fixed
     * fixed size for PGP key IDs it might be more constructive
     * to format this in one call and do a compile-time size
     * check of the constant. If somebody wanted to do
     * something exotic they can easily re-implement
     * this function.
     */
    for (i = 0, n = 0; i < PGP_KEY_ID_SIZE; i += 2) {
        n += snprintf(&buffer[n], len - n, "%02x%02x", keyid[i], keyid[i + 1]);
    }
    buffer[n] = 0x0;
}

/* Get the uid of the first key in the keyring.
 *
 * TODO: Set errno on failure.
 * TODO: Check upstream calls to this function - they likely won't
 *       handle the new error condition.
 */
bool
rnp_key_store_get_first_ring(rnp_key_store_t *ring, char *id, size_t len, int last)
{
    const uint8_t *src;

    /* The NULL test on the ring may not be necessary for non-debug
     * builds - it would be much better that a NULL ring never
     * arrived here in the first place.
     *
     * The ring length check is a temporary fix for a case where
     * an empty ring arrives and causes an access violation in
     * some circumstances.
     */

    errno = 0;

    if (ring == NULL || rnp_key_store_get_key_count(ring) < 1) {
        errno = EINVAL;
        return false;
    }

    memset(id, 0x0, len);

    list_item *key_item = last ? list_back(rnp_key_store_get_keys(ring)) :
                                 list_front(rnp_key_store_get_keys(ring));
    src = pgp_key_get_keyid((pgp_key_t *) key_item);
    rnp_key_store_format_key(id, src, len);

    return true;
}

void
rnp_key_store_clear(rnp_key_store_t *keyring)
{
    for (list_item *key = list_front(keyring->keys); key; key = list_next(key)) {
        pgp_key_free_data((pgp_key_t *) key);
    }
    list_destroy(&keyring->keys);

    for (list_item *item = list_front(keyring->blobs); item; item = list_next(item)) {
        kbx_blob_t *blob = *((kbx_blob_t **) item);
        if (blob->type == KBX_PGP_BLOB) {
            kbx_pgp_blob_t *pgpblob = (kbx_pgp_blob_t *) blob;
            list_destroy(&pgpblob->keys);
            if (pgpblob->sn_size > 0) {
                free(pgpblob->sn);
            }
            list_destroy(&pgpblob->uids);
            list_destroy(&pgpblob->sigs);
        }
        free(blob);
    }
    list_destroy(&keyring->blobs);
}

void
rnp_key_store_free(rnp_key_store_t *keyring)
{
    if (keyring == NULL) {
        return;
    }

    rnp_key_store_clear(keyring);
    free((void *) keyring->path);
    free((void *) keyring->format_label);
    free(keyring);
}

size_t
rnp_key_store_get_key_count(const rnp_key_store_t *keyring)
{
    return list_length(keyring->keys);
}

pgp_key_t *
rnp_key_store_get_key(const rnp_key_store_t *keyring, size_t idx)
{
    return (pgp_key_t *) list_at(keyring->keys, idx);
}

list
rnp_key_store_get_keys(const rnp_key_store_t *keyring)
{
    return keyring->keys;
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

    pgp_key_free_data(dst);
    *dst = tmpkey;
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
    tmpkey.subkey_grips = dst->subkey_grips;
    dst->subkey_grips = NULL;
    for (list_item *li = list_front(src->subkey_grips); li; li = list_next(li)) {
        if (!rnp_key_add_subkey_grip(&tmpkey, (uint8_t *) li)) {
            RNP_LOG("failed to add subkey grip");
        }
    }

    pgp_key_free_data(dst);
    *dst = tmpkey;
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

    for (list_item *ki = list_front(rnp_key_store_get_keys(keyring)); ki; ki = list_next(ki)) {
        pgp_key_t *skey = (pgp_key_t *) ki;
        bool       found = false;

        /* if we have primary_grip then we also added to subkey_grips */
        if (!pgp_key_is_subkey(skey) || pgp_key_get_primary_grip(skey)) {
            continue;
        }

        for (unsigned i = 0; i < pgp_key_get_subsig_count(skey); i++) {
            pgp_subsig_t *subsig = pgp_key_get_subsig(skey, i);

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

        if (found && !pgp_key_link_subkey_grip(key, skey)) {
            return false;
        }
    }

    return true;
}

/* add a key to keyring */
pgp_key_t *
rnp_key_store_add_key(rnp_key_store_t *keyring, pgp_key_t *srckey)
{
    pgp_key_t *added_key = NULL;

    RNP_DLOG("rnp_key_store_add_key");
    assert(pgp_key_get_type(srckey) && pgp_key_get_version(srckey));
    added_key = rnp_key_store_get_key_by_grip(keyring, pgp_key_get_grip(srckey));

    if (added_key) {
        /* we cannot merge G10 keys - so just return it */
        if (srckey->format == G10_KEY_STORE) {
            pgp_key_free_data(srckey);
            return added_key;
        }

        bool mergeres = false;
        /* in case we already have key let's merge it in */
        if (pgp_key_is_subkey(added_key)) {
            pgp_key_t *primary = rnp_key_store_get_primary_key(keyring, added_key);
            if (!primary) {
                primary = rnp_key_store_get_primary_key(keyring, srckey);
            }
            if (!primary) {
                RNP_LOG("no primary key for subkey");
            }
            mergeres = rnp_key_store_merge_subkey(added_key, srckey, primary);
        } else {
            mergeres = rnp_key_store_merge_key(added_key, srckey);
        }

        if (!mergeres) {
            RNP_LOG("failed to merge key or subkey");
            return NULL;
        }
        added_key->validated = added_key->validated && srckey->validated;
        added_key->valid = added_key->valid && srckey->valid;
        pgp_key_free_data(srckey);
    } else {
        added_key = (pgp_key_t *) list_append(&keyring->keys, srckey, sizeof(*srckey));
        /* primary key may be added after subkeys, so let's handle this case correctly */
        if (pgp_key_is_primary_key(added_key) &&
            !rnp_key_store_refresh_subkey_grips(keyring, added_key)) {
            RNP_LOG("failed to refresh subkey grips");
        }
    }

    if (!added_key) {
        RNP_LOG("allocation failed");
        return NULL;
    }

    RNP_DLOG("keyc %lu", rnp_key_store_get_key_count(keyring));

    /* validate all added keys if not disabled */
    if (!keyring->disable_validation && !added_key->validated) {
        added_key->valid = true; // we need to this to check key's signatures
        added_key->valid = !validate_pgp_key(added_key, keyring);

        /* validate/re-validate all subkeys as well */
        if (pgp_key_is_primary_key(added_key)) {
            for (list_item *grip = list_front(added_key->subkey_grips); grip;
                 grip = list_next(grip)) {
                pgp_key_t *subkey = rnp_key_store_get_key_by_grip(keyring, (uint8_t *) grip);
                if (subkey) {
                    subkey->valid = true;
                    subkey->valid = !validate_pgp_key(subkey, keyring);
                }
            }
        }
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
        RNP_LOG("failed to create key copy");
        return NULL;
    }
    exkey = rnp_key_store_get_key_by_grip(keyring, pgp_key_get_grip(srckey));
    expackets = exkey ? pgp_key_get_rawpacket_count(exkey) : 0;
    if (!(exkey = rnp_key_store_add_key(keyring, &keycp))) {
        RNP_LOG("failed to add key to the keyring");
        pgp_key_free_data(&keycp);
        return NULL;
    }

    changed = pgp_key_get_rawpacket_count(exkey) > expackets;
    if (status) {
        *status = changed ?
                    (expackets ? PGP_KEY_IMPORT_STATUS_UPDATED : PGP_KEY_IMPORT_STATUS_NEW) :
                    PGP_KEY_IMPORT_STATUS_UNCHANGED;
    }

    return exkey;
}

bool
rnp_key_store_remove_key(rnp_key_store_t *keyring, const pgp_key_t *key)
{
    // check if we were passed a key that isn't from this ring
    if (!list_is_member(keyring->keys, (list_item *) key)) {
        return false;
    }
    list_remove((list_item *) key);
    return true;
}

bool
rnp_key_store_remove_key_by_id(rnp_key_store_t *keyring, const uint8_t *keyid)
{
    const pgp_key_t *key;

    key = rnp_key_store_get_key_by_id(keyring, keyid, NULL);
    if (key != NULL) {
        return rnp_key_store_remove_key(keyring, key);
    }

    return false;
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
rnp_key_store_get_key_by_id(const rnp_key_store_t *keyring,
                            const uint8_t *        keyid,
                            pgp_key_t *            after)
{
    RNP_DLOG("searching keyring %p", keyring);

    if (!keyring) {
        return NULL;
    }

    // if after is provided, make sure it is a member of the appropriate list
    assert(!after || list_is_member(keyring->keys, (list_item *) after));

    for (list_item *key_item = after ? list_next((list_item *) after) :
                                       list_front(keyring->keys);
         key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        RNP_DHEX("keyring keyid", pgp_key_get_keyid(key), PGP_KEY_ID_SIZE);
        RNP_DHEX("keyid", keyid, PGP_KEY_ID_SIZE);
        if (memcmp(pgp_key_get_keyid(key), keyid, PGP_KEY_ID_SIZE) == 0 ||
            memcmp(pgp_key_get_keyid(key) + PGP_KEY_ID_SIZE / 2, keyid, PGP_KEY_ID_SIZE / 2) ==
              0) {
            return key;
        }
    }
    return NULL;
}

pgp_key_t *
rnp_key_store_get_key_by_userid(const rnp_key_store_t *keyring,
                                const char *           userid,
                                pgp_key_t *            after)
{
    if (!keyring || !userid) {
        return NULL;
    }

    // if after is provided, make sure it is a member of the appropriate list
    assert(!after || list_is_member(keyring->keys, (list_item *) after));
    list_item *start = after ? list_next((list_item *) after) : list_front(keyring->keys);
    for (list_item *key_item = start; key_item; key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        if (pgp_key_has_userid(key, userid)) {
            return key;
        }
    }
    return NULL;
}

pgp_key_t *
rnp_key_store_get_key_by_grip(const rnp_key_store_t *keyring, const uint8_t *grip)
{
    RNP_DLOG("looking keyring %p", keyring);

    if (!grip) {
        return NULL;
    }

    for (list_item *key_item = list_front(keyring->keys); key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        RNP_DHEX("looking for grip", grip, PGP_KEY_GRIP_SIZE);
        RNP_DHEX("key grip", pgp_key_get_grip(key), PGP_KEY_GRIP_SIZE);

        if (memcmp(pgp_key_get_grip(key), grip, PGP_KEY_GRIP_SIZE) == 0) {
            return key;
        }
    }
    return NULL;
}

pgp_key_t *
rnp_key_store_get_key_by_fpr(const rnp_key_store_t *keyring, const pgp_fingerprint_t *fpr)
{
    for (list_item *key = list_front(keyring->keys); key; key = list_next(key)) {
        if (fingerprint_equal(pgp_key_get_fp((pgp_key_t *) key), fpr)) {
            return (pgp_key_t *) key;
        }
    }
    return NULL;
}

pgp_key_t *
rnp_key_store_get_primary_key(const rnp_key_store_t *keyring, const pgp_key_t *subkey)
{
    uint8_t           keyid[PGP_KEY_ID_SIZE] = {0};
    pgp_fingerprint_t keyfp = {};

    if (!pgp_key_is_subkey(subkey)) {
        return NULL;
    }

    if (pgp_key_get_primary_grip(subkey)) {
        return rnp_key_store_get_key_by_grip(keyring, pgp_key_get_primary_grip(subkey));
    }

    for (unsigned i = 0; i < pgp_key_get_subsig_count(subkey); i++) {
        pgp_subsig_t *subsig = pgp_key_get_subsig(subkey, i);
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

/* return the next key which matches, starting searching after *after */
static bool
get_key_by_name(const rnp_key_store_t *keyring,
                const char *           name,
                pgp_key_t *            after,
                pgp_key_t **           key)
{
    pgp_key_t *kp;
    unsigned   i = 0;
    pgp_key_t *keyp;
    uint8_t    keyid[PGP_FINGERPRINT_SIZE];
    size_t     len;
    size_t     binlen = 0;

    *key = NULL;

    if (!keyring || !name) {
        RNP_LOG("keyring, name and after shouldn't be NULL");
        return false;
    }
    assert(!after || list_is_member(keyring->keys, (list_item *) after));
    len = strlen(name);
    RNP_DLOG("[%p] name '%s', len %zu", after, name, len);

    /* first try name as a keyid */
    (void) memset(keyid, 0x0, sizeof(keyid));
    if (ishex(name, len) && hex2bin(name, len, keyid, sizeof(keyid), &binlen)) {
        RNP_DHEX("keyid", keyid, 4);

        if (binlen <= PGP_KEY_ID_SIZE) {
            kp = rnp_key_store_get_key_by_id(keyring, keyid, after);
        } else if (binlen <= PGP_FINGERPRINT_SIZE) {
            pgp_fingerprint_t fp = {};
            memcpy(fp.fingerprint, keyid, binlen);
            fp.length = binlen;
            kp = rnp_key_store_get_key_by_fpr(keyring, &fp);
        } else {
            kp = NULL;
        }

        if (kp) {
            *key = kp;
            return true;
        }
    }
    RNP_DLOG("regex match '%s' after %p", name, after);

    /* match on full name or email address as a NOSUB, ICASE regexp */
#ifndef RNP_USE_STD_REGEX
    regex_t    r;
    if (regcomp(&r, name, REG_EXTENDED | REG_ICASE) != 0) {
        RNP_LOG("Can't compile regex from string: '%s'", name);
        return false;
    }
#else
    std::regex re(name, std::regex_constants::extended | std::regex_constants::icase);
#endif

    for (list_item *key_item = after ? list_next((list_item *) after) :
                                       list_front(keyring->keys);
         key_item;
         key_item = list_next(key_item)) {
        keyp = (pgp_key_t *) key_item;

        for (i = 0; i < pgp_key_get_userid_count(keyp); i++) {
#ifndef RNP_USE_STD_REGEX
            if (regexec(&r, (char *) pgp_key_get_userid(keyp, i), 0, NULL, 0) == 0) {
                RNP_DLOG("MATCHED keyid \"%s\" len %" PRIsize "u",
                         (char *) pgp_key_get_userid(keyp, i),
                         len);
                regfree(&r);
                *key = keyp;
                return true;
            }
#else
            const std::string userid = pgp_key_get_userid(keyp, i);
            if (std::regex_search(userid, re)) {
                RNP_DLOG("MATCHED keyid \"%s\" len %" PRIsize "u",
                         (char *) userid.c_str(),
                         len);
                *key = keyp;
                return true;
            }
#endif
        }
    }
#ifndef RNP_USE_STD_REGEX
    regfree(&r);
#endif
    return true;
}

pgp_key_t *
rnp_key_store_get_key_by_name(const rnp_key_store_t *keyring,
                              const char *           name,
                              pgp_key_t *            after)
{
    pgp_key_t *key = NULL;
    get_key_by_name(keyring, name, after, &key);
    return key;
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
rnp_key_store_get_key_grip(const pgp_key_material_t *key, uint8_t *grip)
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
        grip_hash_mpi(&hash, &key->eg.p, 'p', true);
        grip_hash_mpi(&hash, &key->eg.g, 'g', true);
        grip_hash_mpi(&hash, &key->eg.y, 'y', true);
        break;

    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        if (!grip_hash_ec(&hash, &key->ec)) {
            pgp_hash_finish(&hash, grip);
            return false;
        }
        break;

    default:
        RNP_LOG("unsupported public-key algorithm %d", (int) key->alg);
        pgp_hash_finish(&hash, grip);
        return false;
    }

    return pgp_hash_finish(&hash, grip) == PGP_KEY_GRIP_SIZE;
}

pgp_key_t *
rnp_key_store_search(const rnp_key_store_t * keyring,
                     const pgp_key_search_t *search,
                     pgp_key_t *             after)
{
    // if after is provided, make sure it is a member of the appropriate list
    assert(!after || list_is_member(keyring->keys, (list_item *) after));
    for (list_item *key_item = after ? list_next((list_item *) after) :
                                       list_front(keyring->keys);
         key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        if (rnp_key_matches_search(key, search)) {
            return key;
        }
    }
    return NULL;
}
