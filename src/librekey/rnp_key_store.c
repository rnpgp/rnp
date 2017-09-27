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

#include <stdio.h>
#include <regex.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>

#include <rnp/rnp.h>
#include <rnp/rnp_sdk.h>
#include <rekey/rnp_key_store.h>
#include <librepgp/packet-print.h>

#include "key_store_internal.h"
#include "key_store_pgp.h"
#include "key_store_kbx.h"
#include "key_store_ssh.h"
#include "key_store_g10.h"

#include "pgp-key.h"
#include "crypto/bn.h"
#include "fingerprint.h"
#include "hash.h"

static bool
parse_ks_format(enum key_store_format_t *key_store_format, const char *format)
{
    if (strcmp(format, RNP_KEYSTORE_GPG) == 0) {
        *key_store_format = GPG_KEY_STORE;
    } else if (strcmp(format, RNP_KEYSTORE_KBX) == 0) {
        *key_store_format = KBX_KEY_STORE;
    } else if (strcmp(format, RNP_KEYSTORE_SSH) == 0) {
        *key_store_format = SSH_KEY_STORE;
    } else if (strcmp(format, RNP_KEYSTORE_G10) == 0) {
        *key_store_format = G10_KEY_STORE;
    } else {
        fprintf(stderr, "rnp: unsupported keystore format: \"%s\"\n", format);
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
        return false;
    }

    key_store = calloc(1, sizeof(*key_store));
    if (key_store == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return NULL;
    }

    key_store->format = key_store_format;
    key_store->format_label = strdup(format);
    key_store->path = strdup(path);

    return key_store;
}

bool
rnp_key_store_load_keys(rnp_t *rnp, bool loadsecret)
{
    char      id[MAX_ID_LENGTH];
    pgp_io_t *io = rnp->io;

    rnp_key_store_t *pubring = rnp->pubring;
    rnp_key_store_t *secring = rnp->secring;

    rnp_key_store_clear(rnp->pubring);

    if (pubring->format == SSH_KEY_STORE || secring->format == SSH_KEY_STORE) {
        return rnp_key_store_ssh_load_keys(
          rnp, rnp->pubring, loadsecret ? rnp->secring : NULL);
    }

    if (!rnp_key_store_load_from_file(rnp, rnp->pubring, 0)) {
        fprintf(io->errs, "cannot read pub keyring\n");
        return false;
    }

    if (((rnp_key_store_t *) rnp->pubring)->keyc < 1) {
        fprintf(
          io->errs, "pub keyring '%s' is empty\n", ((rnp_key_store_t *) rnp->pubring)->path);
        return false;
    }

    /* Only read secret keys if we need to */
    if (loadsecret) {
        rnp_key_store_clear(rnp->secring);
        if (!rnp_key_store_load_from_file(rnp, rnp->secring, 0)) {
            fprintf(io->errs, "cannot read sec keyring\n");
            return false;
        }

        if (((rnp_key_store_t *) rnp->secring)->keyc < 1) {
            fprintf(io->errs,
                    "sec keyring '%s' is empty\n",
                    ((rnp_key_store_t *) rnp->secring)->path);
            return false;
        }

        /* Now, if we don't have a valid user, use the first
         * in secring.
         */
        if (!rnp->defkey) {
            if (rnp_key_store_get_first_ring(rnp->secring, id, sizeof(id), 0)) {
                rnp->defkey = strdup(id);
            }
        }

    } else if (!rnp->defkey) {
        /* encrypting - get first in pubring */
        if (rnp_key_store_get_first_ring(rnp->pubring, id, sizeof(id), 0)) {
            rnp->defkey = strdup(id);
        }
    }

    return true;
}

int
rnp_key_store_load_from_file(rnp_t *rnp, rnp_key_store_t *key_store, const unsigned armour)
{
    DIR *          dir;
    bool           rc;
    pgp_memory_t   mem = {0};
    struct dirent *ent;
    char           path[MAXPATHLEN];

    if (key_store->format == SSH_KEY_STORE) {
        return rnp_key_store_ssh_from_file(rnp->io, key_store, key_store->path);
    }

    if (key_store->format == G10_KEY_STORE) {
        dir = opendir(key_store->path);
        if (dir == NULL) {
            fprintf(rnp->io->errs, "Can't open G10 directory: %s\n", strerror(errno));
            return false;
        }

        while ((ent = readdir(dir)) != NULL) {
            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
                continue;
            }

            snprintf(path, MAXPATHLEN, "%s/%s", key_store->path, ent->d_name);

            memset(&mem, 0, sizeof(mem));

            if (rnp_get_debug(__FILE__)) {
                fprintf(rnp->io->errs, "Loading G10 key from file '%s'\n", path);
            }

            if (!pgp_mem_readfile(&mem, path)) {
                fprintf(rnp->io->errs, "Can't read file '%s' to memory\n", path);
                continue;
            }

            // G10 may don't read one file, so, ignore it!
            if (!rnp_key_store_g10_from_mem(rnp->io, rnp->pubring, key_store, &mem)) {
                fprintf(rnp->io->errs, "Can't parse file: %s\n", path);
            }
            pgp_memory_release(&mem);
        }

        return true;
    }

    if (!pgp_mem_readfile(&mem, key_store->path)) {
        return false;
    }

    rc = rnp_key_store_load_from_mem(rnp, key_store, armour, &mem);
    pgp_memory_release(&mem);
    return rc;
}

bool
rnp_key_store_load_from_mem(rnp_t *          rnp,
                            rnp_key_store_t *key_store,
                            const unsigned   armour,
                            pgp_memory_t *   memory)
{
    switch (key_store->format) {
    case GPG_KEY_STORE:
        return rnp_key_store_pgp_read_from_mem(rnp->io, key_store, armour, memory);

    case KBX_KEY_STORE:
        return rnp_key_store_kbx_from_mem(rnp->io, key_store, memory);

    case G10_KEY_STORE:
        return rnp_key_store_g10_from_mem(rnp->io, rnp->pubring, key_store, memory);

    default:
        fprintf(rnp->io->errs,
                "Unsupported load from memory for key-store format: %d\n",
                key_store->format);
    }

    return false;
}

bool
rnp_key_store_write_to_file(rnp_t *rnp, rnp_key_store_t *key_store, const unsigned armour)
{
    bool         rc;
    pgp_memory_t mem = {0};

    if (key_store->format == G10_KEY_STORE) {
        char    path[MAXPATHLEN];
        uint8_t grip[PGP_FINGERPRINT_SIZE];
        char    grips[PGP_FINGERPRINT_HEX_SIZE];

        struct stat path_stat;
        if (stat(key_store->path, &path_stat) != -1) {
            if (!S_ISDIR(path_stat.st_mode)) {
                fprintf(
                  rnp->io->errs, "G10 keystore should be a directory: %s\n", key_store->path);
                return false;
            }
        } else {
            if (errno != ENOENT) {
                fprintf(rnp->io->errs, "stat(%s): %s\n", key_store->path, strerror(errno));
                return false;
            }
            if (mkdir(key_store->path, S_IRWXU) != 0) {
                fprintf(
                  rnp->io->errs, "mkdir(%s, S_IRWXU): %s\n", key_store->path, strerror(errno));
                return false;
            }
        }

        for (int i = 0; i < key_store->keyc; i++) {
            if (!rnp_key_store_get_key_grip(&key_store->keys[i].key.pubkey, grip)) {
                return false;
            }

            snprintf(path,
                     MAXPATHLEN,
                     "%s/%s.key",
                     key_store->path,
                     rnp_strhexdump_upper(grips, grip, 20, ""));

            memset(&mem, 0, sizeof(mem));
            if (!rnp_key_store_g10_key_to_mem(rnp->io, &key_store->keys[i], &mem)) {
                pgp_memory_release(&mem);
                return false;
            }

            rc = pgp_mem_writefile(&mem, path);
            pgp_memory_release(&mem);

            if (!rc) {
                return false;
            }
        }

        return true;
    }

    if (!rnp_key_store_write_to_mem(rnp->io, key_store, armour, &mem)) {
        pgp_memory_release(&mem);
        return false;
    }

    rc = pgp_mem_writefile(&mem, key_store->path);
    pgp_memory_release(&mem);
    return rc;
}

bool
rnp_key_store_write_to_mem(pgp_io_t *          io,
                           rnp_key_store_t *key_store,
                           const unsigned   armour,
                           pgp_memory_t *   memory)
{
    switch (key_store->format) {
    case GPG_KEY_STORE:
        return rnp_key_store_pgp_write_to_mem(io, key_store, armour, memory);

    case KBX_KEY_STORE:
        return rnp_key_store_kbx_to_mem(io, key_store, memory);

    default:
        fprintf(io->errs,
                "Unsupported write to memory for key-store format: %d\n",
                key_store->format);
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
rnp_key_store_format_key(char *buffer, uint8_t *keyid, int len)
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
    uint8_t *src;

    /* The NULL test on the ring may not be necessary for non-debug
     * builds - it would be much better that a NULL ring never
     * arrived here in the first place.
     *
     * The ring length check is a temporary fix for a case where
     * an empty ring arrives and causes an access violation in
     * some circumstances.
     */

    errno = 0;

    if (ring == NULL || ring->keyc < 1) {
        errno = EINVAL;
        return false;
    }

    memset(id, 0x0, len);

    src = (uint8_t *) &ring->keys[(last) ? ring->keyc - 1 : 0].keyid;
    rnp_key_store_format_key(id, src, len);

    return true;
}

void
rnp_key_store_clear(rnp_key_store_t *keyring)
{
    int i;

    if (keyring->keys != NULL) {
        for (i = 0; i < keyring->keyc; i++) {
            pgp_key_free_data(&keyring->keys[i]);
        }
        keyring->keyc = 0;
    }

    if (keyring->blobs != NULL) {
        for (i = 0; i < keyring->blobc; i++) {
            if (keyring->blobs[i]->type == KBX_PGP_BLOB) {
                FREE_ARRAY(((kbx_pgp_blob_t *) (keyring->blobs[i])), key);
                if (((kbx_pgp_blob_t *) (keyring->blobs[i]))->sn_size > 0) {
                    free(((kbx_pgp_blob_t *) (keyring->blobs[i]))->sn);
                }
                FREE_ARRAY(((kbx_pgp_blob_t *) (keyring->blobs[i])), uid);
                FREE_ARRAY(((kbx_pgp_blob_t *) (keyring->blobs[i])), sig);
            }
            free(keyring->blobs[i]);
        }
        keyring->blobc = 0;
    }
}

void
rnp_key_store_free(rnp_key_store_t *keyring)
{
    if (keyring == NULL) {
        return;
    }

    rnp_key_store_clear(keyring);

    FREE_ARRAY(keyring, key);
    FREE_ARRAY(keyring, blob);

    free((void *) keyring->path);
    free((void *) keyring->format_label);

    free(keyring);
}

/**
   \ingroup HighLevel_KeyringList

   \brief Prints all keys in keyring to stdout.

   \param keyring Keyring to use

   \return none
*/
bool
rnp_key_store_list(pgp_io_t *io, const rnp_key_store_t *keyring, const int psigs)
{
    pgp_key_t *key;
    unsigned   n;
    unsigned   keyc = (keyring != NULL) ? keyring->keyc : 0;

    (void) fprintf(io->res, "%u key%s\n", keyc, (keyc == 1) ? "" : "s");

    if (keyring == NULL) {
        return true;
    }

    for (n = 0, key = keyring->keys; n < keyring->keyc; ++n, ++key) {
        if (pgp_is_key_secret(key)) {
            repgp_print_key(io, keyring, key, "sec", &key->key.seckey.pubkey, 0);
        } else {
            repgp_print_key(io, keyring, key, "pub", &key->key.pubkey, psigs);
        }
        (void) fputc('\n', io->res);
    }
    return true;
}

bool
rnp_key_store_json(pgp_io_t *             io,
                   const rnp_key_store_t *keyring,
                   json_object *          obj,
                   const int              psigs)
{
    pgp_key_t *key;
    unsigned   n;
    for (n = 0, key = keyring->keys; n < keyring->keyc; ++n, ++key) {
        json_object * jso = json_object_new_object();
        pgp_pubkey_t *pubkey = &key->key.pubkey;
        const char *  header = NULL;
        if (pgp_is_key_secret(key)) { /* secret key is always shown as "sec" */
            header = "sec";
        } else if (pgp_key_is_primary_key(key)) { /* top-level public key */
            header = "pub";
        } else {
            header = "sub"; /* subkey */
        }
        repgp_sprint_json(io, keyring, key, jso, header, pubkey, psigs);
        json_object_array_add(obj, jso);
    }
    return true;
}

/* append one keyring to another */
bool
rnp_key_store_append_keyring(rnp_key_store_t *keyring, rnp_key_store_t *newring)
{
    unsigned i;

    for (i = 0; i < newring->keyc; i++) {
        EXPAND_ARRAY(keyring, key);
        if (keyring->keys == NULL) {
            return false;
        }
        (void) memcpy(
          &keyring->keys[keyring->keyc], &newring->keys[i], sizeof(newring->keys[i]));
        keyring->keyc += 1;
    }

    for (i = 0; i < newring->blobc; i++) {
        EXPAND_ARRAY(keyring, blob);
        if (keyring->blobs == NULL) {
            return false;
        }
        (void) memcpy(
          &keyring->blobs[keyring->blobc], &newring->blobs[i], sizeof(newring->blobs[i]));
        keyring->blobc += 1;
    }
    return true;
}

/* add a key to keyring */
bool
rnp_key_store_add_key(pgp_io_t *io, rnp_key_store_t *keyring, pgp_key_t *key)
{
    pgp_key_t *newkey;

    if (io && rnp_get_debug(__FILE__)) {
        fprintf(io->errs, "rnp_key_store_add_key\n");
    }

    EXPAND_ARRAY(keyring, key);
    if (keyring->keys == NULL) {
        return false;
    }
    newkey = &keyring->keys[keyring->keyc++];
    *newkey = *key;
    if (io && rnp_get_debug(__FILE__)) {
        fprintf(io->errs, "rnp_key_store_add_key: keyc %u\n", keyring->keyc);
    }

    return true;
}

bool
rnp_key_store_add_keydata(pgp_io_t *         io,
                          rnp_key_store_t *  keyring,
                          pgp_keydata_key_t *keydata,
                          pgp_key_t **       inserted,
                          pgp_content_enum   tag)
{
    pgp_key_t *key;

    if (rnp_get_debug(__FILE__)) {
        fprintf(io->errs, "rnp_key_store_add_keydata to key_store: %p\n", keyring);
    }

    EXPAND_ARRAY(keyring, key);
    if (keyring->keys == NULL) {
        return false;
    }
    key = &keyring->keys[keyring->keyc++];
    (void) memset(key, 0x0, sizeof(*key));
    if (!pgp_keyid(key->keyid, PGP_KEY_ID_SIZE, &keydata->pubkey)) {
        return false;
    }
    if (!pgp_fingerprint(&key->fingerprint, &keydata->pubkey)) {
        return false;
    }
    if (!rnp_key_store_get_key_grip(&keydata->pubkey, key->grip)) {
        return false;
    }
    key->type = tag;
    key->key = *keydata;
    if (inserted) {
        *inserted = key;
    }

    if (rnp_get_debug(__FILE__)) {
        hexdump(io->errs, "added key->keyid", key->keyid, PGP_KEY_ID_SIZE);
        fprintf(io->errs, "rnp_key_store_add_keydata: keyc %u\n", keyring->keyc);
    }

    return true;
}

bool
rnp_key_store_remove_key(pgp_io_t *io, rnp_key_store_t *keyring, const pgp_key_t *key)
{
    int i;

    for (i = 0; i < keyring->keyc; i++) {
        if (key == &keyring->keys[i]) {
            memmove(&keyring->keys[i],
                    &keyring->keys[i + 1],
                    sizeof(pgp_key_t) * (keyring->keyc - i));
            keyring->keyc--;
            return true;
        }
    }

    return false;
}

bool
rnp_key_store_remove_key_by_id(pgp_io_t *io, rnp_key_store_t *keyring, const uint8_t *keyid)
{
    unsigned         from;
    const pgp_key_t *key;

    from = 0;

    key = rnp_key_store_get_key_by_id(io, keyring, keyid, &from, NULL);
    if (key != NULL) {
        return rnp_key_store_remove_key(io, keyring, key);
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
rnp_key_store_get_key_by_id(pgp_io_t *             io,
                            const rnp_key_store_t *keyring,
                            const uint8_t *        keyid,
                            unsigned *             from,
                            pgp_pubkey_t **        pubkey)
{
    if (rnp_get_debug(__FILE__)) {
        fprintf(io->errs, "searching keyring %p\n", keyring);
    }

    for (; keyring && *from < keyring->keyc; *from += 1) {
        if (rnp_get_debug(__FILE__)) {
            hexdump(io->errs, "keyring keyid", keyring->keys[*from].keyid, PGP_KEY_ID_SIZE);
            hexdump(io->errs, "keyid", keyid, PGP_KEY_ID_SIZE);
        }
        if (memcmp(keyring->keys[*from].keyid, keyid, PGP_KEY_ID_SIZE) == 0 ||
            memcmp(&keyring->keys[*from].keyid[PGP_KEY_ID_SIZE / 2],
                   keyid,
                   PGP_KEY_ID_SIZE / 2) == 0) {
            if (pubkey) {
                *pubkey = &keyring->keys[*from].key.pubkey;
            }
            return &keyring->keys[*from];
        }
    }
    return NULL;
}

pgp_key_t *
rnp_key_store_get_key_by_grip(pgp_io_t *io, rnp_key_store_t *keyring, const uint8_t *grip)
{
    if (rnp_get_debug(__FILE__)) {
        fprintf(io->errs, "looking keyring %p\n", keyring);
    }

    for (int i = 0; keyring && i < keyring->keyc; i++) {
        if (rnp_get_debug(__FILE__)) {
            hexdump(io->errs, "looking for grip", grip, PGP_FINGERPRINT_SIZE);
            hexdump(io->errs, "keyring grip", keyring->keys[i].grip, PGP_FINGERPRINT_SIZE);
        }
        if (memcmp(keyring->keys[i].grip, grip, PGP_FINGERPRINT_SIZE) == 0) {
            return &keyring->keys[i];
        }
    }
    return NULL;
}

/* convert a string keyid into a binary keyid */
static void
str2keyid(const char *userid, uint8_t *keyid, size_t len)
{
    static const char *uppers = "0123456789ABCDEF";
    static const char *lowers = "0123456789abcdef";
    const char *       hi;
    const char *       lo;
    uint8_t            hichar;
    uint8_t            lochar;
    size_t             j;
    int                i;

    for (i = 0, j = 0; j < len && userid[i] && userid[i + 1]; i += 2, j++) {
        if ((hi = strchr(uppers, userid[i])) == NULL) {
            if ((hi = strchr(lowers, userid[i])) == NULL) {
                break;
            }
            hichar = (uint8_t)(hi - lowers);
        } else {
            hichar = (uint8_t)(hi - uppers);
        }
        if ((lo = strchr(uppers, userid[i + 1])) == NULL) {
            if ((lo = strchr(lowers, userid[i + 1])) == NULL) {
                break;
            }
            lochar = (uint8_t)(lo - lowers);
        } else {
            lochar = (uint8_t)(lo - uppers);
        }
        keyid[j] = (hichar << 4) | (lochar);
    }
    keyid[j] = 0x0;
}

/* return the next key which matches, starting searching at *from */
static bool
get_key_by_name(pgp_io_t *             io,
                const rnp_key_store_t *keyring,
                const char *           name,
                unsigned *             from,
                pgp_key_t **           key)
{
    pgp_key_t *kp;
    uint8_t ** uidp;
    unsigned   i = 0;
    pgp_key_t *keyp;
    unsigned   savedstart;
    regex_t    r;
    uint8_t    keyid[PGP_KEY_ID_SIZE + 1];
    size_t     len;

    *key = NULL;

    if (!keyring || !name || !from) {
        RNP_LOG_FD(io->errs, "keyring, name and from shouldn't be NULL");
        return false;
    }
    len = strlen(name);
    if (rnp_get_debug(__FILE__)) {
        RNP_LOG_FD(io->outs, "[%u] name '%s', len %zu", *from, name, len);
    }
    /* first try name as a keyid */
    (void) memset(keyid, 0x0, sizeof(keyid));
    str2keyid(name, keyid, sizeof(keyid));
    if (rnp_get_debug(__FILE__)) {
        hexdump(io->outs, "keyid", keyid, 4);
    }
    savedstart = *from;
    if ((kp = rnp_key_store_get_key_by_id(io, keyring, keyid, from, NULL)) != NULL) {
        *key = kp;
        return true;
    }
    *from = savedstart;
    if (rnp_get_debug(__FILE__)) {
        RNP_LOG_FD(io->outs, "regex match '%s' from %u", name, *from);
    }
    /* match on full name or email address as a NOSUB, ICASE regexp */
    if (regcomp(&r, name, REG_EXTENDED | REG_ICASE) != 0) {
        RNP_LOG_FD(io->errs, "Can't compile regex from string: '%s'", name);
        return false;
    }
    for (keyp = &keyring->keys[*from]; *from < keyring->keyc; *from += 1, keyp++) {
        uidp = keyp->uids;
        for (i = 0; i < keyp->uidc; i++, uidp++) {
            if (regexec(&r, (char *) *uidp, 0, NULL, 0) == 0) {
                if (rnp_get_debug(__FILE__)) {
                    RNP_LOG_FD(
                      io->outs, "MATCHED keyid \"%s\" len %" PRIsize "u", (char *) *uidp, len);
                }
                regfree(&r);
                *key = keyp;
                return true;
            }
        }
    }
    regfree(&r);
    return true;
}

/**
   \ingroup HighLevel_KeyringFind

   \brief Finds key from its User ID

   \param keyring Keyring to be searched
   \param userid User ID of required key

   \return Pointer to Key, if found; NULL, if not found

   \note This returns a pointer to the key inside the keyring, not a
   copy.  Do not free it.

*/
bool
rnp_key_store_get_key_by_name(pgp_io_t *             io,
                              const rnp_key_store_t *keyring,
                              const char *           name,
                              pgp_key_t **           key)
{
    unsigned from;

    from = 0;
    return get_key_by_name(io, keyring, name, &from, key);
}

bool
rnp_key_store_get_next_key_by_name(
  pgp_io_t *io, const rnp_key_store_t *keyring, const char *name, unsigned *n, pgp_key_t **key)
{
    return get_key_by_name(io, keyring, name, n, key);
}

static bool
grip_hash_bignum(pgp_hash_t *hash, const BIGNUM *bignum)
{
    uint8_t *bn;
    size_t   len;
    int      padbyte;

    if (BN_is_zero(bignum)) {
        pgp_hash_add(hash, (const uint8_t *) &"\0", 1);
        return true;
    }
    if ((len = (size_t) BN_num_bytes(bignum)) < 1) {
        (void) fprintf(stderr, "grip_hash_bignum: bad size: %zu\n", len);
        return false;
    }
    if ((bn = calloc(1, len + 1)) == NULL) {
        (void) fprintf(stderr, "grip_hash_bignum: bad bn alloc\n");
        return false;
    }
    BN_bn2bin(bignum, bn + 1);
    bn[0] = 0x0;
    padbyte = (bn[1] & 0x80) ? 1 : 0;
    pgp_hash_add(hash, bn, (unsigned) (len + padbyte));
    free(bn);
    return true;
}

/* keygrip is subjectKeyHash from pkcs#15. */
bool
rnp_key_store_get_key_grip(pgp_pubkey_t *key, uint8_t *grip)
{
    pgp_hash_t hash = {0};

    if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
        (void) fprintf(stderr, "rnp_key_store_get_key_grip: bad sha1 alloc\n");
        return false;
    }

    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_SIGN_ONLY:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
        if (!grip_hash_bignum(&hash, key->key.rsa.n)) {
            return false;
        }
        break;

    case PGP_PKA_DSA:
        if (!grip_hash_bignum(&hash, key->key.dsa.p)) {
            return false;
        }
        if (!grip_hash_bignum(&hash, key->key.dsa.q)) {
            return false;
        }
        if (!grip_hash_bignum(&hash, key->key.dsa.g)) {
            return false;
        }
        if (!grip_hash_bignum(&hash, key->key.dsa.y)) {
            return false;
        }
        break;

    case PGP_PKA_ELGAMAL:
        if (!grip_hash_bignum(&hash, key->key.elgamal.p)) {
            return false;
        }
        if (!grip_hash_bignum(&hash, key->key.elgamal.g)) {
            return false;
        }
        if (!grip_hash_bignum(&hash, key->key.elgamal.y)) {
            return false;
        }
        break;

    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        if (!grip_hash_bignum(&hash, key->key.ecc.point)) {
            return false;
        }
        break;

    default:
        (void) fprintf(stderr,
                       "rnp_key_store_get_key_grip: unsupported public-key algorithm %d\n",
                       key->alg);
        pgp_hash_finish(&hash, grip);
        return false;
    }

    return pgp_hash_finish(&hash, grip) == PGP_FINGERPRINT_SIZE;
}
