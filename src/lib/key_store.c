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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <stdio.h>
#include <regex.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "config.h"

#include "rnp.h"
#include "utils.h"
#include "key_store.h"
#include "key_store_internal.h"
#include "key_store_pgp.h"
#include "key_store_kbx.h"
#include "packet-print.h"
#include "pgp-key.h"
#include "packet.h"
#include "utils.h"

#include "key_store_ssh.h"

static void *
rnp_key_store_read_keyring(rnp_t *rnp, const char *path)
{
    rnp_key_store_t *key_store;

    if ((key_store = calloc(1, sizeof(*key_store))) == NULL) {
        (void) fprintf(stderr, "rnp_key_store_read_keyring: bad alloc\n");
        return NULL;
    }

    if (!rnp_key_store_load_from_file(rnp, key_store, 0, path)) {
        free(key_store);
        (void) fprintf(stderr, "rnp_key_store_read_keyring: cannot read %s\n", path);
        return NULL;
    }

    return key_store;
}

int
rnp_key_store_load_keys(rnp_t *rnp, bool loadsecret)
{
    char      id[MAX_ID_LENGTH];
    void *    newring;
    pgp_io_t *io = rnp->io;

    if (rnp->key_store_format == SSH_KEY_STORE) {
        return rnp_key_store_ssh_load_keys(
          rnp, rnp->pubpath, loadsecret ? rnp->secpath : NULL);
    }

    newring = rnp_key_store_read_keyring(rnp, rnp->pubpath);

    if (newring == NULL) {
        fprintf(io->errs, "cannot read pub keyring\n");
        return RNP_FAIL;
    }

    if (rnp->pubring) {
        rnp_key_store_free(rnp->pubring);
        free(rnp->pubring);
    }

    rnp->pubring = newring;

    if (((rnp_key_store_t *) rnp->pubring)->keyc < 1) {
        fprintf(io->errs, "pub keyring is empty\n");
        return RNP_FAIL;
    }

    /* Only read secret keys if we need to */
    if (loadsecret) {
        newring = rnp_key_store_read_keyring(rnp, rnp->secpath);

        if (newring == NULL) {
            fprintf(io->errs, "cannot read sec keyring\n");
            return RNP_FAIL;
        }

        if (rnp->secring) {
            rnp_key_store_free(rnp->secring);
            free(rnp->secring);
        }

        rnp->secring = newring;

        if (((rnp_key_store_t *) rnp->secring)->keyc < 1) {
            fprintf(io->errs, "sec keyring is empty\n");
            return RNP_FAIL;
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

    return RNP_OK;
}

int
rnp_key_store_load_from_file(rnp_t *          rnp,
                             rnp_key_store_t *key_store,
                             const unsigned   armour,
                             const char *     filename)
{
    int          rc;
    pgp_memory_t mem = {0};

    if (rnp->key_store_format == SSH_KEY_STORE) {
        return rnp_key_store_ssh_from_file(rnp->io, key_store, filename);
    }

    if (!pgp_mem_readfile(&mem, filename)) {
        return RNP_FAIL;
    }

    rc = rnp_key_store_load_from_mem(rnp, key_store, armour, &mem);
    pgp_memory_release(&mem);
    return rc;
}

int
rnp_key_store_load_from_mem(rnp_t *          rnp,
                            rnp_key_store_t *key_store,
                            const unsigned   armour,
                            pgp_memory_t *   memory)
{
    switch (rnp->key_store_format) {
    case GPG_KEY_STORE:
        return rnp_key_store_pgp_read_from_mem(rnp->io, key_store, armour, memory);

    case KBX_KEY_STORE:
        return rnp_key_store_kbx_from_mem(rnp->io, key_store, memory);

    case SSH_KEY_STORE:
        return rnp_key_store_ssh_from_mem(rnp->io, key_store, memory);
    }

    return RNP_FAIL;
}

int
rnp_key_store_write_to_file(rnp_t *          rnp,
                            rnp_key_store_t *key_store,
                            const uint8_t *  passphrase,
                            const unsigned   armour,
                            const char *     filename)
{
    int          rc;
    pgp_memory_t mem = {0};

    if (rnp->key_store_format == SSH_KEY_STORE) {
        return rnp_key_store_ssh_to_file(rnp->io, key_store, passphrase, filename);
    }

    if (!rnp_key_store_write_to_mem(rnp, key_store, passphrase, armour, &mem)) {
        return RNP_FAIL;
    }

    rc = pgp_mem_writefile(&mem, filename);
    pgp_memory_release(&mem);
    return rc;
}

int
rnp_key_store_write_to_mem(rnp_t *          rnp,
                           rnp_key_store_t *key_store,
                           const uint8_t *  passphrase,
                           const unsigned   armour,
                           pgp_memory_t *   memory)
{
    switch (rnp->key_store_format) {
    case GPG_KEY_STORE:
        return rnp_key_store_pgp_write_to_mem(rnp->io, key_store, passphrase, armour, memory);

    case KBX_KEY_STORE:
        return rnp_key_store_kbx_to_mem(rnp->io, key_store, passphrase, memory);

    case SSH_KEY_STORE:
        return rnp_key_store_ssh_to_mem(rnp->io, key_store, passphrase, memory);
    }

    return RNP_FAIL;
}

/* Format a PGP key to a readable hexadecimal string in a user supplied
 * buffer.
 *
 * buffer: the buffer to write into
 * sigid:  the PGP key ID to format
 * len:    the length of buffer, including the null terminator
 *
 * TODO: There is no error checking here.
 * TODO: Make this function more general or use an existing one.
 */

void
rnp_key_store_format_key(char *buffer, uint8_t *sigid, int len)
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
        n += snprintf(&buffer[n], len - n, "%02x%02x", sigid[i], sigid[i + 1]);
    }
    buffer[n] = 0x0;
}

/* Get the uid of the first key in the keyring.
 *
 * TODO: Set errno on failure.
 * TODO: Check upstream calls to this function - they likely won't
 *       handle the new error condition.
 */
int
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
        return RNP_FAIL;
    }

    memset(id, 0x0, len);

    src = (uint8_t *) &ring->keys[(last) ? ring->keyc - 1 : 0].sigid;
    rnp_key_store_format_key(id, src, len);

    return RNP_OK;
}

/**
   \ingroup HighLevel_KeyringRead

   \brief Frees keyring's contents (but not keyring itself)

   \param keyring Keyring whose data is to be freed

   \note This does not free keyring itself, just the memory alloc-ed in it.
 */
void
rnp_key_store_free(rnp_key_store_t *keyring)
{
    int i;

    if (keyring->keys != NULL) {
        for (i = 0; i < keyring->keyc; i++) {
            FREE_ARRAY((&keyring->keys[i]), uid);
            FREE_ARRAY((&keyring->keys[i]), subsig);
            FREE_ARRAY((&keyring->keys[i]), revoke);
        }
    }
    FREE_ARRAY(keyring, key);

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
    }
    FREE_ARRAY(keyring, blob);
}

/**
   \ingroup HighLevel_KeyringList

   \brief Prints all keys in keyring to stdout.

   \param keyring Keyring to use

   \return none
*/
int
rnp_key_store_list(pgp_io_t *io, const rnp_key_store_t *keyring, const int psigs)
{
    pgp_key_t *key;
    unsigned   n;
    unsigned   keyc = (keyring != NULL) ? keyring->keyc : 0;

    (void) fprintf(io->res, "%u key%s\n", keyc, (keyc == 1) ? "" : "s");

    if (keyring == NULL) {
        return RNP_OK;
    }

    for (n = 0, key = keyring->keys; n < keyring->keyc; ++n, ++key) {
        if (pgp_is_key_secret(key)) {
            pgp_print_keydata(io, keyring, key, "sec", &key->key.seckey.pubkey, 0);
        } else {
            pgp_print_keydata(io, keyring, key, "signature ", &key->key.pubkey, psigs);
        }
        (void) fputc('\n', io->res);
    }
    return RNP_OK;
}

int
rnp_key_store_json(pgp_io_t *             io,
                   const rnp_key_store_t *keyring,
                   json_object *          obj,
                   const int              psigs)
{
    pgp_key_t *key;
    unsigned   n;
    for (n = 0, key = keyring->keys; n < keyring->keyc; ++n, ++key) {
        json_object *jso = json_object_new_object();
        if (pgp_is_key_secret(key)) {
            pgp_sprint_json(io, keyring, key, jso, "sec", &key->key.seckey.pubkey, psigs);
        } else {
            pgp_sprint_json(io, keyring, key, jso, "signature ", &key->key.pubkey, psigs);
        }
        json_object_array_add(obj, jso);
    }
    return RNP_OK;
}

/* append one keyring to another */
int
rnp_key_store_append_keyring(rnp_key_store_t *keyring, rnp_key_store_t *newring)
{
    unsigned i;

    for (i = 0; i < newring->keyc; i++) {
        EXPAND_ARRAY(keyring, key);
        if (keyring->keys == NULL) {
            return RNP_FAIL;
        }
        (void) memcpy(
          &keyring->keys[keyring->keyc], &newring->keys[i], sizeof(newring->keys[i]));
        keyring->keyc += 1;
    }

    for (i = 0; i < newring->blobc; i++) {
        EXPAND_ARRAY(keyring, blob);
        if (keyring->blobs == NULL) {
            return RNP_FAIL;
        }
        (void) memcpy(
          &keyring->blobs[keyring->blobc], &newring->blobs[i], sizeof(newring->blobs[i]));
        keyring->blobc += 1;
    }
    return RNP_OK;
}

/* add a key to keyring */
int
rnp_key_store_add_key(pgp_io_t *       io,
                      rnp_key_store_t *keyring,
                      pgp_key_t *      key,
                      pgp_content_enum tag)
{
    int        i;
    pgp_key_t *newkey;

    if (rnp_get_debug(__FILE__)) {
        fprintf(io->errs, "rnp_key_store_add_key\n");
    }

    EXPAND_ARRAY(keyring, key);
    if (keyring->keys == NULL) {
        return RNP_FAIL;
    }
    newkey = &keyring->keys[keyring->keyc++];
    memcpy((uint8_t *) newkey + offsetof(pgp_key_t, type),
           (uint8_t *) key + offsetof(pgp_key_t, type),
           sizeof(pgp_key_t) - offsetof(pgp_key_t, type));
    newkey->type = tag;

    for (i = 0; i < key->uidc; i++) {
        EXPAND_ARRAY(newkey, uid);
        if (newkey->uids == NULL) {
            return RNP_FAIL;
        }
        memcpy(&newkey->uids[newkey->uidc], &key->uids[i], sizeof(uint8_t *));
        newkey->uidc++;
    }

    for (i = 0; i < key->packetc; i++) {
        EXPAND_ARRAY(newkey, packet);
        if (newkey->packets == NULL) {
            return RNP_FAIL;
        }
        memcpy(&newkey->packets[newkey->packetc], &key->packets[i], sizeof(pgp_subpacket_t));
        newkey->packetc++;
    }

    for (i = 0; i < key->subsigc; i++) {
        EXPAND_ARRAY(newkey, subsig);
        if (newkey->subsigs == NULL) {
            return RNP_FAIL;
        }
        memcpy(&newkey->subsigs[newkey->subsigc], &key->subsigs[i], sizeof(pgp_subsig_t));
        newkey->subsigc++;
    }

    for (i = 0; i < key->revokec; i++) {
        EXPAND_ARRAY(newkey, revoke);
        if (newkey->revokes == NULL) {
            return RNP_FAIL;
        }
        memcpy(&newkey->revokes[newkey->revokec], &key->revokes[i], sizeof(pgp_revoke_t));
        newkey->revokec++;
    }

    if (rnp_get_debug(__FILE__)) {
        fprintf(io->errs, "rnp_key_store_add_key: keyc %u\n", keyring->keyc);
    }

    return RNP_OK;
}

int
rnp_key_store_add_keydata(pgp_io_t *         io,
                          rnp_key_store_t *  keyring,
                          pgp_keydata_key_t *keydata,
                          pgp_content_enum   tag)
{
    pgp_key_t *key;

    if (rnp_get_debug(__FILE__)) {
        fprintf(io->errs, "rnp_key_store_add_keydata\n");
    }

    if (tag != PGP_PTAG_CT_PUBLIC_SUBKEY) {
        EXPAND_ARRAY(keyring, key);
        if (keyring->keys == NULL) {
            return RNP_FAIL;
        }
        key = &keyring->keys[keyring->keyc++];
        (void) memset(key, 0x0, sizeof(*key));
        pgp_keyid(key->sigid, PGP_KEY_ID_SIZE, &keydata->pubkey);
        pgp_fingerprint(&key->sigfingerprint, &keydata->pubkey);
        key->type = tag;
        key->key = *keydata;
        key->loaded = 1;
    } else {
        // it's is a subkey, adding as enckey to master that was before the key
        // TODO: move to the right way — support multiple subkeys
        key = &keyring->keys[keyring->keyc - 1];
        pgp_keyid(key->encid, PGP_KEY_ID_SIZE, &keydata->pubkey);
        pgp_fingerprint(&key->encfingerprint, &keydata->pubkey);
        (void) memcpy(&key->enckey, &keydata->pubkey, sizeof(key->enckey));
        key->enckey.duration = key->key.pubkey.duration;
    }

    if (rnp_get_debug(__FILE__)) {
        fprintf(io->errs, "rnp_key_store_add_keydata: keyc %u\n", keyring->keyc);
    }

    return RNP_OK;
}

int
rnp_key_store_remove_key(pgp_io_t *io, rnp_key_store_t *keyring, const pgp_key_t *key)
{
    int i;

    for (i = 0; i < keyring->keyc; i++) {
        if (key == &keyring->keys[i]) {
            memmove(&keyring->keys[i],
                    &keyring->keys[i + 1],
                    sizeof(pgp_key_t) * (keyring->keyc - i));
            keyring->keyc--;
            return RNP_OK;
        }
    }

    return RNP_FAIL;
}

int
rnp_key_store_remove_key_by_id(pgp_io_t *io, rnp_key_store_t *keyring, const uint8_t *keyid)
{
    unsigned         from;
    const pgp_key_t *key;

    from = 0;

    key = rnp_key_store_get_key_by_id(io, keyring, keyid, &from, NULL);
    if (key != NULL) {
        return rnp_key_store_remove_key(io, keyring, key);
    }

    return RNP_FAIL;
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
const pgp_key_t *
rnp_key_store_get_key_by_id(pgp_io_t *             io,
                            const rnp_key_store_t *keyring,
                            const uint8_t *        keyid,
                            unsigned *             from,
                            pgp_pubkey_t **        pubkey)
{
    uint8_t nullid[PGP_KEY_ID_SIZE];

    (void) memset(nullid, 0x0, sizeof(nullid));
    for (; keyring && *from < keyring->keyc; *from += 1) {
        if (rnp_get_debug(__FILE__)) {
            hexdump(io->errs, "keyring keyid", keyring->keys[*from].sigid, PGP_KEY_ID_SIZE);
            hexdump(io->errs, "keyid", keyid, PGP_KEY_ID_SIZE);
        }
        if (memcmp(keyring->keys[*from].sigid, keyid, PGP_KEY_ID_SIZE) == 0 ||
            memcmp(&keyring->keys[*from].sigid[PGP_KEY_ID_SIZE / 2],
                   keyid,
                   PGP_KEY_ID_SIZE / 2) == 0) {
            if (pubkey) {
                *pubkey = &keyring->keys[*from].key.pubkey;
            }
            return &keyring->keys[*from];
        }
        if (memcmp(&keyring->keys[*from].encid, nullid, sizeof(nullid)) == 0) {
            continue;
        }
        if (memcmp(&keyring->keys[*from].encid, keyid, PGP_KEY_ID_SIZE) == 0 ||
            memcmp(&keyring->keys[*from].encid[PGP_KEY_ID_SIZE / 2],
                   keyid,
                   PGP_KEY_ID_SIZE / 2) == 0) {
            if (pubkey) {
                *pubkey = &keyring->keys[*from].enckey;
            }
            return &keyring->keys[*from];
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
                const pgp_key_t **     key)
{
    const pgp_key_t *kp;
    uint8_t **       uidp;
    unsigned         i = 0;
    pgp_key_t *      keyp;
    unsigned         savedstart;
    regex_t          r;
    uint8_t          keyid[PGP_KEY_ID_SIZE + 1];
    size_t           len;

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
unsigned
rnp_key_store_get_key_by_name(pgp_io_t *             io,
                              const rnp_key_store_t *keyring,
                              const char *           name,
                              const pgp_key_t **     key)
{
    unsigned from;

    from = 0;
    return get_key_by_name(io, keyring, name, &from, key) ? RNP_OK : RNP_FAIL;
}

unsigned
rnp_key_store_get_next_key_by_name(pgp_io_t *             io,
                                   const rnp_key_store_t *keyring,
                                   const char *           name,
                                   unsigned *             n,
                                   const pgp_key_t **     key)
{
    return get_key_by_name(io, keyring, name, n, key) ? RNP_OK : RNP_FAIL;
}
