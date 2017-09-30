/*-
 * Copyright (c) 2017 Ribose Inc.
 * All rights reserved.
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

#include <rnp/rnp2.h>
#include "list.h"
#include "crypto.h"
#include "signature.h"
#include "pgp-key.h"
#include <librepgp/validate.h>
#include "hash.h"
#include <rnp/rnp_types.h>
#include <stdlib.h>

struct rnp_passphrase_cb_data {
    rnp_passphrase_cb cb_fn;
    void *            cb_data;
};

struct rnp_keyring_st {
    rnp_t            rnp_ctx;
    rnp_key_store_t *store;
};

struct rnp_key_st {
    pgp_key_t *    key;
    rnp_keyring_t *keyring; // associated keyring, may be null
};

static pgp_key_t *
find_suitable_subkey(const pgp_key_t *primary, uint8_t desired_usage)
{
    // fixme copied fron rnp.c
    if (!primary || DYNARRAY_IS_EMPTY(primary, subkey)) {
        return NULL;
    }
    // search in reverse with the assumption that the last
    // in the list would be the newest created subkey, for now
    for (unsigned i = primary->subkeyc; i-- > 0;) {
        pgp_key_t *subkey = primary->subkeys[i];
        if (subkey->key_flags & desired_usage) {
            return subkey;
        }
    }
    return NULL;
}

static pgp_io_t g_ffi_io;

void
rnp_set_io(FILE *output_stream, FILE *error_stream, FILE *result_stream)
{
    g_ffi_io.outs = output_stream;
    g_ffi_io.errs = error_stream;
    g_ffi_io.res = result_stream;
}

static bool
rnp_passphrase_cb_bounce(const pgp_passphrase_ctx_t *ctx,
                         char *                      passphrase,
                         size_t                      passphrase_size,
                         void *                      userdata_void)
{
    struct rnp_passphrase_cb_data *userdata = (struct rnp_passphrase_cb_data *) userdata_void;
    rnp_key_t                      key = calloc(1, sizeof(*key));
    if (!key) {
        return false;
    }
    key->key = (pgp_key_t *) ctx->key;

    int rc = userdata->cb_fn(
      userdata->cb_data, key, "TODO create a context string", passphrase, passphrase_size);
    free(key);
    return (rc == 0);
}

const char *
rnp_result_to_string(rnp_result_t result)
{
    switch (result) {
    case RNP_SUCCESS:
        return "Success";

    case RNP_ERROR_GENERIC:
        return "Unknown error";
    case RNP_ERROR_BAD_FORMAT:
        return "Bad format";
    case RNP_ERROR_BAD_PARAMETERS:
        return "Bad parameters";
    case RNP_ERROR_NOT_IMPLEMENTED:
        return "Not implemented";
    case RNP_ERROR_NOT_SUPPORTED:
        return "Not supported";
    case RNP_ERROR_OUT_OF_MEMORY:
        return "Out of memory";
    case RNP_ERROR_SHORT_BUFFER:
        return "Buffer too short";
    case RNP_ERROR_NULL_POINTER:
        return "Null pointer";

    case RNP_ERROR_ACCESS:
        return "Error accessing file";
    case RNP_ERROR_READ:
        return "Error reading file";
    case RNP_ERROR_WRITE:
        return "Error writing file";

    case RNP_ERROR_BAD_STATE:
        return "Bad state";
    case RNP_ERROR_MAC_INVALID:
        return "Invalid MAC";
    case RNP_ERROR_SIGNATURE_INVALID:
        return "Invalid signature";
    case RNP_ERROR_KEY_GENERATION:
        return "Error during key generation";
    case RNP_ERROR_KEY_NOT_FOUND:
        return "Key not found";
    case RNP_ERROR_NO_SUITABLE_KEY:
        return "Not suitable key";
    case RNP_ERROR_DECRYPT_FAILED:
        return "Decryption failed";
    case RNP_ERROR_NO_SIGNATURES_FOUND:
        return "No signatures found cannot verify";

    case RNP_ERROR_NOT_ENOUGH_DATA:
        return "Not enough data";
    case RNP_ERROR_UNKNOWN_TAG:
        return "Unknown tag";
    case RNP_ERROR_PACKET_NOT_CONSUMED:
        return "Packet not consumed";
    case RNP_ERROR_NO_USERID:
        return "Not userid";
    case RNP_ERROR_EOF:
        return "EOF detected";
    }

    return "Unknown error";
}

rnp_result_t
rnp_get_default_homedir(char **homedir)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!homedir) {
        ret = RNP_ERROR_NULL_POINTER;
        goto done;
    }

    // get the users home dir
    char *home = getenv("HOME");
    if (!home) {
        ret = RNP_ERROR_NOT_SUPPORTED;
        goto done;
    }
    if (!rnp_compose_path_ex(homedir, NULL, home, ".rnp", NULL)) {
        goto done;
    }

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

rnp_result_t
rnp_detect_homedir_formats(const char *homedir, char **pub_format, char **sec_format)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;
    char *       path = NULL;
    size_t       path_size = 0;

    // checks
    if (!homedir || !pub_format || !sec_format) {
        ret = RNP_ERROR_NULL_POINTER;
        goto done;
    }

    // we only support the common cases of GPG+GPG or GPG+G10, we don't
    // support unused combinations like KBX+KBX

    char *pubguess = NULL;
    char *secguess = NULL;
    // check for pubring.kbx file
    if (!rnp_compose_path_ex(&path, &path_size, homedir, "pubring.kbx", NULL)) {
        goto done;
    }
    if (rnp_file_exists(path)) {
        // we have a pubring.kbx, now check for private-keys-v1.d dir
        if (!rnp_compose_path_ex(&path, &path_size, homedir, "private-keys-v1.d", NULL)) {
            goto done;
        }
        if (rnp_dir_exists(path)) {
            pubguess = "KBX";
            secguess = "G10";
        }
    } else {
        // check for pubring.gpg
        if (!rnp_compose_path_ex(&path, &path_size, homedir, "pubring.gpg", NULL)) {
            goto done;
        }
        if (rnp_file_exists(path)) {
            // we have a pubring.gpg, now check for secring.gpg
            if (!rnp_compose_path_ex(&path, &path_size, homedir, "secring.gpg", NULL)) {
                goto done;
            }
            if (rnp_file_exists(path)) {
                pubguess = "GPG";
                secguess = "GPG";
            }
        }
    }
    // set our results
    if ((pubguess && !(*pub_format = strdup(pubguess))) ||
        (secguess && !(*sec_format = strdup(secguess)))) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    // we leave the *formats as NULL if we were not able to determine the format
    // (but no error occurred)

    ret = RNP_SUCCESS;
done:
    if (ret) {
        if (pub_format) {
            free(*pub_format);
            *pub_format = NULL;
        }
        if (sec_format) {
            free(*sec_format);
            *sec_format = NULL;
        }
    }
    free(path);
    return ret;
}

rnp_result_t
rnp_detect_key_format(const uint8_t buf[], size_t buf_len, char **format)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!buf || !format) {
        ret = RNP_ERROR_NULL_POINTER;
        goto done;
    }
    if (!buf_len) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    // ordered from most reliable detection to least
    char *guess = NULL;
    if (buf_len >= 12 && memcmp(buf + 8, "fXBK", 4) == 0) {
        // KBX has a magic KBXf marker
        guess = "KBX";
    } else if (buf[0] == '(' && buf[buf_len - 1] == ')') {
        // G10 is s-exprs and should start end end with parentheses
        guess = "G10";
    } else if (buf[0] & PGP_PTAG_ALWAYS_SET) {
        // this is harder to reliably determine, but could likely be improved
        guess = "GPG";
    }
    if (guess) {
        *format = strdup(guess);
        if (!*format) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

rnp_result_t
rnp_keyring_load_homedir(const char *   homedir,
                         const char *   pub_format,
                         const char *   sec_format,
                         rnp_keyring_t *pubring,
                         rnp_keyring_t *secring)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;
    char *       path = NULL;
    size_t       path_size = 0;

    // checks
    if (!homedir) {
        ret = RNP_ERROR_NULL_POINTER;
        goto done;
    }
    if (!pubring && !secring) {
        // at least one is required
        ret = RNP_ERROR_NULL_POINTER;
        goto done;
    }
    if ((pubring && !pub_format) || (secring && !sec_format)) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    const char *pubname = NULL;
    const char *secname = NULL;
    if (pubring) {
        if (!strcmp(pub_format, "GPG")) {
            pubname = "pubring.gpg";
        } else if (!strcmp(pub_format, "KBX")) {
            pubname = "pubring.kbx";
        } else {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
    }
    if (secring) {
        if (!strcmp(sec_format, "GPG")) {
            secname = "secring.gpg";
        } else if (!strcmp(sec_format, "G10")) {
            secname = "private-keys-v1.d";
        } else {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
    }

    rnp_key_store_t *pubstore = NULL;
    if (pubring) {
        if (!rnp_compose_path_ex(&path, &path_size, homedir, pubname, NULL)) {
            goto done;
        }
        rnp_result_t tmpret = rnp_keyring_create(pubring, pub_format, path);
        if (tmpret) {
            ret = tmpret;
            goto done;
        }
        pubstore = (*pubring)->store;
        if (!rnp_key_store_load_from_file(&g_ffi_io, pubstore, 0, NULL)) {
            goto done;
        }
    }
    if (secring) {
        if (!rnp_compose_path_ex(&path, &path_size, homedir, secname, NULL)) {
            goto done;
        }
        rnp_result_t tmpret = rnp_keyring_create(secring, sec_format, path);
        if (tmpret) {
            ret = tmpret;
            goto done;
        }
        if (!rnp_key_store_load_from_file(&g_ffi_io, (*secring)->store, 0, pubstore)) {
            goto done;
        }
    }

    ret = RNP_SUCCESS;
done:
    if (ret) {
        rnp_keyring_destroy(pubring);
        rnp_keyring_destroy(secring);
    }
    free(path);
    return ret;
}

rnp_result_t
rnp_keyring_create(rnp_keyring_t *ring, const char *format, const char *path)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!ring || !format) {
        ret = RNP_ERROR_NULL_POINTER;
        goto done;
    }

    // fallback to empty path
    if (!path) {
        path = "";
    }

    // proceed
    *ring = malloc(sizeof(**ring));
    if (!*ring) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    (*ring)->store = rnp_key_store_new(format, path);
    if (!(*ring)->store) {
        free(*ring);
        *ring = NULL;
        goto done;
    }

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

rnp_result_t
rnp_keyring_destroy(rnp_keyring_t *ring)
{
    if (ring) {
        if (*ring) {
            rnp_key_store_free((*ring)->store);
        }
        free(*ring);
        *ring = NULL;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_keyring_get_format(rnp_keyring_t ring, char **format)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!ring || !format) {
        ret = RNP_ERROR_NULL_POINTER;
        goto done;
    }
    if (!ring->store) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    *format = strdup(ring->store->format_label);
    if (!*format) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

rnp_result_t
rnp_keyring_get_path(rnp_keyring_t ring, char **path)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!ring || !path) {
        ret = RNP_ERROR_NULL_POINTER;
        goto done;
    }
    if (!ring->store) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    *path = strdup(ring->store->path);
    if (!*path) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

rnp_result_t
rnp_keyring_get_key_count(rnp_keyring_t ring, size_t *count)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!ring || !count) {
        ret = RNP_ERROR_NULL_POINTER;
        goto done;
    }
    if (!ring->store) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    // retrieve the key count
    *count = ring->store->keyc;

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

rnp_result_t
rnp_keyring_get_key_at(rnp_keyring_t ring, size_t idx, rnp_key_t *key)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!ring || !key) {
        ret = RNP_ERROR_NULL_POINTER;
        goto done;
    }
    if (!ring->store) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }
    if (idx >= ring->store->keyc) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    *key = malloc(sizeof(**key));
    if (!*key) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    // retrieve the key
    (*key)->key = &ring->store->keys[idx];

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

rnp_result_t
rnp_keyring_load(rnp_keyring_t *ring, const char *format, const uint8_t buf[], size_t buf_len)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!ring || !format || !buf) {
        ret = RNP_ERROR_NULL_POINTER;
        goto done;
    }
    if (!buf_len) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    // TODO

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

typedef enum {
    ID_TYPE_INVALID,
    ID_TYPE_USERID,
    ID_TYPE_KEYID,
    ID_TYPE_GRIP,
} identifier_type_t;

static bool
parse_identifier_type(const char *type, identifier_type_t *value)
{
    static const struct {
        const char *      key;
        identifier_type_t value;
    } map[] = {
      {"userid", ID_TYPE_USERID}, {"keyid", ID_TYPE_KEYID}, {"grip", ID_TYPE_GRIP},
    };

    for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
        if (!strcmp(type, map[i].key)) {
            if (value) {
                *value = map[i].value;
            }
            return true;
        }
    }
    return false;
}

static rnp_result_t
find_key_by_identifier(rnp_key_store_t * store,
                       identifier_type_t idtype,
                       const char *      identifier,
                       pgp_key_t **      key)
{
    switch (idtype) {
    case ID_TYPE_USERID:
        // TODO: this isn't really a userid search...
        rnp_key_store_get_key_by_name(&g_ffi_io, store, identifier, key);
        break;
    case ID_TYPE_KEYID: {
        uint8_t keyid[PGP_KEY_ID_SIZE];
        if (!rnp_hex_decode(identifier, keyid, sizeof(keyid))) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        unsigned from = 0;
        *key = rnp_key_store_get_key_by_id(&g_ffi_io, store, keyid, &from, NULL);
    } break;
    case ID_TYPE_GRIP: {
        uint8_t grip[PGP_FINGERPRINT_SIZE];
        if (!rnp_hex_decode(identifier, grip, sizeof(grip))) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        *key = rnp_key_store_get_key_by_grip(&g_ffi_io, store, grip);
    } break;
    default:
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_keyring_find_key(rnp_keyring_t ring,
                     const char *  identifier_type,
                     const char *  identifier,
                     rnp_key_t *   key)
{
    if (!ring || !identifier_type || !identifier || !key) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *       found = NULL;
    identifier_type_t idtype;
    if (!parse_identifier_type(identifier_type, &idtype)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_result_t tmpret = find_key_by_identifier(ring->store, idtype, identifier, &found);
    if (tmpret) {
        return tmpret;
    }
    if (found) {
        *key = malloc(sizeof(**key));
        if (!key) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        (*key)->key = found;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_keyring_add_key(rnp_keyring_t ring, rnp_key_t key)
{
    bool ok = rnp_key_store_add_key(&g_ffi_io, ring->store, key->key);

    if (ok)
        return RNP_SUCCESS;
    else
        return RNP_ERROR_GENERIC;
}

rnp_result_t
rnp_keyring_save_to_file(rnp_keyring_t ring, const char *path)
{
    const char *cur_path = ring->store->path;
    bool        armor = false;

    if (path)
        ring->store->path = path;

    bool ok = rnp_key_store_write_to_file(&g_ffi_io, ring->store, armor);

    if (path)
        ring->store->path = cur_path;

    if (ok == false)
        return RNP_ERROR_WRITE;

    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
rnp_keyring_save_to_mem(
  rnp_keyring_t ring, int flags, uint8_t *buf[], size_t *buf_len)
{
    bool         armor = (flags & RNP_EXPORT_FLAG_ARMORED);
    pgp_memory_t memory;

    bool ok = rnp_key_store_write_to_mem(NULL, ring->store, armor, &memory);

    if (!ok)
        return RNP_ERROR_GENERIC;

    return RNP_ERROR_NOT_IMPLEMENTED;
}

static pgp_key_t *
resolve_userid(const rnp_key_store_t *keyring, const char *userid)
{
    pgp_key_t *key = NULL;

    if (userid == NULL) {
        return NULL;
    }

    if ((strlen(userid) > 1) && userid[0] == '0' && userid[1] == 'x') {
        userid += 2;
    }

    rnp_key_store_get_key_by_name(&g_ffi_io, keyring, userid, &key);
    return key;
}

#if 0
rnp_result_t
rnp_insert_armored_public_key(rnp_keyring_t keyring, const char *key)
{
    rnp_result_t     rc = RNP_ERROR_GENERIC;
    rnp_key_store_t *tmp_keystore = NULL;
    list             imported_grips = NULL;
    list_item *      item = NULL;

    tmp_keystore = rnp_key_store_new(RNP_KEYSTORE_GPG, "");
    if (!tmp_keystore) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    pgp_memory_t *membuf = pgp_memory_new();
    pgp_memory_add(membuf, (const uint8_t *) key, strlen(key));

    bool ret = rnp_key_store_load_from_mem(&keyring->rnp_ctx, tmp_keystore, 1, membuf);

    pgp_memory_free(membuf);

    if (ret == false || tmp_keystore->keyc == 0) {
        return RNP_ERROR_BAD_FORMAT;
    }

    rnp_t *rnp = &keyring->rnp_ctx;
    // loop through each key
    for (unsigned i = 0; i < tmp_keystore->keyc; i++) {
        pgp_key_t *      key = &tmp_keystore->keys[i];
        pgp_key_t *      importedkey = NULL;
        rnp_key_store_t *dest = pgp_is_key_secret(key) ? rnp->secring : rnp->pubring;

        // check if it already exists
        importedkey = rnp_key_store_get_key_by_grip(rnp->io, dest, key->grip);
        if (!importedkey) {
            // add it to the dest store
            if (!rnp_key_store_add_key(rnp->io, dest, key)) {
                rc = RNP_ERROR_WRITE;
                goto done;
            }
            // keep track of what keys have been imported
            list_append(&imported_grips, key->grip, sizeof(key->grip));
            importedkey = rnp_key_store_get_key_by_grip(rnp->io, dest, key->grip);
            for (unsigned j = 0; j < key->subkeyc; j++) {
                pgp_key_t *subkey = key->subkeys[j];

                if (!rnp_key_store_add_key(rnp->io, dest, subkey)) {
                    rc = RNP_ERROR_WRITE;
                    goto done;
                }
                // fix up the subkeys dynarray pointers...
                importedkey->subkeys[j] =
                  rnp_key_store_get_key_by_grip(rnp->io, dest, subkey->grip);
                // keep track of what keys have been imported
                list_append(&imported_grips, subkey->grip, sizeof(subkey->grip));
            }
        }
    }

    // update the keyrings on disk
    if (!rnp_key_store_write_to_file(rnp, rnp->secring, 0) ||
        !rnp_key_store_write_to_file(rnp, rnp->pubring, 0)) {
        RNP_LOG("failed to write keyring");
        goto done;
    }

    rc = RNP_SUCCESS;

done:
    // remove all the imported keys from the temporary store,
    // since we're taking ownership of their internal data
    item = list_front(imported_grips);
    while (item) {
        uint8_t *grip = (uint8_t *) item;
        rnp_key_store_remove_key(
          rnp->io, tmp_keystore, rnp_key_store_get_key_by_grip(rnp->io, tmp_keystore, grip));
        item = list_next(item);
    }
    list_destroy(&imported_grips);
    rnp_key_store_free(tmp_keystore);
    return rc;
}
#endif

rnp_result_t
rnp_export_public_key(rnp_key_t key, uint32_t flags, char **buf, size_t *buf_len)
{
    pgp_output_t *output;
    pgp_memory_t *mem;

    bool armor = (flags & RNP_EXPORT_FLAG_ARMORED);

    if (key == NULL) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!pgp_setup_memory_write(NULL, &output, &mem, 128)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    pgp_write_xfer_pubkey(output, key->key, NULL, armor);

    *buf_len = pgp_mem_len(mem);
    if (armor)
        *buf_len += 1;

    *buf = malloc(*buf_len);

    if (*buf == NULL) {
        pgp_teardown_memory_write(output, mem);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    memcpy(*buf, pgp_mem_data(mem), pgp_mem_len(mem));

    if (armor)
        buf[*buf_len - 1] = 0;

    return RNP_SUCCESS;
}

static rnp_result_t
find_key_for(rnp_keyring_t   keyring,
             const char *    userid,
             pgp_key_flags_t flags,
             pgp_seckey_t ** key)
{
    *key = NULL;

    pgp_key_t *keypair = resolve_userid(keyring->store, userid);
    if (keypair == NULL) {
        return RNP_ERROR_KEY_NOT_FOUND;
    }
    if (pgp_key_can_sign(keypair) == false) {
        keypair = find_suitable_subkey(keypair, PGP_KF_SIGN);
        if (!keypair) {
            return RNP_ERROR_NO_SUITABLE_KEY;
        }
    }

    // key exist and might be used to sign, trying get it from secring
    unsigned from = 0;

    keypair =
      rnp_key_store_get_key_by_id(&g_ffi_io, keyring->store, keypair->keyid, &from, NULL);

    if (keypair == NULL) {
        return RNP_ERROR_KEY_NOT_FOUND;
    }

    if (pgp_key_is_locked(keypair) == false) {
        *key = &keypair->key.seckey;
        return RNP_SUCCESS;
    }

    pgp_seckey_t *decrypted_seckey =
      pgp_decrypt_seckey(keypair,
                         &keyring->rnp_ctx.passphrase_provider,
                         &(pgp_passphrase_ctx_t){.op = PGP_OP_SIGN, .key = keypair});

    if (decrypted_seckey == NULL) {
        return RNP_ERROR_DECRYPT_FAILED;
    }

    *key = decrypted_seckey;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_sign(rnp_keyring_t keyring,
         const char *  userid,
         const char *  hash_fn,
         bool          clearsign,
         bool          armor,
         const uint8_t msg[],
         size_t        msg_len,
         uint8_t **    sig,
         size_t *      sig_len)
{
    if (msg == NULL) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (clearsign == true && armor == false) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_seckey_t *seckey = NULL;
    rnp_result_t  res = find_key_for(keyring, userid, PGP_KF_SIGN, &seckey);

    if (res != RNP_SUCCESS) {
        return res;
    }
    if (!seckey) {
        return RNP_ERROR_DECRYPT_FAILED;
    }
    /* sign file */

    rnp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rnp = &keyring->rnp_ctx;
    ctx.halg = pgp_str_to_hash_alg(hash_fn);
    ctx.armour = armor;

    pgp_memory_t *signedmem =
      pgp_sign_buf(&ctx, keyring->rnp_ctx.io, msg, msg_len, seckey, clearsign);

    if (signedmem == NULL) {
        return RNP_ERROR_GENERIC;
    }

    *sig_len = pgp_mem_len(signedmem);
    if (ctx.armour)
        *sig_len += 1;

    *sig = calloc(1, *sig_len);
    if (*sig == NULL) {
        pgp_seckey_free(seckey);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    memcpy(*sig, pgp_mem_data(signedmem), pgp_mem_len(signedmem));
    pgp_memory_free(signedmem);

    pgp_seckey_free(seckey);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_verify(
  rnp_keyring_t keyring, const uint8_t sig[], size_t sig_len, uint8_t **msg, size_t *msg_len)
{
    pgp_memory_t *signedmem = NULL;
    pgp_memory_t *cat = NULL;

    *msg_len = 0;
    *msg = NULL;

    if (sig == NULL) {
        return RNP_ERROR_NULL_POINTER;
    }

    signedmem = pgp_memory_new();
    if (!signedmem) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    cat = pgp_memory_new();
    if (cat == NULL) {
        pgp_memory_free(signedmem);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (!pgp_memory_add(signedmem, sig, sig_len)) {
        return RNP_ERROR_GENERIC;
    }

    pgp_validation_t result;
    (void) memset(&result, 0x0, sizeof(result));
    bool ok =
      pgp_validate_mem(keyring->rnp_ctx.io, &result, signedmem, &cat, false, keyring->store);

    /* signedmem is freed from pgp_validate_mem */

    if (ok) {
        *msg_len = pgp_mem_len(cat);
        *msg = malloc(*msg_len);
        memcpy(*msg, pgp_mem_data(cat), *msg_len);
        pgp_memory_free(cat);
        return RNP_SUCCESS;
    }

    pgp_memory_free(cat);

    if (result.validc + result.invalidc + result.unknownc == 0) {
        return RNP_ERROR_NO_SIGNATURES_FOUND;
    }

    return RNP_ERROR_SIGNATURE_INVALID;
}

rnp_result_t
rnp_sign_detached(rnp_keyring_t keyring,
                  const char *  userid,
                  const char *  hash_fn,
                  bool          armor,
                  const uint8_t msg[],
                  size_t        msg_len,
                  uint8_t **    sig,
                  size_t *      sig_len)
{
    pgp_seckey_t *seckey = NULL;

    if (hash_fn == NULL || msg == NULL || sig == NULL || sig_len == NULL) {
        return RNP_ERROR_NULL_POINTER;
    }

    rnp_result_t res = find_key_for(keyring, userid, PGP_KF_SIGN, &seckey);

    if (res != RNP_SUCCESS) {
        return res;
    }
    if (!seckey) {
        return RNP_ERROR_DECRYPT_FAILED;
    }

    rnp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rnp = &keyring->rnp_ctx;
    ctx.halg = pgp_str_to_hash_alg(hash_fn);
    ctx.armour = armor;

    return pgp_sign_memory_detached(&ctx, seckey, msg, msg_len, sig, sig_len);
}

rnp_result_t
rnp_verify_detached(rnp_keyring_t keyring,
                    const uint8_t msg[],
                    size_t        msg_len,
                    const uint8_t sig[],
                    size_t        sig_len)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
rnp_verify_detached_file(rnp_keyring_t keyring,
                         const char *  file_path,
                         const uint8_t sig[],
                         size_t        sig_len)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

static pgp_compression_type_t
pgp_str_to_zalg(const char *z_alg)
{
    if (z_alg == NULL)
        return PGP_C_NONE;

    if (strcmp(z_alg, "none") == 0)
        return PGP_C_NONE;
    if (strcmp(z_alg, "zlib") == 0)
        return PGP_C_ZLIB;
    if (strcmp(z_alg, "zip") == 0)
        return PGP_C_ZIP;
    if (strcmp(z_alg, "bzip2") == 0)
        return PGP_C_BZIP2;

    // something we don't recognize ...
    return PGP_C_NONE;
}

rnp_result_t
rnp_encrypt(rnp_keyring_t     keyring,
            const char *const recipients[],
            size_t            recipients_len,
            const char *      cipher,
            const char *      z_alg,
            size_t            z_level,
            bool              armored,
            const uint8_t     msg[],
            size_t            msg_len,
            uint8_t **        output,
            size_t *          output_len)
{
    rnp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rnp = &keyring->rnp_ctx;
    ctx.ealg = pgp_str_to_cipher(cipher);
    ctx.zalg = pgp_str_to_zalg(z_alg);
    ctx.zlevel = z_level;
    ctx.armour = armored;

    *output = NULL;
    *output_len = 0;

    if (recipients_len != 1)
        return RNP_ERROR_BAD_PARAMETERS;

    const pgp_key_t *keypair = resolve_userid(keyring->store, recipients[0]);
    if (!keypair)
        return RNP_ERROR_KEY_NOT_FOUND;

    if (pgp_key_can_encrypt(keypair) == false) {
        keypair = find_suitable_subkey(keypair, PGP_KF_ENCRYPT);
        if (!keypair)
            return RNP_ERROR_NO_SUITABLE_KEY;
    }

    pgp_memory_t *enc =
      pgp_encrypt_buf(&ctx, keyring->rnp_ctx.io, msg, msg_len, pgp_get_pubkey(keypair));

    const size_t mem_len = pgp_mem_len(enc);

    if (armored)
        *output_len = mem_len + 1; // space for null
    else
        *output_len = mem_len;

    *output = calloc(1, *output_len);
    if (*output == NULL) {
        pgp_memory_free(enc);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    memcpy(*output, pgp_mem_data(enc), mem_len);
    pgp_memory_free(enc);

    return RNP_SUCCESS;
}

/**
* Decrypt a message
* @param key the private key to attempt decryption with
* @param msg the ciphertext
* @param msg_len length of msg in bytes
* @param output pointer that will be set to a newly allocated
* buffer, length *output_len, free with rnp_buffer_free
* @param output_len will be set to the length of output
*/
rnp_result_t
rnp_decrypt(rnp_keyring_t keyring,
            const uint8_t input[],
            size_t        input_len,
            uint8_t **    output,
            size_t *      output_len)
{
    *output = NULL;
    *output_len = 0;

    if (input == NULL) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (input_len < 32) {
        return RNP_ERROR_SHORT_BUFFER;
    }

    const char *armor_head = "-----BEGIN PGP MESSAGE-----";
    const int   armored = (memcmp(input, armor_head, strlen(armor_head)) == 0);

    pgp_memory_t *mem = pgp_decrypt_buf(&g_ffi_io,
                                        input,
                                        input_len,
                                        keyring->store,
                                        NULL,
                                        armored,
                                        /*use_ssh*/ 0,
                                        1,
                                        &keyring->rnp_ctx.passphrase_provider);

    if (mem == NULL) {
        return RNP_ERROR_DECRYPT_FAILED;
    }

    *output_len = pgp_mem_len(mem);

    *output = malloc(*output_len);
    if (*output == NULL) {
        pgp_memory_free(mem);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    memcpy(*output, pgp_mem_data(mem), *output_len);
    pgp_memory_free(mem);
    return RNP_SUCCESS;
}

/*
static pgp_pubkey_alg_t
pgp_str_to_pka(const char *str)
{
    if (strcmp(str, "RSA") == 0)
        return PGP_PKA_RSA;

    if (strcmp(str, "ECDSA") == 0)
        return PGP_PKA_ECDSA;

    if (strcmp(str, "SM2") == 0)
        return PGP_PKA_SM2;

    if (strcmp(str, "EDDSA") == 0)
        return PGP_PKA_EDDSA;

    return PGP_PKA_NOTHING;
}
*/

static bool
parse_key_flag(const char *usage, uint8_t *value)
{
    static const struct {
        const char *key;
        uint8_t     value;
    } map[] = {
      {"certify", PGP_KF_CERTIFY}, {"sign", PGP_KF_SIGN}, {"encrypt", PGP_KF_ENCRYPT}};

    for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
        if (!rnp_strcasecmp(usage, map[i].key)) {
            *value = map[i].value;
            return true;
        }
    }
    return false;
}

static bool
parse_pubkey_alg(const char *name, pgp_pubkey_alg_t *value)
{
    static const struct {
        const char *key;
        uint8_t     value;
    } map[] = {
      {"RSA", PGP_PKA_RSA},
      {"ECDH", PGP_PKA_ECDH},
      {"ECDSA", PGP_PKA_ECDSA},
      {"EDDSA", PGP_PKA_EDDSA},
      {"SM2", PGP_PKA_SM2},
    };

    for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
        if (!rnp_strcasecmp(name, map[i].key)) {
            *value = map[i].value;
            return true;
        }
    }
    return false;
}

static bool
pk_alg_allows_custom_curve(pgp_pubkey_alg_t pkalg)
{
    switch (pkalg) {
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
        return true;
    default:
        return false;
    }
}

static bool
parse_curve_name(const char *name, pgp_curve_t *value)
{
    *value = find_curve_by_name(name);
    return *value != PGP_CURVE_MAX;
}

static bool
parse_hash_alg(const char *name, pgp_hash_alg_t *value)
{
    *value = pgp_str_to_hash_alg(name);
    return *value != PGP_HASH_UNKNOWN;
}

static bool
parse_symm_alg(const char *name, pgp_symm_alg_t *value)
{
    static const struct {
        const char *   key;
        pgp_symm_alg_t value;
    } map[] = {{"idea", PGP_SA_IDEA},
               {"tripledes", PGP_SA_TRIPLEDES},
               {"cast5", PGP_SA_CAST5},
               {"blowfish", PGP_SA_BLOWFISH},
               {"aes128", PGP_SA_AES_128},
               {"aes192", PGP_SA_AES_192},
               {"aes256", PGP_SA_AES_256},
               {"twofish", PGP_SA_TWOFISH},
               {"camellia128", PGP_SA_CAMELLIA_128},
               {"camellia192", PGP_SA_CAMELLIA_192},
               {"camellia256", PGP_SA_CAMELLIA_256},
               {"sm4", PGP_SA_SM4}};

    for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
        if (!rnp_strcasecmp(name, map[i].key)) {
            *value = map[i].value;
            return true;
        }
    }
    return false;
}

static bool
parse_compress_alg(const char *name, pgp_compression_type_t *value)
{
    static const struct {
        const char *           key;
        pgp_compression_type_t value;
    } map[] = {
      {"none", PGP_C_NONE}, {"zip", PGP_C_ZIP}, {"zlib", PGP_C_ZLIB}, {"bzip2", PGP_C_BZIP2}};

    for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
        if (!rnp_strcasecmp(name, map[i].key)) {
            *value = map[i].value;
            return true;
        }
    }
    return false;
}

static bool
parse_preferences(json_object *jso, pgp_user_prefs_t *prefs)
{
    static const struct {
        const char *   key;
        enum json_type type;
    } properties[] = {{"hashes", json_type_array},
                      {"ciphers", json_type_array},
                      {"compression", json_type_array},
                      {"key server", json_type_string}};

    for (size_t iprop = 0; iprop < ARRAY_SIZE(properties); iprop++) {
        json_object *value = NULL;
        const char * key = properties[iprop].key;

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }

        if (!json_object_is_type(value, properties[iprop].type)) {
            return false;
        }
        if (!rnp_strcasecmp(key, "hashes")) {
            int length = json_object_array_length(value);
            for (int i = 0; i < length; i++) {
                json_object *item = json_object_array_get_idx(value, i);
                if (!json_object_is_type(item, json_type_string)) {
                    return false;
                }
                pgp_hash_alg_t hash_alg;
                if (!parse_hash_alg(json_object_get_string(item), &hash_alg)) {
                    return false;
                }
                EXPAND_ARRAY(prefs, hash_alg);
                prefs->hash_algs[prefs->hash_algc++] = hash_alg;
            }
        } else if (!rnp_strcasecmp(key, "ciphers")) {
            int length = json_object_array_length(value);
            for (int i = 0; i < length; i++) {
                json_object *item = json_object_array_get_idx(value, i);
                if (!json_object_is_type(item, json_type_string)) {
                    return false;
                }
                pgp_symm_alg_t symm_alg;
                if (!parse_symm_alg(json_object_get_string(item), &symm_alg)) {
                    return false;
                }
                EXPAND_ARRAY(prefs, symm_alg);
                prefs->symm_algs[prefs->symm_algc++] = symm_alg;
            }

        } else if (!rnp_strcasecmp(key, "compression")) {
            int length = json_object_array_length(value);
            for (int i = 0; i < length; i++) {
                json_object *item = json_object_array_get_idx(value, i);
                if (!json_object_is_type(item, json_type_string)) {
                    return false;
                }
                pgp_compression_type_t compression;
                if (!parse_compress_alg(json_object_get_string(item), &compression)) {
                    return false;
                }
                EXPAND_ARRAY(prefs, compress_alg);
                prefs->compress_algs[prefs->compress_algc++] = compression;
            }
        } else if (!rnp_strcasecmp(key, "key server")) {
            prefs->key_server = (uint8_t *) strdup(json_object_get_string(value));
            if (!prefs->key_server) {
                return false;
            }
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return true;
}

static bool
parse_keygen_crypto(json_object *jso, rnp_keygen_crypto_params_t *crypto)
{
    static const struct {
        const char *   key;
        enum json_type type;
    } properties[] = {{"type", json_type_string},
                      {"curve", json_type_string},
                      {"length", json_type_int},
                      {"hash", json_type_string}};

    for (size_t i = 0; i < ARRAY_SIZE(properties); i++) {
        json_object *value = NULL;
        const char * key = properties[i].key;

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }

        if (!json_object_is_type(value, properties[i].type)) {
            return false;
        }
        // TODO: make sure there are no duplicate keys in the JSON
        if (!rnp_strcasecmp(key, "type")) {
            if (!parse_pubkey_alg(json_object_get_string(value), &crypto->key_alg)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "length")) {
            // if the key alg is set and isn't RSA, this wouldn't be used
            // (RSA is default, so we have to see if it is set)
            if (crypto->key_alg && crypto->key_alg != PGP_PKA_RSA) {
                return false;
            }
            crypto->rsa.modulus_bit_len = json_object_get_int(value);
        } else if (!rnp_strcasecmp(key, "curve")) {
            if (!pk_alg_allows_custom_curve(crypto->key_alg)) {
                return false;
            }
            if (!parse_curve_name(json_object_get_string(value), &crypto->ecc.curve)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "hash")) {
            if (!parse_hash_alg(json_object_get_string(value), &crypto->hash_alg)) {
                return false;
            }
        } else {
            // shouldn't happen
            return false;
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return true;
}

static bool
parse_keygen_primary(json_object *jso, rnp_keygen_primary_desc_t *desc)
{
    static const char *properties[] = {
      "userid", "usage", "expiration", "preferences", "protection"};
    rnp_selfsig_cert_info *cert = &desc->cert;

    if (!parse_keygen_crypto(jso, &desc->crypto)) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(properties); i++) {
        json_object *value = NULL;
        const char * key = properties[i];

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }
        if (!rnp_strcasecmp(key, "userid")) {
            if (!json_object_is_type(value, json_type_string)) {
                return false;
            }
            const char *userid = json_object_get_string(value);
            if (strlen(userid) >= sizeof(cert->userid)) {
                return false;
            }
            strcpy((char *) cert->userid, userid);
        } else if (!rnp_strcasecmp(key, "usage")) {
            switch (json_object_get_type(value)) {
            case json_type_array: {
                int length = json_object_array_length(value);
                for (int j = 0; j < length; j++) {
                    json_object *item = json_object_array_get_idx(value, j);
                    if (!json_object_is_type(item, json_type_string)) {
                        return false;
                    }
                    uint8_t flag;
                    if (!parse_key_flag(json_object_get_string(item), &flag)) {
                        return false;
                    }
                    if (cert->key_flags & flag) {
                        return false;
                    }
                    cert->key_flags |= flag;
                }
            } break;
            case json_type_string:
                if (!parse_key_flag(json_object_get_string(value), &cert->key_flags)) {
                    return false;
                }
                break;
            default:
                return false;
            }
        } else if (!rnp_strcasecmp(key, "expiration")) {
            // TODO: support some strings formats?
            if (!json_object_is_type(value, json_type_int)) {
                return false;
            }
            cert->key_expiration = json_object_get_int(value);
        } else if (!rnp_strcasecmp(key, "preferences")) {
            if (!json_object_is_type(value, json_type_object)) {
                return false;
            }
            if (!parse_preferences(value, &cert->prefs)) {
                return false;
            }
            if (json_object_object_length(value) != 0) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "protection")) {
            // TODO
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return json_object_object_length(jso) == 0;
}

static bool
parse_keygen_sub(json_object *jso, rnp_keygen_subkey_desc_t *desc)
{
    static const char *       properties[] = {"usage", "expiration"};
    rnp_selfsig_binding_info *binding = &desc->binding;

    if (!parse_keygen_crypto(jso, &desc->crypto)) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(properties); i++) {
        json_object *value = NULL;
        const char * key = properties[i];

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }
        if (!rnp_strcasecmp(key, "usage")) {
            switch (json_object_get_type(value)) {
            case json_type_array: {
                int length = json_object_array_length(value);
                for (int j = 0; j < length; j++) {
                    json_object *item = json_object_array_get_idx(value, j);
                    if (!json_object_is_type(item, json_type_string)) {
                        return false;
                    }
                    uint8_t flag;
                    if (!parse_key_flag(json_object_get_string(item), &flag)) {
                        return false;
                    }
                    if (binding->key_flags & flag) {
                        return false;
                    }
                    binding->key_flags |= flag;
                }
            } break;
            case json_type_string:
                if (!parse_key_flag(json_object_get_string(value), &binding->key_flags)) {
                    return false;
                }
                break;
            default:
                return false;
            }
        } else if (!rnp_strcasecmp(key, "expiration")) {
            // TODO: support some strings formats?
            if (!json_object_is_type(value, json_type_int)) {
                return false;
            }
            binding->key_expiration = json_object_get_int(value);
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return json_object_object_length(jso) == 0;
}

static bool
gen_json_grips(char **result, const pgp_key_t *primary, const pgp_key_t *sub)
{
    bool         ret = false;
    json_object *jso = NULL;
    char         grip[PGP_FINGERPRINT_SIZE * 2 + 1];

    if (!result) {
        return false;
    }

    jso = json_object_new_object();
    if (!jso) {
        return false;
    }

    if (primary) {
        json_object *jsoprimary = json_object_new_object();
        if (!jsoprimary) {
            goto done;
        }
        json_object_object_add(jso, "primary", jsoprimary);
        if (!rnp_hex_encode(
              primary->grip, PGP_FINGERPRINT_SIZE, grip, sizeof(grip), RNP_HEX_UPPERCASE)) {
            goto done;
        }
        json_object *jsogrip = json_object_new_string(grip);
        if (!jsogrip) {
            goto done;
        }
        json_object_object_add(jsoprimary, "grip", jsogrip);
    }
    if (sub) {
        json_object *jsosub = json_object_new_object();
        if (!jsosub) {
            goto done;
        }
        json_object_object_add(jso, "subkey", jsosub);
        if (!rnp_hex_encode(
              sub->grip, PGP_FINGERPRINT_SIZE, grip, sizeof(grip), RNP_HEX_UPPERCASE)) {
            goto done;
        }
        json_object *jsogrip = json_object_new_string(grip);
        if (!jsogrip) {
            goto done;
        }
        json_object_object_add(jsosub, "grip", jsogrip);
    }
    *result = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));

    ret = true;
done:
    json_object_put(jso);
    return ret;
}

rnp_result_t
rnp_generate_key_json(rnp_keyring_t     pubring,
                      rnp_keyring_t     secring,
                      rnp_get_key_cb    getkeycb,
                      rnp_passphrase_cb getpasscb,
                      void *            app_ctx,
                      const char *      json,
                      char **           results)
{
    rnp_result_t              ret = RNP_ERROR_GENERIC;
    json_object *             jso = NULL;
    rnp_keygen_primary_desc_t primary_desc = {{0}};
    rnp_keygen_subkey_desc_t  sub_desc = {{0}};
    char *                    identifier_type = NULL;
    char *                    identifier = NULL;

    // checks
    if (!pubring || !secring || !json || !results) {
        return RNP_ERROR_NULL_POINTER;
    }

    // parse the JSON
    jso = json_tokener_parse(json);
    if (!jso) {
        // syntax error or some other issue
        ret = RNP_ERROR_BAD_FORMAT;
        goto done;
    }

    // locate the appropriate sections
    json_object *jsoprimary = NULL;
    json_object *jsosub = NULL;
    json_object_object_foreach(jso, key, value)
    {
        json_object **dest = NULL;

        if (rnp_strcasecmp(key, "primary") == 0) {
            dest = &jsoprimary;
        } else if (rnp_strcasecmp(key, "subkey") == 0) {
            dest = &jsosub;
        } else {
            // unrecognized key in the object
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }

        // duplicate "primary"/"subkey"
        if (*dest) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
        *dest = value;
    }

    if (jsoprimary && jsosub) { // generating primary+sub
        if (!parse_keygen_primary(jsoprimary, &primary_desc) ||
            !parse_keygen_sub(jsosub, &sub_desc)) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
        pgp_key_t primary_pub = {0};
        pgp_key_t primary_sec = {0};
        pgp_key_t sub_pub = {0};
        pgp_key_t sub_sec = {0};
        if (!pgp_generate_keypair(&primary_desc,
                                  &sub_desc,
                                  true,
                                  &primary_sec,
                                  &primary_pub,
                                  &sub_sec,
                                  &sub_pub,
                                  secring->store->format)) {
            goto done;
        }
        // TODO: error handling
        gen_json_grips(results, &primary_pub, &sub_pub);
        if (pubring) {
            // TODO: error handling
            rnp_key_store_add_key(&g_ffi_io, pubring->store, &primary_pub);
            rnp_key_store_add_key(&g_ffi_io, pubring->store, &sub_pub);
        } else {
            pgp_key_free_data(&primary_pub);
            pgp_key_free_data(&sub_pub);
        }
        if (secring) {
            // TODO: error handling
            rnp_key_store_add_key(&g_ffi_io, secring->store, &primary_sec);
            rnp_key_store_add_key(&g_ffi_io, secring->store, &sub_sec);
        } else {
            pgp_key_free_data(&primary_sec);
            pgp_key_free_data(&sub_sec);
        }
    } else if (jsoprimary && !jsosub) { // generating primary only
        if (!parse_keygen_primary(jsoprimary, &primary_desc)) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
        pgp_key_t primary_pub = {0};
        pgp_key_t primary_sec = {0};
        if (!pgp_generate_primary_key(
              &primary_desc, true, &primary_sec, &primary_pub, secring->store->format)) {
            goto done;
        }
        // TODO: error handling
        gen_json_grips(results, &primary_pub, NULL);
        if (pubring) {
            // TODO: error handling
            rnp_key_store_add_key(&g_ffi_io, pubring->store, &primary_pub);
        } else {
            pgp_key_free_data(&primary_pub);
        }
        if (secring) {
            // TODO: error handling
            rnp_key_store_add_key(&g_ffi_io, secring->store, &primary_sec);
        } else {
            pgp_key_free_data(&primary_sec);
        }
    } else if (jsosub) { // generating subkey only
        json_object *jsoparent = NULL;
        if (!json_object_object_get_ex(jsosub, "primary", &jsoparent) ||
            json_object_object_length(jsoparent) != 1) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
        json_object_object_foreach(jsoparent, key, value)
        {
            if (!json_object_is_type(value, json_type_string)) {
                ret = RNP_ERROR_BAD_FORMAT;
                goto done;
            }
            identifier_type = strdup(key);
            identifier = strdup(json_object_get_string(value));
        }
        if (!identifier_type || !identifier) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        rnp_strlwr(identifier_type);
        json_object_object_del(jsosub, "primary");

        identifier_type_t idtype;
        if (!parse_identifier_type(identifier_type, &idtype)) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }

        pgp_key_t *  primary_pub = NULL;
        pgp_key_t *  primary_sec = NULL;
        rnp_result_t tmpret =
          find_key_by_identifier(pubring->store, idtype, identifier, &primary_pub);
        if (tmpret) {
            ret = tmpret;
            goto done;
        }
        tmpret = find_key_by_identifier(secring->store, idtype, identifier, &primary_sec);
        if (tmpret) {
            ret = tmpret;
            goto done;
        }
        if ((!primary_pub || !primary_sec) && !getkeycb) {
            ret = RNP_ERROR_NULL_POINTER;
            goto done;
        }
        if (!primary_pub) {
            rnp_key_t found = getkeycb(app_ctx, identifier_type, identifier, false);
            if (found) {
                primary_pub = found->key;
            }
        }
        if (!primary_sec) {
            rnp_key_t found = getkeycb(app_ctx, identifier_type, identifier, true);
            if (found) {
                primary_sec = found->key;
            }
        }
        if (!primary_sec || !primary_pub) {
            ret = RNP_ERROR_KEY_NOT_FOUND;
            goto done;
        }
        if (!parse_keygen_sub(jsosub, &sub_desc)) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
        const pgp_passphrase_provider_t provider = {
          .callback = rnp_passphrase_cb_bounce,
          .userdata =
            &(struct rnp_passphrase_cb_data){.cb_fn = getpasscb, .cb_data = app_ctx}};
        pgp_key_t sub_pub = {0};
        pgp_key_t sub_sec = {0};
        if (!pgp_generate_subkey(&sub_desc,
                                 true,
                                 primary_sec,
                                 primary_pub,
                                 &sub_sec,
                                 &sub_pub,
                                 &provider,
                                 secring->store->format)) {
            goto done;
        }
        // TODO: error handling
        gen_json_grips(results, NULL, &sub_pub);
        if (pubring) {
            // TODO: error handling
            rnp_key_store_add_key(&g_ffi_io, pubring->store, &sub_pub);
        } else {
            pgp_key_free_data(&sub_pub);
        }
        if (secring) {
            // TODO: error handling
            rnp_key_store_add_key(&g_ffi_io, secring->store, &sub_sec);
        } else {
            pgp_key_free_data(&sub_sec);
        }
    } else {
        // nothing to generate...
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    json_object_put(jso);
    free(identifier_type);
    free(identifier);
    pgp_free_user_prefs(&primary_desc.cert.prefs);
    return ret;
}

rnp_result_t
rnp_generate_private_key(rnp_key_t *   pubkey,
                         rnp_key_t *   seckey,
                         rnp_keyring_t pubring,
                         rnp_keyring_t secring,
                         const char *  userid,
                         const char *  passphrase,
                         const char *  signature_hash)
{
    rnp_result_t         rc = RNP_ERROR_GENERIC;
    pgp_key_t *          primary_sec = NULL;
    pgp_key_t *          primary_pub = NULL;
    pgp_key_t *          subkey_sec = NULL;
    pgp_key_t *          subkey_pub = NULL;
    const pgp_hash_alg_t hash_alg = pgp_str_to_hash_alg(signature_hash);

    if (hash_alg == PGP_HASH_UNKNOWN) {
        rc = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    if (strlen(userid) >= MAX_ID_LENGTH) {
        rc = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    rnp_keygen_primary_desc_t primary_desc;
    rnp_keygen_subkey_desc_t  subkey_desc;
    memset(&primary_desc, 0, sizeof(primary_desc));
    memset(&subkey_desc, 0, sizeof(subkey_desc));

    const pgp_pubkey_alg_t pri_alg = PGP_PKA_RSA;
    const pgp_pubkey_alg_t sub_alg = PGP_PKA_RSA;

    primary_desc.crypto.key_alg = pri_alg;
    primary_desc.crypto.rsa.modulus_bit_len = 1024;
    primary_desc.crypto.hash_alg = hash_alg;
    strcpy((char *) primary_desc.cert.userid, userid);
    primary_desc.cert.key_flags = pgp_pk_alg_capabilities(pri_alg);
    primary_desc.cert.key_expiration = 0;
    primary_desc.cert.primary = 1;

    subkey_desc.crypto.key_alg = sub_alg;
    subkey_desc.crypto.rsa.modulus_bit_len = 1024;
    subkey_desc.crypto.hash_alg = hash_alg;
    subkey_desc.binding.key_flags = pgp_pk_alg_capabilities(sub_alg); // fixme
    subkey_desc.binding.key_expiration = 0;

    primary_sec = calloc(1, sizeof(*primary_sec));
    primary_pub = calloc(1, sizeof(*primary_pub));
    subkey_sec = calloc(1, sizeof(*subkey_sec));
    subkey_pub = calloc(1, sizeof(*subkey_pub));
    if (!primary_sec || !primary_pub || !subkey_sec || !subkey_pub) {
        rc = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    const key_store_format_t key_format = secring->store->format;

    if (!pgp_generate_keypair(&primary_desc,
                              &subkey_desc,
                              true,
                              primary_sec,
                              primary_pub,
                              subkey_sec,
                              subkey_pub,
                              key_format)) {
        rc = RNP_ERROR_KEY_GENERATION;
        goto done;
    }

    if (!pgp_key_protect_passphrase(primary_sec, key_format, NULL, passphrase)) {
        rc = RNP_ERROR_GENERIC;
        goto done;
    }

    if (!pgp_key_protect_passphrase(subkey_sec, key_format, NULL, passphrase)) {
        rc = RNP_ERROR_GENERIC;
        goto done;
    }

    // add them all to the key store
    if (!rnp_key_store_add_key(&g_ffi_io, secring->store, primary_sec) ||
        !rnp_key_store_add_key(&g_ffi_io, secring->store, subkey_sec) ||
        !rnp_key_store_add_key(&g_ffi_io, pubring->store, primary_pub) ||
        !rnp_key_store_add_key(&g_ffi_io, pubring->store, subkey_pub)) {
        rc = RNP_ERROR_WRITE;
        goto done;
    }

    // update the keyring on disk
    if (!rnp_key_store_write_to_file(&g_ffi_io, secring->store, 0) ||
        !rnp_key_store_write_to_file(&g_ffi_io, pubring->store, 0)) {
        rc = RNP_ERROR_WRITE;
        goto done;
    }

    rc = RNP_SUCCESS;

done:
    free(primary_sec);
    free(primary_pub);
    free(subkey_sec);
    free(subkey_pub);

    return rc;
}

rnp_result_t
rnp_key_free(rnp_key_t *key)
{
    // This does not free key->key which is owned by the keyring
    free(*key);
    *key = NULL;
    return RNP_SUCCESS;
}

void
rnp_buffer_free(void *ptr)
{
    free(ptr);
}

rnp_result_t
rnp_key_get_primary_uid(rnp_key_t key, char **uid)
{
    if (key == NULL || key->key == NULL || uid == NULL)
        return RNP_ERROR_NULL_POINTER;

    if (key->key->uid0_set)
        return rnp_key_get_uid_at(key, key->key->uid0, uid);
    else
        return rnp_key_get_uid_at(key, 0, uid);
}

rnp_result_t
rnp_key_get_uid_count(rnp_key_t key, size_t *count)
{
    if (key == NULL || key->key == NULL || count == NULL)
        return RNP_ERROR_NULL_POINTER;

    *count = key->key->uidc;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_uid_at(rnp_key_t key, size_t idx, char **uid)
{
    if (key == NULL || key->key == NULL || uid == NULL)
        return RNP_ERROR_NULL_POINTER;
    if (idx > key->key->uidc)
        return RNP_ERROR_BAD_PARAMETERS;

    size_t uid_len = strlen((const char *) key->key->uids[idx]);
    *uid = calloc(uid_len + 1, 1);

    if (*uid == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    memcpy(*uid, key->key->uids[idx], uid_len);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_fprint(rnp_key_t key, char **fprint)
{
    if (key == NULL || key->key == NULL || fprint == NULL)
        return RNP_ERROR_NULL_POINTER;

    *fprint = calloc(PGP_FINGERPRINT_HEX_SIZE + 1, 1);
    if (*fprint == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    rnp_strhexdump(
      *fprint, key->key->fingerprint.fingerprint, key->key->fingerprint.length, " ");

    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_keyid(rnp_key_t key, char **keyid)
{
    if (key == NULL || key->key == NULL || keyid == NULL)
        return RNP_ERROR_NULL_POINTER;

    *keyid = calloc(PGP_KEY_ID_SIZE * 2 + 1, 1);
    if (*keyid == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    rnp_strhexdump(*keyid, key->key->keyid, PGP_KEY_ID_SIZE, "");

    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_grip(rnp_key_t key, char **grip)
{
    if (key == NULL || key->key == NULL || grip == NULL)
        return RNP_ERROR_NULL_POINTER;

    size_t hexsize = PGP_FINGERPRINT_SIZE * 2 + 1;
    *grip = calloc(hexsize, 1);
    if (*grip == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    if (!rnp_hex_encode(
          key->key->grip, PGP_FINGERPRINT_SIZE, *grip, hexsize, RNP_HEX_UPPERCASE)) {
        return RNP_ERROR_GENERIC;
    }

    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_locked(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    *result = pgp_key_is_locked(key->key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_unlock(rnp_key_t key, rnp_passphrase_cb cb, void *app_ctx)
{
    if (key == NULL || key->key == NULL || cb == NULL)
        return RNP_ERROR_NULL_POINTER;

    if (pgp_key_is_locked(key->key) == false)
        return RNP_SUCCESS;

    pgp_passphrase_provider_t pass_provider;
    bool                      ok = pgp_key_unlock(key->key, &pass_provider);
    if (ok == false)
        return RNP_ERROR_GENERIC;

    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_protected(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = pgp_key_is_protected(key->key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_protect(rnp_key_t key, const char *passphrase)
{
    if (key == NULL || key->key == NULL || passphrase == NULL)
        return RNP_ERROR_NULL_POINTER;

    if (key->keyring == NULL)
        return RNP_ERROR_BAD_STATE;

    // TODO allow setting protection params
    bool ok =
      pgp_key_protect_passphrase(key->key, (*key->keyring)->store->format, NULL, passphrase);

    if (ok)
        return RNP_SUCCESS;
    return RNP_ERROR_GENERIC;
}

rnp_result_t
rnp_key_unprotect(rnp_key_t key, rnp_passphrase_cb cb, void *app_ctx)
{
    if (key == NULL || key->key == NULL || cb == NULL)
        return RNP_ERROR_NULL_POINTER;
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
rnp_key_is_primary_key(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = pgp_key_is_primary_key(key->key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_subkey(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = pgp_key_is_subkey(key->key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_secret(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = pgp_is_key_secret(key->key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_public(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = pgp_is_key_public(key->key);
    return RNP_SUCCESS;
}
