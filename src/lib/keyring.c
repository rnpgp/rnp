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

#include "config.h"

#include "rnp.h"
#include "keyring_pgp.h"
#include "keyring_ssh.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
keyring_format_key(char *buffer, uint8_t *sigid, int len)
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
        n += snprintf(&buffer[n], len - n, "%02x%02x",
                      sigid[i], sigid[i + 1]);
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
keyring_get_first_ring(keyring_t *ring, char *id, size_t len, int last)
{
    uint8_t	*src;

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
        return 0;
    }

    memset(id, 0x0, len);

    src = (uint8_t *) &ring->keys[(last) ? ring->keyc - 1 : 0].sigid;
    keyring_format_key(id, src, len);

    return 1;
}

/**
   \ingroup HighLevel_KeyringRead

   \brief Frees keyring's contents (but not keyring itself)

   \param keyring Keyring whose data is to be freed

   \note This does not free keyring itself, just the memory alloc-ed in it.
 */
void
keyring_free(keyring_t *keyring)
{
    (void)free(keyring->keys);
    keyring->keys = NULL;
    keyring->keyc = keyring->keyvsize = 0;
}

/**
   \ingroup HighLevel_KeyringList

   \brief Prints all keys in keyring to stdout.

   \param keyring Keyring to use

   \return none
*/
int
keyring_list(io_t *io, const keyring_t *keyring, const int psigs)
{
    pgp_key_t		*key;
    unsigned		 n;

    (void) fprintf(io->res, "%u key%s\n", keyring->keyc,
                   (keyring->keyc == 1) ? "" : "s");
    for (n = 0, key = keyring->keys; n < keyring->keyc; ++n, ++key) {
        if (pgp_is_key_secret(key)) {
            pgp_print_keydata(io, keyring, key, "sec",
                              &key->key.seckey.pubkey, 0);
        } else {
            pgp_print_keydata(io, keyring, key, "signature ", &key->key.pubkey, psigs);
        }
        (void) fputc('\n', io->res);
    }
    return 1;
}

int
keyring_json(io_t *io, const keyring_t *keyring, json_object *obj, const int psigs)
{
    pgp_key_t		*key;
    unsigned		n;
    for (n = 0, key = keyring->keys; n < keyring->keyc; ++n, ++key) {
        json_object *jso = json_object_new_object();
        if (pgp_is_key_secret(key)) {
            pgp_sprint_json(io, keyring, key, jso,
                            "sec", &key->key.seckey.pubkey, psigs);
        } else {
            pgp_sprint_json(io, keyring, key, jso,
                            "signature ", &key->key.pubkey, psigs);
        }
        json_object_array_add(obj,jso);
    }
    return 1;
}

/* append one keyring to another */
int
keyring_append_keyring(keyring_t *keyring, keyring_t *newring)
{
    unsigned	i;

    for (i = 0 ; i < newring->keyc ; i++) {
        EXPAND_ARRAY(keyring, key);
        (void) memcpy(&keyring->keys[keyring->keyc], &newring->keys[i],
                      sizeof(newring->keys[i]));
        keyring->keyc += 1;
    }
    return 1;
}

/* add a key to a public keyring */
int
keyring_add_to_pubring(keyring_t *keyring, const pgp_pubkey_t *pubkey, pgp_content_enum tag)
{
    pgp_key_t	*key;
    time_t		 duration;

    if (rnp_get_debug(__FILE__)) {
        fprintf(stderr, "keyring_add_to_pubring (type %u)\n", tag);
    }
    switch(tag) {
        case PGP_PTAG_CT_PUBLIC_KEY:
            EXPAND_ARRAY(keyring, key);
            key = &keyring->keys[keyring->keyc++];
            duration = key->key.pubkey.duration;
            (void) memset(key, 0x0, sizeof(*key));
            key->type = tag;
            pgp_keyid(key->sigid, PGP_KEY_ID_SIZE, pubkey, keyring->hashtype);
            pgp_fingerprint(&key->sigfingerprint, pubkey, keyring->hashtype);
            key->key.pubkey = *pubkey;
            key->key.pubkey.duration = duration;
            return 1;
        case PGP_PTAG_CT_PUBLIC_SUBKEY:
            /* subkey is not the first */
            key = &keyring->keys[keyring->keyc - 1];
            pgp_keyid(key->encid, PGP_KEY_ID_SIZE, pubkey, keyring->hashtype);
            duration = key->key.pubkey.duration;
            (void) memcpy(&key->enckey, pubkey, sizeof(key->enckey));
            key->enckey.duration = duration;
            return 1;
        default:
            return 0;
    }
}

/* add a key to a secret keyring */
int
keyring_add_to_secring(keyring_t *keyring, const pgp_seckey_t *seckey)
{
    const pgp_pubkey_t	*pubkey;
    pgp_key_t		*key;

    if (rnp_get_debug(__FILE__)) {
        fprintf(stderr, "keyring_add_to_secring\n");
    }
    if (keyring->keyc > 0) {
        key = &keyring->keys[keyring->keyc - 1];
        if (rnp_get_debug(__FILE__) &&
            key->key.pubkey.alg == PGP_PKA_DSA &&
            seckey->pubkey.alg == PGP_PKA_ELGAMAL) {
            fprintf(stderr, "keyring_add_to_secring: found elgamal seckey\n");
        }
    }
    EXPAND_ARRAY(keyring, key);
    key = &keyring->keys[keyring->keyc++];
    (void) memset(key, 0x0, sizeof(*key));
    pubkey = &seckey->pubkey;
    pgp_keyid(key->sigid, PGP_KEY_ID_SIZE, pubkey, keyring->hashtype);
    pgp_fingerprint(&key->sigfingerprint, pubkey, keyring->hashtype);
    key->type = PGP_PTAG_CT_SECRET_KEY;
    key->key.seckey = *seckey;
    if (rnp_get_debug(__FILE__)) {
        fprintf(stderr, "keyring_add_to_secring: keyc %u\n", keyring->keyc);
    }
    return 1;
}
