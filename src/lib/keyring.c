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
#include "rnpdefs.h"
#include "keyring.h"
#include "keyring_pgp.h"
#include "keyring_ssh.h"
#include "packet-print.h"
#include "packet-key.h"
#include "packet.h"

#include <regex.h>
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
keyring_list(pgp_io_t *io, const keyring_t *keyring, const int psigs)
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
keyring_json(pgp_io_t *io, const keyring_t *keyring, json_object *obj, const int psigs)
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

/* add a key to keyring */
int
keyring_add_key(pgp_io_t *io, keyring_t *keyring, pgp_keydata_key_t *keydata, pgp_content_enum tag)
{
    pgp_key_t  *key;

	if (rnp_get_debug(__FILE__)) {
		fprintf(io->errs, "keyring_add_key\n");
	}

	if (tag != PGP_PTAG_CT_PUBLIC_SUBKEY) {
		EXPAND_ARRAY(keyring, key);
		key = &keyring->keys[keyring->keyc++];
		(void) memset(key, 0x0, sizeof(*key));
		pgp_keyid(key->sigid, PGP_KEY_ID_SIZE, &keydata->pubkey, keyring->hashtype);
		pgp_fingerprint(&key->sigfingerprint, &keydata->pubkey, keyring->hashtype);
        key->type = tag;
        key->key = *keydata;
	} else {
        // it's is a subkey, adding as enckey to master that was before the key
        // TODO: move to the right way — support multiple subkeys
        key = &keyring->keys[keyring->keyc - 1];
        pgp_keyid(key->encid, PGP_KEY_ID_SIZE, &keydata->pubkey, keyring->hashtype);
        (void) memcpy(&key->enckey, &keydata->pubkey, sizeof(key->enckey));
        key->enckey.duration = key->key.pubkey.duration;
    }

	if (rnp_get_debug(__FILE__)) {
		fprintf(io->errs, "keyring_add_key: keyc %u\n", keyring->keyc);
	}

	return 1;
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
keyring_get_key_by_id(pgp_io_t *io, const keyring_t *keyring,
                      const uint8_t *keyid, unsigned *from, pgp_pubkey_t **pubkey)
{
	uint8_t	nullid[PGP_KEY_ID_SIZE];

	(void) memset(nullid, 0x0, sizeof(nullid));
	for ( ; keyring && *from < keyring->keyc; *from += 1) {
		if (rnp_get_debug(__FILE__)) {
			hexdump(io->errs, "keyring keyid", keyring->keys[*from].sigid, PGP_KEY_ID_SIZE);
			hexdump(io->errs, "keyid", keyid, PGP_KEY_ID_SIZE);
		}
		if (memcmp(keyring->keys[*from].sigid, keyid, PGP_KEY_ID_SIZE) == 0 ||
		    memcmp(&keyring->keys[*from].sigid[PGP_KEY_ID_SIZE / 2],
				keyid, PGP_KEY_ID_SIZE / 2) == 0) {
			if (pubkey) {
				*pubkey = &keyring->keys[*from].key.pubkey;
			}
			return &keyring->keys[*from];
		}
		if (memcmp(&keyring->keys[*from].encid, nullid, sizeof(nullid)) == 0) {
			continue;
		}
		if (memcmp(&keyring->keys[*from].encid, keyid, PGP_KEY_ID_SIZE) == 0 ||
		    memcmp(&keyring->keys[*from].encid[PGP_KEY_ID_SIZE / 2], keyid, PGP_KEY_ID_SIZE / 2) == 0) {
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
	static const char	*uppers = "0123456789ABCDEF";
	static const char	*lowers = "0123456789abcdef";
	const char		*hi;
	const char		*lo;
	uint8_t			 hichar;
	uint8_t			 lochar;
	size_t			 j;
	int			 i;

	for (i = 0, j = 0 ; j < len && userid[i] && userid[i + 1] ; i += 2, j++) {
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
static const pgp_key_t *
get_key_by_name(pgp_io_t *io, const keyring_t *keyring, const char *name, unsigned *from)
{
	const pgp_key_t	*kp;
	uint8_t			**uidp;
	unsigned    	 	 i = 0;
	pgp_key_t		*keyp;
	unsigned		 savedstart;
	regex_t r;
	uint8_t		 	 keyid[PGP_KEY_ID_SIZE + 1];
	size_t          	 len;

	if (!keyring || !name || !from) {
		return NULL;
	}
	len = strlen(name);
	if (rnp_get_debug(__FILE__)) {
		(void) fprintf(io->outs, "[%u] name '%s', len %zu\n",
			*from, name, len);
	}
	/* first try name as a keyid */
	(void) memset(keyid, 0x0, sizeof(keyid));
	str2keyid(name, keyid, sizeof(keyid));
	if (rnp_get_debug(__FILE__)) {
		hexdump(io->outs, "keyid", keyid, 4);
	}
	savedstart = *from;
	if ((kp = keyring_get_key_by_id(io, keyring, keyid, from, NULL)) != NULL) {
		return kp;
	}
	*from = savedstart;
	if (rnp_get_debug(__FILE__)) {
		(void) fprintf(io->outs, "regex match '%s' from %u\n",
			name, *from);
	}
	/* match on full name or email address as a NOSUB, ICASE regexp */
	(void) regcomp(&r, name, REG_EXTENDED | REG_ICASE);
	for (keyp = &keyring->keys[*from]; *from < keyring->keyc; *from += 1, keyp++) {
		uidp = keyp->uids;
		for (i = 0 ; i < keyp->uidc; i++, uidp++) {
			if (regexec(&r, (char *)*uidp, 0, NULL, 0) == 0) {
				if (rnp_get_debug(__FILE__)) {
					(void) fprintf(io->outs,
						"MATCHED keyid \"%s\" len %" PRIsize "u\n",
					       (char *) *uidp, len);
				}
				regfree(&r);
				return keyp;
			}
		}
	}
	regfree(&r);
	return NULL;
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
const pgp_key_t *
keyring_get_key_by_name(pgp_io_t *io, const keyring_t *keyring, const char *name)
{
	unsigned	from;

	from = 0;
	return get_key_by_name(io, keyring, name, &from);
}

const pgp_key_t *
keyring_get_next_key_by_name(pgp_io_t *io, const keyring_t *keyring, const char *name, unsigned *n)
{
	return get_key_by_name(io, keyring, name, n);
}