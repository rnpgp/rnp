/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
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
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** \file
 */
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: keyring.c,v 1.50 2011/06/25 00:37:44 agc Exp $");
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <regex.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "types.h"
#include "keyring_pgp.h"
#include "packet-parse.h"
#include "signature.h"
#include "rnpsdk.h"
#include "readerwriter.h"
#include "rnpdefs.h"
#include "packet.h"
#include "crypto.h"
#include "validate.h"
#include "rnpdefs.h"
#include "rnpdigest.h"
#include <json.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* read any gpg config file */
static int
conffile(rnp_t *rnp, char *homedir, char *userid, size_t length)
{
    regmatch_t	 matchv[10];
    regex_t		 keyre;
    char		 buf[BUFSIZ];
    FILE		*fp;

    __PGP_USED(rnp);
    (void) snprintf(buf, sizeof(buf), "%s/gpg.conf", homedir);
    if ((fp = fopen(buf, "r")) == NULL) {
        return 0;
    }
    (void) memset(&keyre, 0x0, sizeof(keyre));
    (void) regcomp(&keyre, "^[ \t]*default-key[ \t]+([0-9a-zA-F]+)",
                   REG_EXTENDED);
    while (fgets(buf, (int)sizeof(buf), fp) != NULL) {
        if (regexec(&keyre, buf, 10, matchv, 0) == 0) {
            (void) memcpy(userid, &buf[(int)matchv[1].rm_so],
                          MIN((unsigned)(matchv[1].rm_eo -
                                         matchv[1].rm_so), length));
            if (rnp->passfp == NULL) {
                (void) fprintf(stderr,
                               "rnp: default key set to \"%.*s\"\n",
                               (int)(matchv[1].rm_eo - matchv[1].rm_so),
                               &buf[(int)matchv[1].rm_so]);
            }
        }
    }
    (void) fclose(fp);
    regfree(&keyre);
    return 1;
}

/* read a keyring and return it */
static void *
readkeyring(rnp_t *rnp, const char *name, const char *homedir)
{
    keyring_t	*keyring;
    const unsigned	 noarmor = 0;
    char		 f[MAXPATHLEN];
    char		*filename;

    if ((filename = rnp_getvar(rnp, name)) == NULL) {
        (void) snprintf(f, sizeof(f), "%s/%s.gpg", homedir, name);
        filename = f;
    }
    if ((keyring = calloc(1, sizeof(*keyring))) == NULL) {
        (void) fprintf(stderr, "readkeyring: bad alloc\n");
        return NULL;
    }
    if (!pgp_keyring_fileread(keyring, noarmor, filename)) {
        free(keyring);
        (void) fprintf(stderr, "cannot read %s %s\n", name, filename);
        return NULL;
    }
    rnp_setvar(rnp, name, filename);
    return keyring;
}

int
pgp_keyring_load_keys(rnp_t *rnp, char *homedir)
{
	char     *userid;
	char      id[MAX_ID_LENGTH];
	io_t *io = rnp->io;

	/* TODO: Some of this might be split up into sub-functions. */
	/* TODO: Figure out what unhandled error is causing an
	 *       empty keyring to end up in keyring_get_first_ring
	 *       and ensure that it's not present in the
	 *       ssh implementation too.
	 */

	rnp->pubring = readkeyring(rnp, "pubring", homedir);

	if (rnp->pubring == NULL) {
		fprintf(io->errs, "cannot read pub keyring\n");
		return 0;
	}

	if (((keyring_t *) rnp->pubring)->keyc < 1) {
		fprintf(io->errs, "pub keyring is empty\n");
		return 0;
	}

	/* If a userid has been given, we'll use it. */
	if ((userid = rnp_getvar(rnp, "userid")) == NULL) {
		/* also search in config file for default id */
		memset(id, 0, sizeof(id));
		conffile(rnp, homedir, id, sizeof(id));
		if (id[0] != 0x0) {
			rnp_setvar(rnp, "userid", userid = id);
		}
	}

	/* Only read secret keys if we need to. */
	if (rnp_getvar(rnp, "need seckey")) {

		rnp->secring = readkeyring(rnp, "secring", homedir);

		if (rnp->secring == NULL) {
			fprintf(io->errs, "cannot read sec keyring\n");
			return 0;
		}

		if (((keyring_t *) rnp->secring)->keyc < 1) {
			fprintf(io->errs, "sec keyring is empty\n");
			return 0;
		}

		/* Now, if we don't have a valid user, use the first
		 * in secring.
		 */
		if (! userid && rnp_getvar(rnp,
								   "need userid") != NULL) {

			if (!keyring_get_first_ring(rnp->secring, id,
										sizeof(id), 0)) {
				/* TODO: This is _temporary_. A more
				 *       suitable replacement will be
				 *       required.
				 */
				fprintf(io->errs, "failed to read id\n");
				return 0;
			}

			rnp_setvar(rnp, "userid", userid = id);
		}

	} else if (rnp_getvar(rnp, "need userid") != NULL) {
		/* encrypting - get first in pubring */
		if (! userid && keyring_get_first_ring(
				rnp->pubring, id, sizeof(id), 0)) {
			rnp_setvar(rnp, "userid", userid = id);
		}
	}

	if (! userid && rnp_getvar(rnp, "need userid")) {
		/* if we don't have a user id, and we need one, fail */
		fprintf(io->errs, "cannot find user id\n");
		return 0;
	}

	return 1;
}

/**
   \ingroup HighLevel_Keyring

   \brief Creates a new pgp_key_t struct

   \return A new pgp_key_t struct, initialised to zero.

   \note The returned pgp_key_t struct must be freed after use with pgp_keydata_free.
*/

pgp_key_t  *
pgp_keydata_new(void)
{
	return calloc(1, sizeof(pgp_key_t));
}


/**
 \ingroup HighLevel_Keyring

 \brief Frees keydata and its memory

 \param keydata Key to be freed.

 \note This frees the keydata itself, as well as any other memory alloc-ed by it.
*/
void 
pgp_keydata_free(pgp_key_t *keydata)
{
	unsigned        n;

	for (n = 0; n < keydata->uidc; ++n) {
		pgp_userid_free(&keydata->uids[n]);
	}
	free(keydata->uids);
	keydata->uids = NULL;
	keydata->uidc = 0;

	for (n = 0; n < keydata->packetc; ++n) {
		pgp_subpacket_free(&keydata->packets[n]);
	}
	free(keydata->packets);
	keydata->packets = NULL;
	keydata->packetc = 0;

	if (keydata->type == PGP_PTAG_CT_PUBLIC_KEY) {
		pgp_pubkey_free(&keydata->key.pubkey);
	} else {
		pgp_seckey_free(&keydata->key.seckey);
	}

	free(keydata);
}

/**
 \ingroup HighLevel_KeyGeneral

 \brief Returns the public key in the given keydata.
 \param keydata

  \return Pointer to public key

  \note This is not a copy, do not free it after use.
*/

const pgp_pubkey_t *
pgp_get_pubkey(const pgp_key_t *keydata)
{
	return (keydata->type == PGP_PTAG_CT_PUBLIC_KEY) ?
				&keydata->key.pubkey :
				&keydata->key.seckey.pubkey;
}

/**
\ingroup HighLevel_KeyGeneral

\brief Check whether this is a secret key or not.
*/

unsigned 
pgp_is_key_secret(const pgp_key_t *data)
{
	return data->type != PGP_PTAG_CT_PUBLIC_KEY;
}

/**
 \ingroup HighLevel_KeyGeneral

 \brief Returns the secret key in the given keydata.

 \note This is not a copy, do not free it after use.

 \note This returns a const.  If you need to be able to write to this
 pointer, use pgp_get_writable_seckey
*/

const pgp_seckey_t *
pgp_get_seckey(const pgp_key_t *data)
{
	return (data->type == PGP_PTAG_CT_SECRET_KEY) ?
				&data->key.seckey : NULL;
}

/**
 \ingroup HighLevel_KeyGeneral

  \brief Returns the secret key in the given keydata.

  \note This is not a copy, do not free it after use.

  \note If you do not need to be able to modify this key, there is an
  equivalent read-only function pgp_get_seckey.
*/

pgp_seckey_t *
pgp_get_writable_seckey(pgp_key_t *data)
{
	return (data->type == PGP_PTAG_CT_SECRET_KEY) ?
				&data->key.seckey : NULL;
}

/* utility function to zero out memory */
void
pgp_forget(void *vp, unsigned size)
{
	(void) memset(vp, 0x0, size);
}

typedef struct {
	FILE			*passfp;
	const pgp_key_t	*key;
	char			*passphrase;
	pgp_seckey_t		*seckey;
} decrypt_t;

static pgp_cb_ret_t 
decrypt_cb(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
	const pgp_contents_t	*content = &pkt->u;
	decrypt_t		*decrypt;
	char			 pass[MAX_PASSPHRASE_LENGTH];

	decrypt = pgp_callback_arg(cbinfo);
	switch (pkt->tag) {
	case PGP_PARSER_PTAG:
	case PGP_PTAG_CT_USER_ID:
	case PGP_PTAG_CT_SIGNATURE:
	case PGP_PTAG_CT_SIGNATURE_HEADER:
	case PGP_PTAG_CT_SIGNATURE_FOOTER:
	case PGP_PTAG_CT_TRUST:
		break;

	case PGP_GET_PASSPHRASE:
		(void) pgp_getpassphrase(decrypt->passfp, pass, sizeof(pass));
		*content->skey_passphrase.passphrase = rnp_strdup(pass);
		pgp_forget(pass, (unsigned)sizeof(pass));
		return PGP_KEEP_MEMORY;

	case PGP_PARSER_ERRCODE:
		switch (content->errcode.errcode) {
		case PGP_E_P_MPI_FORMAT_ERROR:
			/* Generally this means a bad passphrase */
			fprintf(stderr, "Bad passphrase!\n");
			return PGP_RELEASE_MEMORY;

		case PGP_E_P_PACKET_CONSUMED:
			/* And this is because of an error we've accepted */
			return PGP_RELEASE_MEMORY;
		default:
			break;
		}
		(void) fprintf(stderr, "parse error: %s\n",
				pgp_errcode(content->errcode.errcode));
		return PGP_FINISHED;

	case PGP_PARSER_ERROR:
		fprintf(stderr, "parse error: %s\n", content->error);
		return PGP_FINISHED;

	case PGP_PTAG_CT_SECRET_KEY:
		if ((decrypt->seckey = calloc(1, sizeof(*decrypt->seckey))) == NULL) {
			(void) fprintf(stderr, "decrypt_cb: bad alloc\n");
			return PGP_FINISHED;
		}
		*decrypt->seckey = content->seckey;
		return PGP_KEEP_MEMORY;

	case PGP_PARSER_PACKET_END:
		/* nothing to do */
		break;

	default:
		fprintf(stderr, "Unexpected tag %d (0x%x)\n", pkt->tag,
			pkt->tag);
		return PGP_FINISHED;
	}

	return PGP_RELEASE_MEMORY;
}

/**
\ingroup Core_Keys
\brief Decrypts secret key from given keydata with given passphrase
\param key Key from which to get secret key
\param passphrase Passphrase to use to decrypt secret key
\return secret key
*/
pgp_seckey_t *
pgp_decrypt_seckey(const pgp_key_t *key, void *passfp)
{
	pgp_stream_t	*stream;
	const int	 printerrors = 1;
	decrypt_t	 decrypt;

	(void) memset(&decrypt, 0x0, sizeof(decrypt));
	decrypt.key = key;
	decrypt.passfp = passfp;
	stream = pgp_new(sizeof(*stream));
	pgp_keydata_reader_set(stream, key);
	pgp_set_callback(stream, decrypt_cb, &decrypt);
	stream->readinfo.accumulate = 1;
	pgp_parse(stream, !printerrors);
	return decrypt.seckey;
}

/**
\ingroup Core_Keys
\brief Set secret key in content
\param content Content to be set
\param key Keydata to get secret key from
*/
void 
pgp_set_seckey(pgp_contents_t *cont, const pgp_key_t *key)
{
	*cont->get_seckey.seckey = &key->key.seckey;
}

/**
\ingroup Core_Keys
\brief Get Key ID from keydata
\param key Keydata to get Key ID from
\return Pointer to Key ID inside keydata
*/
const uint8_t *
pgp_get_key_id(const pgp_key_t *key)
{
	return key->sigid;
}

/**
\ingroup Core_Keys
\brief How many User IDs in this key?
\param key Keydata to check
\return Num of user ids
*/
unsigned 
pgp_get_userid_count(const pgp_key_t *key)
{
	return key->uidc;
}

/**
\ingroup Core_Keys
\brief Get indexed user id from key
\param key Key to get user id from
\param index Which key to get
\return Pointer to requested user id
*/
const uint8_t *
pgp_get_userid(const pgp_key_t *key, unsigned subscript)
{
	return key->uids[subscript];
}

/**
   \ingroup HighLevel_Supported
   \brief Checks whether key's algorithm and type are supported by OpenPGP::SDK
   \param keydata Key to be checked
   \return 1 if key algorithm and type are supported by OpenPGP::SDK; 0 if not
*/

unsigned 
pgp_is_key_supported(const pgp_key_t *key)
{
	if (key->type == PGP_PTAG_CT_PUBLIC_KEY) {
		switch(key->key.pubkey.alg) {
		case PGP_PKA_RSA:
		case PGP_PKA_DSA:
		case PGP_PKA_ELGAMAL:
			return 1;
		default:
			break;
		}
	}
	return 0;
}

/* \todo check where userid pointers are copied */
/**
\ingroup Core_Keys
\brief Copy user id, including contents
\param dst Destination User ID
\param src Source User ID
\note If dst already has a userid, it will be freed.
*/
static uint8_t * 
copy_userid(uint8_t **dst, const uint8_t *src)
{
	size_t          len;

	len = strlen((const char *) src);
	if (*dst) {
		free(*dst);
	}
	if ((*dst = calloc(1, len + 1)) == NULL) {
		(void) fprintf(stderr, "copy_userid: bad alloc\n");
	} else {
		(void) memcpy(*dst, src, len);
	}
	return *dst;
}

/* \todo check where pkt pointers are copied */
/**
\ingroup Core_Keys
\brief Copy packet, including contents
\param dst Destination packet
\param src Source packet
\note If dst already has a packet, it will be freed.
*/
static pgp_subpacket_t * 
copy_packet(pgp_subpacket_t *dst, const pgp_subpacket_t *src)
{
	if (dst->raw) {
		free(dst->raw);
	}
	if ((dst->raw = calloc(1, src->length)) == NULL) {
		(void) fprintf(stderr, "copy_packet: bad alloc\n");
	} else {
		dst->length = src->length;
		(void) memcpy(dst->raw, src->raw, src->length);
	}
	return dst;
}

/**
\ingroup Core_Keys
\brief Add User ID to key
\param key Key to which to add User ID
\param userid User ID to add
\return Pointer to new User ID
*/
uint8_t  *
pgp_add_userid(pgp_key_t *key, const uint8_t *userid)
{
	uint8_t  **uidp;

	EXPAND_ARRAY(key, uid);
	/* initialise new entry in array */
	uidp = &key->uids[key->uidc++];
	*uidp = NULL;
	/* now copy it */
	return copy_userid(uidp, userid);
}

void print_packet_hex(const pgp_subpacket_t *pkt);

/**
\ingroup Core_Keys
\brief Add packet to key
\param keydata Key to which to add packet
\param packet Packet to add
\return Pointer to new packet
*/
pgp_subpacket_t   *
pgp_add_subpacket(pgp_key_t *keydata, const pgp_subpacket_t *packet)
{
	pgp_subpacket_t   *subpktp;

	EXPAND_ARRAY(keydata, packet);
	/* initialise new entry in array */
	subpktp = &keydata->packets[keydata->packetc++];
	subpktp->length = 0;
	subpktp->raw = NULL;
	/* now copy it */
	return copy_packet(subpktp, packet);
}

/**
\ingroup Core_Keys
\brief Add selfsigned User ID to key
\param keydata Key to which to add user ID
\param userid Self-signed User ID to add
\return 1 if OK; else 0
*/
unsigned 
pgp_add_selfsigned_userid(pgp_key_t *key, uint8_t *userid)
{
	pgp_create_sig_t	*sig;
	pgp_subpacket_t	 sigpacket;
	pgp_memory_t		*mem_userid = NULL;
	pgp_output_t		*useridoutput = NULL;
	pgp_memory_t		*mem_sig = NULL;
	pgp_output_t		*sigoutput = NULL;

	/*
         * create signature packet for this userid
         */

	/* create userid pkt */
	pgp_setup_memory_write(&useridoutput, &mem_userid, 128);
	pgp_write_struct_userid(useridoutput, userid);

	/* create sig for this pkt */
	sig = pgp_create_sig_new();
	pgp_sig_start_key_sig(sig, &key->key.seckey.pubkey, userid, PGP_CERT_POSITIVE);
	pgp_add_time(sig, (int64_t)time(NULL), "birth");
	pgp_add_issuer_keyid(sig, key->sigid);
	pgp_add_primary_userid(sig, 1);
	pgp_end_hashed_subpkts(sig);

	pgp_setup_memory_write(&sigoutput, &mem_sig, 128);
	pgp_write_sig(sigoutput, sig, &key->key.seckey.pubkey, &key->key.seckey);

	/* add this packet to key */
	sigpacket.length = pgp_mem_len(mem_sig);
	sigpacket.raw = pgp_mem_data(mem_sig);

	/* add userid to key */
	(void) pgp_add_userid(key, userid);
	(void) pgp_add_subpacket(key, &sigpacket);

	/* cleanup */
	pgp_create_sig_delete(sig);
	pgp_output_delete(useridoutput);
	pgp_output_delete(sigoutput);
	pgp_memory_free(mem_userid);
	pgp_memory_free(mem_sig);

	return 1;
}

/**
\ingroup Core_Keys
\brief Initialise pgp_key_t
\param keydata Keydata to initialise
\param type PGP_PTAG_CT_PUBLIC_KEY or PGP_PTAG_CT_SECRET_KEY
*/
void 
pgp_keydata_init(pgp_key_t *keydata, const pgp_content_enum type)
{
	if (keydata->type != PGP_PTAG_CT_RESERVED) {
		(void) fprintf(stderr,
			"pgp_keydata_init: wrong keydata type\n");
	} else if (type != PGP_PTAG_CT_PUBLIC_KEY &&
		   type != PGP_PTAG_CT_SECRET_KEY) {
		(void) fprintf(stderr, "pgp_keydata_init: wrong type\n");
	} else {
		keydata->type = type;
	}
}

/* used to point to data during keyring read */
typedef struct keyringcb_t {
	keyring_t		*keyring;	/* the keyring we're reading */
} keyringcb_t;


static pgp_cb_ret_t
cb_keyring_read(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
	keyring_t	*keyring;
	pgp_revoke_t	*revocation;
	pgp_key_t	*key;
	keyringcb_t	*cb;

	cb = pgp_callback_arg(cbinfo);
	keyring = cb->keyring;
	switch (pkt->tag) {
	case PGP_PARSER_PTAG:
	case PGP_PTAG_CT_ENCRYPTED_SECRET_KEY:
		/* we get these because we didn't prompt */
		break;
	case PGP_PTAG_CT_SIGNATURE_HEADER:
		key = &keyring->keys[keyring->keyc - 1];
		EXPAND_ARRAY(key, subsig);
		key->subsigs[key->subsigc].uid = key->uidc - 1;
		(void) memcpy(&key->subsigs[key->subsigc].sig, &pkt->u.sig,
				sizeof(pkt->u.sig));
		key->subsigc += 1;
		break;
	case PGP_PTAG_CT_SIGNATURE:
		key = &keyring->keys[keyring->keyc - 1];
		EXPAND_ARRAY(key, subsig);
		key->subsigs[key->subsigc].uid = key->uidc - 1;
		(void) memcpy(&key->subsigs[key->subsigc].sig, &pkt->u.sig,
				sizeof(pkt->u.sig));
		key->subsigc += 1;
		break;
	case PGP_PTAG_CT_TRUST:
		key = &keyring->keys[keyring->keyc - 1];
		key->subsigs[key->subsigc - 1].trustlevel = pkt->u.ss_trust.level;
		key->subsigs[key->subsigc - 1].trustamount = pkt->u.ss_trust.amount;
		break;
	case PGP_PTAG_SS_KEY_EXPIRY:
		EXPAND_ARRAY(keyring, key);
		if (keyring->keyc > 0) {
			keyring->keys[keyring->keyc - 1].key.pubkey.duration = pkt->u.ss_time;
		}
		break;
	case PGP_PTAG_SS_ISSUER_KEY_ID:
		key = &keyring->keys[keyring->keyc - 1];
		(void) memcpy(&key->subsigs[key->subsigc - 1].sig.info.signer_id,
			      pkt->u.ss_issuer,
			      sizeof(pkt->u.ss_issuer));
		key->subsigs[key->subsigc - 1].sig.info.signer_id_set = 1;
		break;
	case PGP_PTAG_SS_CREATION_TIME:
		key = &keyring->keys[keyring->keyc - 1];
		key->subsigs[key->subsigc - 1].sig.info.birthtime = pkt->u.ss_time;
		key->subsigs[key->subsigc - 1].sig.info.birthtime_set = 1;
		break;
	case PGP_PTAG_SS_EXPIRATION_TIME:
		key = &keyring->keys[keyring->keyc - 1];
		key->subsigs[key->subsigc - 1].sig.info.duration = pkt->u.ss_time;
		key->subsigs[key->subsigc - 1].sig.info.duration_set = 1;
		break;
	case PGP_PTAG_SS_PRIMARY_USER_ID:
		key = &keyring->keys[keyring->keyc - 1];
		key->uid0 = key->uidc - 1;
		break;
	case PGP_PTAG_SS_REVOCATION_REASON:
		key = &keyring->keys[keyring->keyc - 1];
		if (key->uidc == 0) {
			/* revoke whole key */
			key->revoked = 1;
			revocation = &key->revocation;
		} else {
			/* revoke the user id */
			EXPAND_ARRAY(key, revoke);
			revocation = &key->revokes[key->revokec];
			key->revokes[key->revokec].uid = key->uidc - 1;
			key->revokec += 1;
		}
		revocation->code = pkt->u.ss_revocation.code;
		revocation->reason = rnp_strdup(pgp_show_ss_rr_code(pkt->u.ss_revocation.code));
		break;
	case PGP_PTAG_CT_SIGNATURE_FOOTER:
	case PGP_PARSER_ERRCODE:
		break;

	default:
		break;
	}

	return PGP_RELEASE_MEMORY;
}

/**
   \ingroup HighLevel_KeyringRead

   \brief Reads a keyring from a file

   \param keyring Pointer to an existing keyring_t struct
   \param armour 1 if file is armoured; else 0
   \param filename Filename of keyring to be read

   \return pgp 1 if OK; 0 on error

   \note Keyring struct must already exist.

   \note Can be used with either a public or secret keyring.

   \note You must call pgp_keyring_free() after usage to free alloc-ed memory.

   \note If you call this twice on the same keyring struct, without calling
   pgp_keyring_free() between these calls, you will introduce a memory leak.

   \sa pgp_keyring_read_from_mem()
   \sa pgp_keyring_free()

*/

unsigned 
pgp_keyring_fileread(keyring_t *keyring,
			const unsigned armour,
			const char *filename)
{
	pgp_stream_t	*stream;
	keyringcb_t	 cb;
	unsigned	 res = 1;
	int		 fd;

	(void) memset(&cb, 0x0, sizeof(cb));
	cb.keyring = keyring;
	stream = pgp_new(sizeof(*stream));

	/* add this for the moment, */
	/*
	 * \todo need to fix the problems with reading signature subpackets
	 * later
	 */

	/* pgp_parse_options(parse,PGP_PTAG_SS_ALL,PGP_PARSE_RAW); */
	pgp_parse_options(stream, PGP_PTAG_SS_ALL, PGP_PARSE_PARSED);

#ifdef O_BINARY
	fd = open(filename, O_RDONLY | O_BINARY);
#else
	fd = open(filename, O_RDONLY);
#endif
	if (fd < 0) {
		pgp_stream_delete(stream);
		perror(filename);
		return 0;
	}
#ifdef USE_MMAP_FOR_FILES
	pgp_reader_set_mmap(stream, fd);
#else
	pgp_reader_set_fd(stream, fd);
#endif

	pgp_set_callback(stream, cb_keyring_read, &cb);

	if (armour) {
		pgp_reader_push_dearmour(stream);
	}
	res = pgp_parse_and_accumulate(keyring, stream);
	pgp_print_errors(pgp_stream_get_errors(stream));

	if (armour) {
		pgp_reader_pop_dearmour(stream);
	}

	(void)close(fd);

	pgp_stream_delete(stream);

	return res;
}

/**
   \ingroup HighLevel_KeyringRead

   \brief Reads a keyring from memory

   \param keyring Pointer to existing keyring_t struct
   \param armour 1 if file is armoured; else 0
   \param mem Pointer to a pgp_memory_t struct containing keyring to be read

   \return pgp 1 if OK; 0 on error

   \note Keyring struct must already exist.

   \note Can be used with either a public or secret keyring.

   \note You must call pgp_keyring_free() after usage to free alloc-ed memory.

   \note If you call this twice on the same keyring struct, without calling
   pgp_keyring_free() between these calls, you will introduce a memory leak.

   \sa pgp_keyring_fileread
   \sa pgp_keyring_free
*/
unsigned 
pgp_keyring_read_from_mem(io_t *io,
				keyring_t *keyring,
				const unsigned armour,
				pgp_memory_t *mem)
{
	pgp_stream_t	*stream;
	const unsigned	 noaccum = 0;
	keyringcb_t	 cb;
	unsigned	 res;

	(void) memset(&cb, 0x0, sizeof(cb));
	cb.keyring = keyring;
	stream = pgp_new(sizeof(*stream));
	pgp_parse_options(stream, PGP_PTAG_SS_ALL, PGP_PARSE_PARSED);
	pgp_setup_memory_read(io, &stream, mem, &cb, cb_keyring_read,
					noaccum);
	if (armour) {
		pgp_reader_push_dearmour(stream);
	}
	res = (unsigned)pgp_parse_and_accumulate(keyring, stream);
	pgp_print_errors(pgp_stream_get_errors(stream));
	if (armour) {
		pgp_reader_pop_dearmour(stream);
	}
	/* don't call teardown_memory_read because memory was passed in */
	pgp_stream_delete(stream);
	return res;
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
pgp_getkeybyid(io_t *io, const keyring_t *keyring,
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
getkeybyname(io_t *io,
			const keyring_t *keyring,
			const char *name,
			unsigned *from)
{
	const pgp_key_t	*kp;
	uint8_t			**uidp;
	unsigned    	 	 i = 0;
	pgp_key_t		*keyp;
	unsigned		 savedstart;
	regex_t			 r;
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
	if ((kp = pgp_getkeybyid(io, keyring, keyid, from, NULL)) != NULL) {
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
pgp_getkeybyname(io_t *io,
			const keyring_t *keyring,
			const char *name)
{
	unsigned	from;

	from = 0;
	return getkeybyname(io, keyring, name, &from);
}

const pgp_key_t *
pgp_getnextkeybyname(io_t *io,
			const keyring_t *keyring,
			const char *name,
			unsigned *n)
{
	return getkeybyname(io, keyring, name, n);
}

/* this interface isn't right - hook into callback for getting passphrase */
char *
pgp_export_key(io_t *io, const pgp_key_t *keydata, uint8_t *passphrase)
{
	pgp_output_t	*output;
	pgp_memory_t	*mem;
	char		*cp;

	__PGP_USED(io);
	pgp_setup_memory_write(&output, &mem, 128);
	if (keydata->type == PGP_PTAG_CT_PUBLIC_KEY) {
		pgp_write_xfer_pubkey(output, keydata, NULL, 1);
	} else {
		pgp_write_xfer_seckey(output, keydata, passphrase,
					strlen((char *)passphrase), NULL, 1);
	}
	cp = rnp_strdup(pgp_mem_data(mem));
	pgp_teardown_memory_write(output, mem);
	return cp;
}
