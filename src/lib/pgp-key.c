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

#include "pgp-key.h"
#include "signature.h"
#include "utils.h"
#include "readerwriter.h"
#include "misc.h"

#include <rnp/rnp_sdk.h>
#include <librepgp/validate.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void
pgp_free_user_prefs(pgp_user_prefs_t *prefs)
{
    if (!prefs) {
        return;
    }
    FREE_ARRAY(prefs, symm_alg);
    FREE_ARRAY(prefs, hash_alg);
    FREE_ARRAY(prefs, compress_alg);
    FREE_ARRAY(prefs, key_server_pref);
    free(prefs->key_server);
    prefs->key_server = NULL;
}

static void
subsig_free(pgp_subsig_t *subsig)
{
    if (!subsig) {
        return;
    }
    // user prefs
    pgp_user_prefs_t *prefs = &subsig->prefs;
    pgp_free_user_prefs(prefs);

    pgp_sig_free(&subsig->sig);
}

static void
revoke_free(pgp_revoke_t *revoke)
{
    if (!revoke) {
        return;
    }
    free(revoke->reason);
    revoke->reason = NULL;
}

/**
   \ingroup HighLevel_Keyring

   \brief Creates a new pgp_key_t struct

   \return A new pgp_key_t struct, initialised to zero.

   \note The returned pgp_key_t struct must be freed after use with pgp_key_free.
*/

pgp_key_t *
pgp_key_new(void)
{
    return calloc(1, sizeof(pgp_key_t));
}

void
pgp_key_free_data(pgp_key_t *key)
{
    unsigned n;

    if (key == NULL) {
        return;
    }

    if (key->uids != NULL) {
        for (n = 0; n < key->uidc; ++n) {
            pgp_userid_free(&key->uids[n]);
        }
        free(key->uids);
        key->uids = NULL;
        key->uidc = 0;
    }

    if (key->packets != NULL) {
        for (n = 0; n < key->packetc; ++n) {
            pgp_rawpacket_free(&key->packets[n]);
        }
        free(key->packets);
        key->packets = NULL;
        key->packetc = 0;
    }

    if (key->subsigs) {
        for (n = 0; n < key->subsigc; ++n) {
            subsig_free(&key->subsigs[n]);
        }
        free(key->subsigs);
        key->subsigs = NULL;
        key->subsigc = 0;
    }

    if (key->revokes) {
        for (n = 0; n < key->revokec; ++n) {
            revoke_free(&key->revokes[n]);
        }
        free(key->revokes);
        key->revokes = NULL;
        key->revokec = 0;
    }
    revoke_free(&key->revocation);

    if (pgp_is_key_public(key)) {
        pgp_pubkey_free(&key->key.pubkey);
    } else {
        pgp_seckey_free(&key->key.seckey);
    }
}

void
pgp_key_free(pgp_key_t *key)
{
    pgp_key_free_data(key);
    free(key);
}

/**
 \ingroup HighLevel_KeyGeneral

 \brief Returns the public key in the given key.
 \param key

  \return Pointer to public key

  \note This is not a copy, do not free it after use.
*/

const pgp_pubkey_t *
pgp_get_pubkey(const pgp_key_t *key)
{
    return pgp_is_key_public(key) ? &key->key.pubkey : &key->key.seckey.pubkey;
}

bool
pgp_is_key_public(const pgp_key_t *key)
{
    return pgp_is_public_key_tag(key->type);
}

bool
pgp_is_key_secret(const pgp_key_t *key)
{
    return pgp_is_secret_key_tag(key->type);
}

bool
pgp_key_can_sign(const pgp_key_t *key)
{
    return key->key_flags & PGP_KF_SIGN;
}

bool
pgp_key_can_certify(const pgp_key_t *key)
{
    return key->key_flags & PGP_KF_CERTIFY;
}

bool
pgp_key_can_encrypt(const pgp_key_t *key)
{
    return key->key_flags & PGP_KF_ENCRYPT;
}

bool
pgp_is_secret_key_tag(pgp_content_enum tag)
{
    switch (tag) {
    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
pgp_is_public_key_tag(pgp_content_enum tag)
{
    switch (tag) {
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
pgp_is_primary_key_tag(pgp_content_enum tag)
{
    switch (tag) {
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_SECRET_KEY:
        return true;
    default:
        return false;
    }
}

bool
pgp_key_is_primary_key(const pgp_key_t *key)
{
    return pgp_is_primary_key_tag(key->type);
}

bool
pgp_is_subkey_tag(pgp_content_enum tag)
{
    switch (tag) {
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
pgp_key_is_subkey(const pgp_key_t *key)
{
    return pgp_is_subkey_tag(key->type);
}

/**
 \ingroup HighLevel_KeyGeneral

 \brief Returns the secret key in the given key.

 \note This is not a copy, do not free it after use.

 \note This returns a const.  If you need to be able to write to this
 pointer, use pgp_get_writable_seckey
*/

const pgp_seckey_t *
pgp_get_seckey(const pgp_key_t *key)
{
    return pgp_is_key_secret(key) ? &key->key.seckey : NULL;
}

/**
 \ingroup HighLevel_KeyGeneral

  \brief Returns the secret key in the given key.

  \note This is not a copy, do not free it after use.

  \note If you do not need to be able to modify this key, there is an
  equivalent read-only function pgp_get_seckey.
*/

pgp_seckey_t *
pgp_get_writable_seckey(pgp_key_t *key)
{
    return pgp_is_key_secret(key) ? &key->key.seckey : NULL;
}

typedef struct {
    const char *     passphrase;
    const pgp_key_t *key;
    pgp_seckey_t *   seckey;
} decrypt_t;

static pgp_cb_ret_t
decrypt_cb(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;
    decrypt_t *           decrypt;

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
        *content->skey_passphrase.passphrase = rnp_strdup(decrypt->passphrase);
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
        (void) fprintf(stderr, "parse error: %s\n", pgp_errcode(content->errcode.errcode));
        return PGP_FINISHED;

    case PGP_PARSER_ERROR:
        fprintf(stderr, "parse error: %s\n", content->error);
        return PGP_FINISHED;

    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
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
        fprintf(stderr, "Unexpected tag %d (0x%x)\n", pkt->tag, pkt->tag);
        return PGP_FINISHED;
    }

    return PGP_RELEASE_MEMORY;
}

pgp_seckey_t *
pgp_decrypt_seckey_parser(const pgp_key_t *key, const char *passphrase)
{
    pgp_stream_t *stream;
    const int     printerrors = 1;
    decrypt_t     decrypt = {0};

    if (!key->packetc || !key->packets) {
        RNP_LOG("can not decrypt secret key without raw packets");
        return NULL;
    }

    decrypt.passphrase = passphrase;
    decrypt.key = key;
    stream = pgp_new(sizeof(*stream));
    if (!pgp_key_reader_set(stream, key)) {
        return NULL;
    }
    pgp_set_callback(stream, decrypt_cb, &decrypt);
    stream->readinfo.accumulate = 1;
    repgp_parse(stream, !printerrors);
    pgp_stream_delete(stream);
    return decrypt.seckey;
}

/**
\ingroup Core_Keys
\brief Decrypts secret key from given key with given passphrase
\param key Key from which to get secret key
\param passphrase Passphrase to use to decrypt secret key
\return secret key
*/
pgp_seckey_t *
pgp_decrypt_seckey(const pgp_key_t *                key,
                   const pgp_passphrase_provider_t *provider,
                   const pgp_passphrase_ctx_t *     ctx)
{
    pgp_seckey_t *        decrypted_seckey = NULL;
    pgp_seckey_decrypt_t *decryptor = NULL;
    char                  passphrase[MAX_PASSPHRASE_LENGTH] = {0};

    // sanity checks
    if (!key || !pgp_is_key_secret(key) || !provider) {
        RNP_LOG("invalid args");
        goto done;
    }
    decryptor = key->key.seckey.decrypt_cb;
    if (!decryptor) {
        RNP_LOG("missing decrypt callback");
        goto done;
    }

    // try an empty passphrase first
    decrypted_seckey = decryptor(key, "");
    if (decrypted_seckey) {
        goto done;
    }

    // ask the provider for a passphrase
    if (!pgp_request_passphrase(provider, ctx, passphrase, sizeof(passphrase))) {
        goto done;
    }
    // attempt to decrypt with the provided passphrase
    decrypted_seckey = decryptor(key, passphrase);

done:
    pgp_forget(passphrase, sizeof(passphrase));
    return decrypted_seckey;
}

/**
\ingroup Core_Keys
\brief Set secret key in content
\param content Content to be set
\param key Key to get secret key from
*/
void
pgp_set_seckey(pgp_contents_t *cont, const pgp_key_t *key)
{
    *cont->get_seckey.seckey = &key->key.seckey;
}

/**
\ingroup Core_Keys
\brief Get Key ID from key
\param key Key to get Key ID from
\return Pointer to Key ID inside key
*/
const uint8_t *
pgp_get_key_id(const pgp_key_t *key)
{
    return key->keyid;
}

/**
\ingroup Core_Keys
\brief How many User IDs in this key?
\param key Key to check
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
    size_t len;

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
static pgp_rawpacket_t *
copy_packet(pgp_rawpacket_t *dst, const pgp_rawpacket_t *src)
{
    if (dst->raw) {
        free(dst->raw);
    }
    if ((dst->raw = calloc(1, src->length)) == NULL) {
        (void) fprintf(stderr, "copy_packet: bad alloc\n");
    } else {
        dst->length = src->length;
        (void) memcpy(dst->raw, src->raw, src->length);
        dst->tag = src->tag;
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
uint8_t *
pgp_add_userid(pgp_key_t *key, const uint8_t *userid)
{
    uint8_t **uidp;

    EXPAND_ARRAY(key, uid);
    if (key->uids == NULL) {
        return NULL;
    }
    /* initialise new entry in array */
    uidp = &key->uids[key->uidc++];
    *uidp = NULL;
    /* now copy it */
    return copy_userid(uidp, userid);
}

/**
\ingroup Core_Keys
\brief Add packet to key
\param key Key to which to add packet
\param packet Packet to add
\return Pointer to new packet
*/
pgp_rawpacket_t *
pgp_add_rawpacket(pgp_key_t *key, const pgp_rawpacket_t *packet)
{
    pgp_rawpacket_t *subpktp;

    EXPAND_ARRAY(key, packet);
    if (key->packets == NULL) {
        return NULL;
    }
    /* initialise new entry in array */
    subpktp = &key->packets[key->packetc++];
    subpktp->length = 0;
    subpktp->raw = NULL;
    /* now copy it */
    return copy_packet(subpktp, packet);
}

/**
\ingroup Core_Keys
\brief Initialise pgp_key_t
\param key Key to initialise
\param type PGP_PTAG_CT_PUBLIC_KEY or PGP_PTAG_CT_SECRET_KEY
*/
void
pgp_key_init(pgp_key_t *key, const pgp_content_enum type)
{
    if (key->type != PGP_PTAG_CT_RESERVED) {
        (void) fprintf(stderr, "pgp_key_init: wrong key type\n");
    }
    switch (type) {
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        break;
    default:
        RNP_LOG("invalid key type: %d", type);
        break;
    }
    key->type = type;
}

char *
pgp_export_key(pgp_io_t *                       io,
               const pgp_key_t *                key,
               const pgp_passphrase_provider_t *passphrase_provider)
{
    pgp_output_t *output;
    pgp_memory_t *mem;
    char *        cp;

    RNP_USED(io);
    if (!pgp_setup_memory_write(NULL, &output, &mem, 128)) {
        RNP_LOG_FD(io->errs, "can't setup memory write\n");
        return NULL;
    }

    if (pgp_is_key_public(key)) {
        pgp_write_xfer_pubkey(output, key, NULL, 1);
    } else {
        pgp_write_xfer_seckey(output, key, NULL, 1);
    }

    const size_t mem_len = pgp_mem_len(mem) + 1;
    if ((cp = (char *) malloc(mem_len)) == NULL) {
        pgp_teardown_memory_write(output, mem);
        return NULL;
    }

    memcpy(cp, pgp_mem_data(mem), mem_len);
    pgp_teardown_memory_write(output, mem);
    cp[mem_len - 1] = '\0';
    return cp;
}

pgp_key_flags_t
pgp_pk_alg_capabilities(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_RSA:
        return PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH | PGP_KF_ENCRYPT;

    case PGP_PKA_RSA_SIGN_ONLY:
        // deprecated, but still usable
        return PGP_KF_SIGN;

    case PGP_PKA_RSA_ENCRYPT_ONLY:
        // deprecated, but still usable
        return PGP_KF_ENCRYPT;

    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN: /* deprecated */
        // These are no longer permitted per the RFC
        return PGP_KF_NONE;

    case PGP_PKA_DSA:
        return PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH;

    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
        return PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH;

    case PGP_PKA_SM2:
        return PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH | PGP_KF_ENCRYPT;

    case PGP_PKA_ECDH:
        return PGP_KF_ENCRYPT;

    case PGP_PKA_ELGAMAL:
        return PGP_KF_ENCRYPT;

    default:
        RNP_LOG("unknown pk alg: %d\n", alg);
        return PGP_KF_NONE;
    }
}

bool
pgp_key_is_locked(const pgp_key_t *key)
{
    if (!pgp_is_key_secret(key)) {
        RNP_LOG("key is not a secret key");
        return false;
    }
    return key->key.seckey.encrypted;
}

bool
pgp_key_unlock(pgp_key_t *key, const pgp_passphrase_provider_t *provider)
{
    pgp_seckey_t *decrypted_seckey = NULL;

    // sanity checks
    if (!key || !provider) {
        return false;
    }

    // see if it's already unlocked
    if (!pgp_key_is_locked(key)) {
        return true;
    }

    decrypted_seckey = pgp_decrypt_seckey(
      key,
      provider,
      &(pgp_passphrase_ctx_t){
        .op = PGP_OP_UNLOCK, .pubkey = pgp_get_pubkey(key), .key_type = key->type});

    if (decrypted_seckey) {
        // this shouldn't really be necessary, but just in case
        pgp_seckey_free_secret_mpis(&key->key.seckey);
        // copy the decrypted mpis into the pgp_key_t
        key->key.seckey.key = decrypted_seckey->key;
        key->key.seckey.encrypted = false;

        // zero out the key material union in the decrypted seckey, since
        // ownership has changed
        pgp_seckey_t nullkey = {{0}};
        decrypted_seckey->key = nullkey.key;
        // now free the rest of the internal seckey
        pgp_seckey_free(decrypted_seckey);
        // free the actual structure
        free(decrypted_seckey);
        return true;
    }
    return false;
}

void
pgp_key_lock(pgp_key_t *key)
{
    // sanity checks
    if (!key || !pgp_is_key_secret(key)) {
        RNP_LOG("invalid args");
        return;
    }

    // see if it's already locked
    if (pgp_key_is_locked(key)) {
        return;
    }

    pgp_seckey_free_secret_mpis(&key->key.seckey);
    key->key.seckey.encrypted = true;
}
