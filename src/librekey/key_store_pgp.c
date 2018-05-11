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

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: keyring.c,v 1.50 2011/06/25 00:37:44 agc Exp $");
#endif

#include <stdlib.h>
#include <string.h>

#include <rnp/rnp_sdk.h>
#include <librepgp/packet-show.h>
#include <librepgp/reader.h>

#include "types.h"
#include "key_store_pgp.h"
#include "pgp-key.h"
#include "utils.h"

void print_packet_hex(const pgp_rawpacket_t *pkt);

/* used to point to data during keyring read */
typedef struct keyringcb_t {
    rnp_key_store_t *         keyring; /* the keyring we're reading */
    pgp_io_t *                io;
    pgp_key_t                 key; /* the key we're currently loading */
    const pgp_key_provider_t *key_provider;
} keyringcb_t;

#define SUBSIG_REQUIRED_BEFORE(str)                                 \
    do {                                                            \
        if (!(subsig)) {                                            \
            RNP_LOG("Signature packet expected before %s.", (str)); \
            PGP_ERROR_1(cbinfo->errors,                             \
                        PGP_E_R_BAD_FORMAT,                         \
                        "Signature packet expected before %s.",     \
                        (str));                                     \
            return PGP_FINISHED;                                    \
        }                                                           \
    } while (0)

static pgp_cb_ret_t
parse_key_attributes(pgp_key_t *key, const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;

    // bail early if errors have already occurred
    if (cbinfo->errors && *cbinfo->errors) {
        // TODO: no way to tell the parser to stop
        return PGP_RELEASE_MEMORY;
    }

    // handle these earlier, since they don't actually
    // require a key
    switch (pkt->tag) {
    case PGP_PARSER_DONE:
    case PGP_PARSER_PTAG:
    case PGP_GET_PASSWORD:
        return PGP_RELEASE_MEMORY;
    case PGP_PARSER_ERROR:
        // these will be printed out later
        PGP_ERROR_1(cbinfo->errors, PGP_E_FAIL, "%s", content->error);
        return PGP_RELEASE_MEMORY;
    default:
        // handle everything else below
        break;
    }

    // we should definitely have a key at this point
    if (!key) {
        PGP_ERROR(cbinfo->errors, PGP_E_R_BAD_FORMAT, "Key packet missing.");
        return PGP_FINISHED;
    }

    pgp_subsig_t *subsig = key->subsigc ? &key->subsigs[key->subsigc - 1] : NULL;
    switch (pkt->tag) {
    case PGP_PTAG_CT_USER_ID:
        if (!pgp_add_userid(key, content->userid)) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to add userid to key.");
            return PGP_FINISHED;
        }
        break;
    case PGP_PARSER_PACKET_END:
        EXPAND_ARRAY(key, packet);
        if (!key->packets) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
            return PGP_RELEASE_MEMORY;
        }
        key->packets[key->packetc++] = content->packet;
        return PGP_KEEP_MEMORY;
    case PGP_PARSER_ERROR:
        RNP_LOG("Error: %s", content->error);
        return PGP_FINISHED;
    case PGP_PARSER_ERRCODE:
        RNP_LOG("parse error: %s", pgp_errcode(content->errcode.errcode));
        break;
    case PGP_PTAG_CT_SIGNATURE: /* v3 sig */
        EXPAND_ARRAY(key, subsig);
        if (key->subsigs == NULL) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
            return PGP_FINISHED;
        }
        subsig = &key->subsigs[key->subsigc++];
        subsig->uid = key->uidc - 1;
        subsig->sig = content->sig;
        return PGP_KEEP_MEMORY;
    case PGP_PTAG_CT_SIGNATURE_HEADER: /* start of v4 sig */
        EXPAND_ARRAY(key, subsig);
        if (key->subsigs == NULL) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
            return PGP_FINISHED;
        }
        subsig = &key->subsigs[key->subsigc++];
        memset(subsig, 0, sizeof(*subsig));
        subsig->uid = key->uidc - 1;
        return PGP_KEEP_MEMORY;
    case PGP_PTAG_CT_SIGNATURE_FOOTER: /* end of v4 sig */
        SUBSIG_REQUIRED_BEFORE("sig footer");
        subsig->sig = content->sig;
        return PGP_KEEP_MEMORY;
    case PGP_PTAG_SS_TRUST:
        SUBSIG_REQUIRED_BEFORE("ss trust");
        subsig->trustlevel = pkt->u.ss_trust.level;
        subsig->trustamount = pkt->u.ss_trust.amount;
        break;
    case PGP_PTAG_SS_KEY_EXPIRY:
        key->expiration = pkt->u.ss_time;
        break;
    case PGP_PTAG_SS_PRIMARY_USER_ID:
        if (content->ss_primary_userid) {
            key->uid0 = key->uidc - 1;
            key->uid0_set = 1;
        }
        break;
    case PGP_PTAG_SS_REVOCATION_REASON: {
        SUBSIG_REQUIRED_BEFORE("ss revocation reason");
        pgp_revoke_t *revocation = NULL;
        if (key->uidc == 0) {
            /* revoke whole key */
            key->revoked = 1;
            revocation = &key->revocation;
        } else {
            /* revoke the user id */
            EXPAND_ARRAY(key, revoke);
            if (key->revokes == NULL) {
                PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                return PGP_FINISHED;
            }
            revocation = &key->revokes[key->revokec];
            key->revokes[key->revokec].uid = key->uidc - 1;
            key->revokec += 1;
        }
        revocation->code = pkt->u.ss_revocation.code;
        revocation->reason = rnp_strdup(pgp_show_ss_rr_code(pkt->u.ss_revocation.code));
    } break;
    case PGP_PTAG_SS_KEY_FLAGS:
        SUBSIG_REQUIRED_BEFORE("ss key flags");
        subsig->key_flags = pkt->u.ss_key_flags.contents[0];
        key->key_flags = subsig->key_flags;
        break;
    case PGP_PTAG_SS_PREFERRED_SKA:
        SUBSIG_REQUIRED_BEFORE("ss preferred symmetric key algs");
        {
            const pgp_data_t *data = &content->ss_skapref;
            pgp_user_prefs_t *prefs = &subsig->prefs;
            for (size_t i = 0; i < data->len; i++) {
                EXPAND_ARRAY(prefs, symm_alg);
                if (!subsig->prefs.symm_algs) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                subsig->prefs.symm_algs[i] = data->contents[i];
                subsig->prefs.symm_algc++;
            }
        }
        break;
    case PGP_PTAG_SS_PREFERRED_HASH:
        SUBSIG_REQUIRED_BEFORE("ss preferred hash algs");
        {
            const pgp_data_t *data = &content->ss_hashpref;
            pgp_user_prefs_t *prefs = &subsig->prefs;
            for (size_t i = 0; i < data->len; i++) {
                EXPAND_ARRAY(prefs, hash_alg);
                if (!subsig->prefs.hash_algs) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                subsig->prefs.hash_algs[i] = data->contents[i];
                subsig->prefs.hash_algc++;
            }
        }
        break;
    case PGP_PTAG_SS_PREF_COMPRESS:
        SUBSIG_REQUIRED_BEFORE("ss preferred compression algs");
        {
            const pgp_data_t *data = &content->ss_zpref;
            pgp_user_prefs_t *prefs = &subsig->prefs;
            for (size_t i = 0; i < data->len; i++) {
                EXPAND_ARRAY(prefs, compress_alg);
                if (!subsig->prefs.compress_algs) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                subsig->prefs.compress_algs[i] = data->contents[i];
                subsig->prefs.compress_algc++;
            }
        }
        break;
    case PGP_PTAG_SS_KEYSERV_PREFS:
        SUBSIG_REQUIRED_BEFORE("ss key server prefs");
        {
            const pgp_data_t *data = &content->ss_key_server_prefs;
            pgp_user_prefs_t *prefs = &subsig->prefs;
            for (size_t i = 0; i < data->len; i++) {
                EXPAND_ARRAY(prefs, key_server_pref);
                if (!subsig->prefs.key_server_prefs) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                subsig->prefs.key_server_prefs[i] = data->contents[i];
                subsig->prefs.key_server_prefc++;
            }
        }
        break;
    case PGP_PTAG_SS_PREF_KEYSERV:
        SUBSIG_REQUIRED_BEFORE("ss preferred key server");
        subsig->prefs.key_server = (uint8_t *) content->ss_keyserv;
        return PGP_KEEP_MEMORY;
    case PGP_PTAG_CT_TRUST:
        // valid, but not currently used
        break;
    default:
        if (pkt->tag >= PGP_PTAG_SIG_SUBPKT_BASE && pkt->tag <= PGP_PTAG_SS_USERDEFINED10) {
            if (rnp_get_debug(__FILE__)) {
                RNP_LOG("Unsupported signature subpacket 0x%x (tag 0x%x)",
                        pkt->tag - PGP_PTAG_SIG_SUBPKT_BASE,
                        pkt->tag);
            }
        } else {
            PGP_ERROR_1(cbinfo->errors, PGP_E_FAIL, "Unexpected tag 0x%02x", pkt->tag);
        }
        break;
    }
    return PGP_RELEASE_MEMORY;
}

static pgp_cb_ret_t
cb_keyattrs_parse(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    pgp_key_t *key = pgp_callback_arg(cbinfo);
    return parse_key_attributes(key, pkt, cbinfo);
}

bool
pgp_parse_key_attrs(pgp_key_t *key, const uint8_t *data, size_t data_len)
{
    pgp_stream_t *stream = NULL;
    bool          ret = false;

    stream = pgp_new(sizeof(*stream));
    if (!stream) {
        goto done;
    }
    if (!pgp_reader_set_memory(stream, data, data_len)) {
        goto done;
    }
    pgp_set_callback(stream, cb_keyattrs_parse, key);
    stream->readinfo.accumulate = 1;
    repgp_parse_options(stream, PGP_PTAG_SS_ALL, REPGP_PARSE_PARSED);
    ret = repgp_parse(stream, 0);
    pgp_print_errors(stream->errors);

done:
    pgp_stream_delete(stream);
    return ret;
}

static bool
finish_loading_key(keyringcb_t *cb, pgp_cbdata_t *cbinfo)
{
    if (pgp_key_is_subkey(&cb->key)) {
        pgp_key_t *primary =
          pgp_get_primary_key_for(cb->io, &cb->key, cb->keyring, cb->key_provider);
        if (!primary) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Subkey missing primary key.");
            return false;
        }
        cb->key.primary_grip = malloc(PGP_FINGERPRINT_SIZE);
        if (!cb->key.primary_grip) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Alloc failed");
            return PGP_FINISHED;
        }
        memcpy(cb->key.primary_grip, primary->grip, PGP_FINGERPRINT_SIZE);
        if (!list_append(&primary->subkey_grips, cb->key.grip, PGP_FINGERPRINT_SIZE)) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Alloc failed");
            return PGP_FINISHED;
        }
    }
    if (!rnp_key_store_add_key(cb->io, cb->keyring, &cb->key)) {
        PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to add key to key store.");
        return false;
    }
    cb->key = (pgp_key_t){0};
    return true;
}

static pgp_cb_ret_t
cb_keyring_parse(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;
    keyringcb_t *         cb;
    pgp_keydata_key_t     keydata;

    cb = pgp_callback_arg(cbinfo);

    switch (pkt->tag) {
    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        // finish up with previous key (if any)
        if (cb->key.type) {
            if (!finish_loading_key(cb, cbinfo)) {
                return PGP_FINISHED;
            }
        }

        // start to process the new key
        bool secret = pgp_is_secret_key_tag(pkt->tag);
        if (secret) {
            keydata.seckey = content->seckey;
        } else {
            keydata.pubkey = content->pubkey;
        }
        if (!pgp_key_from_keydata(&cb->key, &keydata, pkt->tag)) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to create key from keydata.");
            return PGP_FINISHED;
        }
        cb->key.format = GPG_KEY_STORE;
        if (secret) {
            cb->key.is_protected = pgp_is_key_encrypted(&cb->key);
        }
        // Set some default key flags which will be overridden by signature
        // subpackets for V4 keys.
        cb->key.key_flags = pgp_pk_alg_capabilities(pgp_get_key_pkt(&cb->key)->alg);
        return PGP_KEEP_MEMORY;
    case PGP_PTAG_CT_ARMOR_HEADER:
    case PGP_PTAG_CT_ARMOR_TRAILER:
        break;
    case PGP_PARSER_DONE:
        // finish up with previous key (if any)
        if (cb->key.type) {
            if (!finish_loading_key(cb, cbinfo)) {
                return PGP_FINISHED;
            }
        }
        break;
    default:
        return parse_key_attributes(&cb->key, pkt, cbinfo);
    }
    return PGP_RELEASE_MEMORY;
}

/**
   \ingroup HighLevel_KeyringRead

   \brief Reads a keyring from memory

   \param keyring Pointer to existing keyring_t struct
   \param armor 1 if file is armored; else 0
   \param mem Pointer to a pgp_memory_t struct containing keyring to be read

   \return pgp true if OK; false on error

   \note Keyring struct must already exist.

   \note Can be used with either a public or secret keyring.

   \note You must call pgp_keyring_free() after usage to free alloc-ed memory.

   \note If you call this twice on the same keyring struct, without calling
   pgp_keyring_free() between these calls, you will introduce a memory leak.

   \sa pgp_keyring_fileread
   \sa pgp_keyring_free
*/
bool
rnp_key_store_pgp_read_from_mem(pgp_io_t *                io,
                                rnp_key_store_t *         keyring,
                                const unsigned            armor,
                                pgp_memory_t *            mem,
                                const pgp_key_provider_t *key_provider)
{
    pgp_stream_t * stream;
    const unsigned printerrors = 1;
    const unsigned accum = 1;
    keyringcb_t    cb = {0};
    bool           res;

    cb.keyring = keyring;
    cb.io = io;
    cb.key_provider = key_provider;
    if (!pgp_setup_memory_read(io, &stream, mem, &cb, cb_keyring_parse, accum)) {
        (void) fprintf(io->errs, "can't setup memory read\n");
        return false;
    }
    repgp_parse_options(stream, PGP_PTAG_SS_ALL, REPGP_PARSE_PARSED);
    if (armor) {
        pgp_reader_push_dearmor(stream);
    }
    res = repgp_parse(stream, printerrors);
    pgp_print_errors(pgp_stream_get_errors(stream));
    if (armor) {
        pgp_reader_pop_dearmor(stream);
    }
    /* don't call teardown_memory_read because memory was passed in */
    pgp_stream_delete(stream);
    return res;
}

static bool
do_write(pgp_io_t *io, rnp_key_store_t *key_store, pgp_output_t *output, bool secret)
{
    pgp_key_search_t search;
    for (list_item *key_item = list_front(key_store->keys); key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        if (pgp_is_key_secret(key) != secret) {
            continue;
        }
        // skip subkeys, they are written below (orphans are ignored)
        if (!pgp_key_is_primary_key(key)) {
            continue;
        }

        if (key->format != GPG_KEY_STORE) {
            RNP_LOG("incorrect format (conversions not supported): %d", key->format);
            return false;
        }
        if (!pgp_key_write_packets(key, output)) {
            return false;
        }
        for (list_item *subkey_grip = list_front(key->subkey_grips); subkey_grip;
             subkey_grip = list_next(subkey_grip)) {
            search.type = PGP_KEY_SEARCH_GRIP;
            memcpy(search.by.grip, (uint8_t *) subkey_grip, PGP_FINGERPRINT_SIZE);
            pgp_key_t *subkey = NULL;
            for (list_item *subkey_item = list_front(key_store->keys); subkey_item;
                 subkey_item = list_next(subkey_item)) {
                pgp_key_t *candidate = (pgp_key_t *) subkey_item;
                if (pgp_is_key_secret(candidate) != secret) {
                    continue;
                }
                if (rnp_key_matches_search(candidate, &search)) {
                    subkey = candidate;
                    break;
                }
            }
            if (!subkey) {
                RNP_LOG_FD(io->errs, "Missing subkey");
                continue;
            }
            if (!pgp_key_write_packets(subkey, output)) {
                return false;
            }
        }
    }
    return true;
}

int
rnp_key_store_pgp_write_to_mem(pgp_io_t *       io,
                               rnp_key_store_t *key_store,
                               const unsigned   armor,
                               pgp_memory_t *   mem)
{
    unsigned     rc;
    pgp_output_t output = {};

    pgp_writer_set_memory(&output, mem);

    if (armor) {
        pgp_armor_type_t type = PGP_PGP_PUBLIC_KEY_BLOCK;
        if (list_length(key_store->keys) &&
            pgp_is_key_secret((pgp_key_t *) list_front(key_store->keys))) {
            type = PGP_PGP_PRIVATE_KEY_BLOCK;
        }
        pgp_writer_push_armored(&output, type);
    }
    // two separate passes (public keys, then secret keys)
    if (!do_write(io, key_store, &output, false) || !do_write(io, key_store, &output, true)) {
        return false;
    }
    if (armor) {
        pgp_writer_pop(&output);
    }
    rc = pgp_writer_close(&output);
    pgp_writer_info_delete(&output.writer);

    return rc;
}
