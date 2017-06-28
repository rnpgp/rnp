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

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: keyring.c,v 1.50 2011/06/25 00:37:44 agc Exp $");
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <json.h>

#include "types.h"
#include "key_store_pgp.h"
#include "signature.h"
#include "rnpsdk.h"
#include "readerwriter.h"
#include "rnpdefs.h"
#include "packet.h"

void print_packet_hex(const pgp_subpacket_t *pkt);

/* used to point to data during keyring read */
typedef struct keyringcb_t {
    rnp_key_store_t *keyring; /* the keyring we're reading */
} keyringcb_t;

static pgp_cb_ret_t
cb_keyring_read(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    rnp_key_store_t *keyring;
    pgp_revoke_t *   revocation;
    pgp_key_t *      key;
    keyringcb_t *    cb;

    cb = pgp_callback_arg(cbinfo);
    keyring = cb->keyring;
    switch (pkt->tag) {
    case PGP_PARSER_PTAG:
    case PGP_PTAG_CT_ENCRYPTED_SECRET_KEY:
        /* we get these because we didn't prompt */
        break;
    case PGP_PTAG_CT_SIGNATURE_HEADER:
        if (keyring->keyc == 0) {
            break;
        }
        key = &keyring->keys[keyring->keyc - 1];
        EXPAND_ARRAY(key, subsig);
        if (key->subsigs == NULL) {
            break;
        }
        key->subsigs[key->subsigc].uid = key->uidc - 1;
        (void) memcpy(&key->subsigs[key->subsigc].sig, &pkt->u.sig, sizeof(pkt->u.sig));
        key->subsigc += 1;
        break;
    case PGP_PTAG_CT_SIGNATURE:
        if (keyring->keyc == 0) {
            break;
        }
        key = &keyring->keys[keyring->keyc - 1];
        EXPAND_ARRAY(key, subsig);
        if (key->subsigs == NULL) {
            break;
        }
        key->subsigs[key->subsigc].uid = key->uidc - 1;
        (void) memcpy(&key->subsigs[key->subsigc].sig, &pkt->u.sig, sizeof(pkt->u.sig));
        key->subsigc += 1;
        break;
    case PGP_PTAG_CT_TRUST:
        if (keyring->keyc == 0) {
            break;
        }
        key = &keyring->keys[keyring->keyc - 1];
        if (key->subsigc == 0) {
            break;
        }
        key->subsigs[key->subsigc - 1].trustlevel = pkt->u.ss_trust.level;
        key->subsigs[key->subsigc - 1].trustamount = pkt->u.ss_trust.amount;
        break;
    case PGP_PTAG_SS_KEY_EXPIRY:
        EXPAND_ARRAY(keyring, key);
        if (keyring->keys == NULL) {
            break;
        }
        if (keyring->keyc > 0) {
            keyring->keys[keyring->keyc - 1].key.pubkey.duration = pkt->u.ss_time;
        }
        break;
    case PGP_PTAG_SS_ISSUER_KEY_ID:
        if (keyring->keyc == 0) {
            break;
        }
        key = &keyring->keys[keyring->keyc - 1];
        if (key->subsigc == 0) {
            break;
        }
        (void) memcpy(&key->subsigs[key->subsigc - 1].sig.info.signer_id,
                      pkt->u.ss_issuer,
                      sizeof(pkt->u.ss_issuer));
        key->subsigs[key->subsigc - 1].sig.info.signer_id_set = 1;
        break;
    case PGP_PTAG_SS_CREATION_TIME:
        if (keyring->keyc == 0) {
            break;
        }
        key = &keyring->keys[keyring->keyc - 1];
        if (key->subsigc == 0) {
            break;
        }
        key->subsigs[key->subsigc - 1].sig.info.birthtime = pkt->u.ss_time;
        key->subsigs[key->subsigc - 1].sig.info.birthtime_set = 1;
        break;
    case PGP_PTAG_SS_EXPIRATION_TIME:
        if (keyring->keyc == 0) {
            break;
        }
        key = &keyring->keys[keyring->keyc - 1];
        if (key->subsigc == 0) {
            break;
        }
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
            if (key->revokes == NULL) {
                break;
            }
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
int
rnp_key_store_pgp_read_from_mem(pgp_io_t *       io,
                                rnp_key_store_t *keyring,
                                const unsigned   armour,
                                pgp_memory_t *   mem)
{
    pgp_stream_t * stream;
    const unsigned noaccum = 0;
    keyringcb_t    cb;
    unsigned       res;

    (void) memset(&cb, 0x0, sizeof(cb));
    cb.keyring = keyring;
    stream = pgp_new(sizeof(*stream));
    pgp_parse_options(stream, PGP_PTAG_SS_ALL, PGP_PARSE_PARSED);
    if (!pgp_setup_memory_read(io, &stream, mem, &cb, cb_keyring_read, noaccum)) {
        (void) fprintf(io->errs, "can't setup memory read\n");
        return 0;
    }
    if (armour) {
        pgp_reader_push_dearmour(stream);
    }
    res = (unsigned) pgp_parse_and_accumulate(io, keyring, stream);
    pgp_print_errors(pgp_stream_get_errors(stream));
    if (armour) {
        pgp_reader_pop_dearmour(stream);
    }
    /* don't call teardown_memory_read because memory was passed in */
    pgp_stream_delete(stream);
    return res;
}

int
rnp_key_store_pgp_write_to_mem(pgp_io_t *       io,
                               rnp_key_store_t *key_store,
                               const uint8_t *  passphrase,
                               const unsigned   armour,
                               pgp_memory_t *   mem)
{
    int          i;
    unsigned     rc;
    pgp_key_t *  key;
    pgp_output_t output = {};

    __PGP_USED(io);
    pgp_writer_set_memory(&output, mem);

    for (i = 0; i < key_store->keyc; i++) {
        key = &key_store->keys[i];

        if (!pgp_write_xfer_anykey(&output, key, passphrase, NULL, armour)) {
            return 0;
        }
    }

    rc = pgp_writer_close(&output);
    pgp_writer_info_delete(&output.writer);

    return rc;
}
