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

/** \file
 */
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: create.c,v 1.38 2010/11/15 08:03:39 agc Exp $");
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <assert.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <rnp/rnp_def.h>
#include <rnp/rnp_sdk.h>

#include "crypto/common.h"
#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>
#include "signature.h"
#include "packet-create.h"
#include "memory.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "utils.h"
#include "writer.h"

/**
 * \ingroup Core_Create
 * \param length
 * \param type
 * \param output
 * \return 1 if OK, otherwise 0
 */

unsigned
pgp_write_ss_header(pgp_output_t *output, unsigned length, pgp_content_enum type)
{
    // add 1 here since length includes the 1-octet subpacket type
    return pgp_write_length(output, length + 1) &&
           pgp_write_scalar(
             output, (unsigned) (type - (unsigned) PGP_PTAG_SIG_SUBPKT_BASE), 1);
}

/**
 * \ingroup Core_WritePackets
 * \brief Writes a User Id packet
 * \param id
 * \param output
 * \return 1 if OK, otherwise 0
 */
unsigned
pgp_write_struct_userid(pgp_output_t *output, const uint8_t *id)
{
    return pgp_write_ptag(output, PGP_PTAG_CT_USER_ID) &&
           pgp_write_length(output, (unsigned) strlen((const char *) id)) &&
           pgp_write(output, id, (unsigned) strlen((const char *) id));
}

/**
 * \ingroup Core_WritePackets
 * \brief Writes a Public Key packet
 * \param key
 * \param output
 * \return 1 if OK, otherwise 0
 */
bool
pgp_write_struct_pubkey(pgp_output_t *output, pgp_content_enum tag, pgp_key_pkt_t *key)
{
    pgp_dest_t dst;
    bool       res = false;

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    int oldtag = key->tag;
    key->tag = tag;

    if (!stream_write_key(key, &dst)) {
        goto done;
    }

    res = pgp_write(output, mem_dest_get_memory(&dst), dst.writeb);
done:
    key->tag = oldtag;
    dst_close(&dst, true);
    return res;
}

static bool
packet_matches(const pgp_rawpacket_t *pkt, const pgp_content_enum tags[], size_t tag_count)
{
    for (size_t i = 0; i < tag_count; i++) {
        if (pkt->tag == tags[i]) {
            return true;
        }
    }
    return false;
}

static bool
write_matching_packets(pgp_output_t *         output,
                       const pgp_key_t *      key,
                       const rnp_key_store_t *keyring,
                       const pgp_content_enum tags[],
                       size_t                 tag_count)
{
    for (unsigned i = 0; i < key->packetc; i++) {
        pgp_rawpacket_t *pkt = &key->packets[i];

        if (!packet_matches(pkt, tags, tag_count)) {
            RNP_LOG("skipping packet with tag: %d", pkt->tag);
            continue;
        }
        if (!pgp_write(output, pkt->raw, (unsigned) pkt->length)) {
            return false;
        }
    }

    if (!keyring) {
        return true;
    }

    // Export subkeys
    pgp_io_t io = {.errs = stderr, .res = stdout, .outs = stdout};
    for (list_item *grip = list_front(key->subkey_grips); grip; grip = list_next(grip)) {
        const pgp_key_t *subkey =
          rnp_key_store_get_key_by_grip(&io, keyring, (uint8_t *) grip);
        if (!write_matching_packets(output, subkey, NULL, tags, tag_count)) {
            RNP_LOG("Error occured when exporting a subkey");
            return false;
        }
    }

    return true;
}

/**
   \ingroup HighLevel_KeyWrite

   \brief Writes a transferable PGP public key to the given output stream.

   \param key Key to be written
   \param armored Flag is set for armored output
   \param output Output stream

*/

unsigned
pgp_write_xfer_pubkey(pgp_output_t *         output,
                      const pgp_key_t *      key,
                      const rnp_key_store_t *keyring,
                      const unsigned         armored)
{
    static const pgp_content_enum permitted_tags[] = {PGP_PTAG_CT_PUBLIC_KEY,
                                                      PGP_PTAG_CT_PUBLIC_SUBKEY,
                                                      PGP_PTAG_CT_USER_ID,
                                                      PGP_PTAG_CT_SIGNATURE};
    if (armored) {
        pgp_writer_push_armored(output, PGP_PGP_PUBLIC_KEY_BLOCK);
    }
    if (!write_matching_packets(
          output, key, keyring, permitted_tags, ARRAY_SIZE(permitted_tags))) {
        return false;
    }
    if (armored) {
        pgp_writer_info_finalise(&output->errors, &output->writer);
        pgp_writer_pop(output);
    }
    return true;
}

/**
   \ingroup HighLevel_KeyWrite

   \brief Writes a transferable PGP secret key to the given output stream.

   \param key Key to be written
   \param password
   \param pplen
   \param armored Flag is set for armored output
   \param output Output stream

*/

bool
pgp_write_xfer_seckey(pgp_output_t *         output,
                      const pgp_key_t *      key,
                      const rnp_key_store_t *keyring,
                      unsigned               armored)
{
    static const pgp_content_enum permitted_tags[] = {PGP_PTAG_CT_SECRET_KEY,
                                                      PGP_PTAG_CT_SECRET_SUBKEY,
                                                      PGP_PTAG_CT_USER_ID,
                                                      PGP_PTAG_CT_SIGNATURE};

    if (!key->packetc || !key->packets) {
        return false;
    }

    if (armored) {
        pgp_writer_push_armored(output, PGP_PGP_PRIVATE_KEY_BLOCK);
    }
    if (!write_matching_packets(
          output, key, keyring, permitted_tags, ARRAY_SIZE(permitted_tags))) {
        return false;
    }
    if (armored) {
        pgp_writer_info_finalise(&output->errors, &output->writer);
        pgp_writer_pop(output);
    }
    return true;
}

/**
 * \ingroup Core_WritePackets
 * \brief Writes a Secret Key packet.
 * \param key The secret key
 * \param password The password
 * \param pplen Length of password
 * \param output
 * \return 1 if OK; else 0
 */
bool
pgp_write_struct_seckey(pgp_output_t *   output,
                        pgp_content_enum tag,
                        pgp_key_pkt_t *  seckey,
                        const char *     password)
{
    pgp_dest_t dst;
    bool       res = false;

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    int oldtag = seckey->tag;
    seckey->tag = tag;

    if (encrypt_secret_key(seckey, password, NULL)) {
        goto done;
    }

    if (!stream_write_key(seckey, &dst)) {
        goto done;
    }

    res = pgp_write(output, mem_dest_get_memory(&dst), dst.writeb);
done:
    seckey->tag = oldtag;
    dst_close(&dst, true);
    return res;
}

/**
 * \ingroup Core_Create
 *
 * \brief Create a new pgp_output_t structure.
 *
 * \return the new structure.
 * \note It is the responsiblity of the caller to call pgp_output_delete().
 * \sa pgp_output_delete()
 */
pgp_output_t *
pgp_output_new(void)
{
    return calloc(1, sizeof(pgp_output_t));
}

/**
 * \ingroup Core_Create
 * \brief Delete an pgp_output_t strucut and associated resources.
 *
 * Delete an pgp_output_t structure. If a writer is active, then
 * that is also deleted.
 *
 * \param info the structure to be deleted.
 */
void
pgp_output_delete(pgp_output_t *output)
{
    if (!output) {
        return;
    }
    pgp_writer_info_delete(&output->writer);
    free(output);
}

bool
pgp_write_selfsig_cert(pgp_output_t *               output,
                       const pgp_key_pkt_t *        seckey,
                       const pgp_hash_alg_t         hash_alg,
                       const rnp_selfsig_cert_info *cert)
{
    pgp_create_sig_t *sig = NULL;
    bool              ok = false;
    uint8_t           keyid[PGP_KEY_ID_SIZE];
    rng_t             rng = {0};

    if (!output || !seckey || !cert) {
        RNP_LOG("invalid parameters");
        return false;
    }

    if (!rng_init(&rng, RNG_SYSTEM)) {
        RNP_LOG("RNG init failed");
        return false;
    }

    if (pgp_keyid(keyid, sizeof(keyid), seckey)) {
        RNP_LOG("failed to calculate keyid");
        goto end;
    }

    sig = pgp_create_sig_new();
    if (!sig) {
        RNP_LOG("create sig failed");
        goto end;
    }
    if (!pgp_sig_start_key_sig(sig, seckey, cert->userid, PGP_CERT_POSITIVE, hash_alg)) {
        RNP_LOG("failed to start key sig");
        goto end;
    }
    if (!pgp_sig_add_time(sig, (int64_t) time(NULL), PGP_PTAG_SS_CREATION_TIME)) {
        RNP_LOG("failed to add creation time");
        goto end;
    }
    if (cert->key_expiration &&
        !pgp_sig_add_time(sig, cert->key_expiration, PGP_PTAG_SS_KEY_EXPIRY)) {
        RNP_LOG("failed to add key expiration time");
        goto end;
    }
    if (cert->key_flags && !pgp_sig_add_key_flags(sig, &cert->key_flags, 1)) {
        RNP_LOG("failed to add key flags");
        goto end;
    }
    if (cert->primary) {
        pgp_sig_add_primary_userid(sig, 1);
    }
    const pgp_user_prefs_t *prefs = &cert->prefs;
    if (!DYNARRAY_IS_EMPTY(prefs, symm_alg) &&
        !pgp_sig_add_pref_symm_algs(sig, prefs->symm_algs, prefs->symm_algc)) {
        RNP_LOG("failed to add symm alg prefs");
        goto end;
    }
    if (!DYNARRAY_IS_EMPTY(prefs, hash_alg) &&
        !pgp_sig_add_pref_hash_algs(sig, prefs->hash_algs, prefs->hash_algc)) {
        RNP_LOG("failed to add hash alg prefs");
        goto end;
    }
    if (!DYNARRAY_IS_EMPTY(prefs, compress_alg) &&
        !pgp_sig_add_pref_compress_algs(sig, prefs->compress_algs, prefs->compress_algc)) {
        RNP_LOG("failed to add compress alg prefs");
        goto end;
    }
    if (!DYNARRAY_IS_EMPTY(prefs, key_server_pref) &&
        !pgp_sig_add_key_server_prefs(sig, prefs->key_server_prefs, prefs->key_server_prefc)) {
        RNP_LOG("failed to add key server prefs");
        goto end;
    }
    if (prefs->key_server && !pgp_sig_add_preferred_key_server(sig, prefs->key_server)) {
        RNP_LOG("failed to add preferred key server");
        goto end;
    }
    if (!pgp_sig_add_issuer_keyid(sig, keyid)) {
        RNP_LOG("failed to add issuer key id");
        goto end;
    }
    if (!pgp_sig_end_hashed_subpkts(sig)) {
        RNP_LOG("failed to finalize hashed subpkts");
        goto end;
    }

    if (!pgp_sig_write(&rng, output, sig, seckey)) {
        RNP_LOG("failed to write signature");
        goto end;
    }
    ok = true;
end:
    rng_destroy(&rng);
    pgp_create_sig_delete(sig);
    return ok;
}

bool
pgp_write_selfsig_binding(pgp_output_t *                  output,
                          const pgp_key_pkt_t *           primary_sec,
                          const pgp_hash_alg_t            hash_alg,
                          const pgp_key_pkt_t *           subkey,
                          const rnp_selfsig_binding_info *binding)
{
    pgp_create_sig_t *sig = NULL;
    bool              ok = false;
    uint8_t           keyid[PGP_KEY_ID_SIZE];
    rng_t             rng = {0};

    if (!output || !primary_sec || !subkey || !binding) {
        RNP_LOG("invalid parameters");
        goto end;
    }

    if (!rng_init(&rng, RNG_SYSTEM)) {
        RNP_LOG("RNG init failed");
        return false;
    }

    if (pgp_keyid(keyid, sizeof(keyid), primary_sec)) {
        RNP_LOG("failed to calculate keyid");
        goto end;
    }

    sig = pgp_create_sig_new();
    if (!sig) {
        RNP_LOG("create sig failed");
        goto end;
    }
    if (!pgp_sig_start_subkey_sig(sig, primary_sec, subkey, PGP_SIG_SUBKEY, hash_alg)) {
        RNP_LOG("failed to start subkey sig");
        goto end;
    }
    if (!pgp_sig_add_time(sig, (int64_t) time(NULL), PGP_PTAG_SS_CREATION_TIME)) {
        RNP_LOG("failed to add creation time");
        goto end;
    }
    if (binding->key_expiration &&
        !pgp_sig_add_time(sig, binding->key_expiration, PGP_PTAG_SS_KEY_EXPIRY)) {
        RNP_LOG("failed to add key expiration time");
        goto end;
    }
    if (binding->key_flags && !pgp_sig_add_key_flags(sig, &binding->key_flags, 1)) {
        RNP_LOG("failed to add key flags");
        goto end;
    }
    if (!pgp_sig_add_issuer_keyid(sig, keyid)) {
        RNP_LOG("failed to add issuer key id");
        goto end;
    }
    if (!pgp_sig_end_hashed_subpkts(sig)) {
        RNP_LOG("failed to finalize hashed subpkts");
        goto end;
    }

    if (!pgp_sig_write(&rng, output, sig, primary_sec)) {
        RNP_LOG("failed to write signature");
        goto end;
    }
    ok = true;
end:
    rng_destroy(&rng);
    pgp_create_sig_delete(sig);
    return ok;
}
