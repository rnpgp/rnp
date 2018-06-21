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
#include <librepgp/stream-sig.h>
#include <librepgp/stream-armor.h>
#include "packet-create.h"
#include "memory.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "utils.h"
#include "writer.h"

/**
 * \ingroup Core_WritePackets
 * \brief Writes a User Id packet
 * \param id
 * \param output
 * \return 1 if OK, otherwise 0
 */
bool
pgp_write_struct_userid(pgp_output_t *output, const uint8_t *id)
{
    pgp_dest_t       dst;
    pgp_userid_pkt_t uid;
    bool             res = false;

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    uid.tag = PGP_PTAG_CT_USER_ID;
    uid.uid = (uint8_t *) id;
    uid.uid_len = strlen((const char *) id);

    if (!stream_write_userid(&uid, &dst)) {
        goto done;
    }

    res = pgp_write(output, mem_dest_get_memory(&dst), dst.writeb);
done:
    dst_close(&dst, true);
    return res;
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
write_matching_packets(pgp_dest_t *           dst,
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
        dst_write(dst, pkt->raw, (unsigned) pkt->length);
    }

    if (!keyring) {
        return !dst->werr;
    }

    // Export subkeys
    pgp_io_t io = pgp_io_from_fp(stderr, stdout, stdout);
    for (list_item *grip = list_front(key->subkey_grips); grip; grip = list_next(grip)) {
        const pgp_key_t *subkey =
          rnp_key_store_get_key_by_grip(&io, keyring, (uint8_t *) grip);
        if (!write_matching_packets(dst, subkey, NULL, tags, tag_count)) {
            RNP_LOG("Error occured when exporting a subkey");
            return false;
        }
    }

    return !dst->werr;
}

/**
   \ingroup HighLevel_KeyWrite

   \brief Writes a transferable PGP public key to the given output stream.

   \param key Key to be written
   \param armored Flag is set for armored output
   \param output Output stream

*/

bool
pgp_write_xfer_pubkey(pgp_dest_t *           dst,
                      const pgp_key_t *      key,
                      const rnp_key_store_t *keyring,
                      bool                   armored)
{
    static const pgp_content_enum perm_tags[] = {PGP_PTAG_CT_PUBLIC_KEY,
                                                 PGP_PTAG_CT_PUBLIC_SUBKEY,
                                                 PGP_PTAG_CT_USER_ID,
                                                 PGP_PTAG_CT_SIGNATURE};

    pgp_dest_t armordst = {0};
    bool       res = false;

    if (!key->packetc || !key->packets) {
        return false;
    }

    if (armored) {
        if (init_armored_dst(&armordst, dst, PGP_ARMORED_PUBLIC_KEY)) {
            return false;
        }
        dst = &armordst;
    }
    res = write_matching_packets(dst, key, keyring, perm_tags, ARRAY_SIZE(perm_tags));

    if (armored) {
        dst_close(&armordst, !res);
    }
    return res;
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
pgp_write_xfer_seckey(pgp_dest_t *           dst,
                      const pgp_key_t *      key,
                      const rnp_key_store_t *keyring,
                      bool                   armored)
{
    static const pgp_content_enum perm_tags[] = {PGP_PTAG_CT_SECRET_KEY,
                                                 PGP_PTAG_CT_SECRET_SUBKEY,
                                                 PGP_PTAG_CT_USER_ID,
                                                 PGP_PTAG_CT_SIGNATURE};

    pgp_dest_t armordst = {0};
    bool       res = false;

    if (!key->packetc || !key->packets) {
        return false;
    }

    if (armored) {
        if (init_armored_dst(&armordst, dst, PGP_ARMORED_SECRET_KEY)) {
            return false;
        }
        dst = &armordst;
    }
    res = write_matching_packets(dst, key, keyring, perm_tags, ARRAY_SIZE(perm_tags));

    if (armored) {
        dst_close(&armordst, !res);
    }
    return res;
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
    return (pgp_output_t *) calloc(1, sizeof(pgp_output_t));
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
pgp_write_selfsig_cert(pgp_output_t *                 output,
                       const pgp_key_pkt_t *          seckey,
                       const pgp_hash_alg_t           hash_alg,
                       const rnp_selfsig_cert_info_t *cert)
{
    pgp_signature_t         sig = {};
    pgp_userid_pkt_t        uid = {0};
    pgp_hash_t              hash = {0};
    pgp_dest_t              dst = {0};
    bool                    ok = false;
    uint8_t                 keyid[PGP_KEY_ID_SIZE];
    rng_t                   rng = {0};
    const pgp_user_prefs_t *prefs = NULL;

    if (!output || !seckey || !cert) {
        RNP_LOG("invalid parameters");
        return false;
    }

    if (!rng_init(&rng, RNG_SYSTEM)) {
        RNP_LOG("RNG init failed");
        return false;
    }

    if (init_mem_dest(&dst, NULL, 0)) {
        RNP_LOG("alloc failed");
        goto end;
    }

    if (pgp_keyid(keyid, sizeof(keyid), seckey)) {
        RNP_LOG("failed to calculate keyid");
        goto end;
    }

    sig.version = PGP_V4;
    sig.halg = pgp_hash_adjust_alg_to_key(hash_alg, seckey);
    sig.palg = seckey->alg;
    sig.type = PGP_CERT_POSITIVE;

    if (!signature_set_creation(&sig, time(NULL))) {
        RNP_LOG("failed to set creation time");
        goto end;
    }
    if (cert->key_expiration && !signature_set_key_expiration(&sig, cert->key_expiration)) {
        RNP_LOG("failed to set key expiration time");
        goto end;
    }
    if (cert->key_flags && !signature_set_key_flags(&sig, cert->key_flags)) {
        RNP_LOG("failed to set key flags");
        goto end;
    }
    if (cert->primary && !signature_set_primary_uid(&sig, true)) {
        RNP_LOG("failed to set primary userid");
        goto end;
    }
    prefs = &cert->prefs;
    if (!DYNARRAY_IS_EMPTY(prefs, symm_alg) &&
        !signature_set_preferred_symm_algs(&sig, prefs->symm_algs, prefs->symm_algc)) {
        RNP_LOG("failed to set symm alg prefs");
        goto end;
    }
    if (!DYNARRAY_IS_EMPTY(prefs, hash_alg) &&
        !signature_set_preferred_hash_algs(&sig, prefs->hash_algs, prefs->hash_algc)) {
        RNP_LOG("failed to set hash alg prefs");
        goto end;
    }
    if (!DYNARRAY_IS_EMPTY(prefs, compress_alg) &&
        !signature_set_preferred_z_algs(&sig, prefs->compress_algs, prefs->compress_algc)) {
        RNP_LOG("failed to set compress alg prefs");
        goto end;
    }
    if (!DYNARRAY_IS_EMPTY(prefs, key_server_pref) &&
        !signature_set_key_server_prefs(&sig, prefs->key_server_prefs[0])) {
        RNP_LOG("failed to set key server prefs");
        goto end;
    }
    if (prefs->key_server &&
        !signature_set_preferred_key_server(&sig, (char *) prefs->key_server)) {
        RNP_LOG("failed to set preferred key server");
        goto end;
    }
    if (!signature_set_keyid(&sig, keyid)) {
        RNP_LOG("failed to set issuer key id");
        goto end;
    }

    /* we just set fields so no need to free later */
    uid.tag = PGP_PTAG_CT_USER_ID;
    uid.uid = (uint8_t *) cert->userid;
    uid.uid_len = strlen((const char *) cert->userid);

    if (!signature_fill_hashed_data(&sig) ||
        !signature_hash_certification(&sig, seckey, &uid, &hash) ||
        signature_calculate(&sig, &seckey->material, &hash, &rng)) {
        RNP_LOG("failed to calculate signature");
        goto end;
    }

    if (!stream_write_signature(&sig, &dst)) {
        RNP_LOG("failed to write signature");
        goto end;
    }

    ok = pgp_write(output, mem_dest_get_memory(&dst), dst.writeb);
end:
    dst_close(&dst, true);
    rng_destroy(&rng);
    free_signature(&sig);
    return ok;
}

bool
pgp_write_selfsig_binding(pgp_output_t *                    output,
                          const pgp_key_pkt_t *             key,
                          const pgp_hash_alg_t              hash_alg,
                          const pgp_key_pkt_t *             subkey,
                          const rnp_selfsig_binding_info_t *binding)
{
    pgp_signature_t sig = {(pgp_version_t) 0};
    pgp_hash_t      hash = {0};
    pgp_dest_t      dst = {0};
    bool            ok = false;
    uint8_t         keyid[PGP_KEY_ID_SIZE];
    rng_t           rng = {0};

    if (!output || !key || !subkey || !binding) {
        RNP_LOG("invalid parameters");
        goto end;
    }

    if (!rng_init(&rng, RNG_SYSTEM)) {
        RNP_LOG("RNG init failed");
        return false;
    }

    if (init_mem_dest(&dst, NULL, 0)) {
        RNP_LOG("alloc failed");
        goto end;
    }

    if (pgp_keyid(keyid, sizeof(keyid), key)) {
        RNP_LOG("failed to calculate keyid");
        goto end;
    }

    sig.version = PGP_V4;
    sig.halg = pgp_hash_adjust_alg_to_key(hash_alg, key);
    sig.palg = key->alg;
    sig.type = PGP_SIG_SUBKEY;

    if (!signature_set_creation(&sig, time(NULL))) {
        RNP_LOG("failed to set creation time");
        goto end;
    }
    if (binding->key_expiration &&
        !signature_set_key_expiration(&sig, binding->key_expiration)) {
        RNP_LOG("failed to set key expiration time");
        goto end;
    }
    if (binding->key_flags && !signature_set_key_flags(&sig, binding->key_flags)) {
        RNP_LOG("failed to set key flags");
        goto end;
    }
    if (!signature_set_keyid(&sig, keyid)) {
        RNP_LOG("failed to set issuer key id");
        goto end;
    }

    if (!signature_fill_hashed_data(&sig) ||
        !signature_hash_binding(&sig, key, subkey, &hash) ||
        signature_calculate(&sig, &key->material, &hash, &rng)) {
        RNP_LOG("failed to calculate signature");
        goto end;
    }

    if (!stream_write_signature(&sig, &dst)) {
        RNP_LOG("failed to write signature");
        goto end;
    }

    ok = pgp_write(output, mem_dest_get_memory(&dst), dst.writeb);
end:
    dst_close(&dst, true);
    rng_destroy(&rng);
    free_signature(&sig);
    return ok;
}
