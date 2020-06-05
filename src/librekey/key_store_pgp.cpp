/*
 * Copyright (c) 2017-2020 [Ribose Inc](https://www.ribose.com).
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
#include <librepgp/stream-common.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>

#include "types.h"
#include "key_store_pgp.h"
#include "pgp-key.h"

bool
rnp_key_add_signature(pgp_key_t *key, const pgp_signature_t *sig)
{
    pgp_subsig_t *subsig = pgp_key_add_subsig(key);
    if (!subsig) {
        RNP_LOG("Failed to add subsig");
        return false;
    }
    /* setup subsig and key from signature */
    if (!pgp_subsig_from_signature(subsig, sig)) {
        return false;
    }
    subsig->uid = pgp_key_get_userid_count(key) - 1;
    return true;
}

static bool
rnp_key_add_signatures(pgp_key_t *key, list signatures)
{
    for (list_item *sig = list_front(signatures); sig; sig = list_next(sig)) {
        if (!rnp_key_add_signature(key, (pgp_signature_t *) sig)) {
            return false;
        }
    }
    return true;
}

bool
rnp_key_store_add_transferable_subkey(rnp_key_store_t *          keyring,
                                      pgp_transferable_subkey_t *tskey,
                                      pgp_key_t *                pkey)
{
    pgp_key_t skey = {};

    /* create subkey */
    if (!rnp_key_from_transferable_subkey(&skey, tskey, pkey)) {
        RNP_LOG_KEY_PKT("failed to create subkey %s", &tskey->subkey);
        return false;
    }

    /* add it to the storage */
    return rnp_key_store_add_key(keyring, &skey);
}

bool
rnp_key_add_transferable_userid(pgp_key_t *key, pgp_transferable_userid_t *uid)
{
    pgp_userid_t *userid = pgp_key_add_userid(key);
    if (!userid) {
        RNP_LOG("Failed to add userid");
        return false;
    }
    try {
        userid->rawpkt = pgp_rawpacket_t(uid->uid);
    } catch (const std::exception &e) {
        RNP_LOG("Raw packet allocation failed: %s", e.what());
        return false;
    }

    try {
        if (uid->uid.tag == PGP_PKT_USER_ID) {
            userid->str = std::string(uid->uid.uid, uid->uid.uid + uid->uid.uid_len);
        } else {
            userid->str = "(photo)";
        }
    } catch (const std::exception &e) {
        RNP_LOG(
          "%s alloc failed: %s", uid->uid.tag == PGP_PKT_USER_ID ? "uid" : "uattr", e.what());
        return false;
    }

    if (!copy_userid_pkt(&userid->pkt, &uid->uid)) {
        RNP_LOG("failed to copy user id pkt");
        return false;
    }

    if (!rnp_key_add_signatures(key, uid->signatures)) {
        return false;
    }

    return true;
}

bool
rnp_key_store_add_transferable_key(rnp_key_store_t *keyring, pgp_transferable_key_t *tkey)
{
    pgp_key_t  key = {};
    pgp_key_t *addkey = NULL;

    /* create key from transferable key */
    if (!rnp_key_from_transferable_key(&key, tkey)) {
        RNP_LOG_KEY_PKT("failed to create key %s", &tkey->key);
        return false;
    }

    /* temporary disable key validation */
    keyring->disable_validation = true;

    /* add key to the storage before subkeys */
    addkey = rnp_key_store_add_key(keyring, &key);
    if (!addkey) {
        RNP_LOG("Failed to add key to key store.");
        return false;
    }

    /* add subkeys */
    for (list_item *skey = list_front(tkey->subkeys); skey; skey = list_next(skey)) {
        pgp_transferable_subkey_t *subkey = (pgp_transferable_subkey_t *) skey;
        if (!rnp_key_store_add_transferable_subkey(keyring, subkey, addkey)) {
            RNP_LOG("Failed to add subkey to key store.");
            goto error;
        }
    }

    /* now validate/refresh the whole key with subkeys */
    keyring->disable_validation = false;
    pgp_key_revalidate_updated(addkey, keyring);
    return true;
error:
    /* during key addition all fields are copied so will be cleaned below */
    rnp_key_store_remove_key(keyring, addkey);
    return false;
}

bool
rnp_key_from_transferable_key(pgp_key_t *key, pgp_transferable_key_t *tkey)
{
    *key = {};
    /* create key */
    if (!pgp_key_from_pkt(key, &tkey->key)) {
        return false;
    }

    /* add direct-key signatures */
    if (!rnp_key_add_signatures(key, tkey->signatures)) {
        return false;
    }

    /* add userids and their signatures */
    for (list_item *uid = list_front(tkey->userids); uid; uid = list_next(uid)) {
        pgp_transferable_userid_t *tuid = (pgp_transferable_userid_t *) uid;
        if (!rnp_key_add_transferable_userid(key, tuid)) {
            return false;
        }
    }

    return true;
}

bool
rnp_key_from_transferable_subkey(pgp_key_t *                subkey,
                                 pgp_transferable_subkey_t *tskey,
                                 pgp_key_t *                primary)
{
    *subkey = {};

    /* create key */
    if (!pgp_key_from_pkt(subkey, &tskey->subkey)) {
        return false;
    }

    /* add subkey binding signatures */
    if (!rnp_key_add_signatures(subkey, tskey->signatures)) {
        RNP_LOG("failed to add subkey signatures");
        return false;
    }

    /* setup key grips if primary is available */
    if (primary && !pgp_key_link_subkey_grip(primary, subkey)) {
        return false;
    }

    return true;
}

rnp_result_t
rnp_key_store_pgp_read_from_src(rnp_key_store_t *keyring, pgp_source_t *src)
{
    pgp_key_sequence_t        keys = {};
    pgp_transferable_subkey_t tskey = {};
    rnp_result_t              ret = RNP_ERROR_GENERIC;

    /* check whether we have transferable subkey in source */
    if (is_subkey_pkt(stream_pkt_type(src))) {
        if ((ret = process_pgp_subkey(src, &tskey, keyring->skip_parsing_errors))) {
            return ret;
        }
        ret = rnp_key_store_add_transferable_subkey(keyring, &tskey, NULL) ?
                RNP_SUCCESS :
                RNP_ERROR_BAD_STATE;
        transferable_subkey_destroy(&tskey);
        return ret;
    }

    /* process armored or raw transferable key packets sequence(s) */
    if ((ret = process_pgp_keys(src, &keys, keyring->skip_parsing_errors))) {
        return ret;
    }

    for (list_item *key = list_front(keys.keys); key; key = list_next(key)) {
        if (!rnp_key_store_add_transferable_key(keyring, (pgp_transferable_key_t *) key)) {
            ret = RNP_ERROR_BAD_STATE;
            goto done;
        }
    }

    ret = RNP_SUCCESS;
done:
    key_sequence_destroy(&keys);
    return ret;
}

bool
rnp_key_to_src(const pgp_key_t *key, pgp_source_t *src)
{
    pgp_dest_t dst = {};
    bool       res;

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    res = pgp_key_write_packets(key, &dst) &&
          !init_mem_src(src, mem_dest_own_memory(&dst), dst.writeb, true);
    dst_close(&dst, true);
    return res;
}

static bool
do_write(rnp_key_store_t *key_store, pgp_dest_t *dst, bool secret)
{
    for (auto &key : key_store->keys) {
        if (pgp_key_is_secret(&key) != secret) {
            continue;
        }
        // skip subkeys, they are written below (orphans are ignored)
        if (!pgp_key_is_primary_key(&key)) {
            continue;
        }

        if (key.format != PGP_KEY_STORE_GPG) {
            RNP_LOG("incorrect format (conversions not supported): %d", key.format);
            return false;
        }
        if (!pgp_key_write_packets(&key, dst)) {
            return false;
        }
        for (auto &sgrip : key.subkey_grips) {
            pgp_key_t *subkey = rnp_key_store_get_key_by_grip(key_store, sgrip);
            if (!subkey) {
                RNP_LOG("Missing subkey");
                continue;
            }
            if (!pgp_key_write_packets(subkey, dst)) {
                return false;
            }
        }
    }
    return true;
}

bool
rnp_key_store_pgp_write_to_dst(rnp_key_store_t *key_store, pgp_dest_t *dst)
{
    // two separate passes (public keys, then secret keys)
    return do_write(key_store, dst, false) && do_write(key_store, dst, true);
}
