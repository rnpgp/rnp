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

#include <librepgp/stream-common.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>
#include "crypto/mem.h"

#include "types.h"
#include "key_store_pgp.h"
#include "pgp-key.h"

bool
rnp_key_store_add_transferable_subkey(rnp_key_store_t *          keyring,
                                      pgp_transferable_subkey_t *tskey,
                                      pgp_key_t *                pkey)
{
    try {
        /* create subkey */
        pgp_key_t skey(*tskey, pkey);
        /* add it to the storage */
        return rnp_key_store_add_key(keyring, &skey);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        RNP_LOG_KEY_PKT("failed to create subkey %s", tskey->subkey);
        RNP_LOG_KEY("primary key is %s", pkey);
        return false;
    }
}

bool
rnp_key_store_add_transferable_key(rnp_key_store_t *keyring, pgp_transferable_key_t *tkey)
{
    pgp_key_t *addkey = NULL;

    /* create key from transferable key */
    try {
        pgp_key_t key(*tkey);
        /* temporary disable key validation */
        keyring->disable_validation = true;
        /* add key to the storage before subkeys */
        addkey = rnp_key_store_add_key(keyring, &key);
    } catch (const std::exception &e) {
        keyring->disable_validation = false;
        RNP_LOG_KEY_PKT("failed to add key %s", tkey->key);
        return false;
    }

    if (!addkey) {
        keyring->disable_validation = false;
        RNP_LOG("Failed to add key to key store.");
        return false;
    }

    /* add subkeys */
    for (auto &subkey : tkey->subkeys) {
        if (!rnp_key_store_add_transferable_subkey(keyring, &subkey, addkey)) {
            RNP_LOG("Failed to add subkey to key store.");
            keyring->disable_validation = false;
            goto error;
        }
    }

    /* now validate/refresh the whole key with subkeys */
    keyring->disable_validation = false;
    addkey->revalidate(*keyring);
    return true;
error:
    /* during key addition all fields are copied so will be cleaned below */
    rnp_key_store_remove_key(keyring, addkey, false);
    return false;
}

rnp_result_t
rnp_key_store_pgp_read_key_from_src(rnp_key_store_t &keyring,
                                    pgp_source_t &   src,
                                    bool             skiperrors)
{
    pgp_transferable_key_t key;
    rnp_result_t           ret = process_pgp_key_auto(src, key, true, skiperrors);

    if (ret && (!skiperrors || (ret != RNP_ERROR_BAD_FORMAT))) {
        return ret;
    }

    /* check whether we have primary key */
    if (key.key.tag != PGP_PKT_RESERVED) {
        return rnp_key_store_add_transferable_key(&keyring, &key) ? RNP_SUCCESS :
                                                                    RNP_ERROR_BAD_STATE;
    }

    /* we just skipped some unexpected packets and read nothing */
    if (key.subkeys.empty()) {
        return RNP_SUCCESS;
    }

    return rnp_key_store_add_transferable_subkey(&keyring, &key.subkeys.front(), NULL) ?
             RNP_SUCCESS :
             RNP_ERROR_BAD_STATE;
}

rnp_result_t
rnp_key_store_pgp_read_from_src(rnp_key_store_t *keyring, pgp_source_t *src, bool skiperrors)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    /* check whether we have transferable subkey in source */
    if (is_subkey_pkt(stream_pkt_type(src))) {
        pgp_transferable_subkey_t tskey;
        ret = process_pgp_subkey(*src, tskey, skiperrors);
        if (ret) {
            return ret;
        }
        return rnp_key_store_add_transferable_subkey(keyring, &tskey, NULL) ?
                 RNP_SUCCESS :
                 RNP_ERROR_BAD_STATE;
    }

    /* process armored or raw transferable key packets sequence(s) */
    pgp_key_sequence_t keys;
    if ((ret = process_pgp_keys(src, keys, skiperrors))) {
        return ret;
    }

    for (auto &key : keys.keys) {
        if (!rnp_key_store_add_transferable_key(keyring, &key)) {
            return RNP_ERROR_BAD_STATE;
        }
    }
    return RNP_SUCCESS;
}

bool
rnp_key_to_src(const pgp_key_t *key, pgp_source_t *src)
{
    pgp_dest_t dst = {};
    bool       res;

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    key->write(dst);
    res = !dst.werr && !init_mem_src(src, mem_dest_own_memory(&dst), dst.writeb, true);
    dst_close(&dst, true);
    return res;
}

static bool
do_write(rnp_key_store_t *key_store, pgp_dest_t *dst, bool secret)
{
    for (auto &key : key_store->keys) {
        if (key.is_secret() != secret) {
            continue;
        }
        // skip subkeys, they are written below (orphans are ignored)
        if (!key.is_primary()) {
            continue;
        }

        if (key.format != PGP_KEY_STORE_GPG) {
            RNP_LOG("incorrect format (conversions not supported): %d", key.format);
            return false;
        }
        key.write(*dst);
        if (dst->werr) {
            return false;
        }
        for (auto &sfp : key.subkey_fps()) {
            pgp_key_t *subkey = rnp_key_store_get_key_by_fpr(key_store, sfp);
            if (!subkey) {
                RNP_LOG("Missing subkey");
                continue;
            }
            subkey->write(*dst);
            if (dst->werr) {
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
