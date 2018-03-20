/*
 * Copyright (c) 2018, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "stream-def.h"
#include "stream-key.h"
#include "stream-armor.h"
#include "stream-packet.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "defs.h"
#include "types.h"
#include "symmetric.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "list.h"
#include "packet-parse.h"
#include "utils.h"

static void
signature_list_destroy(list *sigs)
{
    for (list_item *li = list_front(*sigs); li; li = list_next(li)) {
        free_signature((pgp_signature_t *) li);
    }
    list_destroy(sigs);
}

void
transferable_key_destroy(pgp_transferable_key_t *key)
{
    for (list_item *li = list_front(key->userids); li; li = list_next(li)) {
        pgp_transferable_userid_t *uid = (pgp_transferable_userid_t *) li;
        free_userid_pkt(&uid->uid);
        signature_list_destroy(&uid->signatures);
    }
    list_destroy(&key->userids);

    for (list_item *li = list_front(key->subkeys); li; li = list_next(li)) {
        pgp_transferable_subkey_t *skey = (pgp_transferable_subkey_t *) li;
        free_key_pkt(&skey->subkey);
        signature_list_destroy(&skey->signatures);
    }
    list_destroy(&key->subkeys);

    signature_list_destroy(&key->signatures);
    free_key_pkt(&key->key);
}

void
key_sequence_destroy(pgp_key_sequence_t *keys)
{
    for (list_item *li = list_front(keys->keys); li; li = list_next(li)) {
        transferable_key_destroy((pgp_transferable_key_t *) li);
    }
    list_destroy(&keys->keys);
}

rnp_result_t
process_pgp_keys(pgp_source_t *src, pgp_key_sequence_t *keys)
{
    int                        ptag;
    bool                       armored = false;
    pgp_source_t               armorsrc = {0};
    bool                       has_secret = false;
    bool                       has_public = false;
    pgp_transferable_key_t *   curkey = NULL;
    pgp_transferable_subkey_t *cursubkey = NULL;
    pgp_transferable_userid_t *curuid = NULL;
    rnp_result_t               ret = RNP_ERROR_GENERIC;

    memset(keys, 0, sizeof(*keys));

    /* check whether keys are armored */
    if (is_armored_source(src)) {
        if ((ret = init_armored_src(&armorsrc, src))) {
            RNP_LOG("failed to parse armored data");
            goto finish;
        }
        armored = true;
        src = &armorsrc;
    }

    /* read sequence of transferable OpenPGP keys as described in RFC 4880, 11.1 - 11.2 */
    while (!src_eof(src)) {
        if ((ptag = stream_pkt_type(src)) < 0) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }

        switch (ptag) {
        case PGP_PTAG_CT_SECRET_KEY:
        case PGP_PTAG_CT_PUBLIC_KEY:
            if (!(curkey = (pgp_transferable_key_t *) list_append(
                    &keys->keys, NULL, sizeof(*curkey)))) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto finish;
            }
            if ((ret = stream_parse_key(src, &curkey->key))) {
                list_remove((list_item *) curkey);
                goto finish;
            }
            cursubkey = NULL;
            curuid = NULL;
            has_secret |= (ptag == PGP_PTAG_CT_SECRET_KEY);
            has_public |= (ptag == PGP_PTAG_CT_PUBLIC_KEY);
            break;
        case PGP_PTAG_CT_PUBLIC_SUBKEY:
        case PGP_PTAG_CT_SECRET_SUBKEY:
            if (!curkey) {
                RNP_LOG("unexpected subkey packet");
                ret = RNP_ERROR_BAD_FORMAT;
                goto finish;
            }
            if (!(cursubkey = (pgp_transferable_subkey_t *) list_append(
                    &curkey->subkeys, NULL, sizeof(*cursubkey)))) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto finish;
            }
            curuid = NULL;
            if ((ret = stream_parse_key(src, &cursubkey->subkey))) {
                list_remove((list_item *) cursubkey);
                goto finish;
            }
            break;
        case PGP_PTAG_CT_SIGNATURE: {
            list *           siglist = NULL;
            pgp_signature_t *sig;

            if (!curkey) {
                RNP_LOG("unexpected signature");
                ret = RNP_ERROR_BAD_FORMAT;
                goto finish;
            }

            if (curuid) {
                siglist = &curuid->signatures;
            } else if (cursubkey) {
                siglist = &cursubkey->signatures;
            } else {
                siglist = &curkey->signatures;
            }

            if (!(sig = (pgp_signature_t *) list_append(siglist, NULL, sizeof(*sig)))) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto finish;
            }
            if ((ret = stream_parse_signature(src, sig))) {
                list_remove((list_item *) sig);
                goto finish;
            }
            break;
        }
        case PGP_PTAG_CT_USER_ID:
        case PGP_PTAG_CT_USER_ATTR:
            if (cursubkey) {
                RNP_LOG("userid after the subkey");
                ret = RNP_ERROR_BAD_FORMAT;
                goto finish;
            }

            if (!(curuid = (pgp_transferable_userid_t *) list_append(
                    &curkey->userids, NULL, sizeof(*curuid)))) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto finish;
            }

            if ((ret = stream_parse_userid(src, &curuid->uid))) {
                list_remove((list_item *) curuid);
                goto finish;
            }
            break;
        case PGP_PTAG_CT_TRUST:
            ret = stream_skip_packet(src);
            break;
        default:
            RNP_LOG("unexpected packet %d in key sequence", ptag);
            ret = RNP_ERROR_BAD_FORMAT;
        }

        if (ret) {
            goto finish;
        }
    }

    if (has_secret && has_public) {
        RNP_LOG("warning! public keys are mixed together with secret ones!");
    }

    ret = RNP_SUCCESS;
finish:
    if (armored) {
        src_close(&armorsrc);
    }
    if (ret) {
        key_sequence_destroy(keys);
    }
    return ret;
}
