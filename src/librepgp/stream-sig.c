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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <rnp/rnp_def.h>
#include "defs.h"
#include "types.h"
#include "utils.h"
#include "stream-sig.h"
#include "stream-packet.h"
#include "hash.h"

bool
signature_matches_onepass(pgp_signature_t *sig, pgp_one_pass_sig_t *onepass)
{
    uint8_t keyid[PGP_KEY_ID_SIZE];

    if (!sig || !onepass) {
        return false;
    }

    if (!signature_get_keyid(sig, keyid)) {
        return false;
    }

    return !memcmp(keyid, onepass->keyid, PGP_KEY_ID_SIZE) && (sig->halg == onepass->halg) &&
           (sig->palg == onepass->palg) && (sig->type == onepass->type);
}

pgp_sig_subpkt_t *
signature_get_subpkt(pgp_signature_t *sig, pgp_sig_subpacket_type_t type)
{
    pgp_sig_subpkt_t *res = NULL;

    if (!sig || (sig->version < PGP_V4)) {
        return NULL;
    }

    for (list_item *sp = list_front(sig->subpkts); sp; sp = list_next(sp)) {
        pgp_sig_subpkt_t *subpkt = (pgp_sig_subpkt_t *) sp;
        if (subpkt->type == type) {
            return subpkt;
        }
    }

    return res;
}

static pgp_sig_subpkt_t *
signature_add_subpkt(pgp_signature_t *        sig,
                     pgp_sig_subpacket_type_t type,
                     size_t                   datalen,
                     bool                     reuse)
{
    pgp_sig_subpkt_t *subpkt = NULL;

    if (!sig) {
        return NULL;
    }

    if (sig->version < PGP_V4) {
        RNP_LOG("wrong signature version");
        return NULL;
    }

    if (reuse && (subpkt = signature_get_subpkt(sig, type))) {
        free(subpkt->data);
        memset(subpkt, 0, sizeof(*subpkt));
    }

    if (!subpkt) {
        pgp_sig_subpkt_t s = {0};
        subpkt = (pgp_sig_subpkt_t *) list_append(&sig->subpkts, &s, sizeof(s));
    }

    if (!subpkt || ((datalen > 0) && !(subpkt->data = calloc(1, datalen)))) {
        RNP_LOG("data allocation failed");
        list_remove((list_item *) subpkt);
        return NULL;
    }

    subpkt->type = type;
    subpkt->len = datalen;

    return subpkt;
}

bool
signature_get_keyfp(pgp_signature_t *sig, uint8_t *fp, size_t len, size_t *outlen)
{
    pgp_sig_subpkt_t *subpkt;

    if (!sig || !fp || !outlen || (sig->version < PGP_V4)) {
        return false;
    }

    *outlen = 0;
    if (!(subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_FPR))) {
        return false;
    }
    *outlen = subpkt->fields.issuer_fp.len;
    if (len >= subpkt->fields.issuer_fp.len) {
        memcpy(fp, subpkt->fields.issuer_fp.fp, subpkt->fields.issuer_fp.len);
        return true;
    }

    return false;
}

bool
signature_set_keyfp(pgp_signature_t *sig, uint8_t *fp, size_t len)
{
    pgp_sig_subpkt_t *subpkt = NULL;

    if (!sig || !fp) {
        return false;
    }

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_FPR, 1 + len, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    subpkt->data[0] = 4;
    memcpy(subpkt->data + 1, fp, len);
    subpkt->fields.issuer_fp.version = subpkt->data[0];
    subpkt->fields.issuer_fp.fp = subpkt->data + 1;
    return true;
}

bool
signature_get_keyid(pgp_signature_t *sig, uint8_t *id)
{
    pgp_sig_subpkt_t *subpkt;

    if (!sig || !id) {
        return false;
    }

    /* version 3 uses signature field */
    if (sig->version < PGP_V4) {
        memcpy(id, sig->signer, PGP_KEY_ID_SIZE);
        return true;
    }

    /* version 4 and up use subpackets */
    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_KEY_ID))) {
        memcpy(id, subpkt->fields.issuer, PGP_KEY_ID_SIZE);
        return true;
    }
    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_FPR))) {
        memcpy(id,
               subpkt->fields.issuer_fp.fp + subpkt->fields.issuer_fp.len - PGP_KEY_ID_SIZE,
               PGP_KEY_ID_SIZE);
        return true;
    }

    return false;
}

bool
signature_set_keyid(pgp_signature_t *sig, uint8_t *id)
{
    pgp_sig_subpkt_t *subpkt;

    if (!sig || !id) {
        return false;
    }

    if (sig->version < PGP_V4) {
        memcpy(sig->signer, id, PGP_KEY_ID_SIZE);
        return true;
    }

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_KEY_ID, PGP_KEY_ID_SIZE, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 0;
    memcpy(subpkt->data, id, PGP_KEY_ID_SIZE);
    subpkt->fields.issuer = subpkt->data;
    return true;
}

uint32_t
signature_get_creation(pgp_signature_t *sig)
{
    pgp_sig_subpkt_t *subpkt;

    if (!sig) {
        return 0;
    }
    if (sig->version < PGP_V4) {
        return sig->creation_time;
    }
    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_CREATION_TIME))) {
        return subpkt->fields.create;
    }

    return 0;
}

bool
signature_set_creation(pgp_signature_t *sig, uint32_t ctime)
{
    pgp_sig_subpkt_t *subpkt;

    if (!sig) {
        return false;
    }
    if (sig->version < PGP_V4) {
        sig->creation_time = ctime;
        return true;
    }

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_CREATION_TIME, 4, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    STORE32BE(subpkt->data, ctime);
    subpkt->fields.create = ctime;
    return true;
}

uint32_t
signature_get_expiration(pgp_signature_t *sig)
{
    pgp_sig_subpkt_t *subpkt;

    if (sig && (sig->version > PGP_V3) &&
        (subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_EXPIRATION_TIME))) {
        return subpkt->fields.expiry;
    }

    return 0;
}

bool
signature_set_expiration(pgp_signature_t *sig, uint32_t etime)
{
    pgp_sig_subpkt_t *subpkt;
    
    if (!sig || (sig->version < PGP_V4)) {
        return false;
    }

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_EXPIRATION_TIME, 4, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    STORE32BE(subpkt->data, etime);
    subpkt->fields.expiry = etime;
    return true;
}

bool
signature_fill_hashed_data(pgp_signature_t *sig)
{
    pgp_packet_body_t hbody;
    bool              res;

    if (!sig) {
        RNP_LOG("null signature");
        return false;
    }
    /* we don't have a need to write v2-v3 signatures */
    if ((sig->version < PGP_V2) || (sig->version > PGP_V4)) {
        RNP_LOG("don't know version %d", (int) sig->version);
        return false;
    }

    if (!init_packet_body(&hbody, 0)) {
        RNP_LOG("allocation failed");
        return false;
    }

    if (sig->version < PGP_V4) {
        res = add_packet_body_byte(&hbody, sig->type) &&
              add_packet_body_uint32(&hbody, sig->creation_time);
    } else {
        res = add_packet_body_byte(&hbody, sig->version) &&
              add_packet_body_byte(&hbody, sig->type) &&
              add_packet_body_byte(&hbody, sig->palg) &&
              add_packet_body_byte(&hbody, sig->halg) &&
              add_packet_body_subpackets(&hbody, sig, true);
    }

    if (res) {
        /* get ownership on body data */
        sig->hashed_data = hbody.data;
        sig->hashed_len = hbody.len;
        return res;
    }

    free_packet_body(&hbody);
    return res;
}

bool
signature_add_hash_trailer(pgp_hash_t *hash, pgp_signature_t *sig)
{
    uint8_t trailer[6] = {0x04, 0xff, 0x00, 0x00, 0x00, 0x00};

    if (!hash || !sig) {
        return false;
    }

    STORE32BE(&trailer[2], sig->hashed_len);
    return !pgp_hash_add(hash, trailer, 6);
}
