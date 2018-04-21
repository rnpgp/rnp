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
#include "crypto.h"
#include "crypto/common.h"

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
signature_hash_key(pgp_key_pkt_t *key, pgp_hash_t *hash)
{
    uint8_t hdr[3] = {0x99, 0x00, 0x00};

    if (!key || !hash) {
        RNP_LOG("null key or hash");
        return false;
    }
    if (!key->hashed_data && !key_fill_hashed_data(key)) {
        RNP_LOG("failed to build hashed data");
        return false;
    }
    write_uint16(hdr + 1, key->hashed_len);

    return !pgp_hash_add(hash, hdr, 3) &&
           !pgp_hash_add(hash, key->hashed_data, key->hashed_len);
}

bool
signature_hash_userid(pgp_userid_pkt_t *uid, pgp_hash_t *hash, pgp_version_t sigver)
{
    uint8_t hdr[5] = {0};

    if (!uid || !hash) {
        RNP_LOG("null uid or hash");
        return false;
    }

    if (sigver < PGP_V4) {
        return !pgp_hash_add(hash, uid->uid, uid->uid_len);
    }

    switch (uid->tag) {
    case PGP_PTAG_CT_USER_ID:
        hdr[0] = 0xB4;
        break;
    case PGP_PTAG_CT_USER_ATTR:
        hdr[0] = 0xD1;
        break;
    default:
        RNP_LOG("wrong uid");
        return false;
    }
    STORE32BE(hdr + 1, uid->uid_len);

    return !pgp_hash_add(hash, hdr, 5) && !pgp_hash_add(hash, uid->uid, uid->uid_len);
}

bool
signature_hash_signature(pgp_signature_t *sig, pgp_hash_t *hash)
{
    uint8_t hdr[5] = {0x88, 0x00, 0x00, 0x00, 0x00};

    if (!sig || !hash) {
        RNP_LOG("null sig or hash");
        return false;
    }

    if (!sig->hashed_data) {
        RNP_LOG("hashed data not filled");
        return false;
    }

    STORE32BE(hdr + 1, sig->hashed_len);
    return !pgp_hash_add(hash, hdr, 5) &&
           !pgp_hash_add(hash, sig->hashed_data, sig->hashed_len);
}

bool
signature_hash_certification(pgp_signature_t * sig,
                             pgp_key_pkt_t *   key,
                             pgp_userid_pkt_t *userid,
                             pgp_hash_t *      hash)
{
    return pgp_hash_create(hash, sig->halg) && signature_hash_key(key, hash) &&
           signature_hash_userid(userid, hash, sig->version);
}

bool
signature_hash_binding(pgp_signature_t *sig,
                       pgp_key_pkt_t *  key,
                       pgp_key_pkt_t *  subkey,
                       pgp_hash_t *     hash)
{
    return pgp_hash_create(hash, sig->halg) && signature_hash_key(key, hash) &&
           signature_hash_key(subkey, hash);
}

bool
signature_hash_finish(pgp_signature_t *sig, pgp_hash_t *hash, uint8_t *hbuf, size_t *hlen)
{
    if (!hash || !sig || !hbuf || !hlen) {
        goto error;
    }
    if (pgp_hash_add(hash, sig->hashed_data, sig->hashed_len)) {
        RNP_LOG("failed to hash sig");
        goto error;
    }
    if (sig->version > PGP_V3) {
        uint8_t trailer[6] = {0x04, 0xff, 0x00, 0x00, 0x00, 0x00};
        STORE32BE(&trailer[2], sig->hashed_len);
        if (pgp_hash_add(hash, trailer, 6)) {
            RNP_LOG("failed to add sig trailer");
            goto error;
        }
    }

    *hlen = pgp_hash_finish(hash, hbuf);
    return true;
error:
    pgp_hash_finish(hash, NULL);
    return false;
}

rnp_result_t
signature_validate(pgp_signature_t *sig, pgp_pubkey_t *key, pgp_hash_t *hash, rng_t *rng)
{
    uint8_t      hval[PGP_MAX_HASH_SIZE];
    size_t       len;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    /* Finalize hash */
    if (!signature_hash_finish(sig, hash, hval, &len)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    if (!key) {
        return RNP_ERROR_NULL_POINTER;
    }

    /* compare lbits */
    if (memcmp(hval, sig->lbits, 2)) {
        RNP_LOG("wrong lbits");
        return RNP_ERROR_SIGNATURE_INVALID;
    }

    /* validate signature */

    switch (sig->palg) {
    case PGP_PKA_DSA: {
        ret = dsa_verify(hval, len, &sig->material.dsa, &key->key.dsa);
        break;
    }
    case PGP_PKA_EDDSA: {
        bignum_t *r = mpi2bn(&sig->material.ecc.r);
        bignum_t *s = mpi2bn(&sig->material.ecc.s);
        bool      res = pgp_eddsa_verify_hash(r, s, hval, len, &key->key.ecc);
        ret = res ? RNP_SUCCESS : RNP_ERROR_SIGNATURE_INVALID;
        bn_free(r);
        bn_free(s);
        break;
    }
    case PGP_PKA_SM2: {
        pgp_ecc_sig_t ecc = {.r = mpi2bn(&sig->material.ecc.r),
                             .s = mpi2bn(&sig->material.ecc.s)};
        ret = pgp_sm2_verify_hash(&ecc, hval, len, &key->key.ecc);
        bn_free(ecc.r);
        bn_free(ecc.s);
        break;
    }
    case PGP_PKA_RSA: {
        ret = pgp_rsa_pkcs1_verify_hash(rng,
                                        sig->material.rsa.s.mpi,
                                        sig->material.rsa.s.len,
                                        sig->halg,
                                        hval,
                                        len,
                                        &key->key.rsa) ?
                RNP_SUCCESS :
                RNP_ERROR_SIGNATURE_INVALID;
        break;
    }
    case PGP_PKA_ECDSA: {
        pgp_ecc_sig_t ecc = {.r = mpi2bn(&sig->material.ecc.r),
                             .s = mpi2bn(&sig->material.ecc.s)};
        ret = pgp_ecdsa_verify_hash(&ecc, hval, len, &key->key.ecc);
        bn_free(ecc.r);
        bn_free(ecc.s);
        break;
    }
    default:
        RNP_LOG("Unknown algorithm");
        ret = RNP_ERROR_BAD_PARAMETERS;
    }

    return ret;
}

rnp_result_t
signature_calculate(pgp_signature_t *sig, pgp_seckey_t *seckey, pgp_hash_t *hash, rng_t *rng)
{
    uint8_t      hval[PGP_MAX_HASH_SIZE];
    size_t       hlen;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    /* Finalize hash and copy left 16 bits to signature */
    if (!signature_hash_finish(sig, hash, hval, &hlen)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    memcpy(sig->lbits, hval, 2);

    if (!seckey) {
        return RNP_ERROR_NULL_POINTER;
    }

    /* sign */
    switch (sig->palg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        sig->material.rsa.s.len = pgp_rsa_pkcs1_sign_hash(rng,
                                                          sig->material.rsa.s.mpi,
                                                          sizeof(sig->material.rsa.s.mpi),
                                                          sig->halg,
                                                          hval,
                                                          hlen,
                                                          &seckey->key.rsa,
                                                          &seckey->pubkey.key.rsa);
        if (!sig->material.rsa.s.len) {
            ret = RNP_ERROR_SIGNING_FAILED;
            RNP_LOG("rsa signing failed");
        } else {
            ret = RNP_SUCCESS;
        }
        break;
    case PGP_PKA_EDDSA: {
        bignum_t *r = bn_new(), *s = bn_new();

        if (!r || !s) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto eddsaend;
        }
        if (pgp_eddsa_sign_hash(
              rng, r, s, hval, hlen, &seckey->key.ecc, &seckey->pubkey.key.ecc) < 0) {
            ret = RNP_ERROR_SIGNING_FAILED;
            goto eddsaend;
        }
        if (!bn2mpi(r, &sig->material.ecc.r) || !bn2mpi(s, &sig->material.ecc.s)) {
            ret = RNP_ERROR_BAD_STATE;
            goto eddsaend;
        }
        ret = RNP_SUCCESS;
    eddsaend:
        bn_free(r);
        bn_free(s);
        break;
    }
    case PGP_PKA_SM2: {
        pgp_ecc_sig_t          eccsig = {NULL, NULL};
        const ec_curve_desc_t *curve = get_curve_desc(seckey->pubkey.key.ecc.curve);

        if (!curve) {
            RNP_LOG("Unknown curve");
            ret = RNP_ERROR_BAD_PARAMETERS;
            break;
        }
        /* "-2" because SM2 on P-521 must work with SHA-512 digest */
        if (BITS_TO_BYTES(curve->bitlen) - 2 > hlen) {
            RNP_LOG("Message hash to small");
            ret = RNP_ERROR_BAD_PARAMETERS;
            break;
        }
        if (pgp_sm2_sign_hash(
              rng, &eccsig, hval, hlen, &seckey->key.ecc, &seckey->pubkey.key.ecc)) {
            RNP_LOG("SM2 signing failed");
            ret = RNP_ERROR_SIGNING_FAILED;
            break;
        }
        if (!bn2mpi(eccsig.r, &sig->material.ecc.r) ||
            !bn2mpi(eccsig.s, &sig->material.ecc.s)) {
            ret = RNP_ERROR_BAD_STATE;
        } else {
            ret = RNP_SUCCESS;
        }
        bn_free(eccsig.r);
        bn_free(eccsig.s);
        break;
    }
    case PGP_PKA_DSA: {
        ret = dsa_sign(rng, &sig->material.dsa, hval, hlen, &seckey->pubkey.key.dsa);
        if (ret != RNP_SUCCESS) {
            RNP_LOG("DSA signing failed");
            break;
        }
        break;
    }
    /*
     * ECDH is signed with ECDSA. This must be changed when ECDH will support
     * X25519, but I need to check how it should be done exactly.
     */
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA: {
        pgp_ecc_sig_t          sigval = {NULL, NULL};
        const ec_curve_desc_t *curve = get_curve_desc(seckey->pubkey.key.ecc.curve);

        if (!curve) {
            RNP_LOG("Unknown curve");
            ret = RNP_ERROR_BAD_PARAMETERS;
            break;
        }
        /* "-2" because ECDSA on P-521 must work with SHA-512 digest */
        if (BITS_TO_BYTES(curve->bitlen) - 2 > hlen) {
            RNP_LOG("Message hash to small");
            ret = RNP_ERROR_BAD_PARAMETERS;
            break;
        }
        if (pgp_ecdsa_sign_hash(
              rng, &sigval, hval, hlen, &seckey->key.ecc, &seckey->pubkey.key.ecc)) {
            RNP_LOG("ECDSA signing failed");
            ret = RNP_ERROR_SIGNING_FAILED;
            break;
        }
        if (!bn2mpi(sigval.r, &sig->material.ecc.r) ||
            !bn2mpi(sigval.s, &sig->material.ecc.s)) {
            ret = RNP_ERROR_BAD_STATE;
        } else {
            ret = RNP_SUCCESS;
        }

        bn_free(sigval.r);
        bn_free(sigval.s);
        break;
    }
    default:
        RNP_LOG("Unsupported algorithm %d", sig->palg);
        break;
    }

    return ret;
}
