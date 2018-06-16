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
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "stream-def.h"
#include "stream-key.h"
#include "stream-armor.h"
#include "stream-packet.h"
#include "stream-sig.h"
#include "defs.h"
#include "types.h"
#include "crypto/symmetric.h"
#include "crypto/s2k.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "list.h"
#include "packet-parse.h"
#include "utils.h"
#include "crypto.h"

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
    forget_secret_key_fields(&key->key.material);

    for (list_item *li = list_front(key->userids); li; li = list_next(li)) {
        pgp_transferable_userid_t *uid = (pgp_transferable_userid_t *) li;
        free_userid_pkt(&uid->uid);
        signature_list_destroy(&uid->signatures);
    }
    list_destroy(&key->userids);

    for (list_item *li = list_front(key->subkeys); li; li = list_next(li)) {
        pgp_transferable_subkey_t *skey = (pgp_transferable_subkey_t *) li;
        forget_secret_key_fields(&skey->subkey.material);
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

static rnp_result_t
process_pgp_key_trusts(pgp_source_t *src)
{
    rnp_result_t ret;
    while (stream_pkt_type(src) == PGP_PTAG_CT_TRUST) {
        if ((ret = stream_skip_packet(src))) {
            RNP_LOG("failed to skip trust packet");
            return ret;
        }
    }
    return RNP_SUCCESS;
}

static rnp_result_t
process_pgp_key_signatures(pgp_source_t *src, list *sigs)
{
    int          ptag;
    rnp_result_t ret = RNP_ERROR_BAD_FORMAT;

    while ((ptag = stream_pkt_type(src)) == PGP_PTAG_CT_SIGNATURE) {
        pgp_signature_t *sig = (pgp_signature_t *) list_append(sigs, NULL, sizeof(*sig));
        if (!sig) {
            RNP_LOG("sig alloc failed");
            return RNP_ERROR_OUT_OF_MEMORY;
        }

        if ((ret = stream_parse_signature(src, sig))) {
            list_remove((list_item *) sig);
            return ret;
        }

        if ((ret = process_pgp_key_trusts(src))) {
            return ret;
        }
    }

    return ptag < 0 ? RNP_ERROR_BAD_FORMAT : RNP_SUCCESS;
}

static rnp_result_t
process_pgp_key_userid(pgp_source_t *src, pgp_transferable_userid_t *uid)
{
    int          ptag;
    rnp_result_t ret = RNP_ERROR_BAD_FORMAT;

    ptag = stream_pkt_type(src);

    if ((ptag != PGP_PTAG_CT_USER_ID) && (ptag != PGP_PTAG_CT_USER_ATTR)) {
        RNP_LOG("wrong uid ptag: %d", ptag);
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((ret = stream_parse_userid(src, &uid->uid))) {
        return ret;
    }

    if ((ret = process_pgp_key_trusts(src))) {
        return ret;
    }

    return process_pgp_key_signatures(src, &uid->signatures);
}

rnp_result_t
process_pgp_subkey(pgp_source_t *src, pgp_transferable_subkey_t *subkey)
{
    int          ptag;
    rnp_result_t ret = RNP_ERROR_BAD_FORMAT;

    if (!is_subkey_pkt(ptag = stream_pkt_type(src))) {
        RNP_LOG("wrong subkey ptag: %d", ptag);
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((ret = stream_parse_key(src, &subkey->subkey))) {
        RNP_LOG("failed to parse subkey");
        return ret;
    }

    if ((ret = process_pgp_key_trusts(src))) {
        return ret;
    }

    return process_pgp_key_signatures(src, &subkey->signatures);
}

rnp_result_t
process_pgp_keys(pgp_source_t *src, pgp_key_sequence_t *keys)
{
    int                     ptag;
    bool                    armored = false;
    pgp_source_t            armorsrc = {0};
    bool                    has_secret = false;
    bool                    has_public = false;
    pgp_transferable_key_t *curkey = NULL;
    rnp_result_t            ret = RNP_ERROR_GENERIC;

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
        ptag = stream_pkt_type(src);

        if ((ptag < 0) || !is_primary_key_pkt(ptag)) {
            RNP_LOG("wrong key tag: %d", ptag);
            ret = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }

        if (!(curkey =
                (pgp_transferable_key_t *) list_append(&keys->keys, NULL, sizeof(*curkey)))) {
            RNP_LOG("key alloc failed");
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto finish;
        }

        if ((ret = process_pgp_key(src, curkey))) {
            goto finish;
        }

        has_secret |= (ptag == PGP_PTAG_CT_SECRET_KEY);
        has_public |= (ptag == PGP_PTAG_CT_PUBLIC_KEY);
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

rnp_result_t
process_pgp_key(pgp_source_t *src, pgp_transferable_key_t *key)
{
    pgp_source_t armorsrc = {0};
    bool         armored = false;
    int          ptag;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    memset(key, 0, sizeof(*key));

    /* check whether keys are armored */
    if (is_armored_source(src)) {
        if ((ret = init_armored_src(&armorsrc, src))) {
            RNP_LOG("failed to parse armored data");
            return ret;
        }
        armored = true;
        src = &armorsrc;
    }

    /* main key packet */
    ptag = stream_pkt_type(src);
    if ((ptag <= 0) || !is_primary_key_pkt(ptag)) {
        RNP_LOG("wrong key packet tag: %d", ptag);
        ret = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }

    if ((ret = stream_parse_key(src, &key->key))) {
        RNP_LOG("failed to parse key pkt");
        goto finish;
    }

    if ((ret = process_pgp_key_trusts(src))) {
        goto finish;
    }

    /* direct-key signatures */
    if ((ret = process_pgp_key_signatures(src, &key->signatures))) {
        RNP_LOG("failed to parse key sigs");
        goto finish;
    }

    /* user ids/attrs with signatures */
    while ((ptag = stream_pkt_type(src))) {
        if ((ptag != PGP_PTAG_CT_USER_ID) && (ptag != PGP_PTAG_CT_USER_ATTR)) {
            break;
        }

        pgp_transferable_userid_t *uid =
          (pgp_transferable_userid_t *) list_append(&key->userids, NULL, sizeof(*uid));
        if (!uid) {
            RNP_LOG("uid alloc failed");
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto finish;
        }

        if ((ret = process_pgp_key_userid(src, uid))) {
            goto finish;
        }
    }

    /* subkeys with signatures */
    while ((ptag = stream_pkt_type(src))) {
        if (!is_subkey_pkt(ptag)) {
            break;
        }

        pgp_transferable_subkey_t *subkey =
          (pgp_transferable_subkey_t *) list_append(&key->subkeys, NULL, sizeof(*subkey));
        if (!subkey) {
            RNP_LOG("subkey alloc failed");
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto finish;
        }

        if ((ret = process_pgp_subkey(src, subkey))) {
            goto finish;
        }
    }

    ret = ptag >= 0 ? RNP_SUCCESS : RNP_ERROR_BAD_FORMAT;
finish:
    if (armored) {
        src_close(&armorsrc);
    }
    if (ret) {
        transferable_key_destroy(key);
    }
    return ret;
}

static bool
write_pgp_signatures(list signatures, pgp_dest_t *dst)
{
    for (list_item *sig = list_front(signatures); sig; sig = list_next(sig)) {
        if (!stream_write_signature((pgp_signature_t *) sig, dst)) {
            return false;
        }
    }

    return true;
}

rnp_result_t
write_pgp_keys(pgp_key_sequence_t *keys, pgp_dest_t *dst, bool armor)
{
    pgp_dest_t   armdst = {0};
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (armor) {
        pgp_armored_msg_t       msgtype = PGP_ARMORED_PUBLIC_KEY;
        pgp_transferable_key_t *fkey = (pgp_transferable_key_t *) list_front(keys->keys);
        if (fkey && is_secret_key_pkt(fkey->key.tag)) {
            msgtype = PGP_ARMORED_SECRET_KEY;
        }

        if ((ret = init_armored_dst(&armdst, dst, msgtype))) {
            return ret;
        }
        dst = &armdst;
    }

    for (list_item *li = list_front(keys->keys); li; li = list_next(li)) {
        pgp_transferable_key_t *key = (pgp_transferable_key_t *) li;

        /* main key */
        if (!stream_write_key(&key->key, dst)) {
            ret = RNP_ERROR_WRITE;
            goto finish;
        }
        /* revocation signatures */
        if (!write_pgp_signatures(key->signatures, dst)) {
            ret = RNP_ERROR_WRITE;
            goto finish;
        }
        /* user ids/attrs and signatures */
        for (list_item *li = list_front(key->userids); li; li = list_next(li)) {
            pgp_transferable_userid_t *uid = (pgp_transferable_userid_t *) li;

            if (!stream_write_userid(&uid->uid, dst) ||
                !write_pgp_signatures(uid->signatures, dst)) {
                ret = RNP_ERROR_WRITE;
                goto finish;
            }
        }
        /* subkeys with signatures */
        for (list_item *li = list_front(key->subkeys); li; li = list_next(li)) {
            pgp_transferable_subkey_t *skey = (pgp_transferable_subkey_t *) li;

            if (!stream_write_key(&skey->subkey, dst) ||
                !write_pgp_signatures(skey->signatures, dst)) {
                ret = RNP_ERROR_WRITE;
                goto finish;
            }
        }
    }

    ret = RNP_SUCCESS;

finish:
    if (armor) {
        dst_close(&armdst, ret);
    }

    return ret;
}

rnp_result_t
write_pgp_key(pgp_transferable_key_t *key, pgp_dest_t *dst, bool armor)
{
    pgp_key_sequence_t keys = {0};
    rnp_result_t       ret = RNP_ERROR_GENERIC;

    if (!list_append(&keys.keys, key, sizeof(*key))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    ret = write_pgp_keys(&keys, dst, armor);
    list_destroy(&keys.keys);
    return ret;
}

static rnp_result_t
decrypt_secret_key_v3(pgp_crypt_t *crypt, uint8_t *dec, const uint8_t *enc, size_t len)
{
    size_t idx;
    size_t pos = 0;
    size_t mpilen;
    size_t blsize;

    if (!(blsize = pgp_cipher_block_size(crypt))) {
        RNP_LOG("wrong crypto");
        return RNP_ERROR_BAD_STATE;
    }

    /* 4 RSA secret mpis with cleartext header */
    for (idx = 0; idx < 4; idx++) {
        if (pos + 2 > len) {
            RNP_LOG("bad v3 secret key data");
            return RNP_ERROR_BAD_FORMAT;
        }
        mpilen = (read_uint16(enc + pos) + 7) >> 3;
        memcpy(dec + pos, enc + pos, 2);
        pos += 2;
        if (pos + mpilen > len) {
            RNP_LOG("bad v3 secret key data");
            return RNP_ERROR_BAD_FORMAT;
        }
        pgp_cipher_cfb_decrypt(crypt, dec + pos, enc + pos, mpilen);
        pos += mpilen;
        if (mpilen < blsize) {
            RNP_LOG("bad rsa v3 mpi len");
            return RNP_ERROR_BAD_FORMAT;
        }
        pgp_cipher_cfb_resync(crypt, enc + pos - blsize);
    }

    /* sum16 */
    if (pos + 2 != len) {
        return RNP_ERROR_BAD_FORMAT;
    }
    memcpy(dec + pos, enc + pos, 2);
    return RNP_SUCCESS;
}

static rnp_result_t
parse_secret_key_mpis(pgp_key_pkt_t *key, const uint8_t *mpis, size_t len)
{
    pgp_packet_body_t body;
    bool              res;

    /* check the cleartext data */
    switch (key->sec_protection.s2k.usage) {
    case PGP_S2KU_NONE:
    case PGP_S2KU_ENCRYPTED: {
        /* calculate and check sum16 of the cleartext */
        uint16_t sum = 0;
        size_t   idx;

        len -= 2;
        for (idx = 0; idx < len; idx++) {
            sum += mpis[idx];
        }
        if (sum != read_uint16(mpis + len)) {
            RNP_LOG("wrong key checksum");
            return RNP_ERROR_DECRYPT_FAILED;
        }
        break;
    }
    case PGP_S2KU_ENCRYPTED_AND_HASHED: {
        /* calculate and check sha1 hash of the cleartext */
        pgp_hash_t hash;
        uint8_t    hval[PGP_MAX_HASH_SIZE];

        if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
            return RNP_ERROR_BAD_STATE;
        }
        len -= PGP_SHA1_HASH_SIZE;
        pgp_hash_add(&hash, mpis, len);
        if (pgp_hash_finish(&hash, hval) != PGP_SHA1_HASH_SIZE) {
            return RNP_ERROR_BAD_STATE;
        }
        if (memcmp(hval, mpis + len, PGP_SHA1_HASH_SIZE)) {
            return RNP_ERROR_DECRYPT_FAILED;
        }
        break;
    }
    default:
        RNP_LOG("unknown s2k usage: %d", (int) key->sec_protection.s2k.usage);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* parse mpis depending on algorithm */
    packet_body_part_from_mem(&body, mpis, len);

    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        res = get_packet_body_mpi(&body, &key->material.rsa.d) &&
              get_packet_body_mpi(&body, &key->material.rsa.p) &&
              get_packet_body_mpi(&body, &key->material.rsa.q) &&
              get_packet_body_mpi(&body, &key->material.rsa.u);
        break;
    case PGP_PKA_DSA:
        res = get_packet_body_mpi(&body, &key->material.dsa.x);
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        res = get_packet_body_mpi(&body, &key->material.ec.x);
        break;
    case PGP_PKA_ELGAMAL:
        res = get_packet_body_mpi(&body, &key->material.eg.x);
        break;
    default:
        RNP_LOG("uknown pk alg : %d", (int) key->alg);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!res) {
        RNP_LOG("failed to parse secret data");
        return RNP_ERROR_BAD_FORMAT;
    }

    if (body.pos < body.len) {
        RNP_LOG("extra data in sec key");
        return RNP_ERROR_BAD_FORMAT;
    }

    key->material.secret = true;

    return RNP_SUCCESS;
}

rnp_result_t
decrypt_secret_key(pgp_key_pkt_t *key, const char *password)
{
    size_t       keysize;
    uint8_t      keybuf[PGP_MAX_KEY_SIZE];
    uint8_t *    decdata = NULL;
    pgp_crypt_t  crypt;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (!key) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!is_secret_key_pkt(key->tag)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* check whether data is not encrypted */
    if (!key->sec_protection.s2k.usage) {
        return parse_secret_key_mpis(key, key->sec_data, key->sec_len);
    }
    /* data is encrypted */
    if (!password) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (key->sec_protection.cipher_mode != PGP_CIPHER_MODE_CFB) {
        RNP_LOG("unsupported secret key encryption mode");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    keysize = pgp_key_size(key->sec_protection.symm_alg);
    if (!keysize || !pgp_s2k_derive_key(&key->sec_protection.s2k, password, keybuf, keysize)) {
        RNP_LOG("failed to derive key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!(decdata = (uint8_t *) malloc(key->sec_len))) {
        RNP_LOG("allocation failed");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto finish;
    }

    if (!pgp_cipher_cfb_start(
          &crypt, key->sec_protection.symm_alg, keybuf, key->sec_protection.iv)) {
        RNP_LOG("failed to start cfb decryption");
        ret = RNP_ERROR_DECRYPT_FAILED;
        goto finish;
    }

    switch (key->version) {
    case PGP_V3:
        if (!is_rsa_key_alg(key->alg)) {
            RNP_LOG("non-RSA v3 key");
            ret = RNP_ERROR_BAD_PARAMETERS;
            break;
        }
        ret = decrypt_secret_key_v3(&crypt, decdata, key->sec_data, key->sec_len);
        break;
    case PGP_V4:
        pgp_cipher_cfb_decrypt(&crypt, decdata, key->sec_data, key->sec_len);
        ret = RNP_SUCCESS;
        break;
    default:
        ret = RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_cipher_cfb_finish(&crypt);
    if (ret) {
        goto finish;
    }

    ret = parse_secret_key_mpis(key, decdata, key->sec_len);
finish:
    pgp_forget(keybuf, sizeof(keybuf));
    if (decdata) {
        pgp_forget(decdata, key->sec_len);
        free(decdata);
    }
    return ret;
}

static bool
write_secret_key_mpis(pgp_packet_body_t *body, pgp_key_pkt_t *key)
{
    pgp_hash_t hash;
    uint8_t    hval[PGP_MAX_HASH_SIZE];
    bool       res = false;

    /* add mpis */
    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        res = add_packet_body_mpi(body, &key->material.rsa.d) &&
              add_packet_body_mpi(body, &key->material.rsa.p) &&
              add_packet_body_mpi(body, &key->material.rsa.q) &&
              add_packet_body_mpi(body, &key->material.rsa.u);
        break;
    case PGP_PKA_DSA:
        res = add_packet_body_mpi(body, &key->material.dsa.x);
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        res = add_packet_body_mpi(body, &key->material.ec.x);
        break;
    case PGP_PKA_ELGAMAL:
        res = add_packet_body_mpi(body, &key->material.eg.x);
        break;
    default:
        RNP_LOG("uknown pk alg : %d", (int) key->alg);
        return false;
    }

    if (!res) {
        return false;
    }

    /* add sum16 if sha1 is not used */
    if (key->sec_protection.s2k.usage != PGP_S2KU_ENCRYPTED_AND_HASHED) {
        uint16_t sum = 0;
        for (size_t i = 0; i < body->len; i++) {
            sum += body->data[i];
        }
        return add_packet_body_uint16(body, sum);
    }

    /* add sha1 hash */
    if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
        RNP_LOG("failed to create sha1 hash");
        return false;
    }
    pgp_hash_add(&hash, body->data, body->len);
    if (pgp_hash_finish(&hash, hval) != PGP_SHA1_HASH_SIZE) {
        RNP_LOG("failed to finish hash");
        return false;
    }
    return add_packet_body(body, hval, PGP_SHA1_HASH_SIZE);
}

rnp_result_t
encrypt_secret_key(pgp_key_pkt_t *key, const char *password, rng_t *rng)
{
    pgp_packet_body_t body;
    uint8_t           keybuf[PGP_MAX_KEY_SIZE];
    size_t            keysize;
    size_t            blsize;
    pgp_crypt_t       crypt;
    rnp_result_t      ret = RNP_ERROR_GENERIC;

    if (!is_secret_key_pkt(key->tag) || !key->material.secret) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (key->sec_protection.s2k.usage &&
        (key->sec_protection.cipher_mode != PGP_CIPHER_MODE_CFB)) {
        RNP_LOG("unsupported secret key encryption mode");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* build secret key data */
    if (!init_packet_body(&body, 0)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!write_secret_key_mpis(&body, key)) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto error;
    }
    /* check whether data is not encrypted */
    if (key->sec_protection.s2k.usage == PGP_S2KU_NONE) {
        free(key->sec_data);
        key->sec_data = body.data;
        key->sec_len = body.len;
        return RNP_SUCCESS;
    }
    /* data is encrypted */
    keysize = pgp_key_size(key->sec_protection.symm_alg);
    blsize = pgp_block_size(key->sec_protection.symm_alg);
    if (!keysize || !blsize) {
        RNP_LOG("wrong symm alg");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto error;
    }
    /* generate iv and s2k salt */
    if (rng) {
        if (!rng_get_data(rng, key->sec_protection.iv, blsize)) {
            ret = RNP_ERROR_RNG;
            goto error;
        }
        if ((key->sec_protection.s2k.specifier != PGP_S2KS_SIMPLE) &&
            !rng_get_data(rng, key->sec_protection.s2k.salt, PGP_SALT_SIZE)) {
            ret = RNP_ERROR_RNG;
            goto error;
        }
    } else {
        /* temporary solution! */
        if (!rng_generate(key->sec_protection.iv, blsize)) {
            ret = RNP_ERROR_RNG;
            goto error;
        }
        if ((key->sec_protection.s2k.specifier != PGP_S2KS_SIMPLE) &&
            !rng_generate(key->sec_protection.s2k.salt, PGP_SALT_SIZE)) {
            ret = RNP_ERROR_RNG;
            goto error;
        }
    }
    /* derive key */
    if (!pgp_s2k_derive_key(&key->sec_protection.s2k, password, keybuf, keysize)) {
        RNP_LOG("failed to derive key");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto error;
    }
    /* encrypt sec data */
    if (key->version < PGP_V4) {
        RNP_LOG("encryption of v3 keys is not supported");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto error;
    }
    if (!pgp_cipher_cfb_start(
          &crypt, key->sec_protection.symm_alg, keybuf, key->sec_protection.iv)) {
        RNP_LOG("failed to start cfb encryption");
        ret = RNP_ERROR_DECRYPT_FAILED;
        goto error;
    }
    pgp_cipher_cfb_encrypt(&crypt, body.data, body.data, body.len);
    pgp_cipher_cfb_finish(&crypt);
    free(key->sec_data);
    key->sec_data = body.data;
    key->sec_len = body.len;
    /* cleanup cleartext fields */
    forget_secret_key_fields(&key->material);
    return RNP_SUCCESS;
error:
    pgp_forget(keybuf, sizeof(keybuf));
    pgp_forget(body.data, body.len);
    free_packet_body(&body);
    return ret;
}

void
forget_secret_key_fields(pgp_key_material_t *key)
{
    if (!key || !key->secret) {
        return;
    }

    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        mpi_forget(&key->rsa.d);
        mpi_forget(&key->rsa.p);
        mpi_forget(&key->rsa.q);
        mpi_forget(&key->rsa.u);
        break;
    case PGP_PKA_DSA:
        mpi_forget(&key->dsa.x);
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        mpi_forget(&key->eg.x);
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        mpi_forget(&key->ec.x);
        break;
    default:
        RNP_LOG("unknown key algorithm: %d", (int) key->alg);
    }

    key->secret = false;
}

/* internally used struct to pass parameters to functions */
typedef struct validate_info_t {
    pgp_signatures_info_t *result;
    const rnp_key_store_t *keystore;
    pgp_key_pkt_t *        key;
    pgp_key_pkt_t *        subkey;
    pgp_userid_pkt_t *     uid;
    rng_t *                rng;
} validate_info_t;

static rnp_result_t
validate_pgp_key_signature(const pgp_signature_t *sig, validate_info_t *info)
{
    rnp_result_t         res = RNP_ERROR_SIGNATURE_INVALID;
    uint8_t              signer_id[PGP_KEY_ID_SIZE] = {0};
    pgp_io_t             io = {.outs = stdout, .errs = stderr, .res = stdout};
    pgp_signature_info_t sinfo = {0};

    if (!signature_get_keyid(sig, signer_id)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    sinfo.signer = rnp_key_store_get_key_by_id(&io, info->keystore, signer_id, NULL);
    if (!sinfo.signer) {
        sinfo.no_signer = true;
        goto done;
    }
    if (!pgp_key_can_sign(sinfo.signer)) {
        RNP_LOG("WARNING: signature made with key that can not sign");
    }

    switch (sig->type) {
    case PGP_CERT_GENERIC:
    case PGP_CERT_PERSONA:
    case PGP_CERT_CASUAL:
    case PGP_CERT_POSITIVE:
    case PGP_SIG_REV_CERT: {
        if (!info->key || !info->uid || info->subkey) {
            RNP_LOG("wrong certification parameters");
            res = RNP_ERROR_SIGNATURE_INVALID;
            break;
        }
        res = signature_validate_certification(
          sig, info->key, info->uid, pgp_get_key_material(sinfo.signer), info->rng);
        break;
    }
    case PGP_SIG_SUBKEY:
        if (!info->key || info->uid || !info->subkey) {
            RNP_LOG("wrong binding parameters");
            res = RNP_ERROR_SIGNATURE_INVALID;
            break;
        }

        /* subkey binding always uses main key's material */
        res = signature_validate_binding(sig, info->key, info->subkey, info->rng);
        break;
    case PGP_SIG_DIRECT:
        if (!info->key || info->uid || info->subkey) {
            RNP_LOG("wrong direct sig parameters");
            res = RNP_ERROR_SIGNATURE_INVALID;
            break;
        }
        res = signature_validate_direct(
          sig, info->key, pgp_get_key_material(sinfo.signer), info->rng);
        break;
    case PGP_SIG_STANDALONE:
    case PGP_SIG_PRIMARY:
    case PGP_SIG_REV_KEY:
    case PGP_SIG_REV_SUBKEY:
    case PGP_SIG_TIMESTAMP:
    case PGP_SIG_3RD_PARTY:
        RNP_LOG("signature type %d verification is not supported yet", (int) sig->type);
        res = RNP_ERROR_SIGNATURE_INVALID;
        break;
    default:
        RNP_LOG("unexpected signature type %d", (int) sig->type);
        res = RNP_ERROR_SIGNATURE_INVALID;
    }

    sinfo.valid = !res;
    if (sinfo.valid) {
        /* for valid signature we check creation/expiration time */
        uint32_t now = time(NULL);
        uint32_t creation = signature_get_creation(sig);
        uint32_t expiration = signature_get_expiration(sig);

        if (creation && (creation > now)) {
            sinfo.expired = true;
            RNP_LOG("signature created in future");
        }
        if (creation && expiration && (creation + expiration <= now)) {
            sinfo.expired = true;
            RNP_LOG("signature expired");
        }
    }

done:
    if (!(sinfo.sig = (pgp_signature_t *) calloc(1, sizeof(*sig)))) {
        RNP_LOG("sig alloc failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!copy_signature_packet(sinfo.sig, sig)) {
        free(sinfo.sig);
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!list_append(&info->result->sigs, &sinfo, sizeof(sinfo))) {
        free_signature(sinfo.sig);
        free(sinfo.sig);
        RNP_LOG("failed to add signature to the list");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (sinfo.no_signer) {
        info->result->unknownc++;
    } else if (sinfo.expired) {
        info->result->expiredc++;
    } else if (sinfo.valid) {
        info->result->validc++;
    } else {
        RNP_LOG("bad signature");
        info->result->invalidc++;
    }

    return RNP_SUCCESS;
}

static rnp_result_t
validate_pgp_key_signature_list(list sigs, validate_info_t *info)
{
    rnp_result_t res = RNP_SUCCESS;

    for (list_item *s = list_front(sigs); s; s = list_next(s)) {
        if ((res = validate_pgp_key_signature((pgp_signature_t *) s, info))) {
            return res;
        }
    }

    return RNP_SUCCESS;
}

rnp_result_t
validate_pgp_key_signatures(pgp_signatures_info_t *result,
                            const pgp_key_t *      key,
                            const rnp_key_store_t *keyring)
{
    pgp_source_t           src = {0};
    pgp_dest_t             dst = {0};
    pgp_transferable_key_t tkey = {{0}};
    rnp_result_t           res = RNP_ERROR_GENERIC;
    validate_info_t        info = {0};
    rng_t                  rng = {0};

    /* write raw key packets to the memory and load transferable key */
    if ((res = init_mem_dest(&dst, NULL, 0))) {
        return res;
    }

    for (unsigned i = 0; i < key->packetc; i++) {
        dst_write(&dst, key->packets[i].raw, key->packets[i].length);
    }

    if ((res = init_mem_src(&src, mem_dest_own_memory(&dst), dst.writeb, true))) {
        dst_close(&dst, true);
        return res;
    }

    dst_close(&dst, false);
    res = process_pgp_key(&src, &tkey);
    src_close(&src);
    if (res) {
        return res;
    }

    if (!rng_init(&rng, RNG_SYSTEM)) {
        res = RNP_ERROR_RNG;
        goto done;
    }
    info.rng = &rng;
    info.result = result;
    info.keystore = keyring;

    /* validate direct-key signatures */
    info.key = &tkey.key;
    info.uid = NULL;
    info.subkey = NULL;
    if ((res = validate_pgp_key_signature_list(tkey.signatures, &info))) {
        goto done;
    }

    /* validate certifications */
    for (list_item *uid = list_front(tkey.userids); uid; uid = list_next(uid)) {
        pgp_transferable_userid_t *tuid = (pgp_transferable_userid_t *) uid;
        info.uid = &tuid->uid;
        if ((res = validate_pgp_key_signature_list(tuid->signatures, &info))) {
            goto done;
        }
    }

    /* validate subkey signatures */
    info.uid = NULL;
    for (list_item *sk = list_front(tkey.subkeys); sk; sk = list_next(sk)) {
        pgp_transferable_subkey_t *skey = (pgp_transferable_subkey_t *) sk;
        info.subkey = &skey->subkey;
        if ((res = validate_pgp_key_signature_list(skey->signatures, &info))) {
            goto done;
        }
    }

done:
    transferable_key_destroy(&tkey);
    rng_destroy(&rng);
    return res;
}
