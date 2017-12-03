/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
#include "stream-write.h"
#include "stream-packet.h"
#include "stream-armor.h"
#include "list.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#include <rnp/rnp_def.h>
#include "pgp-key.h"
#include "fingerprint.h"
#include "defs.h"
#include "types.h"
#include "symmetric.h"
#include "signature.h"
#include "crypto/s2k.h"
#include "crypto/sm2.h"
#include "crypto.h"
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

/* 8192 bytes, as GnuPG */
#define PARTIAL_PKT_SIZE_BITS (13)
#define PARTIAL_PKT_BLOCK_SIZE (1 << PARTIAL_PKT_SIZE_BITS)

/* common fields for encrypted, compressed and literal data */
typedef struct pgp_dest_packet_param_t {
    pgp_dest_t *writedst;      /* destination to write to, could be partial */
    pgp_dest_t *origdst;       /* original dest passed to init_*_dst */
    bool        partial;       /* partial length packet */
    bool        indeterminate; /* indeterminate length packet */
    int         tag;           /* packet tag */
} pgp_dest_packet_param_t;

typedef struct pgp_dest_compressed_param_t {
    pgp_dest_packet_param_t pkt;
    pgp_compression_type_t  alg;
    union {
        z_stream  z;
        bz_stream bz;
    };
    bool    zstarted;                        /* whether we initialize zlib/bzip2  */
    uint8_t cache[PGP_INPUT_CACHE_SIZE / 2]; /* pre-allocated cache for compression */
    size_t  len;                             /* number of bytes cached */
} pgp_dest_compressed_param_t;

typedef struct pgp_dest_encrypted_param_t {
    pgp_dest_packet_param_t pkt;         /* underlying packet-related params */
    bool                    has_mdc;     /* encrypted with mdc, i.e. tag 18 */
    pgp_crypt_t             encrypt;     /* encrypting crypto */
    pgp_symm_alg_t          ealg;        /* encryption algorithm */
    pgp_hash_t              mdc;         /* mdc SHA1 hash */
    uint8_t cache[PGP_INPUT_CACHE_SIZE]; /* pre-allocated cache for encryption */
} pgp_dest_encrypted_param_t;

typedef struct pgp_dest_signed_param_t {
    pgp_dest_t *writedst;  /* destination to write to */
    rnp_ctx_t * ctx;       /* rnp operation context with additional parameters */
    list        onepasses; /* one-pass entries written to the stream begin */
    list        keys;      /* signing keys in the same order as onepasses (if any) */
    list        hashes;    /* hashes to pass raw data through and then sign */
} pgp_dest_signed_param_t;

typedef struct pgp_dest_partial_param_t {
    pgp_dest_t *writedst;
    uint8_t     part[PARTIAL_PKT_BLOCK_SIZE];
    uint8_t     parthdr; /* header byte for the current part */
    size_t      partlen; /* length of the current part, up to PARTIAL_PKT_BLOCK_SIZE */
    size_t      len;     /* bytes cached in part */
} pgp_dest_partial_param_t;

static rnp_result_t
partial_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    pgp_dest_partial_param_t *param = dst->param;
    int                       wrlen;

    if (!param) {
        RNP_LOG("wrong param");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (len > param->partlen - param->len) {
        /* we have full part - in block and in buf */
        wrlen = param->partlen - param->len;
        dst_write(param->writedst, &param->parthdr, 1);
        dst_write(param->writedst, param->part, param->len);
        dst_write(param->writedst, buf, wrlen);

        buf = (uint8_t *) buf + wrlen;
        len -= wrlen;
        param->len = 0;

        /* writing all full parts directly from buf */
        while (len >= param->partlen) {
            dst_write(param->writedst, &param->parthdr, 1);
            dst_write(param->writedst, buf, param->partlen);
            buf = (uint8_t *) buf + param->partlen;
            len -= param->partlen;
        }
    }

    /* caching rest of the buf */
    if (len > 0) {
        memcpy(&param->part[param->len], buf, len);
        param->len += len;
    }

    return RNP_SUCCESS;
}

static rnp_result_t
partial_dst_finish(pgp_dest_t *dst)
{
    pgp_dest_partial_param_t *param = dst->param;
    uint8_t                   hdr[5];
    int                       lenlen;

    lenlen = write_packet_len(hdr, param->len);
    dst_write(param->writedst, hdr, lenlen);
    dst_write(param->writedst, param->part, param->len);

    return param->writedst->werr;
}

static void
partial_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_partial_param_t *param = dst->param;

    if (!param) {
        return;
    }

    free(param);
    dst->param = NULL;
}

static rnp_result_t
init_partial_pkt_dst(pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_partial_param_t *param;

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = dst->param;
    param->writedst = writedst;
    param->partlen = PARTIAL_PKT_BLOCK_SIZE;
    param->parthdr = 0xE0 | PARTIAL_PKT_SIZE_BITS;
    dst->param = param;
    dst->write = partial_dst_write;
    dst->finish = partial_dst_finish;
    dst->close = partial_dst_close;
    dst->type = PGP_STREAM_PARLEN_PACKET;

    return RNP_SUCCESS;
}

/** @brief helper function for streamed packets (literal, encrypted and compressed).
 *  Allocates part len destination if needed and writes header
 **/
static bool
init_streamed_packet(pgp_dest_packet_param_t *param, pgp_dest_t *dst)
{
    rnp_result_t ret;
    uint8_t      bt;

    if (param->partial) {
        bt = param->tag | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
        dst_write(dst, &bt, 1);

        if ((param->writedst = calloc(1, sizeof(*param->writedst))) == NULL) {
            RNP_LOG("part len dest allocation failed");
            return false;
        }
        ret = init_partial_pkt_dst(param->writedst, dst);
        if (ret != RNP_SUCCESS) {
            free(param->writedst);
            param->writedst = NULL;
            return false;
        }
        param->origdst = dst;
    } else if (param->indeterminate) {
        if (param->tag > 0xf) {
            RNP_LOG("indeterminate tag > 0xf");
        }

        bt = ((param->tag & 0xf) << PGP_PTAG_OF_CONTENT_TAG_SHIFT) |
             PGP_PTAG_OLD_LEN_INDETERMINATE;
        dst_write(dst, &bt, 1);

        param->writedst = dst;
        param->origdst = dst;
    } else {
        RNP_LOG("wrong call");
        return false;
    }

    return true;
}

static rnp_result_t
finish_streamed_packet(pgp_dest_packet_param_t *param)
{
    return param->partial ? dst_finish(param->writedst) : RNP_SUCCESS;
}

static void
close_streamed_packet(pgp_dest_packet_param_t *param, bool discard)
{
    if (param->partial) {
        dst_close(param->writedst, discard);
        free(param->writedst);
        param->writedst = NULL;
    }
}

static rnp_result_t
encrypted_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    pgp_dest_encrypted_param_t *param = dst->param;
    size_t                      sz;

    if (!param) {
        RNP_LOG("wrong param");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (param->has_mdc) {
        pgp_hash_add(&param->mdc, buf, len);
    }

    while (len > 0) {
        sz = len > sizeof(param->cache) ? sizeof(param->cache) : len;
        pgp_cipher_cfb_encrypt(&param->encrypt, param->cache, buf, sz);
        dst_write(param->pkt.writedst, param->cache, sz);
        len -= sz;
        buf = (uint8_t *) buf + sz;
    }

    return RNP_SUCCESS;
}

static rnp_result_t
encrypted_dst_finish(pgp_dest_t *dst)
{
    uint8_t                     mdcbuf[MDC_V1_SIZE];
    pgp_dest_encrypted_param_t *param = dst->param;

    if (param->has_mdc) {
        mdcbuf[0] = MDC_PKT_TAG;
        mdcbuf[1] = MDC_V1_SIZE - 2;
        pgp_hash_add(&param->mdc, mdcbuf, 2);
        pgp_hash_finish(&param->mdc, &mdcbuf[2]);
        pgp_cipher_cfb_encrypt(&param->encrypt, mdcbuf, mdcbuf, MDC_V1_SIZE);
        dst_write(param->pkt.writedst, mdcbuf, MDC_V1_SIZE);
    }

    return finish_streamed_packet(&param->pkt);
}

static void
encrypted_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_encrypted_param_t *param = dst->param;

    if (!param) {
        return;
    }

    pgp_hash_finish(&param->mdc, NULL);
    pgp_cipher_finish(&param->encrypt);
    close_streamed_packet(&param->pkt, discard);
    free(param);
    dst->param = NULL;
}

static rnp_result_t
encrypted_add_recipient(pgp_write_handler_t *handler,
                        pgp_dest_t *         dst,
                        const char *         userid,
                        const uint8_t *      key,
                        const unsigned       keylen)
{
    pgp_key_request_ctx_t       keyctx = {0};
    pgp_key_t *                 userkey;
    pgp_pubkey_t *              pubkey;
    uint8_t                     enckey[PGP_MAX_KEY_SIZE + 3];
    unsigned                    checksum = 0;
    pgp_pk_sesskey_pkt_t        pkey = {0};
    pgp_dest_encrypted_param_t *param = dst->param;
    rnp_result_t                ret = RNP_ERROR_GENERIC;

    if (!handler->key_provider) {
        RNP_LOG("no key provider");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    keyctx.op = PGP_OP_ENCRYPT_SYM;
    keyctx.secret = false;
    keyctx.stype = PGP_KEY_SEARCH_USERID;
    keyctx.search.userid = userid;

    /* Get the key if any */
    if (!pgp_request_key(handler->key_provider, &keyctx, &userkey)) {
        RNP_LOG("key for recipient '%s' not found", userid);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* Use primary key if good for encryption, otherwise look in subkey list */
    if (pgp_key_can_encrypt(userkey)) {
        pubkey = &userkey->key.pubkey;
    } else {
        pgp_key_t *subkey = find_suitable_subkey(userkey, PGP_KF_ENCRYPT);
        if (!subkey) {
            return RNP_ERROR_NO_SUITABLE_KEY;
        }
        pubkey = &subkey->key.pubkey;
    }

    /* Fill pkey */
    pkey.version = PGP_PKSK_V3;
    pkey.alg = pubkey->alg;
    if (!pgp_keyid(pkey.key_id, PGP_KEY_ID_SIZE, pubkey)) {
        RNP_LOG("key id calculation failed");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* Encrypt the session key */
    enckey[0] = param->ealg;
    memcpy(&enckey[1], key, keylen);

    /* Calculate checksum */
    for (unsigned i = 1; i <= keylen; i++) {
        checksum += enckey[i];
    }
    enckey[keylen + 1] = (checksum >> 8) & 0xff;
    enckey[keylen + 2] = checksum & 0xff;

    switch (pubkey->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
        pkey.params.rsa.mlen = pgp_rsa_encrypt_pkcs1(rnp_ctx_rng_handle(handler->ctx),
                                                     pkey.params.rsa.m,
                                                     sizeof(pkey.params.rsa.m),
                                                     enckey,
                                                     keylen + 3,
                                                     &pubkey->key.rsa);
        if (pkey.params.rsa.mlen <= 0) {
            RNP_LOG("pgp_rsa_encrypt_pkcs1 failed");
            ret = RNP_ERROR_GENERIC;
            goto finish;
        }
        break;
    case PGP_PKA_SM2: {
        size_t outlen = sizeof(pkey.params.sm2.m);
        ret = pgp_sm2_encrypt(rnp_ctx_rng_handle(handler->ctx),
                              pkey.params.sm2.m,
                              &outlen,
                              enckey,
                              keylen + 3,
                              PGP_HASH_SM3,
                              &pubkey->key.ecc);

        if (ret != RNP_SUCCESS) {
            RNP_LOG("pgp_sm2_encrypt failed");
            goto finish;
        }

        pkey.params.sm2.mlen = outlen;

    } break;
    case PGP_PKA_ECDH: {
        pgp_fingerprint_t fingerprint;
        size_t            outlen = sizeof(pkey.params.ecdh.m);
        bignum_t *        p;

        if (!pgp_fingerprint(&fingerprint, pubkey)) {
            RNP_LOG("ECDH fingerprint calculation failed");
            ret = RNP_ERROR_GENERIC;
            goto finish;
        }

        if (!(p = bn_new())) {
            RNP_LOG("allocation failed");
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto finish;
        }

        ret = pgp_ecdh_encrypt_pkcs5(rnp_ctx_rng_handle(handler->ctx),
                                     enckey,
                                     keylen + 3,
                                     pkey.params.ecdh.m,
                                     &outlen,
                                     p,
                                     &pubkey->key.ecdh,
                                     &fingerprint);

        if (ret != RNP_SUCCESS) {
            RNP_LOG("ECDH encryption failed %d", ret);
            bn_free(p);
            goto finish;
        }

        pkey.params.ecdh.mlen = outlen;
        (void) bn_num_bytes(
          p,
          (size_t *) &pkey.params.ecdh.plen); // can't fail as pgp_ecdh_encrypt_pkcs5 succeded
        (void) bn_bn2bin(p, pkey.params.ecdh.p);
        bn_free(p);
    } break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN: {
        int outlen;

        outlen = pgp_elgamal_public_encrypt_pkcs1(rnp_ctx_rng_handle(handler->ctx),
                                                  pkey.params.eg.g,
                                                  pkey.params.eg.m,
                                                  enckey,
                                                  keylen + 3,
                                                  &pubkey->key.elgamal);
        if (outlen <= 0) {
            ret = RNP_ERROR_GENERIC;
            RNP_LOG("pgp_elgamal_public_encrypt failed");
            goto finish;
        }

        pkey.params.eg.glen = outlen / 2;
        pkey.params.eg.mlen = outlen / 2;
    } break;
    default:
        RNP_LOG("unsupported alg: %d", pubkey->alg);
        goto finish;
    }

    /* Writing symmetric key encrypted session key packet */
    if (!stream_write_pk_sesskey(&pkey, param->pkt.origdst)) {
        ret = RNP_ERROR_WRITE;
        goto finish;
    }

    ret = RNP_SUCCESS;
finish:
    pgp_forget(enckey, sizeof(enckey));
    pgp_forget(&checksum, sizeof(checksum));
    return ret;
}

static rnp_result_t
encrypted_add_password(rnp_symmetric_pass_info_t *pass,
                       pgp_dest_t *               dst,
                       uint8_t *                  key,
                       const unsigned             keylen,
                       bool                       singlepass)
{
    pgp_sk_sesskey_t            skey = {0};
    unsigned                    s2keylen; /* length of the s2k key */
    pgp_crypt_t                 kcrypt;
    pgp_dest_encrypted_param_t *param = dst->param;

    skey.version = PGP_SKSK_V4;
    /* Following algorithm may differ from ctx's one if not singlepass */
    skey.alg = param->ealg;
    if (singlepass) {
        s2keylen = keylen;
    } else if ((s2keylen = pgp_key_size(skey.alg)) == 0) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    skey.s2k = pass->s2k;

    if (singlepass) {
        /* if there are no public keys then we do not encrypt session key in the packet */
        skey.enckeylen = 0;
        memcpy(key, pass->key, s2keylen);
    } else {
        /* Currently we are using the same sym algo for key and stream encryption */
        skey.enckeylen = keylen + 1;
        skey.enckey[0] = param->ealg;
        memcpy(&skey.enckey[1], key, keylen);
        skey.alg = pass->s2k_cipher;
        if (!pgp_cipher_start(&kcrypt, skey.alg, pass->key, NULL)) {
            RNP_LOG("key encryption failed");
            return RNP_ERROR_BAD_PARAMETERS;
        }
        pgp_cipher_cfb_encrypt(&kcrypt, skey.enckey, skey.enckey, skey.enckeylen);
        pgp_cipher_finish(&kcrypt);
    }

    /* Writing symmetric key encrypted session key packet */
    if (!stream_write_sk_sesskey(&skey, param->pkt.origdst)) {
        return RNP_ERROR_WRITE;
    }
    return RNP_SUCCESS;
}
static rnp_result_t
init_encrypted_dst(pgp_write_handler_t *handler, pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_encrypted_param_t *param;
    bool                        singlepass = true;
    unsigned                    pkeycount = 0;
    uint8_t                     enckey[PGP_MAX_KEY_SIZE] = {0}; /* content encryption key */
    uint8_t                     enchdr[PGP_MAX_BLOCK_SIZE + 2]; /* encrypted header */
    uint8_t                     mdcver = 1;
    unsigned                    keylen;
    unsigned                    blsize;
    rnp_result_t                ret = RNP_ERROR_GENERIC;

    keylen = pgp_key_size(handler->ctx->ealg);
    if (!keylen) {
        RNP_LOG("unknown symmetric algorithm");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = dst->param;
    dst->write = encrypted_dst_write;
    dst->finish = encrypted_dst_finish;
    dst->close = encrypted_dst_close;
    dst->type = PGP_STREAM_ENCRYPTED;
    param->has_mdc = true;
    param->ealg = handler->ctx->ealg;
    param->pkt.origdst = writedst;

    pkeycount = list_length(handler->ctx->recipients);
    if ((pkeycount > 0) || (list_length(handler->ctx->passwords) > 1)) {
        if (!rng_get_data(rnp_ctx_rng_handle(handler->ctx), enckey, keylen)) {
            ret = RNP_ERROR_RNG;
            goto finish;
        }
        singlepass = false;
    }

    /* Configuring and writing pk-encrypted session keys */
    if (pkeycount > 0) {
        for (list_item *id = list_front(handler->ctx->recipients); id; id = list_next(id)) {
            ret = encrypted_add_recipient(handler, dst, (char *) id, enckey, keylen);
            if (ret != RNP_SUCCESS) {
                goto finish;
            }
        }
    }

    /* Configuring and writing sk-encrypted session key(s) */
    for (list_item *pi = list_front(handler->ctx->passwords); pi; pi = list_next(pi)) {
        encrypted_add_password(
          (rnp_symmetric_pass_info_t *) pi, dst, enckey, keylen, singlepass);
    }

    /* Initializing partial packet writer */
    param->pkt.partial = true;
    param->pkt.indeterminate = false;
    param->pkt.tag = param->has_mdc ? PGP_PTAG_CT_SE_IP_DATA : PGP_PTAG_CT_SE_DATA;

    /* initializing partial data length writer */
    /* we may use intederminate len packet here as well, for compatibility or so on */
    if (!init_streamed_packet(&param->pkt, writedst)) {
        RNP_LOG("failed to init streamed packet");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* initializing the mdc */
    if (param->has_mdc) {
        dst_write(param->pkt.writedst, &mdcver, 1);

        if (!pgp_hash_create(&param->mdc, PGP_HASH_SHA1)) {
            RNP_LOG("cannot create sha1 hash");
            ret = RNP_ERROR_GENERIC;
            goto finish;
        }
    }

    /* initializing the crypto */
    if (!pgp_cipher_start(&param->encrypt, param->ealg, enckey, NULL)) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* generating and writing iv/password check bytes */
    blsize = pgp_block_size(param->ealg);
    if (!rng_get_data(rnp_ctx_rng_handle(handler->ctx), enchdr, blsize)) {
        ret = RNP_ERROR_RNG;
        goto finish;
    }

    enchdr[blsize] = enchdr[blsize - 2];
    enchdr[blsize + 1] = enchdr[blsize - 1];
    if (param->has_mdc) {
        pgp_hash_add(&param->mdc, enchdr, blsize + 2);
    }
    pgp_cipher_cfb_encrypt(&param->encrypt, enchdr, enchdr, blsize + 2);
    /* RFC 4880, 5.13: Unlike the Symmetrically Encrypted Data Packet, no special CFB
     * resynchronization is done after encrypting this prefix data. */
    if (!param->has_mdc) {
        pgp_cipher_cfb_resync(&param->encrypt, enchdr + 2);
    }
    dst_write(param->pkt.writedst, enchdr, blsize + 2);

    ret = RNP_SUCCESS;
finish:
    for (list_item *pi = list_front(handler->ctx->passwords); pi; pi = list_next(pi)) {
        rnp_symmetric_pass_info_t *pass = (rnp_symmetric_pass_info_t *) pi;
        pgp_forget(pass, sizeof(*pass));
    }
    list_destroy(&handler->ctx->passwords);
    pgp_forget(enckey, sizeof(enckey));
    if (ret != RNP_SUCCESS) {
        encrypted_dst_close(dst, true);
    }

    return ret;
}

static rnp_result_t
signed_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    pgp_dest_signed_param_t *param = dst->param;
    dst_write(param->writedst, buf, len);
    return RNP_SUCCESS;
}

static rnp_result_t
signed_add_signature(pgp_dest_signed_param_t *param, pgp_signature_t *sig, pgp_key_t *seckey)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

static rnp_result_t
signed_dst_finish(pgp_dest_t *dst)
{
    pgp_signature_t          sig;
    rnp_result_t             ret;
    pgp_dest_signed_param_t *param = dst->param;

    for (list_item *op = list_back(param->onepasses), *key = list_back(param->keys); op && key;
         op = list_prev(op), key = list_prev(key)) {
        memset(&sig, 0, sizeof(sig));
        sig.halg = ((pgp_one_pass_sig_t *) op)->halg;
        sig.palg = ((pgp_one_pass_sig_t *) op)->palg;
        sig.type = ((pgp_one_pass_sig_t *) op)->type;
        sig.version = 4;

        if ((ret = signed_add_signature(param, &sig, (pgp_key_t *) key))) {
            return ret;
        }
    }

    return RNP_SUCCESS;
}

static void
signed_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_signed_param_t *param = dst->param;

    if (!param) {
        return;
    }

    pgp_hash_list_free(&param->hashes);
    list_destroy(&param->onepasses);
    list_destroy(&param->keys);

    free(param);
    dst->param = NULL;
}

static void
signed_dst_update(pgp_dest_t *dst, const void *buf, size_t len)
{
    pgp_dest_signed_param_t *param = dst->param;
    pgp_hash_list_update(param->hashes, buf, len);
}

static rnp_result_t
signed_add_one_pass(pgp_dest_signed_param_t *param, pgp_key_t *key, bool last)
{
    pgp_one_pass_sig_t onepass = {0};
    pgp_hash_alg_t     halg;

    /* Add hash to the list */
    halg = pgp_pick_hash_alg(param->ctx, &key->key.seckey);
    if (!pgp_hash_list_add(&param->hashes, halg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    onepass.version = 3;
    onepass.type = PGP_SIG_BINARY;
    onepass.halg = halg;
    onepass.palg = key->key.pubkey.alg;
    memcpy(onepass.keyid, key->keyid, PGP_KEY_ID_SIZE);
    onepass.nested = !!last;

    if (!stream_write_one_pass(&onepass, param->writedst)) {
        return RNP_ERROR_WRITE;
    }

    if (!list_append(&param->onepasses, &onepass, sizeof(onepass)) ||
        !list_append(&param->keys, &key, sizeof(key))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    return RNP_SUCCESS;
}

static rnp_result_t
init_signed_dst(pgp_write_handler_t *handler, pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_signed_param_t *param;
    rnp_result_t             ret = RNP_ERROR_GENERIC;
    pgp_key_t *              key = NULL;
    pgp_key_request_ctx_t    keyctx = {
      .op = PGP_OP_SIGN, .secret = true, .stype = PGP_KEY_SEARCH_USERID};

    if (!handler->key_provider) {
        RNP_LOG("no key provider");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = dst->param;
    param->writedst = writedst;
    param->ctx = handler->ctx;
    dst->write = signed_dst_write;
    dst->finish = signed_dst_finish;
    dst->close = signed_dst_close;
    dst->type = PGP_STREAM_SIGNED;

    /* writing one-pass signatures */
    for (list_item *sg = list_front(handler->ctx->signers); sg; sg = list_next(sg)) {
        keyctx.search.userid = (char *) sg;
        if (!pgp_request_key(handler->key_provider, &keyctx, &key)) {
            RNP_LOG("signer's key not found: %s", (char *) sg);
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto finish;
        }

        ret = signed_add_one_pass(param, key, sg == list_back(handler->ctx->signers));
        if (ret) {
            RNP_LOG("failed to add signer %s", (char *) sg);
            goto finish;
        }
    }

    ret = RNP_SUCCESS;
finish:
    if (ret != RNP_SUCCESS) {
        signed_dst_close(dst, true);
    }

    return ret;
}

static rnp_result_t
compressed_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    pgp_dest_compressed_param_t *param = dst->param;
    int                          zret;

    if (!param) {
        RNP_LOG("wrong param");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if ((param->alg == PGP_C_ZIP) || (param->alg == PGP_C_ZLIB)) {
        param->z.next_in = (unsigned char *) buf;
        param->z.avail_in = len;
        param->z.next_out = param->cache + param->len;
        param->z.avail_out = sizeof(param->cache) - param->len;

        while (param->z.avail_in > 0) {
            zret = deflate(&param->z, Z_NO_FLUSH);
            /* Z_OK, Z_BUF_ERROR are ok for us, Z_STREAM_END will not happen here */
            if (zret == Z_STREAM_ERROR) {
                RNP_LOG("wrong deflate state");
                return RNP_ERROR_BAD_STATE;
            }

            /* writing only full blocks, the rest will be written in close */
            if (param->z.avail_out == 0) {
                dst_write(param->pkt.writedst, param->cache, sizeof(param->cache));
                param->len = 0;
                param->z.next_out = param->cache;
                param->z.avail_out = sizeof(param->cache);
            }
        }

        param->len = sizeof(param->cache) - param->z.avail_out;
        return RNP_SUCCESS;
    } else if (param->alg == PGP_C_BZIP2) {
#ifdef HAVE_BZLIB_H
        param->bz.next_in = (char *) buf;
        param->bz.avail_in = len;
        param->bz.next_out = (char *) (param->cache + param->len);
        param->bz.avail_out = sizeof(param->cache) - param->len;

        while (param->bz.avail_in > 0) {
            zret = BZ2_bzCompress(&param->bz, BZ_RUN);
            if (zret < 0) {
                RNP_LOG("error %d", zret);
                return RNP_ERROR_BAD_STATE;
            }

            /* writing only full blocks, the rest will be written in close */
            if (param->bz.avail_out == 0) {
                dst_write(param->pkt.writedst, param->cache, sizeof(param->cache));
                param->len = 0;
                param->bz.next_out = (char *) param->cache;
                param->bz.avail_out = sizeof(param->cache);
            }
        }

        param->len = sizeof(param->cache) - param->bz.avail_out;
        return RNP_SUCCESS;
#else
        return RNP_ERROR_NOT_IMPLEMENTED;
#endif
    } else {
        RNP_LOG("unknown algorithm");
        return RNP_ERROR_BAD_PARAMETERS;
    }
}

static rnp_result_t
compressed_dst_finish(pgp_dest_t *dst)
{
    int                          zret;
    pgp_dest_compressed_param_t *param = dst->param;

    if ((param->alg == PGP_C_ZIP) || (param->alg == PGP_C_ZLIB)) {
        param->z.next_in = Z_NULL;
        param->z.avail_in = 0;
        param->z.next_out = param->cache + param->len;
        param->z.avail_out = sizeof(param->cache) - param->len;
        do {
            zret = deflate(&param->z, Z_FINISH);

            if (zret == Z_STREAM_ERROR) {
                RNP_LOG("wrong deflate state");
                return RNP_ERROR_BAD_STATE;
            }

            if (param->z.avail_out == 0) {
                dst_write(param->pkt.writedst, param->cache, sizeof(param->cache));
                param->len = 0;
                param->z.next_out = param->cache;
                param->z.avail_out = sizeof(param->cache);
            }
        } while (zret != Z_STREAM_END);

        param->len = sizeof(param->cache) - param->z.avail_out;
        dst_write(param->pkt.writedst, param->cache, param->len);
    } else if (param->alg == PGP_C_BZIP2) {
#ifdef HAVE_BZLIB_H
        param->bz.next_in = NULL;
        param->bz.avail_in = 0;
        param->bz.next_out = (char *) (param->cache + param->len);
        param->bz.avail_out = sizeof(param->cache) - param->len;

        do {
            zret = BZ2_bzCompress(&param->bz, BZ_FINISH);
            if (zret < 0) {
                RNP_LOG("wrong bzip2 state %d", zret);
                return RNP_ERROR_BAD_STATE;
            }

            /* writing only full blocks, the rest will be written in close */
            if (param->bz.avail_out == 0) {
                dst_write(param->pkt.writedst, param->cache, sizeof(param->cache));
                param->len = 0;
                param->bz.next_out = (char *) param->cache;
                param->bz.avail_out = sizeof(param->cache);
            }
        } while (zret != BZ_STREAM_END);

        param->len = sizeof(param->cache) - param->bz.avail_out;
        dst_write(param->pkt.writedst, param->cache, param->len);
#endif
    }

    if (param->pkt.writedst->werr) {
        return param->pkt.writedst->werr;
    }

    return finish_streamed_packet(&param->pkt);
}

static void
compressed_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_compressed_param_t *param = dst->param;

    if (!param) {
        return;
    }

    if (param->zstarted) {
        if ((param->alg == PGP_C_ZIP) || (param->alg == PGP_C_ZLIB)) {
            deflateEnd(&param->z);
        } else if (param->alg == PGP_C_BZIP2) {
#ifdef HAVE_BZLIB_H
            BZ2_bzCompressEnd(&param->bz);
#endif
        }
    }

    close_streamed_packet(&param->pkt, discard);
    free(param);
    dst->param = NULL;
}

static rnp_result_t
init_compressed_dst(pgp_write_handler_t *handler, pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_compressed_param_t *param;
    rnp_result_t                 ret = RNP_ERROR_GENERIC;
    uint8_t                      buf;
    int                          zret;

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = dst->param;
    dst->write = compressed_dst_write;
    dst->finish = compressed_dst_finish;
    dst->close = compressed_dst_close;
    dst->type = PGP_STREAM_COMPRESSED;
    param->alg = handler->ctx->zalg;
    param->pkt.partial = true;
    param->pkt.indeterminate = false;
    param->pkt.tag = PGP_PTAG_CT_COMPRESSED;

    /* initializing partial length or indeterminate packet, writing header */
    if (!init_streamed_packet(&param->pkt, writedst)) {
        RNP_LOG("failed to init streamed packet");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* compression algorithm */
    buf = param->alg;
    dst_write(param->pkt.writedst, &buf, 1);

    /* initializing compression */
    switch (param->alg) {
    case PGP_C_ZIP:
    case PGP_C_ZLIB:
        (void) memset(&param->z, 0x0, sizeof(param->z));
        if (param->alg == PGP_C_ZIP) {
            zret = deflateInit2(
              &param->z, handler->ctx->zlevel, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
        } else {
            zret = deflateInit(&param->z, handler->ctx->zlevel);
        }

        if (zret != Z_OK) {
            RNP_LOG("failed to init zlib, error %d", zret);
            ret = RNP_ERROR_NOT_SUPPORTED;
            goto finish;
        }
        break;
#ifdef HAVE_BZLIB_H
    case PGP_C_BZIP2:
        (void) memset(&param->bz, 0x0, sizeof(param->bz));
        zret = BZ2_bzCompressInit(&param->bz, handler->ctx->zlevel, 0, 0);
        if (zret != BZ_OK) {
            RNP_LOG("failed to init bz, error %d", zret);
            ret = RNP_ERROR_NOT_SUPPORTED;
            goto finish;
        }
        break;
#endif
    default:
        RNP_LOG("unknown compression algorithm");
        ret = RNP_ERROR_NOT_SUPPORTED;
        goto finish;
    }
    param->zstarted = true;
    ret = RNP_SUCCESS;
finish:
    if (ret != RNP_SUCCESS) {
        compressed_dst_close(dst, true);
    }

    return ret;
}

static rnp_result_t
literal_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    pgp_dest_packet_param_t *param = dst->param;

    if (!param) {
        RNP_LOG("wrong param");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    dst_write(param->writedst, buf, len);
    return RNP_SUCCESS;
}

static rnp_result_t
literal_dst_finish(pgp_dest_t *dst)
{
    return finish_streamed_packet(dst->param);
}

static void
literal_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_packet_param_t *param = dst->param;

    if (!param) {
        return;
    }

    close_streamed_packet(param, discard);
    free(param);
    dst->param = NULL;
}

static rnp_result_t
init_literal_dst(pgp_write_handler_t *handler, pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_packet_param_t *param;
    rnp_result_t             ret = RNP_ERROR_GENERIC;
    int                      flen;
    uint8_t                  buf[4];

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = dst->param;
    dst->write = literal_dst_write;
    dst->finish = literal_dst_finish;
    dst->close = literal_dst_close;
    dst->type = PGP_STREAM_LITERAL;
    param->partial = true;
    param->indeterminate = false;
    param->tag = PGP_PTAG_CT_LITDATA;

    /* initializing partial length or indeterminate packet, writing header */
    if (!init_streamed_packet(param, writedst)) {
        RNP_LOG("failed to init streamed packet");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }
    /* content type - forcing binary now */
    buf[0] = (uint8_t) 'b';
    /* filename */
    if (handler->ctx->filename) {
        flen = strlen(handler->ctx->filename);
        if (flen > 255) {
            RNP_LOG("filename too long, truncating");
            flen = 255;
        }
    } else {
        flen = 0;
    }
    buf[1] = (uint8_t) flen;
    dst_write(param->writedst, buf, 2);
    if (flen > 0) {
        dst_write(param->writedst, handler->ctx->filename, flen);
    }
    /* timestamp */
    STORE32BE(buf, handler->ctx->filemtime);
    dst_write(param->writedst, buf, 4);
    ret = RNP_SUCCESS;
finish:
    if (ret != RNP_SUCCESS) {
        literal_dst_close(dst, true);
    }

    return ret;
}

rnp_result_t
rnp_encrypt_src(pgp_write_handler_t *handler, pgp_source_t *src, pgp_dest_t *dst)
{
    /* stack of the streams would be as following:
       [armoring stream] - if armoring is enabled
       encrypting stream, partial writing stream
       [compressing stream, partial writing stream] - if compression is enabled
       literal data stream, partial writing stream
    */
    uint8_t      readbuf[PGP_INPUT_CACHE_SIZE];
    ssize_t      read;
    pgp_dest_t   dests[4];
    int          destc = 0;
    rnp_result_t ret = RNP_ERROR_GENERIC;
    bool         discard;

    /* pushing armoring stream, which will write to the output */
    if (handler->ctx->armor) {
        if ((ret = init_armored_dst(&dests[destc], dst, PGP_ARMORED_MESSAGE))) {
            goto finish;
        }
        destc++;
    }

    /* pushing encrypting stream, which will write to the output or armoring stream */
    if ((ret = init_encrypted_dst(handler, &dests[destc], destc ? &dests[destc - 1] : dst))) {
        goto finish;
    }
    destc++;

    /* if compression is enabled then pushing compressing stream */
    if (handler->ctx->zlevel > 0) {
        if ((ret = init_compressed_dst(handler, &dests[destc], &dests[destc - 1]))) {
            goto finish;
        }
        destc++;
    }

    /* pushing literal data stream */
    if ((ret = init_literal_dst(handler, &dests[destc], &dests[destc - 1]))) {
        goto finish;
    }
    destc++;

    /* processing source stream */
    while (!src->eof) {
        read = src_read(src, readbuf, sizeof(readbuf));
        if (read < 0) {
            RNP_LOG("failed to read from source");
            ret = RNP_ERROR_READ;
            goto finish;
        }

        if (read > 0) {
            dst_write(&dests[destc - 1], readbuf, read);

            for (int i = destc - 1; i >= 0; i--) {
                if (dests[i].werr != RNP_SUCCESS) {
                    RNP_LOG("failed to process data");
                    ret = RNP_ERROR_WRITE;
                    goto finish;
                }
            }
        }
    }

    /* finalizing destinations */
    for (int i = destc - 1; i >= 0; i--) {
        ret = dst_finish(&dests[i]);
        if (ret != RNP_SUCCESS) {
            RNP_LOG("failed to finish stream");
            goto finish;
        }
    }

    ret = RNP_SUCCESS;
finish:
    discard = ret != RNP_SUCCESS;
    for (int i = destc - 1; i >= 0; i--) {
        dst_close(&dests[i], discard);
    }

    return ret;
}

rnp_result_t
rnp_sign_src(pgp_write_handler_t *handler, pgp_source_t *src, pgp_dest_t *dst)
{
    /* stack of the streams would be as following:
       [armoring stream] - if armoring is enabled
       [compressing stream, partial writing stream] - if compression is enabled
       signing stream
       literal data stream, partial writing stream
    */
    uint8_t      readbuf[PGP_INPUT_CACHE_SIZE];
    ssize_t      read;
    pgp_dest_t   dests[4];
    pgp_dest_t * signdst = NULL;
    int          destc = 0;
    rnp_result_t ret = RNP_SUCCESS;
    bool         discard;

    /* pushing armoring stream, which will write to the output */
    if (handler->ctx->armor) {
        ret = init_armored_dst(&dests[destc], dst, PGP_ARMORED_MESSAGE);
        if (ret != RNP_SUCCESS) {
            goto finish;
        }
        destc++;
    }

    /* if compression is enabled then pushing compressing stream */
    if (handler->ctx->zlevel > 0) {
        ret = init_compressed_dst(handler, &dests[destc], destc ? &dests[destc - 1] : dst);
        if (ret != RNP_SUCCESS) {
            goto finish;
        }
        destc++;
    }

    /* pushing signing stream, which will write to the output or previous compressed or
     * armoring stream */
    ret = init_signed_dst(handler, &dests[destc], destc ? &dests[destc - 1] : dst);
    if (ret != RNP_SUCCESS) {
        goto finish;
    }
    signdst = &dests[destc++];

    /* pushing literal data stream */
    ret = init_literal_dst(handler, &dests[destc], &dests[destc - 1]);
    if (ret != RNP_SUCCESS) {
        goto finish;
    }
    destc++;

    /* processing source stream */
    while (!src->eof) {
        read = src_read(src, readbuf, sizeof(readbuf));
        if (read < 0) {
            RNP_LOG("failed to read from source");
            ret = RNP_ERROR_READ;
            goto finish;
        }

        if (read > 0) {
            dst_write(&dests[destc - 1], readbuf, read);
            signed_dst_update(signdst, readbuf, read);

            for (int i = destc - 1; i >= 0; i--) {
                if (dests[i].werr != RNP_SUCCESS) {
                    RNP_LOG("failed to process data");
                    ret = RNP_ERROR_WRITE;
                    goto finish;
                }
            }
        }
    }

    /* finalizing destinations */
    for (int i = destc - 1; i >= 0; i--) {
        ret = dst_finish(&dests[i]);
        if (ret != RNP_SUCCESS) {
            RNP_LOG("failed to finish stream");
            goto finish;
        }
    }

finish:
    discard = ret != RNP_SUCCESS;
    for (int i = destc - 1; i >= 0; i--) {
        dst_close(&dests[i], discard);
    }

    return ret;
}
