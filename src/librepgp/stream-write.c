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
#include "stream-def.h"
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
#include "crypto/s2k.h"
#include "crypto/sm2.h"
#include "crypto/eddsa.h"
#include "crypto/ecdsa.h"
#include "crypto.h"
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

/* 8192 bytes, as GnuPG */
#define PGP_PARTIAL_PKT_SIZE_BITS (13)
#define PGP_PARTIAL_PKT_BLOCK_SIZE (1 << PGP_PARTIAL_PKT_SIZE_BITS)

/* common fields for encrypted, compressed and literal data */
typedef struct pgp_dest_packet_param_t {
    pgp_dest_t *writedst;                 /* destination to write to, could be partial */
    pgp_dest_t *origdst;                  /* original dest passed to init_*_dst */
    bool        partial;                  /* partial length packet */
    bool        indeterminate;            /* indeterminate length packet */
    int         tag;                      /* packet tag */
    uint8_t     hdr[PGP_MAX_HEADER_SIZE]; /* header, including length, as it was written */
    size_t      hdrlen;                   /* number of bytes in hdr */
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
    pgp_dest_packet_param_t pkt;     /* underlying packet-related params */
    rnp_ctx_t *             ctx;     /* rnp operation context with additional parameters */
    bool                    has_mdc; /* encrypted with mdc, i.e. tag 18 */
    bool                    aead;    /* we use AEAD encryption */
    pgp_crypt_t             encrypt; /* encrypting crypto */
    pgp_hash_t              mdc;     /* mdc SHA1 hash */
    pgp_aead_alg_t          aalg;    /* AEAD algorithm used */
    uint8_t                 iv[PGP_MAX_BLOCK_SIZE];  /* iv for AEAD mode */
    uint8_t                 ad[PGP_AEAD_MAX_AD_LEN]; /* additional data for AEAD mode */
    size_t                  adlen;    /* length of additional data, including chunk idx */
    size_t                  chunklen; /* length of the AEAD chunk in bytes */
    size_t                  chunkout; /* how many bytes from the chunk were written out */
    size_t                  chunkidx; /* index of the current AEAD chunk */
    size_t                  cachelen; /* how many bytes are in cache, for AEAD */
    uint8_t cache[PGP_PARTIAL_PKT_BLOCK_SIZE]; /* pre-allocated cache for encryption */
} pgp_dest_encrypted_param_t;

typedef struct pgp_dest_signed_param_t {
    pgp_dest_t *             writedst; /* destination to write to */
    rnp_ctx_t *              ctx;      /* rnp operation context with additional parameters */
    pgp_password_provider_t *password_provider; /* password provider from write handler */
    list                     onepasses; /* one-pass entries written to the stream begin */
    list                     keys;   /* signing keys in the same order as onepasses (if any) */
    list                     hashes; /* hashes to pass raw data through and then sign */
    bool                     clr_start;           /* we are on the start of the line */
    uint8_t                  clr_buf[CT_BUF_LEN]; /* buffer to hold partial line data */
    size_t                   clr_buflen;          /* number of bytes in buffer */
} pgp_dest_signed_param_t;

typedef struct pgp_dest_partial_param_t {
    pgp_dest_t *writedst;
    uint8_t     part[PGP_PARTIAL_PKT_BLOCK_SIZE];
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
    param->partlen = PGP_PARTIAL_PKT_BLOCK_SIZE;
    param->parthdr = 0xE0 | PGP_PARTIAL_PKT_SIZE_BITS;
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

    if (param->partial) {
        param->hdr[0] = param->tag | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
        dst_write(dst, &param->hdr, 1);

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

        param->hdr[1] = ((pgp_dest_partial_param_t *) param->writedst->param)->parthdr;
        param->hdrlen = 2;
    } else if (param->indeterminate) {
        if (param->tag > 0xf) {
            RNP_LOG("indeterminate tag > 0xf");
        }

        param->hdr[0] = ((param->tag & 0xf) << PGP_PTAG_OF_CONTENT_TAG_SHIFT) |
                        PGP_PTAG_OLD_LEN_INDETERMINATE;
        param->hdrlen = 1;
        dst_write(dst, &param->hdr, 1);

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
encrypted_dst_write_cfb(pgp_dest_t *dst, const void *buf, size_t len)
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
encrypted_start_aead_chunk(pgp_dest_encrypted_param_t *param, size_t idx, bool last)
{
    uint8_t  nonce[PGP_AEAD_MAX_NONCE_LEN];
    size_t   nlen;
    size_t   taglen;
    bool     res;
    uint64_t total;

    taglen = pgp_cipher_aead_tag_len(param->aalg);

    /* finish the previous chunk if needed*/
    if ((idx > 0) && (param->chunkout + param->cachelen > 0)) {
        if (param->cachelen + taglen > sizeof(param->cache)) {
            RNP_LOG("wrong state in aead");
            return RNP_ERROR_BAD_STATE;
        }

        if (!pgp_cipher_aead_finish(
              &param->encrypt, param->cache, param->cache, param->cachelen)) {
            return RNP_ERROR_BAD_STATE;
        }

        dst_write(param->pkt.writedst, param->cache, param->cachelen + taglen);
    }

    /* set chunk index for additional data */
    STORE64BE(param->ad + param->adlen - 8, idx);

    if (last) {
        total = idx ? (idx - 1) * param->chunklen : 0;
        total += param->cachelen + param->chunkout;
        STORE64BE(param->ad + param->adlen, total);
        param->adlen += 8;
    }
    pgp_cipher_aead_set_ad(&param->encrypt, param->ad, param->adlen);

    /* set chunk index for nonce */
    nlen = pgp_cipher_aead_nonce(param->aalg, param->iv, nonce, idx);

    /* start cipher */
    res = pgp_cipher_aead_start(&param->encrypt, nonce, nlen);

    /* write final authentication tag */
    if (last) {
        res = res && pgp_cipher_aead_finish(&param->encrypt, param->cache, param->cache, 0);
        if (res) {
            dst_write(param->pkt.writedst, param->cache, taglen);
        }
    }

    param->chunkidx = idx;
    param->chunkout = 0;

    return res ? RNP_SUCCESS : RNP_ERROR_BAD_PARAMETERS;
}

/* @brief Encrypt and write aead block. Len must be multiple of granularity
          Uses param->cache to store encryption result
*/
static rnp_result_t
encrypted_dst_write_aead_block(pgp_dest_encrypted_param_t *param, const void *in, size_t len)
{
    size_t sz = len;

    while (len > 0) {
        sz = MIN(MIN(param->chunklen - param->chunkout, len), sizeof(param->cache));

        if (!pgp_cipher_aead_update(&param->encrypt, param->cache, in, sz)) {
            return RNP_ERROR_BAD_STATE;
        }

        dst_write(param->pkt.writedst, param->cache, sz);

        param->chunkout += sz;
        if (param->chunkout == param->chunklen) {
            encrypted_start_aead_chunk(param, param->chunkidx + 1, false);
        }

        len -= sz;
        in = (uint8_t *) in + sz;
    }

    return RNP_SUCCESS;
}

static rnp_result_t
encrypted_dst_write_aead(pgp_dest_t *dst, const void *buf, size_t len)
{
    pgp_dest_encrypted_param_t *param = dst->param;
    size_t                      sz;
    size_t                      gran;
    rnp_result_t                res;

    if (!param) {
        RNP_LOG("wrong param");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!len) {
        return RNP_SUCCESS;
    }

    /* because of botan's FFI granularity we need to make things a bit complicated */
    gran = pgp_cipher_aead_granularity(&param->encrypt);

    /* checking whether we have something left in cache */
    if (param->cachelen > 0) {
        if (param->cachelen + len < gran) {
            memcpy(param->cache + param->cachelen, buf, len);
            param->cachelen += len;
            return RNP_SUCCESS;
        }

        sz = (param->cachelen + gran - 1) / gran * gran - param->cachelen;
        memcpy(param->cache + param->cachelen, buf, sz);

        if ((res =
               encrypted_dst_write_aead_block(param, param->cache, param->cachelen + sz))) {
            return res;
        }

        buf = (uint8_t *) buf + sz;
        len -= sz;
        param->cachelen = 0;
    }

    /* we rely on the fact that chunklen and cache are multiples of granularity */
    sz = len / gran * gran;
    res = encrypted_dst_write_aead_block(param, buf, sz);

    if (!res && (sz < len)) {
        param->cachelen = len - sz;
        memcpy(param->cache, (uint8_t *) buf + sz, param->cachelen);
    }

    return res;
}

static rnp_result_t
encrypted_dst_finish(pgp_dest_t *dst)
{
    uint8_t                     mdcbuf[MDC_V1_SIZE];
    pgp_dest_encrypted_param_t *param = dst->param;
    rnp_result_t                res;

    if (param->aead) {
        size_t chunks = param->chunkidx;
        if ((param->chunkout > 0) || (param->cachelen > 0)) {
            chunks++;
        }
        res = encrypted_start_aead_chunk(param, chunks, true);
        pgp_cipher_aead_destroy(&param->encrypt);

        if (res) {
            return res;
        }
    } else if (param->has_mdc) {
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

    if (!param->aead) {
        pgp_hash_finish(&param->mdc, NULL);
        pgp_cipher_cfb_finish(&param->encrypt);
    } else {
        pgp_cipher_aead_destroy(&param->encrypt);
    }
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
    userkey =
      find_suitable_key(PGP_OP_ENCRYPT_SYM, userkey, handler->key_provider, PGP_KF_ENCRYPT);
    if (!userkey) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    pubkey = &userkey->key.pubkey;

    /* Fill pkey */
    pkey.version = PGP_PKSK_V3;
    pkey.alg = pubkey->alg;
    if (!pgp_keyid(pkey.key_id, PGP_KEY_ID_SIZE, pubkey)) {
        RNP_LOG("key id calculation failed");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* Encrypt the session key */
    enckey[0] = param->ctx->ealg;
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
    case PGP_PKA_ELGAMAL: {
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

static void
encrypted_sesk_set_ad(pgp_crypt_t *crypt, pgp_sk_sesskey_t *skey)
{
    uint8_t ad_data[4];

    ad_data[0] = PGP_PTAG_CT_SK_SESSION_KEY | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
    ad_data[1] = skey->version;
    ad_data[2] = skey->alg;
    ad_data[3] = skey->aalg;

    pgp_cipher_aead_set_ad(crypt, ad_data, 4);
}

static rnp_result_t
encrypted_add_password(rnp_symmetric_pass_info_t * pass,
                       pgp_dest_encrypted_param_t *param,
                       uint8_t *                   key,
                       const unsigned              keylen,
                       bool                        singlepass)
{
    pgp_sk_sesskey_t skey = {0};
    unsigned         s2keylen; /* length of the s2k key */
    pgp_crypt_t      kcrypt;
    uint8_t          nonce[PGP_AEAD_MAX_NONCE_LEN];
    bool             res;

    skey.alg = param->ctx->ealg;
    skey.s2k = pass->s2k;

    if (!param->aead) {
        skey.version = PGP_SKSK_V4;
        /* Following algorithm may differ from ctx's one if not singlepass */
        if (singlepass) {
            s2keylen = keylen;
        } else if ((s2keylen = pgp_key_size(skey.alg)) == 0) {
            return RNP_ERROR_BAD_PARAMETERS;
        }

        if (singlepass) {
            /* if there are no public keys then we do not encrypt session key in the packet */
            skey.enckeylen = 0;
            memcpy(key, pass->key, s2keylen);
        } else {
            /* Currently we are using the same sym algo for key and stream encryption */
            skey.enckeylen = keylen + 1;
            skey.enckey[0] = param->ctx->ealg;
            memcpy(&skey.enckey[1], key, keylen);
            skey.alg = pass->s2k_cipher;
            if (!pgp_cipher_cfb_start(&kcrypt, skey.alg, pass->key, NULL)) {
                RNP_LOG("key encryption failed");
                return RNP_ERROR_BAD_PARAMETERS;
            }
            pgp_cipher_cfb_encrypt(&kcrypt, skey.enckey, skey.enckey, skey.enckeylen);
            pgp_cipher_cfb_finish(&kcrypt);
        }
    } else {
        /* AEAD-encrypted v5 packet */
        if ((param->ctx->aalg != PGP_AEAD_EAX) && (param->ctx->aalg != PGP_AEAD_OCB)) {
            RNP_LOG("unsupported AEAD algorithm");
            return RNP_ERROR_BAD_PARAMETERS;
        }

        skey.version = PGP_SKSK_V5;
        skey.aalg = param->ctx->aalg;
        skey.ivlen = pgp_cipher_aead_nonce_len(skey.aalg);
        skey.enckeylen = keylen + pgp_cipher_aead_tag_len(skey.aalg);

        if (!rng_get_data(rnp_ctx_rng_handle(param->ctx), skey.iv, skey.ivlen)) {
            return RNP_ERROR_RNG;
        }

        /* initialize cipher */
        if (!pgp_cipher_aead_init(&kcrypt, skey.alg, skey.aalg, pass->key, false)) {
            return RNP_ERROR_BAD_PARAMETERS;
        }

        /* set additional data */
        encrypted_sesk_set_ad(&kcrypt, &skey);

        /* calculate nonce */
        size_t nlen = pgp_cipher_aead_nonce(skey.aalg, skey.iv, nonce, 0);

        /* start cipher, encrypt key and get tag */
        res = pgp_cipher_aead_start(&kcrypt, nonce, nlen) &&
              pgp_cipher_aead_finish(&kcrypt, skey.enckey, key, keylen);

        pgp_cipher_aead_destroy(&kcrypt);

        if (!res) {
            return RNP_ERROR_BAD_STATE;
        }
    }

    /* Writing symmetric key encrypted session key packet */
    if (!stream_write_sk_sesskey(&skey, param->pkt.origdst)) {
        return RNP_ERROR_WRITE;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
encrypted_start_cfb(pgp_dest_encrypted_param_t *param, uint8_t *enckey)
{
    uint8_t  mdcver = 1;
    uint8_t  enchdr[PGP_MAX_BLOCK_SIZE + 2]; /* encrypted header */
    unsigned blsize;

    if (param->has_mdc) {
        /* initializing the mdc */
        dst_write(param->pkt.writedst, &mdcver, 1);

        if (!pgp_hash_create(&param->mdc, PGP_HASH_SHA1)) {
            RNP_LOG("cannot create sha1 hash");
            return RNP_ERROR_GENERIC;
        }
    }

    /* initializing the crypto */
    if (!pgp_cipher_cfb_start(&param->encrypt, param->ctx->ealg, enckey, NULL)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* generating and writing iv/password check bytes */
    blsize = pgp_block_size(param->ctx->ealg);
    if (!rng_get_data(rnp_ctx_rng_handle(param->ctx), enchdr, blsize)) {
        return RNP_ERROR_RNG;
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

    return RNP_SUCCESS;
}

static rnp_result_t
encrypted_start_aead(pgp_dest_encrypted_param_t *param, uint8_t *enckey)
{
    uint8_t hdr[4 + PGP_AEAD_MAX_NONCE_LEN];
    size_t  gran;
    size_t  nlen;

    if (pgp_block_size(param->ctx->ealg) != 16) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* fill header */
    hdr[0] = 1;
    hdr[1] = param->ctx->ealg;
    hdr[2] = param->ctx->aalg;
    hdr[3] = 4; /* 1Kb chunks */

    /* generate iv */
    nlen = pgp_cipher_aead_nonce_len(param->ctx->aalg);
    if (!rng_get_data(rnp_ctx_rng_handle(param->ctx), param->iv, nlen)) {
        return RNP_ERROR_RNG;
    }
    memcpy(hdr + 4, param->iv, nlen);

    /* output header */
    dst_write(param->pkt.writedst, hdr, 4 + nlen);

    /* initialize encryption */
    param->chunklen = 1L << (hdr[3] + 6);
    param->chunkout = 0;

    /* fill additional/authenticated data */
    param->ad[0] = PGP_PTAG_CT_AEAD_ENCRYPTED | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
    memcpy(param->ad + 1, hdr, 4);
    memset(param->ad + 5, 0, 8);
    param->adlen = 13;

    /* initialize cipher */
    if (!pgp_cipher_aead_init(
          &param->encrypt, param->ctx->ealg, param->ctx->aalg, enckey, false)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* chunklen must be multiple of granularity */
    gran = pgp_cipher_aead_granularity(&param->encrypt);
    if ((param->chunklen < gran) || (param->chunklen % gran)) {
        RNP_LOG("wrong chunk size or cipher granularity");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    return encrypted_start_aead_chunk(param, 0, false);
}

static rnp_result_t
init_encrypted_dst(pgp_write_handler_t *handler, pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_encrypted_param_t *param;
    bool                        singlepass = true;
    unsigned                    pkeycount = 0;
    unsigned                    skeycount = 0;
    uint8_t                     enckey[PGP_MAX_KEY_SIZE] = {0}; /* content encryption key */
    unsigned                    keylen;
    rnp_result_t                ret = RNP_ERROR_GENERIC;

    keylen = pgp_key_size(handler->ctx->ealg);
    if (!keylen) {
        RNP_LOG("unknown symmetric algorithm");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (handler->ctx->aalg) {
        if ((handler->ctx->aalg != PGP_AEAD_EAX) && (handler->ctx->aalg != PGP_AEAD_OCB)) {
            RNP_LOG("unknown AEAD algorithm");
            return RNP_ERROR_BAD_PARAMETERS;
        }

        if ((pgp_block_size(handler->ctx->ealg) != 16)) {
            RNP_LOG("wrong AEAD symmetric algorithm");
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = dst->param;
    param->has_mdc = true;
    param->aead = handler->ctx->aalg != PGP_AEAD_NONE;
    param->aalg = handler->ctx->aalg;
    param->ctx = handler->ctx;
    param->pkt.origdst = writedst;
    dst->write = param->aead ? encrypted_dst_write_aead : encrypted_dst_write_cfb;
    dst->finish = encrypted_dst_finish;
    dst->close = encrypted_dst_close;
    dst->type = PGP_STREAM_ENCRYPTED;

    pkeycount = list_length(handler->ctx->recipients);
    skeycount = list_length(handler->ctx->passwords);

    if (!pkeycount && !skeycount) {
        RNP_LOG("no recipients");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    if ((pkeycount > 0) || (skeycount > 1) || param->aead) {
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
        ret = encrypted_add_password(
          (rnp_symmetric_pass_info_t *) pi, param, enckey, keylen, singlepass);
        if (ret != RNP_SUCCESS) {
            goto finish;
        }
    }

    /* Initializing partial packet writer */
    param->pkt.partial = true;
    param->pkt.indeterminate = false;
    if (param->aead) {
        param->pkt.tag = PGP_PTAG_CT_AEAD_ENCRYPTED;
    } else {
        param->pkt.tag = param->has_mdc ? PGP_PTAG_CT_SE_IP_DATA : PGP_PTAG_CT_SE_DATA;
    }

    /* initializing partial data length writer */
    /* we may use intederminate len packet here as well, for compatibility or so on */
    if (!init_streamed_packet(&param->pkt, writedst)) {
        RNP_LOG("failed to init streamed packet");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    if (param->aead) {
        /* initialize AEAD encryption */
        ret = encrypted_start_aead(param, enckey);
    } else {
        /* initialize old CFB or CFB with MDC */
        ret = encrypted_start_cfb(param, enckey);
    }

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

static void
cleartext_dst_writeline(pgp_dest_signed_param_t *param,
                        const uint8_t *          buf,
                        size_t                   len,
                        bool                     eol)
{
    const uint8_t *ptr;

    /* dash-escaping line if needed */
    if (param->clr_start && len &&
        ((buf[0] == CH_DASH) || ((len >= 4) && !strncmp((const char *) buf, ST_FROM, 4)))) {
        dst_write(param->writedst, ST_DASHSP, 2);
    }

    /* output data */
    dst_write(param->writedst, buf, len);

    if (eol) {
        /* skipping trailing eol - \n, or \r\n. For the last line eol may be true without \n */
        bool hashcrlf = false;
        ptr = buf + len - 1;
        if (*ptr == CH_LF) {
            ptr--;
            hashcrlf = true;

            if ((ptr >= buf) && (*ptr == CH_CR)) {
                ptr--;
            }
        }

        /* skipping trailing spaces */
        while ((ptr >= buf) && ((*ptr == CH_SPACE) || (*ptr == CH_TAB))) {
            ptr--;
        }

        /* hashing line body and \r\n */
        pgp_hash_list_update(param->hashes, buf, ptr + 1 - buf);
        if (hashcrlf) {
            pgp_hash_list_update(param->hashes, ST_CRLF, 2);
        }
        param->clr_start = hashcrlf;
    } else if (len > 0) {
        /* hashing just line's data */
        pgp_hash_list_update(param->hashes, buf, len);
        param->clr_start = false;
    }
}

static size_t
cleartext_dst_scanline(const uint8_t *buf, size_t len, bool *eol)
{
    for (const uint8_t *ptr = buf, *end = buf + len; ptr < end; ptr++) {
        if (*ptr == CH_LF) {
            if (eol) {
                *eol = true;
            }
            return ptr - buf + 1;
        }
    }

    if (eol) {
        *eol = false;
    }
    return len;
}

static rnp_result_t
cleartext_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    const uint8_t *          linebg = buf;
    size_t                   linelen;
    size_t                   cplen;
    bool                     eol;
    pgp_dest_signed_param_t *param = dst->param;

    if (param->clr_buflen > 0) {
        /* number of edge cases may happen here */
        linelen = cleartext_dst_scanline(linebg, len, &eol);

        if (param->clr_buflen + linelen < sizeof(param->clr_buf)) {
            /* fits into buffer */
            memcpy(param->clr_buf + param->clr_buflen, linebg, linelen);
            param->clr_buflen += linelen;
            if (!eol) {
                /* do not write the line if we don't have whole */
                return RNP_SUCCESS;
            }

            cleartext_dst_writeline(param, param->clr_buf, param->clr_buflen, true);
            param->clr_buflen = 0;
        } else {
            /* we have line longer than 4k */
            cplen = sizeof(param->clr_buf) - param->clr_buflen;
            memcpy(param->clr_buf + param->clr_buflen, linebg, cplen);
            cleartext_dst_writeline(param, param->clr_buf, sizeof(param->clr_buf), false);

            if (eol || (linelen >= sizeof(param->clr_buf))) {
                cleartext_dst_writeline(param, linebg + cplen, linelen - cplen, eol);
                param->clr_buflen = 0;
            } else {
                param->clr_buflen = linelen - cplen;
                memcpy(param->clr_buf, linebg + cplen, param->clr_buflen);
                return RNP_SUCCESS;
            }
        }

        linebg += linelen;
        len -= linelen;
    }

    /* if we get here then we don't have data in param->clr_buf */
    while (len > 0) {
        linelen = cleartext_dst_scanline(linebg, len, &eol);

        if (!eol && (linelen < sizeof(param->clr_buf))) {
            memcpy(param->clr_buf, linebg, linelen);
            param->clr_buflen = linelen;
            return RNP_SUCCESS;
        }

        cleartext_dst_writeline(param, linebg, linelen, eol);
        linebg += linelen;
        len -= linelen;
    }

    return RNP_SUCCESS;
}

static rnp_result_t
signed_fill_signature(pgp_dest_signed_param_t *param, pgp_signature_t *sig, pgp_key_t *seckey)
{
    pgp_seckey_t *     deckey = NULL;
    pgp_hash_t         hash;
    pgp_password_ctx_t ctx = {.op = PGP_OP_SIGN, .key = seckey};
    uint8_t            hval[PGP_MAX_HASH_SIZE];
    size_t             hlen;
    bool               res;
    rnp_result_t       ret = RNP_ERROR_GENERIC;

    /* fill signature fields */
    res =
      signature_set_keyfp(sig, seckey->fingerprint.fingerprint, seckey->fingerprint.length) &&
      signature_set_keyid(sig, seckey->keyid) &&
      signature_set_creation(sig, param->ctx->sigcreate) &&
      signature_set_expiration(sig, param->ctx->sigexpire) && signature_fill_hashed_data(sig);

    if (!res) {
        RNP_LOG("failed to fill the signature data");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (!pgp_hash_copy(&hash, pgp_hash_list_get(param->hashes, sig->halg))) {
        RNP_LOG("failed to obtain hash");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* finalize hash and copy left 16 bits to signature */
    pgp_hash_add(&hash, sig->hashed_data, sig->hashed_len);
    hlen = pgp_hash_finish(&hash, hval);
    memcpy(sig->lbits, hval, 2);

    /* decrypt the secret key if needed */
    if (seckey->key.seckey.encrypted) {
        deckey = pgp_decrypt_seckey(seckey, param->password_provider, &ctx);
        if (!deckey) {
            return RNP_ERROR_BAD_PASSWORD;
        }
    } else {
        deckey = &(seckey->key.seckey);
    }

    /* sign */
    switch (sig->palg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        sig->material.rsa.slen = pgp_rsa_pkcs1_sign_hash(param->ctx->rng,
                                                         sig->material.rsa.s,
                                                         sizeof(sig->material.rsa.s),
                                                         sig->halg,
                                                         hval,
                                                         hlen,
                                                         &deckey->key.rsa,
                                                         &deckey->pubkey.key.rsa);
        if (!sig->material.rsa.slen) {
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
              param->ctx->rng, r, s, hval, hlen, &deckey->key.ecc, &deckey->pubkey.key.ecc) <
            0) {
            ret = RNP_ERROR_SIGNING_FAILED;
            goto eddsaend;
        } else {
            ret = RNP_SUCCESS;
        }

        bn_num_bytes(r, &sig->material.ecc.rlen);
        bn_num_bytes(s, &sig->material.ecc.slen);
        bn_bn2bin(r, sig->material.ecc.r);
        bn_bn2bin(s, sig->material.ecc.s);

    eddsaend:
        bn_free(r);
        bn_free(s);
        break;
    }
    case PGP_PKA_SM2: {
        pgp_ecc_sig_t          sigval = {NULL, NULL};
        const ec_curve_desc_t *curve = get_curve_desc(deckey->pubkey.key.ecc.curve);

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

        if (pgp_sm2_sign_hash(param->ctx->rng,
                              &sigval,
                              hval,
                              hlen,
                              &deckey->key.ecc,
                              &deckey->pubkey.key.ecc) != RNP_SUCCESS) {
            RNP_LOG("SM2 signing failed");
            ret = RNP_ERROR_SIGNING_FAILED;
            break;
        }

        bn_num_bytes(sigval.r, &sig->material.ecc.rlen);
        bn_num_bytes(sigval.s, &sig->material.ecc.slen);
        bn_bn2bin(sigval.r, sig->material.ecc.r);
        bn_bn2bin(sigval.s, sig->material.ecc.s);
        bn_free(sigval.r);
        bn_free(sigval.s);
        ret = RNP_SUCCESS;
        break;
    }
    case PGP_PKA_DSA: {
        pgp_dsa_sig_t dsasig = {0};
        ret = dsa_sign(
          param->ctx->rng, &dsasig, hval, hlen, &deckey->key.dsa, &deckey->pubkey.key.dsa);
        if (ret != RNP_SUCCESS) {
            RNP_LOG("DSA signing failed");
            break;
        }

        (void)bn_num_bytes(dsasig.r, &sig->material.dsa.rlen);
        (void)bn_num_bytes(dsasig.s, &sig->material.dsa.slen);
        (void)bn_bn2bin(dsasig.r, sig->material.dsa.r);
        (void)bn_bn2bin(dsasig.s, sig->material.dsa.s);
        bn_free(dsasig.r);
        bn_free(dsasig.s);
        ret = RNP_SUCCESS;
        break;
    }

    /*
     * ECDH is signed with ECDSA. This must be changed when ECDH will support
     * X25519, but I need to check how it should be done exactly.
     */
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA: {
        pgp_ecc_sig_t          sigval = {NULL, NULL};
        const ec_curve_desc_t *curve = get_curve_desc(deckey->pubkey.key.ecc.curve);

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

        if (pgp_ecdsa_sign_hash(param->ctx->rng,
                                &sigval,
                                hval,
                                hlen,
                                &deckey->key.ecc,
                                &deckey->pubkey.key.ecc) != RNP_SUCCESS) {
            RNP_LOG("ECDSA signing failed");
            ret = RNP_ERROR_SIGNING_FAILED;
            break;
        }

        bn_num_bytes(sigval.r, &sig->material.ecc.rlen);
        bn_num_bytes(sigval.s, &sig->material.ecc.slen);
        bn_bn2bin(sigval.r, sig->material.ecc.r);
        bn_bn2bin(sigval.s, sig->material.ecc.s);
        bn_free(sigval.r);
        bn_free(sigval.s);
        ret = RNP_SUCCESS;
        break;
    }
    default:
        RNP_LOG("Unsupported algorithm %d", sig->palg);
        break;
    }

    /* destroy decrypted secret key */
    if (seckey->key.seckey.encrypted) {
        pgp_seckey_free(deckey);
        free(deckey);
        deckey = NULL;
    }

    return ret;
}

static rnp_result_t
signed_write_signature(pgp_dest_signed_param_t *param,
                       pgp_one_pass_sig_t *     onepass,
                       pgp_key_t *              seckey,
                       pgp_dest_t *             writedst)
{
    pgp_signature_t sig = {0};
    rnp_result_t    ret;

    sig.version = 4;
    if (onepass) {
        sig.halg = onepass->halg;
        sig.palg = onepass->palg;
        sig.type = onepass->type;
    } else {
        sig.halg = pgp_hash_adjust_alg_to_key(param->ctx->halg, &seckey->key.seckey.pubkey);
        sig.palg = seckey->key.pubkey.alg;
        sig.type = param->ctx->detached ? PGP_SIG_BINARY : PGP_SIG_TEXT;
    }

    if (!(ret = signed_fill_signature(param, &sig, seckey))) {
        ret = stream_write_signature(&sig, writedst) ? RNP_SUCCESS : RNP_ERROR_WRITE;
    }

    free_signature(&sig);
    return ret;
}

static rnp_result_t
signed_dst_finish(pgp_dest_t *dst)
{
    rnp_result_t             ret;
    pgp_dest_signed_param_t *param = dst->param;

    /* attached signature, first signature should correspond last onepass */
    for (list_item *op = list_back(param->onepasses), *key = list_back(param->keys); op && key;
         op = list_prev(op), key = list_prev(key)) {
        pgp_one_pass_sig_t *onepass = (pgp_one_pass_sig_t *) op;
        pgp_key_t *         seckey = *(pgp_key_t **) key;

        if ((ret = signed_write_signature(param, onepass, seckey, param->writedst))) {
            return ret;
        }
    }

    return RNP_SUCCESS;
}

static rnp_result_t
signed_detached_dst_finish(pgp_dest_t *dst)
{
    rnp_result_t             ret;
    pgp_dest_signed_param_t *param = dst->param;

    /* just calculating and writing signatures to the output */
    for (list_item *key = list_front(param->keys); key; key = list_next(key)) {
        pgp_key_t *seckey = *(pgp_key_t **) key;

        if ((ret = signed_write_signature(param, NULL, seckey, param->writedst))) {
            return ret;
        }
    }

    return RNP_SUCCESS;
}

static rnp_result_t
cleartext_dst_finish(pgp_dest_t *dst)
{
    pgp_dest_t               armordst = {0};
    rnp_result_t             ret;
    pgp_dest_signed_param_t *param = dst->param;

    /* writing cached line if any */
    if (param->clr_buflen > 0) {
        cleartext_dst_writeline(param, param->clr_buf, param->clr_buflen, true);
    }
    /* trailing \r\n which is not hashed */
    dst_write(param->writedst, ST_CRLF, 2);

    /* writing signatures to the armored stream, which outputs to param->writedst */
    if ((ret = init_armored_dst(&armordst, param->writedst, PGP_ARMORED_SIGNATURE))) {
        return ret;
    }

    for (list_item *key = list_front(param->keys); key; key = list_next(key)) {
        pgp_key_t *seckey = *(pgp_key_t **) key;

        if ((ret = signed_write_signature(param, NULL, seckey, &armordst))) {
            break;
        }
    }

    if (ret == RNP_SUCCESS) {
        ret = dst_finish(&armordst);
    }

    dst_close(&armordst, ret != RNP_SUCCESS);
    return ret;
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
signed_add_signer(pgp_dest_signed_param_t *param, pgp_key_t *key, bool last)
{
    pgp_one_pass_sig_t onepass = {0};
    pgp_hash_alg_t     halg;

    /* Add hash to the list */
    halg = pgp_hash_adjust_alg_to_key(param->ctx->halg, &key->key.seckey.pubkey);
    if (!pgp_hash_list_add(&param->hashes, halg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* Write one-pass signature if not detached/cleartext */
    if (!param->ctx->detached && !param->ctx->clearsign) {
        onepass.version = 3;
        onepass.type = PGP_SIG_BINARY;
        onepass.halg = halg;
        onepass.palg = key->key.pubkey.alg;
        memcpy(onepass.keyid, key->keyid, PGP_KEY_ID_SIZE);
        onepass.nested = last;

        if (!stream_write_one_pass(&onepass, param->writedst)) {
            return RNP_ERROR_WRITE;
        }

        if (!list_append(&param->onepasses, &onepass, sizeof(onepass))) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }

    /* Save the private key for later usage */
    if (!list_append(&param->keys, &key, sizeof(key))) {
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
    const char *hname;

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
    param->password_provider = handler->password_provider;
    if (param->ctx->clearsign) {
        dst->type = PGP_STREAM_CLEARTEXT;
        dst->write = cleartext_dst_write;
        dst->finish = cleartext_dst_finish;
        param->clr_start = true;
    } else {
        dst->type = PGP_STREAM_SIGNED;
        dst->write = signed_dst_write;
        dst->finish = param->ctx->detached ? signed_detached_dst_finish : signed_dst_finish;
    }
    dst->close = signed_dst_close;

    /* Getting signer's keys, writing one-pass signatures if needed */
    for (list_item *sg = list_front(handler->ctx->signers); sg; sg = list_next(sg)) {
        keyctx.search.userid = (char *) sg;
        if (!pgp_request_key(handler->key_provider, &keyctx, &key)) {
            RNP_LOG("signer's key not found: %s", (char *) sg);
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto finish;
        }

        ret = signed_add_signer(param, key, sg == list_back(handler->ctx->signers));
        if (ret) {
            RNP_LOG("failed to add one-pass signature for signer %s", (char *) sg);
            goto finish;
        }
    }

    /* Do we have any signatures? */
    if (!list_length(param->hashes)) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* Writing headers for cleartext signed document */
    if (param->ctx->clearsign) {
        dst_write(param->writedst, ST_CLEAR_BEGIN, strlen(ST_CLEAR_BEGIN));
        dst_write(param->writedst, ST_CRLF, strlen(ST_CRLF));
        dst_write(param->writedst, ST_HEADER_HASH, strlen(ST_HEADER_HASH));

        for (list_item *hash = list_front(param->hashes); hash; hash = list_next(hash)) {
            hname = pgp_hash_name((pgp_hash_t *) hash);
            dst_write(param->writedst, hname, strlen(hname));
            if (hash != list_back(param->hashes)) {
                dst_write(param->writedst, ST_COMMA, 1);
            }
        }

        dst_write(param->writedst, ST_CRLFCRLF, strlen(ST_CRLFCRLF));
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

static rnp_result_t
process_stream_sequence(pgp_source_t *src, pgp_dest_t *streams, unsigned count)
{
    uint8_t *    readbuf = NULL;
    ssize_t      read;
    pgp_dest_t * sstream = NULL; /* signed stream if any, to call signed_dst_update on it */
    pgp_dest_t * wstream = NULL; /* stream to dst_write() source data, may be empty */
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (!(readbuf = calloc(1, PGP_INPUT_CACHE_SIZE))) {
        RNP_LOG("allocation failure");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto finish;
    }

    /* check whether we have signed stream and stream for data output */
    for (int i = count - 1; i >= 0; i--) {
        if (streams[i].type == PGP_STREAM_SIGNED) {
            sstream = &streams[i];
        } else if ((streams[i].type == PGP_STREAM_CLEARTEXT) ||
                   (streams[i].type == PGP_STREAM_LITERAL)) {
            wstream = &streams[i];
        }
    }

    /* processing source stream */
    while (!src->eof) {
        read = src_read(src, readbuf, PGP_INPUT_CACHE_SIZE);
        if (read < 0) {
            RNP_LOG("failed to read from source");
            ret = RNP_ERROR_READ;
            goto finish;
        } else if (!read) {
            continue;
        }

        if (sstream) {
            signed_dst_update(sstream, readbuf, read);
        }

        if (wstream) {
            dst_write(wstream, readbuf, read);

            for (int i = count - 1; i >= 0; i--) {
                if (streams[i].werr != RNP_SUCCESS) {
                    RNP_LOG("failed to process data");
                    ret = RNP_ERROR_WRITE;
                    goto finish;
                }
            }
        }
    }

    /* finalizing destinations */
    for (int i = count - 1; i >= 0; i--) {
        ret = dst_finish(&streams[i]);
        if (ret != RNP_SUCCESS) {
            RNP_LOG("failed to finish stream");
            goto finish;
        }
    }

    ret = RNP_SUCCESS;
finish:
    free(readbuf);
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
    pgp_dest_t   dests[4];
    int          destc = 0;
    rnp_result_t ret = RNP_ERROR_GENERIC;

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

    /* processing stream sequence */
    ret = process_stream_sequence(src, dests, destc);
finish:
    for (int i = destc - 1; i >= 0; i--) {
        dst_close(&dests[i], ret != RNP_SUCCESS);
    }

    return ret;
}

rnp_result_t
rnp_sign_src(pgp_write_handler_t *handler, pgp_source_t *src, pgp_dest_t *dst)
{
    /* stack of the streams would be as following:
       [armoring stream] - if armoring is enabled
       [compressing stream, partial writing stream] - compression is enabled, and not detached
       signing stream
       literal data stream, partial writing stream - if not detached or cleartext signature
    */
    pgp_dest_t   dests[4];
    unsigned     destc = 0;
    rnp_result_t ret = RNP_SUCCESS;

    /* pushing armoring stream, which will write to the output */
    if (handler->ctx->armor && !handler->ctx->clearsign) {
        ret = init_armored_dst(&dests[destc], dst, PGP_ARMORED_MESSAGE);
        if (ret != RNP_SUCCESS) {
            goto finish;
        }
        destc++;
    }

    /* if compression is enabled then pushing compressing stream */
    if (!handler->ctx->detached && !handler->ctx->clearsign && (handler->ctx->zlevel > 0)) {
        if ((ret =
               init_compressed_dst(handler, &dests[destc], destc ? &dests[destc - 1] : dst))) {
            goto finish;
        }
        destc++;
    }

    /* pushing signing stream, which will use handler->ctx to distinguish between
     * attached/detached/cleartext signature */
    if ((ret = init_signed_dst(handler, &dests[destc], destc ? &dests[destc - 1] : dst))) {
        goto finish;
    }
    destc++;

    /* pushing literal data stream, if not detached/cleartext signature */
    if (!handler->ctx->detached && !handler->ctx->clearsign) {
        if ((ret = init_literal_dst(handler, &dests[destc], &dests[destc - 1]))) {
            goto finish;
        }
        destc++;
    }

    /* process source with streams stack */
    ret = process_stream_sequence(src, dests, destc);
finish:
    for (int i = destc - 1; i >= 0; i--) {
        dst_close(&dests[i], ret != RNP_SUCCESS);
    }
    return ret;
}
