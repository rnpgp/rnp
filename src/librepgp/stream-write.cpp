/*
 * Copyright (c) 2017-2020, [Ribose Inc](https://www.ribose.com).
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
#ifdef HAVE_UNISTD_H
#include <sys/param.h>
#include <unistd.h>
#else
#include "uniwin.h"
#endif
#include <string.h>
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif
#include <rnp/rnp_def.h>
#include "stream-def.h"
#include "stream-ctx.h"
#include "stream-write.h"
#include "stream-packet.h"
#include "stream-armor.h"
#include "stream-sig.h"
#include "list.h"
#include "pgp-key.h"
#include "fingerprint.h"
#include "types.h"
#include "crypto/signatures.h"
#include "defaults.h"
#include <time.h>
#include <algorithm>

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
    uint8_t                 iv[PGP_AEAD_MAX_NONCE_LEN]; /* iv for AEAD mode */
    uint8_t                 ad[PGP_AEAD_MAX_AD_LEN];    /* additional data for AEAD mode */
    size_t                  adlen;    /* length of additional data, including chunk idx */
    size_t                  chunklen; /* length of the AEAD chunk in bytes */
    size_t                  chunkout; /* how many bytes from the chunk were written out */
    size_t                  chunkidx; /* index of the current AEAD chunk */
    size_t                  cachelen; /* how many bytes are in cache, for AEAD */
    uint8_t                 cache[PGP_AEAD_CACHE_LEN]; /* pre-allocated cache for encryption */
} pgp_dest_encrypted_param_t;

typedef struct pgp_dest_signer_info_t {
    pgp_one_pass_sig_t onepass;
    pgp_key_t *        key;
    pgp_hash_alg_t     halg;
    int64_t            sigcreate;
    uint64_t           sigexpire;
} pgp_dest_signer_info_t;

typedef struct pgp_dest_signed_param_t {
    pgp_dest_t *             writedst; /* destination to write to */
    rnp_ctx_t *              ctx;      /* rnp operation context with additional parameters */
    pgp_password_provider_t *password_provider;   /* password provider from write handler */
    std::vector<pgp_dest_signer_info_t> siginfos; /* list of  pgp_dest_signer_info_t */
    std::vector<pgp_hash_t> hashes;    /* hashes to pass raw data through and then sign */
    bool                    clr_start; /* we are on the start of the line */
    uint8_t                 clr_buf[CT_BUF_LEN]; /* buffer to hold partial line data */
    size_t                  clr_buflen;          /* number of bytes in buffer */

    pgp_dest_signed_param_t() = default;
    ~pgp_dest_signed_param_t();
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
    pgp_dest_partial_param_t *param = (pgp_dest_partial_param_t *) dst->param;
    if (!param) {
        RNP_LOG("wrong param");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (len > param->partlen - param->len) {
        /* we have full part - in block and in buf */
        size_t wrlen = param->partlen - param->len;
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
    pgp_dest_partial_param_t *param = (pgp_dest_partial_param_t *) dst->param;
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
    pgp_dest_partial_param_t *param = (pgp_dest_partial_param_t *) dst->param;

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

    param = (pgp_dest_partial_param_t *) dst->param;
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

        if ((param->writedst = (pgp_dest_t *) calloc(1, sizeof(*param->writedst))) == NULL) {
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
        return true;
    }

    if (param->indeterminate) {
        if (param->tag > 0xf) {
            RNP_LOG("indeterminate tag > 0xf");
        }

        param->hdr[0] = ((param->tag & 0xf) << PGP_PTAG_OF_CONTENT_TAG_SHIFT) |
                        PGP_PTAG_OLD_LEN_INDETERMINATE;
        param->hdrlen = 1;
        dst_write(dst, &param->hdr, 1);

        param->writedst = dst;
        param->origdst = dst;
        return true;
    }

    RNP_LOG("wrong call");
    return false;
}

static rnp_result_t
finish_streamed_packet(pgp_dest_packet_param_t *param)
{
    if (param->partial) {
        return dst_finish(param->writedst);
    }
    return RNP_SUCCESS;
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
    pgp_dest_encrypted_param_t *param = (pgp_dest_encrypted_param_t *) dst->param;
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
        pgp_cipher_cfb_encrypt(&param->encrypt, param->cache, (const uint8_t *) buf, sz);
        dst_write(param->pkt.writedst, param->cache, sz);
        len -= sz;
        buf = (uint8_t *) buf + sz;
    }

    return RNP_SUCCESS;
}

#if defined(ENABLE_AEAD)
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
        if (!(param->chunkout + param->cachelen)) {
            /* we need to clearly reset it since cipher was initialized but not finished */
            pgp_cipher_aead_reset(&param->encrypt);
        }

        total = idx * param->chunklen;
        if (param->cachelen + param->chunkout) {
            if (param->chunklen < (param->cachelen + param->chunkout)) {
                RNP_LOG("wrong last chunk state in aead");
                return RNP_ERROR_BAD_STATE;
            }
            total -= param->chunklen - param->cachelen - param->chunkout;
        }

        STORE64BE(param->ad + param->adlen, total);
        param->adlen += 8;
    }
    if (!pgp_cipher_aead_set_ad(&param->encrypt, param->ad, param->adlen)) {
        RNP_LOG("failed to set ad");
        return RNP_ERROR_BAD_STATE;
    }

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
#endif

static rnp_result_t
encrypted_dst_write_aead(pgp_dest_t *dst, const void *buf, size_t len)
{
#if !defined(ENABLE_AEAD)
    RNP_LOG("AEAD is not enabled.");
    return RNP_ERROR_WRITE;
#else
    pgp_dest_encrypted_param_t *param = (pgp_dest_encrypted_param_t *) dst->param;

    size_t       sz;
    size_t       gran;
    rnp_result_t res;

    if (!param) {
        RNP_LOG("wrong param");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!len) {
        return RNP_SUCCESS;
    }

    /* because of botan's FFI granularity we need to make things a bit complicated */
    gran = pgp_cipher_aead_granularity(&param->encrypt);

    if (param->cachelen > param->chunklen - param->chunkout) {
        RNP_LOG("wrong AEAD cache state");
        return RNP_ERROR_BAD_STATE;
    }

    while (len > 0) {
        sz = std::min(sizeof(param->cache) - PGP_AEAD_MAX_TAG_LEN - param->cachelen, len);
        sz = std::min(sz, param->chunklen - param->chunkout - param->cachelen);
        memcpy(param->cache + param->cachelen, buf, sz);
        param->cachelen += sz;

        if (param->cachelen == param->chunklen - param->chunkout) {
            /* we have the tail of the chunk in cache */
            if ((res = encrypted_start_aead_chunk(param, param->chunkidx + 1, false))) {
                return res;
            }
            param->cachelen = 0;
        } else if (param->cachelen >= gran) {
            /* we have part of the chunk - so need to adjust it to the granularity */
            size_t gransz = param->cachelen - param->cachelen % gran;
            if (!pgp_cipher_aead_update(&param->encrypt, param->cache, param->cache, gransz)) {
                return RNP_ERROR_BAD_STATE;
            }
            dst_write(param->pkt.writedst, param->cache, gransz);
            memmove(param->cache, param->cache + gransz, param->cachelen - gransz);
            param->cachelen -= gransz;
            param->chunkout += gransz;
        }

        len -= sz;
        buf = (uint8_t *) buf + sz;
    }

    return RNP_SUCCESS;
#endif
}

static rnp_result_t
encrypted_dst_finish(pgp_dest_t *dst)
{
    pgp_dest_encrypted_param_t *param = (pgp_dest_encrypted_param_t *) dst->param;

    if (param->aead) {
#if !defined(ENABLE_AEAD)
        RNP_LOG("AEAD is not enabled.");
        rnp_result_t res = RNP_ERROR_NOT_IMPLEMENTED;
#else
        size_t chunks = param->chunkidx;
        /* if we didn't write anything in current chunk then discard it and restart */
        if (param->chunkout || param->cachelen) {
            chunks++;
        }

        rnp_result_t res = encrypted_start_aead_chunk(param, chunks, true);
        pgp_cipher_aead_destroy(&param->encrypt);
#endif
        if (res) {
            finish_streamed_packet(&param->pkt);
            return res;
        }
    } else if (param->has_mdc) {
        uint8_t mdcbuf[MDC_V1_SIZE];
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
    pgp_dest_encrypted_param_t *param = (pgp_dest_encrypted_param_t *) dst->param;

    if (!param) {
        return;
    }

    if (param->aead) {
#if defined(ENABLE_AEAD)
        pgp_cipher_aead_destroy(&param->encrypt);
#endif
    } else {
        pgp_hash_finish(&param->mdc, NULL);
        pgp_cipher_cfb_finish(&param->encrypt);
    }
    close_streamed_packet(&param->pkt, discard);
    free(param);
    dst->param = NULL;
}

static rnp_result_t
encrypted_add_recipient(pgp_write_handler_t *handler,
                        pgp_dest_t *         dst,
                        pgp_key_t *          userkey,
                        const uint8_t *      key,
                        const unsigned       keylen)
{
    pgp_pk_sesskey_t            pkey;
    pgp_dest_encrypted_param_t *param = (pgp_dest_encrypted_param_t *) dst->param;
    rnp_result_t                ret = RNP_ERROR_GENERIC;

    /* Use primary key if good for encryption, otherwise look in subkey list */
    userkey =
      find_suitable_key(PGP_OP_ENCRYPT_SYM, userkey, handler->key_provider, PGP_KF_ENCRYPT);
    if (!userkey) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    if (!userkey->valid()) {
        RNP_LOG("attempt to use invalid key as recipient");
        return RNP_ERROR_NO_SUITABLE_KEY;
    }

    /* Fill pkey */
    pkey.version = PGP_PKSK_V3;
    pkey.alg = userkey->alg();
    pkey.key_id = userkey->keyid();

    /* Encrypt the session key */
    rnp::secure_array<uint8_t, PGP_MAX_KEY_SIZE + 3> enckey;
    enckey[0] = param->ctx->ealg;
    memcpy(&enckey[1], key, keylen);

    /* Calculate checksum */
    rnp::secure_array<unsigned, 1> checksum;

    for (unsigned i = 1; i <= keylen; i++) {
        checksum[0] += enckey[i];
    }
    enckey[keylen + 1] = (checksum[0] >> 8) & 0xff;
    enckey[keylen + 2] = checksum[0] & 0xff;

    pgp_encrypted_material_t material;

    switch (userkey->alg()) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY: {
        ret = rsa_encrypt_pkcs1(rnp_ctx_rng_handle(handler->ctx),
                                &material.rsa,
                                enckey.data(),
                                keylen + 3,
                                &userkey->material().rsa);
        if (ret) {
            RNP_LOG("rsa_encrypt_pkcs1 failed");
            return ret;
        }
        break;
    }
    case PGP_PKA_SM2: {
#if defined(ENABLE_SM2)
        ret = sm2_encrypt(rnp_ctx_rng_handle(handler->ctx),
                          &material.sm2,
                          enckey.data(),
                          keylen + 3,
                          PGP_HASH_SM3,
                          &userkey->material().ec);
        if (ret) {
            RNP_LOG("sm2_encrypt failed");
            return ret;
        }
        break;
#else
        RNP_LOG("sm2_encrypt is not available");
        return RNP_ERROR_NOT_IMPLEMENTED;
#endif
    }
    case PGP_PKA_ECDH: {
        ret = ecdh_encrypt_pkcs5(rnp_ctx_rng_handle(handler->ctx),
                                 &material.ecdh,
                                 enckey.data(),
                                 keylen + 3,
                                 &userkey->material().ec,
                                 userkey->fp());
        if (ret) {
            RNP_LOG("ECDH encryption failed %d", ret);
            return ret;
        }
        break;
    }
    case PGP_PKA_ELGAMAL: {
        ret = elgamal_encrypt_pkcs1(rnp_ctx_rng_handle(handler->ctx),
                                    &material.eg,
                                    enckey.data(),
                                    keylen + 3,
                                    &userkey->material().eg);
        if (ret) {
            RNP_LOG("pgp_elgamal_public_encrypt failed");
            return ret;
        }
        break;
    }
    default:
        RNP_LOG("unsupported alg: %d", (int) userkey->alg());
        return ret;
    }

    /* Writing symmetric key encrypted session key packet */
    try {
        pkey.write_material(material);
        pkey.write(*param->pkt.origdst);
        return param->pkt.origdst->werr;
    } catch (const std::exception &e) {
        return RNP_ERROR_WRITE;
    }
}

#if defined(ENABLE_AEAD)
static bool
encrypted_sesk_set_ad(pgp_crypt_t *crypt, pgp_sk_sesskey_t *skey)
{
    uint8_t ad_data[4];

    ad_data[0] = PGP_PKT_SK_SESSION_KEY | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
    ad_data[1] = skey->version;
    ad_data[2] = skey->alg;
    ad_data[3] = skey->aalg;

    return pgp_cipher_aead_set_ad(crypt, ad_data, 4);
}
#endif

static rnp_result_t
encrypted_add_password(rnp_symmetric_pass_info_t * pass,
                       pgp_dest_encrypted_param_t *param,
                       uint8_t *                   key,
                       const unsigned              keylen,
                       bool                        singlepass)
{
    pgp_sk_sesskey_t skey = {};
    unsigned         s2keylen; /* length of the s2k key */
    pgp_crypt_t      kcrypt;

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
            memcpy(key, pass->key.data(), s2keylen);
        } else {
            /* Currently we are using the same sym algo for key and stream encryption */
            skey.enckeylen = keylen + 1;
            skey.enckey[0] = param->ctx->ealg;
            memcpy(&skey.enckey[1], key, keylen);
            skey.alg = pass->s2k_cipher;
            if (!pgp_cipher_cfb_start(&kcrypt, skey.alg, pass->key.data(), NULL)) {
                RNP_LOG("key encryption failed");
                return RNP_ERROR_BAD_PARAMETERS;
            }
            pgp_cipher_cfb_encrypt(&kcrypt, skey.enckey, skey.enckey, skey.enckeylen);
            pgp_cipher_cfb_finish(&kcrypt);
        }
    } else {
#if !defined(ENABLE_AEAD)
        RNP_LOG("AEAD support is not enabled.");
        return RNP_ERROR_NOT_IMPLEMENTED;
#else
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
        if (!pgp_cipher_aead_init(&kcrypt, skey.alg, skey.aalg, pass->key.data(), false)) {
            return RNP_ERROR_BAD_PARAMETERS;
        }

        /* set additional data */
        if (!encrypted_sesk_set_ad(&kcrypt, &skey)) {
            return RNP_ERROR_BAD_STATE;
        }

        /* calculate nonce */
        uint8_t nonce[PGP_AEAD_MAX_NONCE_LEN];
        size_t  nlen = pgp_cipher_aead_nonce(skey.aalg, skey.iv, nonce, 0);

        /* start cipher, encrypt key and get tag */
        bool res = pgp_cipher_aead_start(&kcrypt, nonce, nlen) &&
                   pgp_cipher_aead_finish(&kcrypt, skey.enckey, key, keylen);

        pgp_cipher_aead_destroy(&kcrypt);

        if (!res) {
            return RNP_ERROR_BAD_STATE;
        }
#endif
    }

    /* Writing symmetric key encrypted session key packet */
    try {
        skey.write(*param->pkt.origdst);
    } catch (const std::exception &e) {
        return RNP_ERROR_WRITE;
    }
    return param->pkt.origdst->werr;
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
#if !defined(ENABLE_AEAD)
    RNP_LOG("AEAD support is not enabled.");
    return RNP_ERROR_NOT_IMPLEMENTED;
#else
    uint8_t hdr[4 + PGP_AEAD_MAX_NONCE_LEN];
    size_t  nlen;

    if (pgp_block_size(param->ctx->ealg) != 16) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* fill header */
    hdr[0] = 1;
    hdr[1] = param->ctx->ealg;
    hdr[2] = param->ctx->aalg;
    hdr[3] = param->ctx->abits;

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
    param->ad[0] = PGP_PKT_AEAD_ENCRYPTED | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
    memcpy(param->ad + 1, hdr, 4);
    memset(param->ad + 5, 0, 8);
    param->adlen = 13;

    /* initialize cipher */
    if (!pgp_cipher_aead_init(
          &param->encrypt, param->ctx->ealg, param->ctx->aalg, enckey, false)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    return encrypted_start_aead_chunk(param, 0, false);
#endif
}

static rnp_result_t
init_encrypted_dst(pgp_write_handler_t *handler, pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_encrypted_param_t *param;
    bool                        singlepass = true;
    unsigned                    pkeycount = 0;
    unsigned                    skeycount = 0;
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

        if ((handler->ctx->abits < 0) || (handler->ctx->abits > 56)) {
            RNP_LOG("wrong AEAD chunk bits");
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_dest_encrypted_param_t *) dst->param;
    param->has_mdc = true;
    param->aead = handler->ctx->aalg != PGP_AEAD_NONE;
    param->aalg = handler->ctx->aalg;
    param->ctx = handler->ctx;
    param->pkt.origdst = writedst;
    dst->write = param->aead ? encrypted_dst_write_aead : encrypted_dst_write_cfb;
    dst->finish = encrypted_dst_finish;
    dst->close = encrypted_dst_close;
    dst->type = PGP_STREAM_ENCRYPTED;

    pkeycount = handler->ctx->recipients.size();
    skeycount = handler->ctx->passwords.size();

    rnp::secure_array<uint8_t, PGP_MAX_KEY_SIZE> enckey; /* content encryption key */
    if (!pkeycount && !skeycount) {
        RNP_LOG("no recipients");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    if ((pkeycount > 0) || (skeycount > 1) || param->aead) {
        if (!rng_get_data(rnp_ctx_rng_handle(handler->ctx), enckey.data(), keylen)) {
            ret = RNP_ERROR_RNG;
            goto finish;
        }
        singlepass = false;
    }

    /* Configuring and writing pk-encrypted session keys */
    for (auto recipient : handler->ctx->recipients) {
        ret = encrypted_add_recipient(handler, dst, recipient, enckey.data(), keylen);
        if (ret) {
            goto finish;
        }
    }

    /* Configuring and writing sk-encrypted session key(s) */
    for (auto &passinfo : handler->ctx->passwords) {
        ret = encrypted_add_password(&passinfo, param, enckey.data(), keylen, singlepass);
        if (ret != RNP_SUCCESS) {
            goto finish;
        }
    }

    /* Initializing partial packet writer */
    param->pkt.partial = true;
    param->pkt.indeterminate = false;
    if (param->aead) {
        param->pkt.tag = PGP_PKT_AEAD_ENCRYPTED;
    } else {
        param->pkt.tag = param->has_mdc ? PGP_PKT_SE_IP_DATA : PGP_PKT_SE_DATA;
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
        ret = encrypted_start_aead(param, enckey.data());
    } else {
        /* initialize old CFB or CFB with MDC */
        ret = encrypted_start_cfb(param, enckey.data());
    }
finish:
    handler->ctx->passwords.clear();
    if (ret) {
        encrypted_dst_close(dst, true);
    }
    return ret;
}

static rnp_result_t
signed_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    pgp_dest_signed_param_t *param = (pgp_dest_signed_param_t *) dst->param;
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
        bool hashcrlf = false;
        ptr = buf + len - 1;

        /* skipping trailing characters - space, tab, carriage return, line feed */
        while ((ptr >= buf) && ((*ptr == CH_SPACE) || (*ptr == CH_TAB) || (*ptr == CH_CR) ||
                                (*ptr == CH_LF))) {
            if (*ptr == CH_LF) {
                hashcrlf = true;
            }
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
    const uint8_t *          linebg = (const uint8_t *) buf;
    size_t                   linelen;
    size_t                   cplen;
    bool                     eol;
    pgp_dest_signed_param_t *param = (pgp_dest_signed_param_t *) dst->param;

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
signed_fill_signature(pgp_dest_signed_param_t *param,
                      pgp_signature_t *        sig,
                      pgp_dest_signer_info_t * signer)
{
    const pgp_key_pkt_t *deckey = NULL;
    pgp_hash_t           hash;
    pgp_password_ctx_t   ctx = {.op = PGP_OP_SIGN, .key = signer->key};
    rnp_result_t         ret = RNP_ERROR_GENERIC;

    /* fill signature fields */
    try {
        sig->set_keyfp(signer->key->fp());
        sig->set_keyid(signer->key->keyid());
        sig->set_creation(signer->sigcreate ? signer->sigcreate : time(NULL));
        sig->set_expiration(signer->sigexpire);
    } catch (const std::exception &e) {
        RNP_LOG("failed to setup signature fields: %s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!signature_fill_hashed_data(sig)) {
        RNP_LOG("failed to fill the signature data");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (!pgp_hash_copy(&hash, pgp_hash_list_get(param->hashes, sig->halg))) {
        RNP_LOG("failed to obtain hash");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* decrypt the secret key if needed */
    if (signer->key->encrypted()) {
        deckey = pgp_decrypt_seckey(signer->key, param->password_provider, &ctx);
        if (!deckey) {
            RNP_LOG("wrong secret key password");
            pgp_hash_finish(&hash, NULL);
            return RNP_ERROR_BAD_PASSWORD;
        }
    } else {
        deckey = &signer->key->pkt();
    }

    /* calculate the signature */
    ret = signature_calculate(sig, &deckey->material, &hash, rnp_ctx_rng_handle(param->ctx));

    /* destroy decrypted secret key */
    if (signer->key->encrypted()) {
        delete deckey;
    }
    return ret;
}

static rnp_result_t
signed_write_signature(pgp_dest_signed_param_t *param,
                       pgp_dest_signer_info_t * signer,
                       pgp_dest_t *             writedst)
{
    pgp_signature_t sig;
    sig.version = (pgp_version_t) 4;
    if (signer->onepass.version) {
        sig.halg = signer->onepass.halg;
        sig.palg = signer->onepass.palg;
        sig.set_type(signer->onepass.type);
    } else {
        sig.halg = pgp_hash_adjust_alg_to_key(signer->halg, &signer->key->pkt());
        sig.palg = signer->key->alg();
        sig.set_type(param->ctx->detached ? PGP_SIG_BINARY : PGP_SIG_TEXT);
    }

    rnp_result_t ret = signed_fill_signature(param, &sig, signer);
    if (ret) {
        return ret;
    }
    try {
        sig.write(*writedst);
        return writedst->werr;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_WRITE;
    }
}

static rnp_result_t
signed_dst_finish(pgp_dest_t *dst)
{
    rnp_result_t             ret;
    pgp_dest_signed_param_t *param = (pgp_dest_signed_param_t *) dst->param;

    /* attached signature, we keep onepasses in order of signatures */
    for (auto &sinfo : param->siginfos) {
        if ((ret = signed_write_signature(param, &sinfo, param->writedst))) {
            RNP_LOG("failed to calculate signature");
            return ret;
        }
    }

    return RNP_SUCCESS;
}

static rnp_result_t
signed_detached_dst_finish(pgp_dest_t *dst)
{
    rnp_result_t             ret;
    pgp_dest_signed_param_t *param = (pgp_dest_signed_param_t *) dst->param;

    /* just calculating and writing signatures to the output */
    for (auto &sinfo : param->siginfos) {
        if ((ret = signed_write_signature(param, &sinfo, param->writedst))) {
            RNP_LOG("failed to calculate detached signature");
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
    pgp_dest_signed_param_t *param = (pgp_dest_signed_param_t *) dst->param;

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

    for (auto &sinfo : param->siginfos) {
        if ((ret = signed_write_signature(param, &sinfo, &armordst))) {
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
    pgp_dest_signed_param_t *param = (pgp_dest_signed_param_t *) dst->param;
    if (!param) {
        return;
    }
    delete param;
    dst->param = NULL;
}

static void
signed_dst_update(pgp_dest_t *dst, const void *buf, size_t len)
{
    pgp_dest_signed_param_t *param = (pgp_dest_signed_param_t *) dst->param;
    pgp_hash_list_update(param->hashes, buf, len);
}

static rnp_result_t
signed_add_signer(pgp_dest_signed_param_t *param, rnp_signer_info_t *signer, bool last)
{
    pgp_dest_signer_info_t sinfo = {};

    if (!signer->key->is_secret()) {
        RNP_LOG("secret key required for signing");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* copy fields */
    sinfo.key = signer->key;
    sinfo.sigcreate = signer->sigcreate;
    sinfo.sigexpire = signer->sigexpire;

    /* Add hash to the list */
    sinfo.halg = pgp_hash_adjust_alg_to_key(signer->halg, &signer->key->pkt());
    if (!pgp_hash_list_add(param->hashes, sinfo.halg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // Do not add onepass for detached/clearsign
    if (param->ctx->detached || param->ctx->clearsign) {
        sinfo.onepass.version = 0;
        try {
            param->siginfos.push_back(sinfo);
            return RNP_SUCCESS;
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }

    // Setup and add onepass
    sinfo.onepass.version = 3;
    sinfo.onepass.type = PGP_SIG_BINARY;
    sinfo.onepass.halg = sinfo.halg;
    sinfo.onepass.palg = sinfo.key->alg();
    sinfo.onepass.keyid = sinfo.key->keyid();
    sinfo.onepass.nested = false;
    try {
        param->siginfos.push_back(sinfo);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    // write onepasses in reverse order so signature order will match signers list
    if (!last) {
        return RNP_SUCCESS;
    }
    try {
        for (auto it = param->siginfos.rbegin(); it != param->siginfos.rend(); it++) {
            pgp_dest_signer_info_t &sinfo = *it;
            sinfo.onepass.nested = &sinfo == &param->siginfos.front();
            sinfo.onepass.write(*param->writedst);
        }
        return param->writedst->werr;
    } catch (const std::exception &e) {
        return RNP_ERROR_WRITE;
    }
}

pgp_dest_signed_param_t::~pgp_dest_signed_param_t()
{
    for (auto &hash : hashes) {
        pgp_hash_finish(&hash, NULL);
    }
}

static rnp_result_t
init_signed_dst(pgp_write_handler_t *handler, pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_signed_param_t *param;
    rnp_result_t             ret = RNP_ERROR_GENERIC;
    const char *             hname;

    if (!handler->key_provider) {
        RNP_LOG("no key provider");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!init_dst_common(dst, 0)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    try {
        param = new pgp_dest_signed_param_t();
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    dst->param = param;
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

    /* Getting signer's infos, writing one-pass signatures if needed */
    for (auto &sg : handler->ctx->signers) {
        ret = signed_add_signer(param, &sg, &sg == &handler->ctx->signers.back());
        if (ret) {
            RNP_LOG("failed to add one-pass signature for signer");
            goto finish;
        }
    }

    /* Do we have any signatures? */
    if (param->hashes.empty()) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* Writing headers for cleartext signed document */
    if (param->ctx->clearsign) {
        dst_write(param->writedst, ST_CLEAR_BEGIN, strlen(ST_CLEAR_BEGIN));
        dst_write(param->writedst, ST_CRLF, strlen(ST_CRLF));
        dst_write(param->writedst, ST_HEADER_HASH, strlen(ST_HEADER_HASH));

        for (const auto &hash : param->hashes) {
            hname = pgp_hash_name(&hash);
            dst_write(param->writedst, hname, strlen(hname));
            if (&hash != &param->hashes.back()) {
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
    pgp_dest_compressed_param_t *param = (pgp_dest_compressed_param_t *) dst->param;
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
    pgp_dest_compressed_param_t *param = (pgp_dest_compressed_param_t *) dst->param;

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
    }
#ifdef HAVE_BZLIB_H
    if (param->alg == PGP_C_BZIP2) {
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
    }
#endif

    if (param->pkt.writedst->werr) {
        return param->pkt.writedst->werr;
    }

    return finish_streamed_packet(&param->pkt);
}

static void
compressed_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_compressed_param_t *param = (pgp_dest_compressed_param_t *) dst->param;

    if (!param) {
        return;
    }

    if (param->zstarted) {
        if ((param->alg == PGP_C_ZIP) || (param->alg == PGP_C_ZLIB)) {
            deflateEnd(&param->z);
        }
#ifdef HAVE_BZLIB_H
        if (param->alg == PGP_C_BZIP2) {
            BZ2_bzCompressEnd(&param->bz);
        }
#endif
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

    param = (pgp_dest_compressed_param_t *) dst->param;
    dst->write = compressed_dst_write;
    dst->finish = compressed_dst_finish;
    dst->close = compressed_dst_close;
    dst->type = PGP_STREAM_COMPRESSED;
    param->alg = (pgp_compression_type_t) handler->ctx->zalg;
    param->pkt.partial = true;
    param->pkt.indeterminate = false;
    param->pkt.tag = PGP_PKT_COMPRESSED;

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
    pgp_dest_packet_param_t *param = (pgp_dest_packet_param_t *) dst->param;

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
    return finish_streamed_packet((pgp_dest_packet_param_t *) dst->param);
}

static void
literal_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_packet_param_t *param = (pgp_dest_packet_param_t *) dst->param;

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
    size_t                   flen = 0;
    uint8_t                  buf[4];

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_dest_packet_param_t *) dst->param;
    dst->write = literal_dst_write;
    dst->finish = literal_dst_finish;
    dst->close = literal_dst_close;
    dst->type = PGP_STREAM_LITERAL;
    param->partial = true;
    param->indeterminate = false;
    param->tag = PGP_PKT_LITDATA;

    /* initializing partial length or indeterminate packet, writing header */
    if (!init_streamed_packet(param, writedst)) {
        RNP_LOG("failed to init streamed packet");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }
    /* content type - forcing binary now */
    buf[0] = (uint8_t) 'b';
    /* filename */
    flen = handler->ctx->filename.size();
    if (flen > 255) {
        RNP_LOG("filename too long, truncating");
        flen = 255;
    }
    buf[1] = (uint8_t) flen;
    dst_write(param->writedst, buf, 2);
    if (flen) {
        dst_write(param->writedst, handler->ctx->filename.c_str(), flen);
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
    pgp_dest_t * sstream = NULL; /* signed stream if any, to call signed_dst_update on it */
    pgp_dest_t * wstream = NULL; /* stream to dst_write() source data, may be empty */
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (!(readbuf = (uint8_t *) calloc(1, PGP_INPUT_CACHE_SIZE))) {
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
        size_t read = 0;
        if (!src_read(src, readbuf, PGP_INPUT_CACHE_SIZE, &read)) {
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
    rnp_result_t ret = RNP_ERROR_GENERIC;

    /* pushing armoring stream, which will write to the output */
    if (handler->ctx->armor && !handler->ctx->clearsign) {
        pgp_armored_msg_t msgt =
          handler->ctx->detached ? PGP_ARMORED_SIGNATURE : PGP_ARMORED_MESSAGE;
        ret = init_armored_dst(&dests[destc], dst, msgt);
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

rnp_result_t
rnp_encrypt_sign_src(pgp_write_handler_t *handler, pgp_source_t *src, pgp_dest_t *dst)
{
    /* stack of the streams would be as following:
       [armoring stream] - if armoring is enabled
       [encrypting stream, partial writing stream]
       [compressing stream, partial writing stream] - compression is enabled
       signing stream
       literal data stream, partial writing stream
    */
    pgp_dest_t   dests[5];
    unsigned     destc = 0;
    rnp_result_t ret = RNP_SUCCESS;

    /* we may use only attached signatures here */
    if (handler->ctx->clearsign || handler->ctx->detached) {
        RNP_LOG("cannot clearsign or sign detached together with encryption");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* pushing armoring stream, which will write to the output */
    if (handler->ctx->armor) {
        ret = init_armored_dst(&dests[destc], dst, PGP_ARMORED_MESSAGE);
        if (ret != RNP_SUCCESS) {
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

    /* pushing signing stream */
    if ((ret = init_signed_dst(handler, &dests[destc], &dests[destc - 1]))) {
        goto finish;
    }
    destc++;

    /* pushing literal data stream */
    if ((ret = init_literal_dst(handler, &dests[destc], &dests[destc - 1]))) {
        goto finish;
    }
    destc++;

    /* process source with streams stack */
    ret = process_stream_sequence(src, dests, destc);
finish:
    for (int i = destc - 1; i >= 0; i--) {
        dst_close(&dests[i], ret != RNP_SUCCESS);
    }
    return ret;
}

rnp_result_t
rnp_compress_src(pgp_source_t &src, pgp_dest_t &dst, pgp_compression_type_t zalg, int zlevel)
{
    pgp_write_handler_t handler = {};
    rnp_ctx_t           ctx;
    ctx.zalg = zalg;
    ctx.zlevel = zlevel;
    handler.ctx = &ctx;

    pgp_dest_t   compressed = {};
    rnp_result_t ret = init_compressed_dst(&handler, &compressed, &dst);
    if (ret) {
        goto done;
    }
    ret = dst_write_src(&src, &compressed);
done:
    dst_close(&compressed, ret);
    return ret;
}

rnp_result_t
rnp_wrap_src(pgp_source_t &src, pgp_dest_t &dst, const std::string &filename, uint32_t modtime)
{
    pgp_write_handler_t handler = {};
    rnp_ctx_t           ctx;
    ctx.filename = filename;
    ctx.filemtime = modtime;
    handler.ctx = &ctx;

    pgp_dest_t   literal = {};
    rnp_result_t ret = init_literal_dst(&handler, &literal, &dst);
    if (ret) {
        goto done;
    }

    ret = dst_write_src(&src, &literal);
done:
    dst_close(&literal, ret);
    return ret;
}

rnp_result_t
rnp_raw_encrypt_src(pgp_source_t &src, pgp_dest_t &dst, const std::string &password)
{
    pgp_write_handler_t handler = {};
    rnp_ctx_t           ctx;
    rng_t               rng = {};

    if (!rng_init(&rng, RNG_SYSTEM)) {
        return RNP_ERROR_BAD_STATE;
    }
    ctx.rng = &rng;
    ctx.ealg = DEFAULT_PGP_SYMM_ALG;
    handler.ctx = &ctx;
    pgp_dest_t encrypted = {};

    rnp_result_t ret = rnp_ctx_add_encryption_password(
      ctx, password.c_str(), DEFAULT_PGP_HASH_ALG, DEFAULT_PGP_SYMM_ALG, 0);
    if (ret) {
        goto done;
    }

    ret = init_encrypted_dst(&handler, &encrypted, &dst);
    if (ret) {
        goto done;
    }

    ret = dst_write_src(&src, &encrypted);
done:
    dst_close(&encrypted, ret);
    rng_destroy(&rng);
    return ret;
}
