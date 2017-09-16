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
#include "defs.h"
#include "types.h"
#include "symmetric.h"
#include "crypto/s2k.h"
#include "crypto.h"
#include "misc.h"
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

/* 8192 bytes, as GnuPG */
#define PARTIAL_PKT_SIZE_BITS   (13)
#define PARTIAL_PKT_BLOCK_SIZE  (1 << PARTIAL_PKT_SIZE_BITS)

/* structure to write non-stream packets without need to precalculate the length */
typedef struct pgp_packet_body_t {
    int      tag;        /* packet tag */
    uint8_t *data;       /* packet body data */
    size_t   len;        /* current len of the data */
    size_t   allocated;  /* allocated bytes in data */
} pgp_packet_body_t;

/* common fields for encrypted, compressed and literal data */
typedef struct pgp_dest_packet_param_t {
    pgp_dest_t   *writedst;             /* source to write to, could be partial */
    pgp_dest_t   *origdst;              /* original dest passed to init_*_dst */
    bool          partial;              /* partial length packet */
    bool          indeterminate;        /* indeterminate length packet */
    int           tag;                  /* packet tag */
} pgp_dest_packet_param_t;

typedef struct pgp_dest_compressed_param_t {
    pgp_dest_packet_param_t pkt;
    pgp_compression_type_t  alg;
    union {
        z_stream  z;
        bz_stream bz;
    };
    bool                    zstarted; /* whether we initialize zlib/bzip2  */
    uint8_t                 cache[PGP_INPUT_CACHE_SIZE / 2]; /* pre-allocated cache for compression */
    size_t                  len; /* number of bytes cached */
} pgp_dest_compressed_param_t;

typedef struct pgp_dest_encrypted_param_t {
    pgp_dest_packet_param_t pkt;        /* underlying packet-related params */
    bool          has_mdc;              /* encrypted with mdc, i.e. tag 18 */
    pgp_crypt_t   encrypt;              /* encrypting crypto */
    pgp_hash_t    mdc;                  /* mdc SHA1 hash */
    uint8_t       cache[PGP_INPUT_CACHE_SIZE]; /* pre-allocated cache for encryption */
} pgp_dest_encrypted_param_t;

typedef struct pgp_dest_partial_param_t {
    pgp_dest_t *writedst;
    uint8_t     part[PARTIAL_PKT_BLOCK_SIZE];
    uint8_t     parthdr;    /* header byte for the current part */
    size_t      partlen;    /* length of the current part, up to PARTIAL_PKT_BLOCK_SIZE */
    size_t      len;        /* bytes cached in part */
} pgp_dest_partial_param_t;

bool init_packet_body(pgp_packet_body_t *body, int tag)
{
    body->data = malloc(16);
    if (!body->data) {
        return false;
    }
    body->allocated = 16;
    body->tag = tag;
    body->len = 0;
    return true;
}

bool add_packet_body(pgp_packet_body_t *body, void *data, size_t len)
{
    void * newdata;
    size_t newlen;

    if (body->len + len > body->allocated) {
        newlen = (body->len + len) * 2;
        newdata = realloc(body->data, newlen);
        if (!newdata) {
            return false;
        }
        body->data = newdata;
        body->allocated = newlen;
    }

    memcpy(body->data + body->len, data, len);
    body->len += len;

    return true;
}

bool add_packet_body_byte(pgp_packet_body_t *body, uint8_t byte)
{
    if (body->len < body->allocated) {
        body->data[body->len] = byte;
        body->len++;
        return true;
    } else {
        return add_packet_body(body, &byte, 1);
    }
}

size_t write_packet_len(uint8_t *buf, size_t len)
{
    if (len < 192) {
        buf[0] = len;
        return 1;
    } else if (len < 8192 + 192) {
        buf[0] = ((len - 192) >> 8) + 192;
        buf[1] = (len - 192) & 0xff;
        return 2;
    } else {
        buf[0] = 0xff;
        buf[1] = (uint8_t)(len >> 24);
        buf[2] = (uint8_t)(len >> 16);
        buf[3] = (uint8_t)(len >> 8);
        buf[4] = (uint8_t)(len);
        return 5;
    }
}

void flush_packet_body(pgp_packet_body_t *body, pgp_dest_t *dst)
{
    uint8_t hdr[6];
    size_t  hlen;

    hdr[0] = body->tag | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
    hlen = 1 + write_packet_len(&hdr[1], body->len);
    dst_write(dst, hdr, hlen);
    dst_write(dst, body->data, body->len);
    free(body->data);
}

void free_packet_body(pgp_packet_body_t *body)
{
    free(body->data);
    body->data = NULL;
}

void stream_write_pkt_tag(int tag, pgp_dest_t *dst)
{
    uint8_t bt;

    bt = tag | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
    dst_write(dst, &bt, 1);
}

void stream_write_indeterminate_pkt_tag(int tag, pgp_dest_t *dst)
{
    uint8_t bt;

    bt = ((tag & 0xf) << PGP_PTAG_OF_CONTENT_TAG_SHIFT) | PGP_PTAG_OLD_LEN_INDETERMINATE;
    dst_write(dst, &bt, 1);
}

void partial_dst_write(pgp_dest_t *dst, void *buf, size_t len)
{
    pgp_dest_partial_param_t *param = dst->param;
    int                       wrlen;
    
    if (!param) {
        (void) fprintf(stderr, "partial_dst_write: wrong param\n");
        dst->werr = RNP_ERROR_BAD_PARAMETERS;
        return;
    }

    if (len > param->partlen - param->len) {
        /* we have full part - in block and in buf */
        wrlen = param->partlen - param->len;
        dst_write(param->writedst, &param->parthdr, 1);
        dst_write(param->writedst, param->part, param->len);
        dst_write(param->writedst, buf, wrlen);

        buf = (uint8_t*)buf + wrlen;
        len -= wrlen;
        param->len = 0;

        /* writing all full parts directly from buf */
        while (len >= param->partlen) {
            dst_write(param->writedst, &param->parthdr, 1);
            dst_write(param->writedst, buf, param->partlen);
            buf = (uint8_t*)buf + param->partlen;
            len -= param->partlen;
        }
    }

    /* caching rest of the buf */
    if (len > 0) {
        memcpy(&param->part[param->len], buf, len);
        param->len += len;
    }

    dst->werr = RNP_SUCCESS;
}

void partial_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_partial_param_t *param = dst->param;
    uint8_t hdr[5];
    int     lenlen;

    if (!param) {
        return;
    }

    if (!discard) {
        lenlen = write_packet_len(hdr, param->len);
        dst_write(param->writedst, hdr, lenlen);
        dst_write(param->writedst, param->part, param->len);
    }

    free(param);
    dst->param = NULL;
}

pgp_errcode_t init_partial_pkt_dst(pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_partial_param_t *param;

    if ((param = calloc(1, sizeof(*param))) == NULL) {
        (void) fprintf(stderr, "init_partial_pkt_dst: allocation failed\n");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param->writedst = writedst;
    param->partlen = PARTIAL_PKT_BLOCK_SIZE;
    param->parthdr = 0xE0 | PARTIAL_PKT_SIZE_BITS;
    param->len = 0;
    dst->param = param;
    dst->writefunc = partial_dst_write;
    dst->closefunc = partial_dst_close;
    dst->type = PGP_STREAM_PARLEN_PACKET;

    return RNP_SUCCESS;
}

/** @brief helper function for streamed packets (literal, encrypted and compressed).
 *  Allocates part len destination if needed and writes header
 **/
bool init_streamed_packet(pgp_dest_packet_param_t *param, pgp_dest_t *dst)
{
    pgp_errcode_t ret;

    if (param->partial) {
        stream_write_pkt_tag(param->tag, dst);

        if ((param->writedst = calloc(1, sizeof(*param->writedst))) == NULL) {
            (void) fprintf(stderr, "init_streamed_packet: part len dest allocation failed\n");
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
            (void) fprintf(stderr, "init_streamed_packet: tag > 0xf for indeterminate packet\n");
        }
        stream_write_indeterminate_pkt_tag(param->tag, dst);
        param->writedst = dst;
        param->origdst = dst;
    } else {
        (void) fprintf(stderr, "init_streamed_packet: wrong call\n");
        return false;
    }

    return true;
}

void close_streamed_packet(pgp_dest_packet_param_t *param, bool discard)
{
    if (param->partial) {
        dst_close(param->writedst, discard);
        free(param->writedst);
        param->writedst = NULL;
    }
}

bool stream_write_sk_sesskey(pgp_sk_sesskey_t *skey, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;
    
    if (!init_packet_body(&pktbody, PGP_PTAG_CT_SK_SESSION_KEY)) {
        return false;
    }

    res = add_packet_body_byte(&pktbody, 4) &&
          add_packet_body_byte(&pktbody, skey->alg) &&
          add_packet_body_byte(&pktbody, skey->s2k_specifier) &&
          add_packet_body_byte(&pktbody, skey->hash_alg);

    switch (skey->s2k_specifier) {
        case PGP_S2KS_SIMPLE:
            break;
        case PGP_S2KS_SALTED:
            res = res && add_packet_body(&pktbody, skey->salt, sizeof(skey->salt));
            break;
        case PGP_S2KS_ITERATED_AND_SALTED:
            res = res && add_packet_body(&pktbody, skey->salt, sizeof(skey->salt)) &&
                         add_packet_body_byte(&pktbody, skey->s2k_iterations);
            break;
    }

    if (skey->enckeylen > 0) {
        res = res && add_packet_body(&pktbody, skey->enckey, skey->enckeylen);
    }

    if (res) {
        flush_packet_body(&pktbody, dst);
        return true;
    } else {
        free_packet_body(&pktbody);
        return false;
    }
}

void encrypted_dst_write(pgp_dest_t *dst, void *buf, size_t len)
{
    pgp_dest_encrypted_param_t *param = dst->param;
    size_t sz;
    
    if (!param) {
        (void) fprintf(stderr, "encrypted_dst_write: wrong param\n");
        dst->werr = RNP_ERROR_BAD_PARAMETERS;
        return;
    }

    if (param->has_mdc) {
        pgp_hash_add(&param->mdc, buf, len);
    }

    while (len > 0) {
        sz = len > sizeof(param->cache) ? sizeof(param->cache) : len;
        pgp_cipher_cfb_encrypt(&param->encrypt, param->cache, buf, sz);
        dst_write(param->pkt.writedst, param->cache, sz);
        len -= sz;
        buf = (uint8_t*)buf + sz;
    }

    dst->werr = RNP_SUCCESS;
}

void encrypted_dst_close(pgp_dest_t *dst, bool discard)
{
    uint8_t mdcbuf[MDC_V1_SIZE];
    pgp_dest_encrypted_param_t *param = dst->param;
    if (!param) {
        return;
    }

    if (param->has_mdc) {
        if (!discard) {
            mdcbuf[0] = MDC_PKT_TAG;
            mdcbuf[1] = MDC_V1_SIZE - 2;
            pgp_hash_add(&param->mdc, mdcbuf, 2);
            pgp_hash_finish(&param->mdc, &mdcbuf[2]);
            pgp_cipher_cfb_encrypt(&param->encrypt, mdcbuf, mdcbuf, MDC_V1_SIZE);
            dst_write(param->pkt.writedst, mdcbuf, MDC_V1_SIZE);
        } else if (param->mdc.handle) {
            pgp_hash_finish(&param->mdc, mdcbuf);
        }
    }

    close_streamed_packet(&param->pkt, discard);
    free(param);
    dst->param = NULL;
}

pgp_errcode_t init_encrypted_dst(pgp_write_handler_t *handler, pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_encrypted_param_t *param;
    pgp_sk_sesskey_t            skey = {0};
    pgp_crypt_t                 kcrypt;
    int                         pkeycount = 0;
    uint8_t                     enckey[PGP_MAX_KEY_SIZE];  /* content encryption key */
    uint8_t                     s2key[PGP_MAX_KEY_SIZE];   /* s2k calculated key */
    uint8_t                     enchdr[PGP_MAX_BLOCK_SIZE + 2]; /* encrypted header */
    uint8_t                     mdcver = 1;
    char                        passphrase[MAX_PASSPHRASE_LENGTH] = {0};
    int                         keylen;
    int                         blsize;
    pgp_symm_alg_t              ealg;  /* content encryption algorithm */
    pgp_errcode_t               ret = RNP_SUCCESS;

    /* currently we implement only single-password symmetric encryption */

    ealg = handler->ctx->ealg;
    keylen = pgp_key_size(ealg);
    if (!keylen) {
        (void) fprintf(stderr, "init_encrypted_dst: unknown symmetric algorithm\n");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if ((param = calloc(1, sizeof(*param))) == NULL) {
        (void) fprintf(stderr, "init_encrypted_dst: allocation failed\n");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    dst->param = param;
    dst->writefunc = encrypted_dst_write;
    dst->closefunc = encrypted_dst_close;
    dst->type = PGP_STREAM_ENCRYPTED;
    param->has_mdc = true;

    /* configuring and writing sym-encrypted session key */

    skey.version = 4;
    skey.alg = ealg;
    skey.s2k_specifier = PGP_S2KS_ITERATED_AND_SALTED;
    skey.s2k_iterations = pgp_s2k_encode_iterations(PGP_S2K_DEFAULT_ITERATIONS);
    skey.hash_alg = handler->ctx->halg == PGP_HASH_UNKNOWN ? PGP_HASH_SHA256 : handler->ctx->halg;
    pgp_random(skey.salt, sizeof(skey.salt));

    if (!pgp_request_passphrase(handler->passphrase_provider, &(pgp_passphrase_ctx_t){.op = PGP_OP_ENCRYPT_SYM, .pubkey = NULL, .key_type = 0}, passphrase, sizeof(passphrase))) {
        (void) fprintf(stderr, "init_encrypted_dst: no encryption passphrase\n");
        ret = RNP_ERROR_BAD_PASSPHRASE;
        goto finish;
    }

    if (pgp_s2k_iterated(skey.hash_alg, s2key, keylen, passphrase, skey.salt, pgp_s2k_decode_iterations(skey.s2k_iterations))) {
        (void) fprintf(stderr, "init_encrypted_dst: s2k failed\n");
        ret = RNP_ERROR_GENERIC;
        goto finish;
    }

    if (pkeycount == 0) {
        /* if there are no public keys then we do not encrypt session key in the packet */
        skey.enckeylen = 0;
        memcpy(enckey, s2key, keylen);
    } else {
        /* Currently we are using the same sym algo for key and stream encryption */
        pgp_random(enckey, keylen);
        skey.enckeylen = keylen + 1;
        skey.enckey[0] = skey.alg;
        memcpy(&skey.enckey[1], enckey, keylen);
        if (!pgp_cipher_start(&kcrypt, skey.alg, s2key, NULL)) {
            (void) fprintf(stderr, "init_encrypted_dst: key encryption failed\n");
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto finish;
        }
        pgp_cipher_cfb_encrypt(&kcrypt, skey.enckey, skey.enckey, skey.enckeylen);
        pgp_cipher_finish(&kcrypt);
    }

    /* writing session key packet */
    if (!stream_write_sk_sesskey(&skey, writedst)) {
        goto finish;
    }

    param->pkt.partial = true;
    param->pkt.indeterminate = false;
    param->pkt.tag = param->has_mdc ? PGP_PTAG_CT_SE_IP_DATA : PGP_PTAG_CT_SE_DATA;

    /* initializing partial data length writer */
    /* we may use intederminate len packet here as well, for compatibility or so on */
    if (!init_streamed_packet(&param->pkt, writedst)) {
        (void) fprintf(stderr, "init_encrypted_dst: failed to init streamed packet\n");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* initializing the mdc */
    if (param->has_mdc) {
        dst_write(param->pkt.writedst, &mdcver, 1);

        if (!pgp_hash_create(&param->mdc, PGP_HASH_SHA1)) {
            (void) fprintf(stderr, "init_encrypted_dst: cannot create sha1 hash\n");
            ret = RNP_ERROR_GENERIC;
            goto finish;
        }
    }

    /* initializing the crypto */
    if (!pgp_cipher_start(&param->encrypt, ealg, enckey, NULL)) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* generating and writing iv/password check bytes */
    blsize = pgp_block_size(ealg);
    pgp_random(enchdr, blsize);
    enchdr[blsize] = enchdr[blsize - 2];
    enchdr[blsize + 1] = enchdr[blsize - 1];
    if (param->has_mdc) {
        pgp_hash_add(&param->mdc, enchdr, blsize + 2);
    }    
    pgp_cipher_cfb_encrypt(&param->encrypt, enchdr, enchdr, blsize + 2);
    /* RFC 4880, 5.13: Unlike the Symmetrically Encrypted Data Packet, no special CFB resynchronization is done after encrypting this prefix data. */
    if (!param->has_mdc) {
        pgp_cipher_cfb_resync_v2(&param->encrypt);
    }
    dst_write(param->pkt.writedst, enchdr, blsize + 2);

    finish:
    pgp_forget(enckey, sizeof(enckey));
    pgp_forget(s2key, sizeof(s2key));
    pgp_forget(passphrase, sizeof(passphrase));
    if (ret != RNP_SUCCESS) {
        encrypted_dst_close(dst, true);
    }

    return ret;
}

void compressed_dst_write(pgp_dest_t *dst, void *buf, size_t len)
{
    pgp_dest_compressed_param_t *param = dst->param;
    int zret;
    
    if (!param) {
        (void) fprintf(stderr, "compressed_dst_write: wrong param\n");
        dst->werr = RNP_ERROR_BAD_PARAMETERS;
        return;
    }

    if ((param->alg == PGP_C_ZIP) || (param->alg == PGP_C_ZLIB)) {
        param->z.next_in = buf;
        param->z.avail_in = len;
        param->z.next_out = param->cache + param->len;
        param->z.avail_out = sizeof(param->cache) - param->len;
    
        while (param->z.avail_in > 0) {
            zret = deflate(&param->z, Z_NO_FLUSH);
            /* Z_OK, Z_BUF_ERROR are ok for us, Z_STREAM_END will not happen here */
            if (zret == Z_STREAM_ERROR) {
                (void) fprintf(stderr, "compressed_dst_write: wrong deflate state\n");
                dst->werr = RNP_ERROR_BAD_STATE;
                return;
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
    } else if (param->alg == PGP_C_BZIP2) {
        #ifdef HAVE_BZLIB_H
        param->bz.next_in = buf;
        param->bz.avail_in = len;
        param->bz.next_out = (char*)(param->cache + param->len);
        param->bz.avail_out = sizeof(param->cache) - param->len;
    
        while (param->bz.avail_in > 0) {
            zret = BZ2_bzCompress(&param->bz, BZ_RUN);
            if (zret != BZ_OK) {
                (void) fprintf(stderr, "compressed_dst_write: wrong bzip2 state\n");
                dst->werr = RNP_ERROR_BAD_STATE;
                return;
            }
    
            /* writing only full blocks, the rest will be written in close */
            if (param->bz.avail_out == 0) {
                dst_write(param->pkt.writedst, param->cache, sizeof(param->cache));
                param->len = 0;
                param->bz.next_out = (char*)param->cache;
                param->bz.avail_out = sizeof(param->cache);
            }
        }

        param->len = sizeof(param->cache) - param->bz.avail_out;
        #endif
    }
    else {
        (void) fprintf(stderr, "compressed_dst_write: unknown algorithm\n");
        dst->werr = RNP_ERROR_BAD_PARAMETERS;
    }
}

void compressed_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_compressed_param_t *param = dst->param;
    int zret;

    if (!param) {
        return;
    }

    if (!discard) {
        if ((param->alg == PGP_C_ZIP) || (param->alg == PGP_C_ZLIB)) {
            param->z.next_in = Z_NULL;
            param->z.avail_in = 0;
            param->z.next_out = param->cache + param->len;
            param->z.avail_out = sizeof(param->cache) - param->len;
            do {
                zret = deflate(&param->z, Z_FINISH);
    
                if (zret == Z_STREAM_ERROR) {
                    (void) fprintf(stderr, "compressed_dst_close: wrong deflate state\n");
                    break;
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
            param->bz.next_out = (char*)(param->cache + param->len);
            param->bz.avail_out = sizeof(param->cache) - param->len;
        
            do {
                zret = BZ2_bzCompress(&param->bz, BZ_FINISH);
                if ((zret != BZ_OK) && (zret != BZ_STREAM_END)) {
                    (void) fprintf(stderr, "compressed_dst_write: wrong bzip2 state %d\n", zret);
                    dst->werr = RNP_ERROR_BAD_STATE;
                    return;
                }
        
                /* writing only full blocks, the rest will be written in close */
                if (param->bz.avail_out == 0) {
                    dst_write(param->pkt.writedst, param->cache, sizeof(param->cache));
                    param->len = 0;
                    param->bz.next_out = (char*)param->cache;
                    param->bz.avail_out = sizeof(param->cache);
                }
            } while (zret != BZ_STREAM_END);

            param->len = sizeof(param->cache) - param->bz.avail_out;
            dst_write(param->pkt.writedst, param->cache, param->len);
            #endif
        }
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

pgp_errcode_t init_compressed_dst(pgp_write_handler_t *handler, pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_compressed_param_t *param;
    pgp_errcode_t                ret = RNP_SUCCESS;
    uint8_t                      buf;
    int                          zret;

    /* setting up param */
    if ((param = calloc(1, sizeof(*param))) == NULL) {
        (void) fprintf(stderr, "init_compressed_dst: allocation failed\n");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    dst->param = param;
    dst->writefunc = compressed_dst_write;
    dst->closefunc = compressed_dst_close;
    dst->type = PGP_STREAM_COMPRESSED;
    param->alg = handler->ctx->zalg;
    param->len = 0;
    param->pkt.partial = true;
    param->pkt.indeterminate = false;
    param->pkt.tag = PGP_PTAG_CT_COMPRESSED;

    /* initializing partial length or indeterminate packet, writing header */
    if (!init_streamed_packet(&param->pkt, writedst)) {
        (void) fprintf(stderr, "init_compressed_dst: failed to init streamed packet\n");
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
                zret = deflateInit2(&param->z, handler->ctx->zlevel, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
            } else {
                zret = deflateInit(&param->z, handler->ctx->zlevel);
            }

            if (zret != Z_OK) {
                (void) fprintf(stderr, "init_compressed_dst: failed to init zlib, error %d\n", zret);
                ret = RNP_ERROR_NOT_SUPPORTED;
                goto finish;
            }
            break;
#ifdef HAVE_BZLIB_H
        case PGP_C_BZIP2:
            (void) memset(&param->bz, 0x0, sizeof(param->bz));
            zret = BZ2_bzCompressInit(&param->bz, handler->ctx->zlevel, 0, 0);
            if (zret != BZ_OK) {
                (void) fprintf(stderr, "init_compressed_dst: failed to init bz, error %d\n", zret);
                ret = RNP_ERROR_NOT_SUPPORTED;
                goto finish;
            }
            break;
#endif
        default:
            (void) fprintf(stderr, "init_compressed_dst: unknown compression algorithm\n");
            ret = RNP_ERROR_NOT_SUPPORTED;
            goto finish;
    }
    param->zstarted = true;
    
    finish:
    if (ret != RNP_SUCCESS) {
        compressed_dst_close(dst, true);
    }

    return ret;
}

void literal_dst_write(pgp_dest_t *dst, void *buf, size_t len)
{
    pgp_dest_packet_param_t *param = dst->param;
    
    if (!param) {
        (void) fprintf(stderr, "literal_dst_write: wrong param\n");
        dst->werr = RNP_ERROR_BAD_PARAMETERS;
        return;
    }

    dst_write(param->writedst, buf, len);
    dst->werr = RNP_SUCCESS;
}

void literal_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_packet_param_t *param = dst->param;

    if (!param) {
        return;
    }

    close_streamed_packet(param, discard);
    free(param);
    dst->param = NULL;
}

pgp_errcode_t init_literal_dst(pgp_write_handler_t *handler, pgp_dest_t *dst, pgp_dest_t *writedst)
{
    pgp_dest_packet_param_t *param;
    pgp_errcode_t            ret = RNP_SUCCESS;
    int                      flen;
    uint8_t                  buf[4];

    if ((param = calloc(1, sizeof(*param))) == NULL) {
        (void) fprintf(stderr, "init_literal_dst: allocation failed\n");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    dst->param = param;
    dst->writefunc = literal_dst_write;
    dst->closefunc = literal_dst_close;
    dst->type = PGP_STREAM_LITERAL;
    param->partial = true;
    param->indeterminate = false;
    param->tag = PGP_PTAG_CT_LITDATA;

    /* initializing partial length or indeterminate packet, writing header */
    if (!init_streamed_packet(param, writedst)) {
        (void) fprintf(stderr, "init_literal_dst: failed to init streamed packet\n");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }
    /* content type - forcing binary now */
    buf[0] = (uint8_t)'b';
    /* filename */
    if (handler->ctx->filename) {
        flen = strlen(handler->ctx->filename);
        if (flen > 255) {
            (void) fprintf(stderr, "init_literal_dst: filename too long, truncating\n");
            flen = 255;
        }
    } else {
        flen = 0;
    }
    buf[1] = (uint8_t)flen;
    dst_write(param->writedst, buf, 2);
    if (flen > 0) {
        dst_write(param->writedst, handler->ctx->filename, flen);
    }
    /* timestamp */
    buf[0] = (uint8_t)(handler->ctx->filemtime >> 24);
    buf[1] = (uint8_t)(handler->ctx->filemtime >> 16);
    buf[2] = (uint8_t)(handler->ctx->filemtime >> 8);
    buf[3] = (uint8_t)(handler->ctx->filemtime);
    dst_write(param->writedst, buf, 4);
    
    finish:
    if (ret != RNP_SUCCESS) {
        literal_dst_close(dst, true);
    }

    return ret;
}

pgp_errcode_t init_armored_dst(pgp_write_handler_t *handler, pgp_dest_t *dst, pgp_dest_t *writedst)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

pgp_errcode_t rnp_encrypt_src(pgp_write_handler_t *handler, pgp_source_t *src, pgp_dest_t *dst)
{
    /* stack of the streams would be as following:
       [armoring stream] - if armoring is enabled
       encrypting stream, partial writing stream
       [compressing stream, partial writing stream] - if compression is enabled
       literal data stream, partial writing stream
    */
    uint8_t       readbuf[PGP_INPUT_CACHE_SIZE];
    ssize_t       read;
    pgp_dest_t    dests[4];
    int           destc = 0;
    pgp_errcode_t ret = RNP_SUCCESS;
    bool          discard;

    /* pushing armoring stream, which will write to the output */
    if (handler->ctx->armour) {
        ret = init_armored_dst(handler, &dests[destc], dst);
        if (ret != RNP_SUCCESS) {
            goto finish;
        }
        destc++;
    }

    /* pushing encrypting stream, which will write to the output or armoring stream */
    ret = init_encrypted_dst(handler, &dests[destc], destc ? &dests[destc - 1] : dst);
    if (ret != RNP_SUCCESS) {
        goto finish;
    }
    destc++;

    /* if compression is enabled then pushing compressing stream */
    if (handler->ctx->zlevel > 0) {
        ret = init_compressed_dst(handler, &dests[destc], &dests[destc - 1]);
        if (ret != RNP_SUCCESS) {
            goto finish;
        }
        destc++;
    }

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
            (void) fprintf(stderr, "rnp_encrypt_src: failed to read from source\n");
            ret = RNP_ERROR_READ;
            goto finish;
        }

        if (read > 0) {
            dst_write(&dests[destc - 1], readbuf, read);

            for (int i = destc - 1; i >=0; i--) {
                if (dests[i].werr != RNP_SUCCESS) {
                    (void) fprintf(stderr, "rnp_encrypt_src: failed to output data\n");
                    ret = RNP_ERROR_WRITE;
                    goto finish;
                }
            }
        }
    }

    finish:
    discard = ret != RNP_SUCCESS;
    for (int i = destc - 1; i >= 0 ; i--) {
        dst_close(&dests[i], discard);
    }

    return ret;
}
