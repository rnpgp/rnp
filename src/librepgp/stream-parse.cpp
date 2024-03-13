/*
 * Copyright (c) 2017-2023, [Ribose Inc](https://www.ribose.com).
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
#include <string.h>
#include <string>
#include <vector>
#include <time.h>
#include <cinttypes>
#include <cassert>
#include <rnp/rnp_def.h>
#include "stream-ctx.h"
#include "stream-def.h"
#include "stream-parse.h"
#include "stream-armor.h"
#include "stream-packet.h"
#include "stream-sig.h"
#include "str-utils.h"
#include "types.h"
#include "crypto/s2k.h"
#include "crypto.h"
#include "crypto/signatures.h"
#include "fingerprint.h"
#include "pgp-key.h"

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

typedef enum pgp_message_t {
    PGP_MESSAGE_UNKNOWN = 0,
    PGP_MESSAGE_NORMAL,
    PGP_MESSAGE_DETACHED,
    PGP_MESSAGE_CLEARTEXT
} pgp_message_t;

typedef struct pgp_processing_ctx_t {
    pgp_parse_handler_t     handler;
    pgp_source_t *          signed_src;
    pgp_source_t *          literal_src;
    pgp_message_t           msg_type;
    pgp_dest_t              output;
    std::list<pgp_source_t> sources;

    ~pgp_processing_ctx_t();
} pgp_processing_ctx_t;

/* common fields for encrypted, compressed and literal data */
typedef struct pgp_source_packet_param_t {
    pgp_source_t *   readsrc; /* source to read from, could be partial*/
    pgp_source_t *   origsrc; /* original source passed to init_*_src */
    pgp_packet_hdr_t hdr;     /* packet header info */
} pgp_source_packet_param_t;

typedef struct pgp_source_encrypted_param_t {
    pgp_source_packet_param_t     pkt{};     /* underlying packet-related params */
    std::vector<pgp_sk_sesskey_t> symencs;   /* array of sym-encrypted session keys */
    std::vector<pgp_pk_sesskey_t> pubencs;   /* array of pk-encrypted session keys */
    rnp::AuthType                 auth_type; /* Authentication type */
    bool        auth_validated{};            /* Auth tag (MDC or AEAD) was already validated */
    pgp_crypt_t decrypt{};                   /* decrypting crypto */
    std::unique_ptr<rnp::Hash> mdc;          /* mdc SHA1 hash */
    size_t                     chunklen{};   /* size of AEAD chunk in bytes */
    size_t                     chunkin{};    /* number of bytes read from the current chunk */
    size_t                     chunkidx{};   /* index of the current chunk */
    uint8_t                    cache[PGP_AEAD_CACHE_LEN]; /* read cache */
    size_t                     cachelen{};                /* number of bytes in the cache */
    size_t                     cachepos{}; /* index of first unread byte in the cache */
    pgp_aead_hdr_t             aead_hdr;   /* AEAD encryption parameters */
    uint8_t                    aead_ad[PGP_AEAD_MAX_AD_LEN]; /* additional data */
    size_t                     aead_adlen{}; /* length of the additional data */
    pgp_symm_alg_t             salg;         /* data encryption algorithm */
    pgp_parse_handler_t *      handler{};    /* parsing handler with callbacks */

    pgp_source_encrypted_param_t() : auth_type(rnp::AuthType::None), salg(PGP_SA_UNKNOWN)
    {
    }

    bool
    use_cfb()
    {
        return auth_type != rnp::AuthType::AEADv1;
    }
} pgp_source_encrypted_param_t;

typedef struct pgp_source_signed_param_t {
    pgp_parse_handler_t *handler;         /* parsing handler with callbacks */
    pgp_source_t *       readsrc;         /* source to read from */
    bool                 detached;        /* detached signature */
    bool                 cleartext;       /* source is cleartext signed */
    bool                 clr_eod;         /* cleartext data is over */
    bool                 clr_fline;       /* first line of the cleartext */
    bool                 clr_mline;       /* in the middle of the very long line */
    uint8_t              out[CT_BUF_LEN]; /* cleartext output cache for easier parsing */
    size_t               outlen;          /* total bytes in out */
    size_t               outpos;          /* offset of first available byte in out */
    bool                 max_line_warn;   /* warning about too long line is already issued */
    size_t               text_line_len;   /* length of a current line in a text document */
    long stripped_crs; /* number of trailing CR characters stripped from the end of the last
                          processed chunk */

    std::vector<pgp_one_pass_sig_t>   onepasses;  /* list of one-pass singatures */
    std::list<pgp_signature_t>        sigs;       /* list of signatures */
    std::vector<pgp_signature_info_t> siginfos;   /* signature validation info */
    rnp::HashList                     hashes;     /* hash contexts */
    rnp::HashList                     txt_hashes; /* hash contexts for text-mode sigs */

    pgp_source_signed_param_t() = default;
    ~pgp_source_signed_param_t() = default;
} pgp_source_signed_param_t;

typedef struct pgp_source_compressed_param_t {
    pgp_source_packet_param_t pkt; /* underlying packet-related params */
    pgp_compression_type_t    alg;
    union {
        z_stream  z;
        bz_stream bz;
    };
    uint8_t in[PGP_INPUT_CACHE_SIZE / 2];
    size_t  inpos;
    size_t  inlen;
    bool    zend;
} pgp_source_compressed_param_t;

typedef struct pgp_source_literal_param_t {
    pgp_source_packet_param_t pkt; /* underlying packet-related params */
    pgp_literal_hdr_t         hdr; /* literal packet fields */
} pgp_source_literal_param_t;

typedef struct pgp_source_partial_param_t {
    pgp_source_t *readsrc; /* source to read from */
    int           type;    /* type of the packet */
    size_t        psize;   /* size of the current part */
    size_t        pleft;   /* bytes left to read from the current part */
    bool          last;    /* current part is last */
} pgp_source_partial_param_t;

static bool
is_pgp_source(pgp_source_t &src)
{
    uint8_t buf;
    if (!src_peek_eq(&src, &buf, 1)) {
        return false;
    }

    switch (get_packet_type(buf)) {
    case PGP_PKT_PK_SESSION_KEY:
    case PGP_PKT_SK_SESSION_KEY:
    case PGP_PKT_ONE_PASS_SIG:
    case PGP_PKT_SIGNATURE:
    case PGP_PKT_SE_DATA:
    case PGP_PKT_SE_IP_DATA:
    case PGP_PKT_COMPRESSED:
    case PGP_PKT_LITDATA:
    case PGP_PKT_MARKER:
        return true;
    default:
        return false;
    }
}

static bool
partial_pkt_src_read(pgp_source_t *src, void *buf, size_t len, size_t *readres)
{
    if (src->eof) {
        *readres = 0;
        return true;
    }

    pgp_source_partial_param_t *param = (pgp_source_partial_param_t *) src->param;
    if (!param) {
        return false;
    }

    size_t read;
    size_t write = 0;
    while (len > 0) {
        if (!param->pleft && param->last) {
            // we have the last chunk
            *readres = write;
            return true;
        }
        if (!param->pleft) {
            // reading next chunk
            if (!stream_read_partial_chunk_len(param->readsrc, &read, &param->last)) {
                return false;
            }
            param->psize = read;
            param->pleft = read;
        }

        if (!param->pleft) {
            *readres = write;
            return true;
        }

        read = param->pleft > len ? len : param->pleft;
        if (!src_read(param->readsrc, buf, read, &read)) {
            RNP_LOG("failed to read data chunk");
            return false;
        }
        if (!read) {
            RNP_LOG("unexpected eof");
            *readres = write;
            return true;
        }
        write += read;
        len -= read;
        buf = (uint8_t *) buf + read;
        param->pleft -= read;
    }

    *readres = write;
    return true;
}

static void
partial_pkt_src_close(pgp_source_t *src)
{
    pgp_source_partial_param_t *param = (pgp_source_partial_param_t *) src->param;
    if (param) {
        free(src->param);
        src->param = NULL;
    }
}

static rnp_result_t
init_partial_pkt_src(pgp_source_t *src, pgp_source_t *readsrc, pgp_packet_hdr_t &hdr)
{
    pgp_source_partial_param_t *param;
    if (!init_src_common(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    assert(hdr.partial);
    /* we are sure that header is indeterminate */
    param = (pgp_source_partial_param_t *) src->param;
    param->type = hdr.tag;
    param->psize = get_partial_pkt_len(hdr.hdr[1]);
    param->pleft = param->psize;
    param->last = false;
    param->readsrc = readsrc;

    src->read = partial_pkt_src_read;
    src->close = partial_pkt_src_close;
    src->type = PGP_STREAM_PARLEN_PACKET;

    if (param->psize < PGP_PARTIAL_PKT_FIRST_PART_MIN_SIZE) {
        RNP_LOG("first part of partial length packet sequence has size %d and that's less "
                "than allowed by the protocol",
                (int) param->psize);
    }

    return RNP_SUCCESS;
}

static bool
literal_src_read(pgp_source_t *src, void *buf, size_t len, size_t *read)
{
    pgp_source_literal_param_t *param = (pgp_source_literal_param_t *) src->param;
    if (!param) {
        return false;
    }
    return src_read(param->pkt.readsrc, buf, len, read);
}

static void
literal_src_close(pgp_source_t *src)
{
    pgp_source_literal_param_t *param = (pgp_source_literal_param_t *) src->param;
    if (param) {
        if (param->pkt.hdr.partial) {
            src_close(param->pkt.readsrc);
            free(param->pkt.readsrc);
            param->pkt.readsrc = NULL;
        }

        free(src->param);
        src->param = NULL;
    }
}

static bool
compressed_src_read(pgp_source_t *src, void *buf, size_t len, size_t *readres)
{
    pgp_source_compressed_param_t *param = (pgp_source_compressed_param_t *) src->param;
    if (!param) {
        return false;
    }

    if (src->eof || param->zend) {
        *readres = 0;
        return true;
    }

    if (param->alg == PGP_C_NONE) {
        if (!src_read(param->pkt.readsrc, buf, len, readres)) {
            RNP_LOG("failed to read uncompressed data");
            return false;
        }
        return true;
    }
    if ((param->alg == PGP_C_ZIP) || (param->alg == PGP_C_ZLIB)) {
        param->z.next_out = (Bytef *) buf;
        param->z.avail_out = len;
        param->z.next_in = param->in + param->inpos;
        param->z.avail_in = param->inlen - param->inpos;

        while ((param->z.avail_out > 0) && (!param->zend)) {
            if (param->z.avail_in == 0) {
                size_t read = 0;
                if (!src_read(param->pkt.readsrc, param->in, sizeof(param->in), &read)) {
                    RNP_LOG("failed to read data");
                    return false;
                }
                param->z.next_in = param->in;
                param->z.avail_in = read;
                param->inlen = read;
                param->inpos = 0;
            }
            int ret = inflate(&param->z, Z_SYNC_FLUSH);
            if (ret == Z_STREAM_END) {
                param->zend = true;
                if (param->z.avail_in > 0) {
                    RNP_LOG("data beyond the end of z stream");
                }
                break;
            }
            if (ret != Z_OK) {
                RNP_LOG("inflate error %d", ret);
                return false;
            }
            if (!param->z.avail_in && src_eof(param->pkt.readsrc)) {
                RNP_LOG("unexpected end of zlib stream");
                return false;
            }
        }
        param->inpos = param->z.next_in - param->in;
        *readres = len - param->z.avail_out;
        return true;
    }
#ifdef HAVE_BZLIB_H
    if (param->alg == PGP_C_BZIP2) {
        param->bz.next_out = (char *) buf;
        param->bz.avail_out = len;
        param->bz.next_in = (char *) (param->in + param->inpos);
        param->bz.avail_in = param->inlen - param->inpos;

        while ((param->bz.avail_out > 0) && (!param->zend)) {
            if (param->bz.avail_in == 0) {
                size_t read = 0;
                if (!src_read(param->pkt.readsrc, param->in, sizeof(param->in), &read)) {
                    RNP_LOG("failed to read data");
                    return false;
                }
                param->bz.next_in = (char *) param->in;
                param->bz.avail_in = read;
                param->inlen = read;
                param->inpos = 0;
            }
            int ret = BZ2_bzDecompress(&param->bz);
            if (ret == BZ_STREAM_END) {
                param->zend = true;
                if (param->bz.avail_in > 0) {
                    RNP_LOG("data beyond the end of z stream");
                }
                break;
            }
            if (ret != BZ_OK) {
                RNP_LOG("bzdecompress error %d", ret);
                return false;
            }
            if (!param->bz.avail_in && src_eof(param->pkt.readsrc)) {
                RNP_LOG("unexpected end of bzip stream");
                return false;
            }
        }

        param->inpos = (uint8_t *) param->bz.next_in - param->in;
        *readres = len - param->bz.avail_out;
        return true;
    }
#endif
    return false;
}

static void
compressed_src_close(pgp_source_t *src)
{
    pgp_source_compressed_param_t *param = (pgp_source_compressed_param_t *) src->param;
    if (!param) {
        return;
    }

    if (param->pkt.hdr.partial) {
        src_close(param->pkt.readsrc);
        free(param->pkt.readsrc);
        param->pkt.readsrc = NULL;
    }

#ifdef HAVE_BZLIB_H
    if (param->alg == PGP_C_BZIP2) {
        BZ2_bzDecompressEnd(&param->bz);
    }
#endif
    if ((param->alg == PGP_C_ZIP) || (param->alg == PGP_C_ZLIB)) {
        inflateEnd(&param->z);
    }

    free(src->param);
    src->param = NULL;
}

#if defined(ENABLE_AEAD)
static bool
encrypted_start_aead_chunk(pgp_source_encrypted_param_t *param, size_t idx, bool last)
{
    uint8_t nonce[PGP_AEAD_MAX_NONCE_LEN];
    size_t  nlen;

    /* set chunk index for additional data */
    STORE64BE(param->aead_ad + param->aead_adlen - 8, idx);

    if (last) {
        uint64_t total = idx * param->chunklen;
        if (idx && param->chunkin) {
            total -= param->chunklen - param->chunkin;
        }

        if (!param->chunkin) {
            /* reset the crypto in case we had empty chunk before the last one */
            pgp_cipher_aead_reset(&param->decrypt);
        }
        STORE64BE(param->aead_ad + param->aead_adlen, total);
        param->aead_adlen += 8;
    }

    if (!pgp_cipher_aead_set_ad(&param->decrypt, param->aead_ad, param->aead_adlen)) {
        RNP_LOG("failed to set ad");
        return false;
    }

    /* setup chunk */
    param->chunkidx = idx;
    param->chunkin = 0;

    /* set chunk index for nonce */
    nlen = pgp_cipher_aead_nonce(param->aead_hdr.aalg, param->aead_hdr.iv, nonce, idx);

    /* start cipher */
    return pgp_cipher_aead_start(&param->decrypt, nonce, nlen);
}

/* read and decrypt bytes to the cache. Should be called only on empty cache. */
static bool
encrypted_src_read_aead_part(pgp_source_encrypted_param_t *param)
{
    bool   lastchunk = false;
    bool   chunkend = false;
    bool   res = false;
    size_t read;
    size_t tagread;
    size_t taglen;

    param->cachepos = 0;
    param->cachelen = 0;

    if (param->auth_validated) {
        return true;
    }

    /* it is always 16 for defined EAX and OCB, however this may change in future */
    taglen = pgp_cipher_aead_tag_len(param->aead_hdr.aalg);
    read = sizeof(param->cache) - 2 * PGP_AEAD_MAX_TAG_LEN;

    if (read >= param->chunklen - param->chunkin) {
        read = param->chunklen - param->chunkin;
        chunkend = true;
    } else {
        read = read - read % pgp_cipher_aead_granularity(&param->decrypt);
    }

    if (!src_read(param->pkt.readsrc, param->cache, read, &read)) {
        return false;
    }

    /* checking whether we have enough input for the final tags */
    if (!src_peek(param->pkt.readsrc, param->cache + read, taglen * 2, &tagread)) {
        return false;
    }

    if (tagread < taglen * 2) {
        /* this would mean the end of the stream */
        if ((param->chunkin == 0) && (read + tagread == taglen)) {
            /* we have empty chunk and final tag */
            chunkend = false;
            lastchunk = true;
        } else if (read + tagread >= 2 * taglen) {
            /* we have end of chunk and final tag */
            chunkend = true;
            lastchunk = true;
        } else {
            RNP_LOG("unexpected end of data");
            return false;
        }
    }

    if (!chunkend && !lastchunk) {
        param->chunkin += read;
        res = pgp_cipher_aead_update(&param->decrypt, param->cache, param->cache, read);
        if (res) {
            param->cachelen = read;
        }
        return res;
    }

    if (chunkend) {
        if (tagread > taglen) {
            src_skip(param->pkt.readsrc, tagread - taglen);
        }

        res = pgp_cipher_aead_finish(
          &param->decrypt, param->cache, param->cache, read + tagread - taglen);
        if (!res) {
            RNP_LOG("failed to finalize aead chunk");
            return res;
        }
        param->cachelen = read + tagread - 2 * taglen;
        param->chunkin += param->cachelen;
    }

    size_t chunkidx = param->chunkidx;
    if (chunkend && param->chunkin) {
        chunkidx++;
    }

    if (!(res = encrypted_start_aead_chunk(param, chunkidx, lastchunk))) {
        RNP_LOG("failed to start aead chunk");
        return res;
    }

    if (lastchunk) {
        if (tagread > 0) {
            src_skip(param->pkt.readsrc, tagread);
        }

        size_t off = read + tagread - taglen;
        res = pgp_cipher_aead_finish(
          &param->decrypt, param->cache + off, param->cache + off, taglen);
        if (!res) {
            RNP_LOG("wrong last chunk");
            return res;
        }
        param->auth_validated = true;
    }

    return res;
}
#endif

static bool
encrypted_src_read_aead(pgp_source_t *src, void *buf, size_t len, size_t *read)
{
#if !defined(ENABLE_AEAD)
    return false;
#else
    pgp_source_encrypted_param_t *param = (pgp_source_encrypted_param_t *) src->param;
    size_t                        cbytes;
    size_t                        left = len;

    do {
        /* check whether we have something in the cache */
        cbytes = param->cachelen - param->cachepos;
        if (cbytes > 0) {
            if (cbytes >= left) {
                memcpy(buf, param->cache + param->cachepos, left);
                param->cachepos += left;
                if (param->cachepos == param->cachelen) {
                    param->cachepos = param->cachelen = 0;
                }
                *read = len;
                return true;
            }
            memcpy(buf, param->cache + param->cachepos, cbytes);
            buf = (uint8_t *) buf + cbytes;
            left -= cbytes;
            param->cachepos = param->cachelen = 0;
        }

        /* read something into cache */
        if (!encrypted_src_read_aead_part(param)) {
            return false;
        }
    } while ((left > 0) && (param->cachelen > 0));

    *read = len - left;
    return true;
#endif
}

static bool
encrypted_src_read_cfb(pgp_source_t *src, void *buf, size_t len, size_t *readres)
{
    pgp_source_encrypted_param_t *param = (pgp_source_encrypted_param_t *) src->param;
    if (param == NULL) {
        return false;
    }

    if (src->eof) {
        *readres = 0;
        return true;
    }

    size_t read;
    if (!src_read(param->pkt.readsrc, buf, len, &read)) {
        return false;
    }
    if (!read) {
        *readres = 0;
        return true;
    }

    bool    parsemdc = false;
    uint8_t mdcbuf[MDC_V1_SIZE];
    if (param->auth_type == rnp::AuthType::MDC) {
        size_t mdcread = 0;
        /* make sure there are always 22 bytes left on input */
        if (!src_peek(param->pkt.readsrc, mdcbuf, MDC_V1_SIZE, &mdcread) ||
            (mdcread + read < MDC_V1_SIZE)) {
            RNP_LOG("wrong mdc read state");
            return false;
        }
        if (mdcread < MDC_V1_SIZE) {
            src_skip(param->pkt.readsrc, mdcread);
            size_t mdcsub = MDC_V1_SIZE - mdcread;
            memmove(&mdcbuf[mdcsub], mdcbuf, mdcread);
            memcpy(mdcbuf, (uint8_t *) buf + read - mdcsub, mdcsub);
            read -= mdcsub;
            parsemdc = true;
        }
    }

    pgp_cipher_cfb_decrypt(&param->decrypt, (uint8_t *) buf, (uint8_t *) buf, read);

    if (param->auth_type == rnp::AuthType::MDC) {
        try {
            param->mdc->add(buf, read);

            if (parsemdc) {
                pgp_cipher_cfb_decrypt(&param->decrypt, mdcbuf, mdcbuf, MDC_V1_SIZE);
                pgp_cipher_cfb_finish(&param->decrypt);
                param->mdc->add(mdcbuf, 2);
                uint8_t hash[PGP_SHA1_HASH_SIZE] = {0};
                param->mdc->finish(hash);
                param->mdc = nullptr;

                if ((mdcbuf[0] != MDC_PKT_TAG) || (mdcbuf[1] != MDC_V1_SIZE - 2)) {
                    RNP_LOG("mdc header check failed");
                    return false;
                }

                if (memcmp(&mdcbuf[2], hash, PGP_SHA1_HASH_SIZE) != 0) {
                    RNP_LOG("mdc hash check failed");
                    return false;
                }
                param->auth_validated = true;
            }
        } catch (const std::exception &e) {
            RNP_LOG("mdc update failed: %s", e.what());
            return false;
        }
    }
    *readres = read;
    return true;
}

static rnp_result_t
encrypted_src_finish(pgp_source_t *src)
{
    pgp_source_encrypted_param_t *param = (pgp_source_encrypted_param_t *) src->param;

    /* report to the handler that decryption is finished */
    if (param->handler->on_decryption_done) {
        bool validated = (param->auth_type != rnp::AuthType::None) && param->auth_validated;
        param->handler->on_decryption_done(validated, param->handler->param);
    }

    if ((param->auth_type == rnp::AuthType::None) || param->auth_validated) {
        return RNP_SUCCESS;
    }
    switch (param->auth_type) {
    case rnp::AuthType::MDC:
        RNP_LOG("mdc was not validated");
        break;
    case rnp::AuthType::AEADv1:
        RNP_LOG("aead last chunk was not validated");
        break;
    default:
        RNP_LOG("auth was not validated");
        break;
    }
    return RNP_ERROR_BAD_STATE;
}

static void
encrypted_src_close(pgp_source_t *src)
{
    pgp_source_encrypted_param_t *param = (pgp_source_encrypted_param_t *) src->param;
    if (!param) {
        return;
    }
    if (param->pkt.hdr.partial) {
        src_close(param->pkt.readsrc);
        free(param->pkt.readsrc);
        param->pkt.readsrc = NULL;
    }

    if (!param->use_cfb()) {
#if defined(ENABLE_AEAD)
        pgp_cipher_aead_destroy(&param->decrypt);
#endif
    } else {
        pgp_cipher_cfb_finish(&param->decrypt);
    }

    delete param;
    src->param = NULL;
}

static void
add_hash_for_sig(pgp_source_signed_param_t *param, pgp_sig_type_t stype, pgp_hash_alg_t halg)
{
    /* Cleartext always uses param->hashes instead of param->txt_hashes */
    if (!param->cleartext && (stype == PGP_SIG_TEXT)) {
        param->txt_hashes.add_alg(halg);
    }
    param->hashes.add_alg(halg);
}

static const rnp::Hash *
get_hash_for_sig(pgp_source_signed_param_t &param, pgp_signature_info_t &sinfo)
{
    /* Cleartext always uses param->hashes instead of param->txt_hashes */
    if (!param.cleartext && (sinfo.sig->type() == PGP_SIG_TEXT)) {
        return param.txt_hashes.get(sinfo.sig->halg);
    }
    return param.hashes.get(sinfo.sig->halg);
}

static void
signed_validate_signature(pgp_source_signed_param_t &param, pgp_signature_info_t &sinfo)
{
    /* Check signature type */
    if (!sinfo.sig->is_document()) {
        RNP_LOG("Invalid document signature type: %d", (int) sinfo.sig->type());
        sinfo.valid = false;
        return;
    }
    /* Find signing key */
    pgp_key_request_ctx_t keyctx(PGP_OP_VERIFY, false, PGP_KEY_SEARCH_FINGERPRINT);

    /* Get signer's fp or keyid */
    if (sinfo.sig->has_keyfp()) {
        keyctx.search.by.fingerprint = sinfo.sig->keyfp();
    } else if (sinfo.sig->has_keyid()) {
        keyctx.search.type = PGP_KEY_SEARCH_KEYID;
        keyctx.search.by.keyid = sinfo.sig->keyid();
    } else {
        RNP_LOG("cannot get signer's key fp or id from signature.");
        sinfo.unknown = true;
        return;
    }
    /* Get the public key */
    pgp_key_t *key = pgp_request_key(param.handler->key_provider, &keyctx);
    if (!key) {
        /* fallback to secret key */
        keyctx.secret = true;
        if (!(key = pgp_request_key(param.handler->key_provider, &keyctx))) {
            RNP_LOG("signer's key not found");
            sinfo.no_signer = true;
            return;
        }
    }
    try {
        /* Get the hash context and clone it. */
        auto hash = get_hash_for_sig(param, sinfo);
        if (!hash) {
            RNP_LOG("failed to get hash context.");
            return;
        }
        auto shash = hash->clone();
        key->validate_sig(sinfo, *shash, *param.handler->ctx->ctx);
    } catch (const std::exception &e) {
        RNP_LOG("Signature validation failed: %s", e.what());
        sinfo.valid = false;
    }
}

static long
stripped_line_len(uint8_t *begin, uint8_t *end)
{
    uint8_t *stripped_end = end;

    while (stripped_end >= begin && (*stripped_end == CH_CR || *stripped_end == CH_LF)) {
        stripped_end--;
    }

    return stripped_end - begin + 1;
}

static void
signed_src_update(pgp_source_t *src, const void *buf, size_t len)
{
    if (!len) {
        return;
    }
    /* check for extremely unlikely pointer overflow/wrap case */
    if (((uint8_t *) buf + len) < ((uint8_t *) buf + len - 1)) {
        signed_src_update(src, buf, len - 1);
        uint8_t last = *((uint8_t *) buf + len - 1);
        signed_src_update(src, &last, 1);
    }
    pgp_source_signed_param_t *param = (pgp_source_signed_param_t *) src->param;
    try {
        param->hashes.add(buf, len);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
    }
    /* update text-mode sig hashes */
    if (param->txt_hashes.hashes.empty()) {
        return;
    }

    uint8_t *ch = (uint8_t *) buf;
    uint8_t *linebeg = ch;
    uint8_t *end = (uint8_t *) buf + len;
    /* we support LF and CRLF line endings */
    while (ch < end) {
        /* continue if not reached LF */
        if (*ch != CH_LF) {
            if (*ch != CH_CR && param->stripped_crs > 0) {
                while (param->stripped_crs--) {
                    try {
                        param->txt_hashes.add(ST_CR, 1);
                    } catch (const std::exception &e) {
                        RNP_LOG("%s", e.what());
                    }
                }
                param->stripped_crs = 0;
            }

            if (!param->max_line_warn && param->text_line_len >= MAXIMUM_GNUPG_LINELEN) {
                RNP_LOG("Canonical text document signature: line is too long, may cause "
                        "incompatibility with other implementations. Consider using binary "
                        "signature instead.");
                param->max_line_warn = true;
            }

            ch++;
            param->text_line_len++;
            continue;
        }
        /* reached eol: dump line contents */
        param->stripped_crs = 0;
        param->text_line_len = 0;
        if (ch > linebeg) {
            long stripped_len = stripped_line_len(linebeg, ch);
            if (stripped_len > 0) {
                try {
                    param->txt_hashes.add(linebeg, stripped_len);
                } catch (const std::exception &e) {
                    RNP_LOG("%s", e.what());
                }
            }
        }
        /* dump EOL */
        try {
            param->txt_hashes.add(ST_CRLF, 2);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
        }
        ch++;
        linebeg = ch;
    }
    /* check if we have undumped line contents */
    if (linebeg < end) {
        long stripped_len = stripped_line_len(linebeg, end - 1);
        if (stripped_len < end - linebeg) {
            param->stripped_crs = end - linebeg - stripped_len;
        }
        if (stripped_len > 0) {
            try {
                param->txt_hashes.add(linebeg, stripped_len);
            } catch (const std::exception &e) {
                RNP_LOG("%s", e.what());
            }
        }
    }
}

static bool
signed_src_read(pgp_source_t *src, void *buf, size_t len, size_t *read)
{
    pgp_source_signed_param_t *param = (pgp_source_signed_param_t *) src->param;
    if (!param) {
        return false;
    }
    return src_read(param->readsrc, buf, len, read);
}

static void
signed_src_close(pgp_source_t *src)
{
    pgp_source_signed_param_t *param = (pgp_source_signed_param_t *) src->param;
    if (!param) {
        return;
    }
    delete param;
    src->param = NULL;
}

#define MAX_SIGNATURES 16384

static rnp_result_t
signed_read_single_signature(pgp_source_signed_param_t *param,
                             pgp_source_t *             readsrc,
                             pgp_signature_t **         sig)
{
    uint8_t ptag;
    if (!src_peek_eq(readsrc, &ptag, 1)) {
        RNP_LOG("failed to read signature packet header");
        return RNP_ERROR_READ;
    }

    int ptype = get_packet_type(ptag);
    if (ptype != PGP_PKT_SIGNATURE) {
        RNP_LOG("unexpected packet %d", ptype);
        return RNP_ERROR_BAD_FORMAT;
    }

    if (param->siginfos.size() >= MAX_SIGNATURES) {
        RNP_LOG("Too many signatures in the stream.");
        return RNP_ERROR_BAD_FORMAT;
    }

    try {
        param->siginfos.emplace_back();
        pgp_signature_info_t &siginfo = param->siginfos.back();
        pgp_signature_t       readsig;
        if (readsig.parse(*readsrc)) {
            RNP_LOG("failed to parse signature");
            siginfo.unknown = true;
            if (sig) {
                *sig = NULL;
            }
            return RNP_SUCCESS;
        }
        param->sigs.push_back(std::move(readsig));
        siginfo.sig = &param->sigs.back();
        if (sig) {
            *sig = siginfo.sig;
        }
        return RNP_SUCCESS;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
}

static rnp_result_t
signed_read_cleartext_signatures(pgp_source_t &src, pgp_source_signed_param_t *param)
{
    try {
        rnp::ArmoredSource armor(*param->readsrc);
        while (!armor.eof()) {
            auto ret = signed_read_single_signature(param, &armor.src(), NULL);
            if (ret) {
                return ret;
            }
        }
        return RNP_SUCCESS;
    } catch (const rnp::rnp_exception &e) {
        RNP_LOG("%s", e.what());
        return e.code();
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_BAD_FORMAT;
    }
}

static rnp_result_t
signed_read_signatures(pgp_source_t *src)
{
    pgp_source_signed_param_t *param = (pgp_source_signed_param_t *) src->param;

    /* reading signatures */
    for (auto op = param->onepasses.rbegin(); op != param->onepasses.rend(); op++) {
        pgp_signature_t *sig = NULL;
        rnp_result_t     ret = signed_read_single_signature(param, src, &sig);
        /* we have more onepasses then signatures */
        if (ret == RNP_ERROR_READ) {
            RNP_LOG("Warning: premature end of signatures");
            return param->siginfos.size() ? RNP_SUCCESS : ret;
        }
        if (ret) {
            return ret;
        }
        if (sig && !sig->matches_onepass(*op)) {
            RNP_LOG("Warning: signature doesn't match one-pass");
        }
    }
    return RNP_SUCCESS;
}

static rnp_result_t
signed_src_finish(pgp_source_t *src)
{
    pgp_source_signed_param_t *param = (pgp_source_signed_param_t *) src->param;
    rnp_result_t               ret = RNP_ERROR_GENERIC;

    if (param->cleartext) {
        ret = signed_read_cleartext_signatures(*src, param);
    } else {
        ret = signed_read_signatures(src);
    }

    if (ret) {
        return ret;
    }

    if (!src_eof(src)) {
        RNP_LOG("warning: unexpected data on the stream end");
    }

    /* validating signatures */
    for (auto &sinfo : param->siginfos) {
        if (!sinfo.sig) {
            continue;
        }
        signed_validate_signature(*param, sinfo);
    }

    /* checking the validation results */
    ret = RNP_ERROR_SIGNATURE_INVALID;
    for (auto &sinfo : param->siginfos) {
        if (sinfo.valid) {
            /* If we have at least one valid signature then data is safe to process */
            ret = RNP_SUCCESS;
            break;
        }
    }

    /* call the callback with signature infos */
    if (param->handler->on_signatures) {
        param->handler->on_signatures(param->siginfos, param->handler->param);
    }
    return ret;
}

/*
 * str is a string to tokenize.
 * delims is a string containing a list of delimiter characters.
 * result is a container<string_type> that supports push_back.
 */
template <typename T>
static void
tokenize(const typename T::value_type &str, const typename T::value_type &delims, T &result)
{
    typedef typename T::value_type::size_type string_size_t;
    const string_size_t                       npos = T::value_type::npos;

    result.clear();
    string_size_t current;
    string_size_t next = 0;
    do {
        next = str.find_first_not_of(delims, next);
        if (next == npos) {
            break;
        }
        current = next;
        next = str.find_first_of(delims, current);
        string_size_t count = (next == npos) ? npos : (next - current);
        result.push_back(str.substr(current, count));
    } while (next != npos);
}

static bool
cleartext_parse_headers(pgp_source_t *src)
{
    pgp_source_signed_param_t *param = (pgp_source_signed_param_t *) src->param;
    char                       hdr[1024] = {0};
    char *                     hval;
    pgp_hash_alg_t             halg;
    size_t                     hdrlen;

    do {
        if (!src_peek_line(param->readsrc, hdr, sizeof(hdr), &hdrlen)) {
            RNP_LOG("failed to peek line");
            return false;
        }

        if (!hdrlen) {
            break;
        }

        if (rnp::is_blank_line(hdr, hdrlen)) {
            src_skip(param->readsrc, hdrlen);
            break;
        }

        try {
            if ((hdrlen >= 6) && !strncmp(hdr, ST_HEADER_HASH, 6)) {
                hval = hdr + 6;

                std::string remainder = hval;

                const std::string        delimiters = ", \t";
                std::vector<std::string> tokens;

                tokenize(remainder, delimiters, tokens);

                for (const auto &token : tokens) {
                    if ((halg = rnp::Hash::alg(token.c_str())) == PGP_HASH_UNKNOWN) {
                        RNP_LOG("unknown halg: %s", token.c_str());
                        continue;
                    }
                    add_hash_for_sig(param, PGP_SIG_TEXT, halg);
                }
            } else {
                RNP_LOG("unknown header '%s'", hdr);
            }
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }

        src_skip(param->readsrc, hdrlen);

        if (!src_skip_eol(param->readsrc)) {
            return false;
        }
    } while (1);

    /* we have exactly one empty line after the headers */
    return src_skip_eol(param->readsrc);
}

static void
cleartext_process_line(pgp_source_t *src, const uint8_t *buf, size_t len, bool eol)
{
    pgp_source_signed_param_t *param = (pgp_source_signed_param_t *) src->param;
    uint8_t *                  bufen = (uint8_t *) buf + len - 1;

    /* check for dashes only if we are not in the middle */
    if (!param->clr_mline && (len > 0) && (buf[0] == CH_DASH)) {
        if ((len > 1) && (buf[1] == CH_SPACE)) {
            buf += 2;
            len -= 2;
        } else if ((len > 5) && !memcmp(buf, ST_DASHES, 5)) {
            param->clr_eod = true;
            return;
        } else {
            RNP_LOG("dash at the line begin");
        }
    }

    /* hash eol if it is not the first line and we are not in the middle */
    if (!param->clr_fline && !param->clr_mline) {
        /* we hash \r\n after the previous line to not hash the last eol before the sig */
        signed_src_update(src, ST_CRLF, 2);
    }

    if (!len) {
        return;
    }

    if (len + param->outlen > sizeof(param->out)) {
        RNP_LOG("wrong state");
        return;
    }

    /* if we have eol after this line then strip trailing spaces and tabs */
    if (eol) {
        for (; (bufen >= buf) &&
               ((*bufen == CH_SPACE) || (*bufen == CH_TAB) || (*bufen == CH_CR));
             bufen--)
            ;
    }

    if ((len = bufen + 1 - buf)) {
        memcpy(param->out + param->outlen, buf, len);
        param->outlen += len;
        signed_src_update(src, buf, len);
    }
}

static bool
cleartext_src_read(pgp_source_t *src, void *buf, size_t len, size_t *readres)
{
    pgp_source_signed_param_t *param = (pgp_source_signed_param_t *) src->param;
    if (!param) {
        return false;
    }

    uint8_t  srcb[CT_BUF_LEN];
    uint8_t *cur, *en, *bg;
    size_t   read = 0;
    size_t   origlen = len;

    read = param->outlen - param->outpos;
    if (read >= len) {
        memcpy(buf, param->out + param->outpos, len);
        param->outpos += len;
        if (param->outpos == param->outlen) {
            param->outpos = param->outlen = 0;
        }
        *readres = len;
        return true;
    } else if (read > 0) {
        memcpy(buf, param->out + param->outpos, read);
        len -= read;
        buf = (uint8_t *) buf + read;
        param->outpos = param->outlen = 0;
    }

    if (param->clr_eod) {
        *readres = origlen - len;
        return true;
    }

    do {
        if (!src_peek(param->readsrc, srcb, sizeof(srcb), &read)) {
            return false;
        } else if (!read) {
            break;
        }

        /* processing data line by line, eol could be \n or \r\n */
        for (cur = srcb, bg = srcb, en = cur + read; cur < en; cur++) {
            if ((*cur == CH_LF) ||
                ((*cur == CH_CR) && (cur + 1 < en) && (*(cur + 1) == CH_LF))) {
                cleartext_process_line(src, bg, cur - bg, true);
                /* processing eol */
                if (param->clr_eod) {
                    break;
                }

                /* processing eol */
                param->clr_fline = false;
                param->clr_mline = false;
                if (*cur == CH_CR) {
                    param->out[param->outlen++] = *cur++;
                }
                param->out[param->outlen++] = *cur;
                bg = cur + 1;
            }
        }

        /* if line is larger then 4k then just dump it out */
        if ((bg == srcb) && !param->clr_eod) {
            /* if last char is \r, and it's not the end of stream, then do not dump it */
            if ((en > bg) && (*(en - 1) == CH_CR) && (read > 1)) {
                en--;
            }
            cleartext_process_line(src, bg, en - bg, false);
            param->clr_mline = true;
            bg = en;
        }
        src_skip(param->readsrc, bg - srcb);

        /* put data from the param->out to buf */
        read = param->outlen > len ? len : param->outlen;
        memcpy(buf, param->out, read);
        buf = (uint8_t *) buf + read;
        len -= read;

        if (read == param->outlen) {
            param->outlen = 0;
        } else {
            param->outpos = read;
        }

        /* we got to the signature marker */
        if (param->clr_eod || !len) {
            break;
        }
    } while (1);

    *readres = origlen - len;
    return true;
}

static bool
encrypted_decrypt_cfb_header(pgp_source_encrypted_param_t *param,
                             pgp_symm_alg_t                alg,
                             uint8_t *                     key)
{
    pgp_crypt_t crypt;
    uint8_t     enchdr[PGP_MAX_BLOCK_SIZE + 2];
    uint8_t     dechdr[PGP_MAX_BLOCK_SIZE + 2];
    unsigned    blsize;

    if (!(blsize = pgp_block_size(alg))) {
        return false;
    }

    /* reading encrypted header to check the password validity */
    if (!src_peek_eq(param->pkt.readsrc, enchdr, blsize + 2)) {
        RNP_LOG("failed to read encrypted header");
        return false;
    }

    /* having symmetric key in keybuf let's decrypt blocksize + 2 bytes and check them */
    if (!pgp_cipher_cfb_start(&crypt, alg, key, NULL)) {
        RNP_LOG("failed to start cipher");
        return false;
    }

    pgp_cipher_cfb_decrypt(&crypt, dechdr, enchdr, blsize + 2);

    if ((dechdr[blsize] != dechdr[blsize - 2]) || (dechdr[blsize + 1] != dechdr[blsize - 1])) {
        RNP_LOG("checksum check failed");
        goto error;
    }

    src_skip(param->pkt.readsrc, blsize + 2);
    param->decrypt = crypt;

    /* init mdc if it is here */
    /* RFC 4880, 5.13: Unlike the Symmetrically Encrypted Data Packet, no special CFB
     * resynchronization is done after encrypting this prefix data. */
    if (param->auth_type == rnp::AuthType::None) {
        pgp_cipher_cfb_resync(&param->decrypt, enchdr + 2);
        return true;
    }

    try {
        param->mdc = rnp::Hash::create(PGP_HASH_SHA1);
        param->mdc->add(dechdr, blsize + 2);
    } catch (const std::exception &e) {
        RNP_LOG("cannot create sha1 hash: %s", e.what());
        goto error;
    }
    return true;
error:
    pgp_cipher_cfb_finish(&crypt);
    return false;
}

static bool
encrypted_start_aead(pgp_source_encrypted_param_t *param, pgp_symm_alg_t alg, uint8_t *key)
{
#if !defined(ENABLE_AEAD)
    RNP_LOG("AEAD is not enabled.");
    return false;
#else
    size_t gran;

    if (alg != param->aead_hdr.ealg) {
        return false;
    }

    /* initialize cipher with key */
    if (!pgp_cipher_aead_init(
          &param->decrypt, param->aead_hdr.ealg, param->aead_hdr.aalg, key, true)) {
        return false;
    }

    gran = pgp_cipher_aead_granularity(&param->decrypt);
    if (gran > sizeof(param->cache)) {
        RNP_LOG("wrong granularity");
        return false;
    }

    return encrypted_start_aead_chunk(param, 0, false);
#endif
}

static bool
encrypted_try_key(pgp_source_encrypted_param_t *param,
                  pgp_pk_sesskey_t *            sesskey,
                  pgp_key_pkt_t *               seckey,
                  rnp::SecurityContext &        ctx)
{
    pgp_encrypted_material_t encmaterial;
    try {
        if (!sesskey->parse_material(encmaterial)) {
            return false;
        }
        seckey->material.validate(ctx, false);
        if (!seckey->material.valid()) {
            RNP_LOG("Attempt to decrypt using the key with invalid material.");
            return false;
        }
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }

    rnp::secure_array<uint8_t, PGP_MPINT_SIZE> decbuf;
    /* Decrypting session key value */
    rnp_result_t        err;
    bool                res = false;
    pgp_key_material_t *keymaterial = &seckey->material;
    size_t              declen = 0;
    switch (sesskey->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
        err = rsa_decrypt_pkcs1(
          &ctx.rng, decbuf.data(), &declen, &encmaterial.rsa, &keymaterial->rsa);
        if (err) {
            RNP_LOG("RSA decryption failure");
            return false;
        }
        break;
    case PGP_PKA_SM2:
#if defined(ENABLE_SM2)
        declen = decbuf.size();
        err = sm2_decrypt(decbuf.data(), &declen, &encmaterial.sm2, &keymaterial->ec);
        if (err != RNP_SUCCESS) {
            RNP_LOG("SM2 decryption failure, error %x", (int) err);
            return false;
        }
        break;
#else
        RNP_LOG("SM2 decryption is not available.");
        return false;
#endif
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN: {
        const rnp_result_t ret = elgamal_decrypt_pkcs1(
          &ctx.rng, decbuf.data(), &declen, &encmaterial.eg, &keymaterial->eg);
        if (ret) {
            RNP_LOG("ElGamal decryption failure [%X]", ret);
            return false;
        }
        break;
    }
    case PGP_PKA_ECDH: {
        if (!curve_supported(keymaterial->ec.curve)) {
            RNP_LOG("ECDH decrypt: curve %d is not supported.", (int) keymaterial->ec.curve);
            return false;
        }
        pgp_fingerprint_t fingerprint;
        if (pgp_fingerprint(fingerprint, *seckey)) {
            RNP_LOG("ECDH fingerprint calculation failed");
            return false;
        }
        if ((keymaterial->ec.curve == PGP_CURVE_25519) &&
            !x25519_bits_tweaked(keymaterial->ec)) {
            RNP_LOG("Warning: bits of 25519 secret key are not tweaked.");
        }
        declen = decbuf.size();
        err = ecdh_decrypt_pkcs5(
          decbuf.data(), &declen, &encmaterial.ecdh, &keymaterial->ec, fingerprint);
        if (err != RNP_SUCCESS) {
            RNP_LOG("ECDH decryption error %u", err);
            return false;
        }
        break;
    }
    default:
        RNP_LOG("unsupported public key algorithm %d\n", seckey->alg);
        return false;
    }

    /* Check algorithm and key length */
    if (!pgp_is_sa_supported(decbuf[0])) {
        RNP_LOG("Unsupported symmetric algorithm %" PRIu8, decbuf[0]);
        return false;
    }

    pgp_symm_alg_t salg = static_cast<pgp_symm_alg_t>(decbuf[0]);
    size_t         keylen = pgp_key_size(salg);
    if (declen != keylen + 3) {
        RNP_LOG("invalid symmetric key length");
        return false;
    }

    /* Validate checksum */
    rnp::secure_array<unsigned, 1> checksum;
    for (unsigned i = 1; i <= keylen; i++) {
        checksum[0] += decbuf[i];
    }

    if ((checksum[0] & 0xffff) !=
        (decbuf[keylen + 2] | ((unsigned) decbuf[keylen + 1] << 8))) {
        RNP_LOG("wrong checksum\n");
        return false;
    }

    if (param->use_cfb()) {
        /* Decrypt header */
        res = encrypted_decrypt_cfb_header(param, salg, &decbuf[1]);
    } else {
        /* Start AEAD decrypting, assuming we have correct key */
        res = encrypted_start_aead(param, salg, &decbuf[1]);
    }
    if (res) {
        param->salg = salg;
    }
    return res;
}

#if defined(ENABLE_AEAD)
static bool
encrypted_sesk_set_ad(pgp_crypt_t *crypt, pgp_sk_sesskey_t *skey)
{
    /* TODO: this method is exact duplicate as in stream-write.c. Not sure where to put it */
    uint8_t ad_data[4];

    ad_data[0] = PGP_PKT_SK_SESSION_KEY | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
    ad_data[1] = skey->version;
    ad_data[2] = skey->alg;
    ad_data[3] = skey->aalg;

    return pgp_cipher_aead_set_ad(crypt, ad_data, 4);
}
#endif

static int
encrypted_try_password(pgp_source_encrypted_param_t *param, const char *password)
{
    bool keyavail = false; /* tried password at least once */

    for (auto &skey : param->symencs) {
        rnp::secure_array<uint8_t, PGP_MAX_KEY_SIZE + 1> keybuf;
        /* deriving symmetric key from password */
        size_t keysize = pgp_key_size(skey.alg);
        if (!keysize || !pgp_s2k_derive_key(&skey.s2k, password, keybuf.data(), keysize)) {
            continue;
        }
        pgp_crypt_t    crypt;
        pgp_symm_alg_t alg;

        if (skey.version == PGP_SKSK_V4) {
            /* v4 symmetrically-encrypted session key */
            if (skey.enckeylen > 0) {
                /* decrypting session key */
                if (!pgp_cipher_cfb_start(&crypt, skey.alg, keybuf.data(), NULL)) {
                    continue;
                }

                pgp_cipher_cfb_decrypt(&crypt, keybuf.data(), skey.enckey, skey.enckeylen);
                pgp_cipher_cfb_finish(&crypt);

                alg = (pgp_symm_alg_t) keybuf[0];
                keysize = pgp_key_size(alg);
                if (!keysize || (keysize + 1 != skey.enckeylen)) {
                    continue;
                }
                memmove(keybuf.data(), keybuf.data() + 1, keysize);
            } else {
                alg = (pgp_symm_alg_t) skey.alg;
            }

            if (!pgp_block_size(alg)) {
                continue;
            }
            keyavail = true;
        } else if (skey.version == PGP_SKSK_V5) {
#if !defined(ENABLE_AEAD)
            continue;
#else
            /* v5 AEAD-encrypted session key */
            size_t taglen = pgp_cipher_aead_tag_len(skey.aalg);
            size_t ceklen = pgp_key_size(param->aead_hdr.ealg);
            if (!taglen || !ceklen || (ceklen + taglen != skey.enckeylen)) {
                RNP_LOG("CEK len/alg mismatch");
                continue;
            }
            alg = skey.alg;

            /* initialize cipher */
            if (!pgp_cipher_aead_init(&crypt, skey.alg, skey.aalg, keybuf.data(), true)) {
                continue;
            }

            /* set additional data */
            if (!encrypted_sesk_set_ad(&crypt, &skey)) {
                RNP_LOG("failed to set ad");
                continue;
            }

            /* calculate nonce */
            uint8_t nonce[PGP_AEAD_MAX_NONCE_LEN];
            size_t  noncelen = pgp_cipher_aead_nonce(skey.aalg, skey.iv, nonce, 0);

            /* start cipher, decrypt key and verify tag */
            keyavail =
              pgp_cipher_aead_start(&crypt, nonce, noncelen) &&
              pgp_cipher_aead_finish(&crypt, keybuf.data(), skey.enckey, skey.enckeylen);
            pgp_cipher_aead_destroy(&crypt);

            /* we have decrypted key so let's start decryption */
            if (!keyavail) {
                continue;
            }
#endif
        } else {
            continue;
        }

        /* Decrypt header for CFB */
        if (param->use_cfb() && !encrypted_decrypt_cfb_header(param, alg, keybuf.data())) {
            continue;
        }
        if (!param->use_cfb() &&
            !encrypted_start_aead(param, param->aead_hdr.ealg, keybuf.data())) {
            continue;
        }

        param->salg = param->use_cfb() ? alg : param->aead_hdr.ealg;
        /* inform handler that we used this symenc */
        if (param->handler->on_decryption_start) {
            param->handler->on_decryption_start(NULL, &skey, param->handler->param);
        }
        return 1;
    }

    if (!param->use_cfb() && pgp_block_size(param->aead_hdr.ealg)) {
        /* we know aead symm alg even if we wasn't able to start decryption */
        param->salg = param->aead_hdr.ealg;
    }

    if (!keyavail) {
        RNP_LOG("no supported sk available");
        return -1;
    }
    return 0;
}

/** @brief Initialize common to stream packets params, including partial data source */
static rnp_result_t
init_packet_params(pgp_source_packet_param_t &param)
{
    param.origsrc = NULL;

    /* save packet header */
    rnp_result_t ret = stream_peek_packet_hdr(param.readsrc, &param.hdr);
    if (ret) {
        return ret;
    }
    src_skip(param.readsrc, param.hdr.hdr_len);
    if (!param.hdr.partial) {
        return RNP_SUCCESS;
    }

    /* initialize partial reader if needed */
    pgp_source_t *partsrc = (pgp_source_t *) calloc(1, sizeof(*partsrc));
    if (!partsrc) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    rnp_result_t errcode = init_partial_pkt_src(partsrc, param.readsrc, param.hdr);
    if (errcode) {
        free(partsrc);
        return errcode;
    }
    param.origsrc = param.readsrc;
    param.readsrc = partsrc;
    return RNP_SUCCESS;
}

rnp_result_t
init_literal_src(pgp_source_t *src, pgp_source_t *readsrc)
{
    rnp_result_t                ret = RNP_ERROR_GENERIC;
    pgp_source_literal_param_t *param;
    uint8_t                     format = 0;
    uint8_t                     nlen = 0;
    uint8_t                     timestamp[4];

    if (!init_src_common(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_source_literal_param_t *) src->param;
    param->pkt.readsrc = readsrc;
    src->read = literal_src_read;
    src->close = literal_src_close;
    src->type = PGP_STREAM_LITERAL;

    /* Reading packet length/checking whether it is partial */
    if ((ret = init_packet_params(param->pkt))) {
        goto finish;
    }

    /* data format */
    if (!src_read_eq(param->pkt.readsrc, &format, 1)) {
        RNP_LOG("failed to read data format");
        ret = RNP_ERROR_READ;
        goto finish;
    }

    switch (format) {
    case 'b':
    case 't':
    case 'u':
    case 'l':
    case '1':
    case 'm':
        break;
    default:
        RNP_LOG("Warning: unknown data format %" PRIu8 ", ignoring.", format);
        break;
    }
    param->hdr.format = format;
    /* file name */
    if (!src_read_eq(param->pkt.readsrc, &nlen, 1)) {
        RNP_LOG("failed to read file name length");
        ret = RNP_ERROR_READ;
        goto finish;
    }
    if (nlen && !src_read_eq(param->pkt.readsrc, param->hdr.fname, nlen)) {
        RNP_LOG("failed to read file name");
        ret = RNP_ERROR_READ;
        goto finish;
    }
    param->hdr.fname[nlen] = 0;
    param->hdr.fname_len = nlen;
    /* timestamp */
    if (!src_read_eq(param->pkt.readsrc, timestamp, 4)) {
        RNP_LOG("failed to read file timestamp");
        ret = RNP_ERROR_READ;
        goto finish;
    }
    param->hdr.timestamp = read_uint32(timestamp);

    if (!param->pkt.hdr.indeterminate && !param->pkt.hdr.partial) {
        /* format filename-length filename timestamp */
        const uint16_t nbytes = 1 + 1 + nlen + 4;
        if (param->pkt.hdr.pkt_len < nbytes) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
        src->size = param->pkt.hdr.pkt_len - nbytes;
        src->knownsize = 1;
    }
    ret = RNP_SUCCESS;
finish:
    if (ret != RNP_SUCCESS) {
        src_close(src);
    }
    return ret;
}

bool
get_literal_src_hdr(pgp_source_t *src, pgp_literal_hdr_t *hdr)
{
    pgp_source_literal_param_t *param;

    if (src->type != PGP_STREAM_LITERAL) {
        RNP_LOG("wrong stream");
        return false;
    }

    param = (pgp_source_literal_param_t *) src->param;
    *hdr = param->hdr;
    return true;
}

rnp_result_t
init_compressed_src(pgp_source_t *src, pgp_source_t *readsrc)
{
    rnp_result_t                   errcode = RNP_ERROR_GENERIC;
    pgp_source_compressed_param_t *param;
    uint8_t                        alg;
    int                            zret;

    if (!init_src_common(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_source_compressed_param_t *) src->param;
    param->pkt.readsrc = readsrc;
    src->read = compressed_src_read;
    src->close = compressed_src_close;
    src->type = PGP_STREAM_COMPRESSED;

    /* Reading packet length/checking whether it is partial */
    errcode = init_packet_params(param->pkt);
    if (errcode != RNP_SUCCESS) {
        goto finish;
    }

    /* Reading compression algorithm */
    if (!src_read_eq(param->pkt.readsrc, &alg, 1)) {
        RNP_LOG("failed to read compression algorithm");
        errcode = RNP_ERROR_READ;
        goto finish;
    }

    /* Initializing decompression */
    switch (alg) {
    case PGP_C_NONE:
        break;
    case PGP_C_ZIP:
    case PGP_C_ZLIB:
        (void) memset(&param->z, 0x0, sizeof(param->z));
        zret =
          alg == PGP_C_ZIP ? (int) inflateInit2(&param->z, -15) : (int) inflateInit(&param->z);
        if (zret != Z_OK) {
            RNP_LOG("failed to init zlib, error %d", zret);
            errcode = RNP_ERROR_READ;
            goto finish;
        }
        break;
#ifdef HAVE_BZLIB_H
    case PGP_C_BZIP2:
        (void) memset(&param->bz, 0x0, sizeof(param->bz));
        zret = BZ2_bzDecompressInit(&param->bz, 0, 0);
        if (zret != BZ_OK) {
            RNP_LOG("failed to init bz, error %d", zret);
            errcode = RNP_ERROR_READ;
            goto finish;
        }
        break;
#endif
    default:
        RNP_LOG("unknown compression algorithm: %d", (int) alg);
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    param->alg = (pgp_compression_type_t) alg;
    param->inlen = 0;
    param->inpos = 0;

    errcode = RNP_SUCCESS;
finish:
    if (errcode != RNP_SUCCESS) {
        src_close(src);
    }
    return errcode;
}

bool
get_compressed_src_alg(pgp_source_t *src, uint8_t *alg)
{
    pgp_source_compressed_param_t *param;

    if (src->type != PGP_STREAM_COMPRESSED) {
        RNP_LOG("wrong stream");
        return false;
    }

    param = (pgp_source_compressed_param_t *) src->param;
    *alg = param->alg;
    return true;
}

bool
get_aead_src_hdr(pgp_source_t *src, pgp_aead_hdr_t *hdr)
{
    uint8_t hdrbt[4] = {0};

    if (!src_read_eq(src, hdrbt, 4)) {
        return false;
    }

    hdr->version = hdrbt[0];
    hdr->ealg = (pgp_symm_alg_t) hdrbt[1];
    hdr->aalg = (pgp_aead_alg_t) hdrbt[2];
    hdr->csize = hdrbt[3];

    if (!(hdr->ivlen = pgp_cipher_aead_nonce_len(hdr->aalg))) {
        RNP_LOG("wrong aead nonce length: alg %d", (int) hdr->aalg);
        return false;
    }

    return src_read_eq(src, hdr->iv, hdr->ivlen);
}

#define MAX_RECIPIENTS 16384

static rnp_result_t
encrypted_read_packet_data(pgp_source_encrypted_param_t *param)
{
    int ptype;
    /* Reading pk/sk encrypted session key(s) */
    try {
        size_t errors = 0;
        bool   stop = false;
        while (!stop) {
            if (param->pubencs.size() + param->symencs.size() + errors > MAX_RECIPIENTS) {
                RNP_LOG("Too many recipients of the encrypted message. Aborting.");
                return RNP_ERROR_BAD_STATE;
            }
            uint8_t ptag;
            if (!src_peek_eq(param->pkt.readsrc, &ptag, 1)) {
                RNP_LOG("failed to read packet header");
                return RNP_ERROR_READ;
            }
            ptype = get_packet_type(ptag);
            switch (ptype) {
            case PGP_PKT_SK_SESSION_KEY: {
                pgp_sk_sesskey_t skey;
                rnp_result_t     ret = skey.parse(*param->pkt.readsrc);
                if (ret == RNP_ERROR_READ) {
                    RNP_LOG("SKESK: Premature end of data.");
                    return ret;
                }
                if (ret) {
                    RNP_LOG("Failed to parse SKESK, skipping.");
                    errors++;
                    continue;
                }
                param->symencs.push_back(skey);
                break;
            }
            case PGP_PKT_PK_SESSION_KEY: {
                pgp_pk_sesskey_t pkey;
                rnp_result_t     ret = pkey.parse(*param->pkt.readsrc);
                if (ret == RNP_ERROR_READ) {
                    RNP_LOG("PKESK: Premature end of data.");
                    return ret;
                }
                if (ret) {
                    RNP_LOG("Failed to parse PKESK, skipping.");
                    errors++;
                    continue;
                }
                param->pubencs.push_back(pkey);
                break;
            }
            case PGP_PKT_SE_DATA:
            case PGP_PKT_SE_IP_DATA:
            case PGP_PKT_AEAD_ENCRYPTED:
                stop = true;
                break;
            default:
                RNP_LOG("unknown packet type: %d", ptype);
                return RNP_ERROR_BAD_FORMAT;
            }
        }
    } catch (const rnp::rnp_exception &e) {
        RNP_LOG("%s: %d", e.what(), e.code());
        return e.code();
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_GENERIC;
    }

    /* Reading packet length/checking whether it is partial */
    rnp_result_t errcode = init_packet_params(param->pkt);
    if (errcode) {
        return errcode;
    }

    /* Reading header of encrypted packet */
    if (ptype == PGP_PKT_AEAD_ENCRYPTED) {
        param->auth_type = rnp::AuthType::AEADv1;
        uint8_t hdr[4];
        if (!src_peek_eq(param->pkt.readsrc, hdr, 4)) {
            return RNP_ERROR_READ;
        }

        if (!get_aead_src_hdr(param->pkt.readsrc, &param->aead_hdr)) {
            RNP_LOG("failed to read AEAD header");
            return RNP_ERROR_READ;
        }

        /* check AEAD encrypted data packet header */
        if (param->aead_hdr.version != 1) {
            RNP_LOG("unknown aead ver: %d", param->aead_hdr.version);
            return RNP_ERROR_BAD_FORMAT;
        }
        if ((param->aead_hdr.aalg != PGP_AEAD_EAX) && (param->aead_hdr.aalg != PGP_AEAD_OCB)) {
            RNP_LOG("unknown aead alg: %d", (int) param->aead_hdr.aalg);
            return RNP_ERROR_BAD_FORMAT;
        }
        if (param->aead_hdr.csize > 56) {
            RNP_LOG("too large chunk size: %d", param->aead_hdr.csize);
            return RNP_ERROR_BAD_FORMAT;
        }
        if (param->aead_hdr.csize > 16) {
            RNP_LOG("Warning: AEAD chunk bits > 16.");
        }
        param->chunklen = 1L << (param->aead_hdr.csize + 6);

        /* build additional data */
        param->aead_adlen = 13;
        param->aead_ad[0] = param->pkt.hdr.hdr[0];
        memcpy(param->aead_ad + 1, hdr, 4);
        memset(param->aead_ad + 5, 0, 8);
    } else if (ptype == PGP_PKT_SE_IP_DATA) {
        uint8_t mdcver;
        if (!src_read_eq(param->pkt.readsrc, &mdcver, 1)) {
            return RNP_ERROR_READ;
        }

        if (mdcver != 1) {
            RNP_LOG("unknown mdc ver: %d", (int) mdcver);
            return RNP_ERROR_BAD_FORMAT;
        }
        param->auth_type = rnp::AuthType::MDC;
    }
    param->auth_validated = false;

    return RNP_SUCCESS;
}

#define MAX_HIDDEN_TRIES 64

static rnp_result_t
init_encrypted_src(pgp_parse_handler_t *handler, pgp_source_t *src, pgp_source_t *readsrc)
{
    if (!init_src_common(src, 0)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    pgp_source_encrypted_param_t *param = new (std::nothrow) pgp_source_encrypted_param_t();
    if (!param) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    src->param = param;
    param->pkt.readsrc = readsrc;
    param->handler = handler;

    src->close = encrypted_src_close;
    src->finish = encrypted_src_finish;
    src->type = PGP_STREAM_ENCRYPTED;

    /* Read the packet-related information */
    rnp_result_t errcode = encrypted_read_packet_data(param);
    if (errcode) {
        goto finish;
    }

    src->read = !param->use_cfb() ? encrypted_src_read_aead : encrypted_src_read_cfb;

    /* Obtaining the symmetric key */
    if (!handler->password_provider) {
        RNP_LOG("no password provider");
        errcode = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* informing handler about the available pubencs/symencs */
    if (handler->on_recipients) {
        handler->on_recipients(param->pubencs, param->symencs, handler->param);
    }

    bool have_key;
    have_key = false;
    /* Trying public-key decryption */
    if (!param->pubencs.empty()) {
        if (!handler->key_provider) {
            RNP_LOG("no key provider");
            errcode = RNP_ERROR_BAD_PARAMETERS;
            goto finish;
        }

        pgp_key_request_ctx_t keyctx(PGP_OP_DECRYPT, true, PGP_KEY_SEARCH_KEYID);

        size_t pubidx = 0;
        size_t hidden_tries = 0;
        errcode = RNP_ERROR_NO_SUITABLE_KEY;
        while (pubidx < param->pubencs.size()) {
            auto &pubenc = param->pubencs[pubidx];
            keyctx.search.by.keyid = pubenc.key_id;
            /* Get the key if any */
            pgp_key_t *seckey = pgp_request_key(handler->key_provider, &keyctx);
            if (!seckey) {
                pubidx++;
                continue;
            }
            /* Check whether key fits our needs */
            bool hidden = pubenc.key_id == pgp_key_id_t({});
            if (!hidden || (++hidden_tries >= MAX_HIDDEN_TRIES)) {
                pubidx++;
            }
            if (!seckey->has_secret() || !seckey->can_encrypt()) {
                continue;
            }
            /* Check whether key is of required algorithm for hidden keyid */
            if (hidden && seckey->alg() != pubenc.alg) {
                continue;
            }
            /* Decrypt key */
            rnp::KeyLocker seclock(*seckey);
            if (!seckey->unlock(*handler->password_provider, PGP_OP_DECRYPT)) {
                errcode = RNP_ERROR_BAD_PASSWORD;
                continue;
            }

            /* Try to initialize the decryption */
            rnp::LogStop logstop(hidden);
            if (encrypted_try_key(param, &pubenc, &seckey->pkt(), *handler->ctx->ctx)) {
                have_key = true;
                /* inform handler that we used this pubenc */
                if (handler->on_decryption_start) {
                    handler->on_decryption_start(&pubenc, NULL, handler->param);
                }
                break;
            }
        }
    }

    /* Trying password-based decryption */
    if (!have_key && !param->symencs.empty()) {
        rnp::secure_array<char, MAX_PASSWORD_LENGTH> password;
        pgp_password_ctx_t                           pass_ctx(PGP_OP_DECRYPT_SYM);
        if (!pgp_request_password(
              handler->password_provider, &pass_ctx, password.data(), password.size())) {
            errcode = RNP_ERROR_BAD_PASSWORD;
            goto finish;
        }

        int intres = encrypted_try_password(param, password.data());
        if (intres > 0) {
            have_key = true;
        } else if (intres < 0) {
            errcode = RNP_ERROR_NOT_SUPPORTED;
        } else {
            errcode = RNP_ERROR_BAD_PASSWORD;
        }
    }

    /* report decryption start to the handler */
    if (handler->on_decryption_info) {
        handler->on_decryption_info(param->auth_type == rnp::AuthType::MDC,
                                    param->aead_hdr.aalg,
                                    param->salg,
                                    handler->param);
    }

    if (!have_key) {
        RNP_LOG("failed to obtain decrypting key or password");
        if (!errcode) {
            errcode = RNP_ERROR_NO_SUITABLE_KEY;
        }
        goto finish;
    }
    errcode = RNP_SUCCESS;
finish:
    if (errcode != RNP_SUCCESS) {
        src_close(src);
    }
    return errcode;
}

static rnp_result_t
init_cleartext_signed_src(pgp_source_t *src)
{
    char                       buf[64];
    size_t                     hdrlen = strlen(ST_CLEAR_BEGIN);
    pgp_source_signed_param_t *param = (pgp_source_signed_param_t *) src->param;

    /* checking header line */
    if (!src_read_eq(param->readsrc, buf, hdrlen)) {
        RNP_LOG("failed to read header");
        return RNP_ERROR_READ;
    }

    if (memcmp(ST_CLEAR_BEGIN, buf, hdrlen)) {
        RNP_LOG("wrong header");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* eol */
    if (!src_skip_eol(param->readsrc)) {
        RNP_LOG("no eol after the cleartext header");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* parsing Hash headers */
    if (!cleartext_parse_headers(src)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    /* now we are good to go */
    param->clr_fline = true;
    return RNP_SUCCESS;
}

#define MAX_SIG_ERRORS 65536

static rnp_result_t
init_signed_src(pgp_parse_handler_t *handler, pgp_source_t *src, pgp_source_t *readsrc)
{
    rnp_result_t               errcode = RNP_ERROR_GENERIC;
    pgp_source_signed_param_t *param;
    uint8_t                    ptag;
    int                        ptype;
    pgp_signature_t *          sig = NULL;
    bool                       cleartext;
    size_t                     sigerrors = 0;

    if (!init_src_common(src, 0)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    try {
        param = new pgp_source_signed_param_t();
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    src->param = param;

    cleartext = is_cleartext_source(readsrc);
    param->readsrc = readsrc;
    param->handler = handler;
    param->cleartext = cleartext;
    param->stripped_crs = 0;
    src->read = cleartext ? cleartext_src_read : signed_src_read;
    src->close = signed_src_close;
    src->finish = signed_src_finish;
    src->type = cleartext ? PGP_STREAM_CLEARTEXT : PGP_STREAM_SIGNED;

    /* we need key provider to validate signatures */
    if (!handler->key_provider) {
        RNP_LOG("no key provider");
        errcode = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    if (cleartext) {
        errcode = init_cleartext_signed_src(src);
        goto finish;
    }

    /* Reading one-pass and signature packets */
    while (true) {
        /* stop early if we are in zip-bomb with erroneous packets */
        if (sigerrors >= MAX_SIG_ERRORS) {
            RNP_LOG("Too many one-pass/signature errors. Stopping.");
            errcode = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }

        size_t readb = readsrc->readb;
        if (!src_peek_eq(readsrc, &ptag, 1)) {
            RNP_LOG("failed to read packet header");
            errcode = RNP_ERROR_READ;
            goto finish;
        }

        ptype = get_packet_type(ptag);

        if (ptype == PGP_PKT_ONE_PASS_SIG) {
            if (param->onepasses.size() >= MAX_SIGNATURES) {
                RNP_LOG("Too many one-pass signatures.");
                errcode = RNP_ERROR_BAD_FORMAT;
                goto finish;
            }
            pgp_one_pass_sig_t onepass;
            try {
                errcode = onepass.parse(*readsrc);
            } catch (const std::exception &e) {
                errcode = RNP_ERROR_GENERIC;
            }
            if (errcode) {
                if (errcode == RNP_ERROR_READ) {
                    goto finish;
                }
                if (readb == readsrc->readb) {
                    errcode = RNP_ERROR_BAD_FORMAT;
                    goto finish;
                }
                sigerrors++;
                continue;
            }

            try {
                param->onepasses.push_back(onepass);
            } catch (const std::exception &e) {
                RNP_LOG("%s", e.what());
                errcode = RNP_ERROR_OUT_OF_MEMORY;
                goto finish;
            }

            /* adding hash context */
            try {
                add_hash_for_sig(param, onepass.type, onepass.halg);
            } catch (const std::exception &e) {
                RNP_LOG("Failed to create hash %d for onepass %d : %s.",
                        (int) onepass.halg,
                        (int) onepass.type,
                        e.what());
                errcode = RNP_ERROR_BAD_PARAMETERS;
                goto finish;
            }

            if (onepass.nested) {
                /* despite the name non-zero value means that it is the last one-pass */
                break;
            }
        } else if (ptype == PGP_PKT_SIGNATURE) {
            /* no need to check the error here - we already know tag */
            if (signed_read_single_signature(param, readsrc, &sig)) {
                sigerrors++;
            }
            /* adding hash context */
            if (sig) {
                try {
                    add_hash_for_sig(param, sig->type(), sig->halg);
                } catch (const std::exception &e) {
                    RNP_LOG("Failed to create hash %d for sig %d : %s.",
                            (int) sig->halg,
                            (int) sig->type(),
                            e.what());
                    errcode = RNP_ERROR_BAD_PARAMETERS;
                    goto finish;
                }
            }
        } else {
            break;
        }

        /* check if we are not it endless loop */
        if (readb == readsrc->readb) {
            errcode = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
        /* for detached signature we'll get eof */
        if (src_eof(readsrc)) {
            param->detached = true;
            break;
        }
    }

    /* checking what we have now */
    if (param->onepasses.empty() && param->sigs.empty()) {
        RNP_LOG("no signatures");
        errcode = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }
    if (!param->onepasses.empty() && !param->sigs.empty()) {
        RNP_LOG("warning: one-passes are mixed with signatures");
    }

    errcode = RNP_SUCCESS;
finish:
    if (errcode != RNP_SUCCESS) {
        src_close(src);
    }

    return errcode;
}

pgp_processing_ctx_t::~pgp_processing_ctx_t()
{
    for (auto &src : sources) {
        src_close(&src);
    }
}

/** @brief build PGP source sequence down to the literal data packet
 *
 **/
static rnp_result_t
init_packet_sequence(pgp_processing_ctx_t &ctx, pgp_source_t &src)
{
    pgp_source_t *lsrc = &src;
    size_t        srcnum = ctx.sources.size();

    while (1) {
        uint8_t ptag = 0;
        if (!src_peek_eq(lsrc, &ptag, 1)) {
            RNP_LOG("cannot read packet tag");
            return RNP_ERROR_READ;
        }

        int type = get_packet_type(ptag);
        if (type < 0) {
            RNP_LOG("wrong pkt tag %d", (int) ptag);
            return RNP_ERROR_BAD_FORMAT;
        }

        if (ctx.sources.size() - srcnum == MAXIMUM_NESTING_LEVEL) {
            RNP_LOG("Too many nested OpenPGP packets");
            return RNP_ERROR_BAD_FORMAT;
        }

        pgp_source_t psrc = {};
        rnp_result_t ret = RNP_ERROR_BAD_FORMAT;
        switch (type) {
        case PGP_PKT_PK_SESSION_KEY:
        case PGP_PKT_SK_SESSION_KEY:
            ret = init_encrypted_src(&ctx.handler, &psrc, lsrc);
            break;
        case PGP_PKT_ONE_PASS_SIG:
        case PGP_PKT_SIGNATURE:
            ret = init_signed_src(&ctx.handler, &psrc, lsrc);
            break;
        case PGP_PKT_COMPRESSED:
            ret = init_compressed_src(&psrc, lsrc);
            break;
        case PGP_PKT_LITDATA:
            if ((lsrc != &src) && (lsrc->type != PGP_STREAM_ENCRYPTED) &&
                (lsrc->type != PGP_STREAM_SIGNED) && (lsrc->type != PGP_STREAM_COMPRESSED)) {
                RNP_LOG("unexpected literal pkt");
                ret = RNP_ERROR_BAD_FORMAT;
                break;
            }
            ret = init_literal_src(&psrc, lsrc);
            break;
        case PGP_PKT_MARKER:
            if (ctx.sources.size() != srcnum) {
                RNP_LOG("Warning: marker packet wrapped in pgp stream.");
            }
            ret = stream_parse_marker(*lsrc);
            if (ret) {
                RNP_LOG("Invalid marker packet");
                return ret;
            }
            continue;
        default:
            RNP_LOG("unexpected pkt %d", type);
            ret = RNP_ERROR_BAD_FORMAT;
        }

        if (ret) {
            return ret;
        }

        try {
            ctx.sources.push_back(psrc);
            lsrc = &ctx.sources.back();
        } catch (const std::exception &e) {
            src_close(&psrc);
            RNP_LOG("%s", e.what());
            return RNP_ERROR_OUT_OF_MEMORY;
        }

        if (lsrc->type == PGP_STREAM_LITERAL) {
            ctx.literal_src = lsrc;
            ctx.msg_type = PGP_MESSAGE_NORMAL;
            return RNP_SUCCESS;
        }
        if (lsrc->type == PGP_STREAM_SIGNED) {
            ctx.signed_src = lsrc;
            pgp_source_signed_param_t *param = (pgp_source_signed_param_t *) lsrc->param;
            if (param->detached) {
                ctx.msg_type = PGP_MESSAGE_DETACHED;
                return RNP_SUCCESS;
            }
        }
    }
}

static rnp_result_t
init_cleartext_sequence(pgp_processing_ctx_t &ctx, pgp_source_t &src)
{
    pgp_source_t clrsrc = {};
    rnp_result_t res;

    if ((res = init_signed_src(&ctx.handler, &clrsrc, &src))) {
        return res;
    }
    try {
        ctx.sources.push_back(clrsrc);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        src_close(&clrsrc);
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
init_armored_sequence(pgp_processing_ctx_t &ctx, pgp_source_t &src)
{
    pgp_source_t armorsrc = {};
    rnp_result_t res;

    if ((res = init_armored_src(&armorsrc, &src))) {
        return res;
    }

    try {
        ctx.sources.push_back(armorsrc);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        src_close(&armorsrc);
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return init_packet_sequence(ctx, ctx.sources.back());
}

rnp_result_t
process_pgp_source(pgp_parse_handler_t *handler, pgp_source_t &src)
{
    rnp_result_t         res = RNP_ERROR_BAD_FORMAT;
    rnp_result_t         fres;
    pgp_processing_ctx_t ctx = {};
    pgp_source_t *       decsrc = NULL;
    pgp_source_t         datasrc = {0};
    pgp_dest_t *         outdest = NULL;
    bool                 closeout = true;
    uint8_t *            readbuf = NULL;

    ctx.handler = *handler;
    /* Building readers sequence. Checking whether it is binary data */
    if (is_pgp_source(src)) {
        res = init_packet_sequence(ctx, src);
    } else {
        /* Trying armored or cleartext data */
        if (is_cleartext_source(&src)) {
            /* Initializing cleartext message */
            res = init_cleartext_sequence(ctx, src);
        } else if (is_armored_source(&src)) {
            /* Initializing armored message */
            res = init_armored_sequence(ctx, src);
        } else {
            RNP_LOG("not an OpenPGP data provided");
            res = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
    }

    if (res != RNP_SUCCESS) {
        goto finish;
    }

    if ((readbuf = (uint8_t *) calloc(1, PGP_INPUT_CACHE_SIZE)) == NULL) {
        RNP_LOG("allocation failure");
        res = RNP_ERROR_OUT_OF_MEMORY;
        goto finish;
    }

    if (ctx.msg_type == PGP_MESSAGE_DETACHED) {
        /* detached signature case */
        if (!handler->ctx->detached) {
            RNP_LOG("Unexpected detached signature input.");
            res = RNP_ERROR_BAD_STATE;
            goto finish;
        }
        if (!handler->src_provider || !handler->src_provider(handler, &datasrc)) {
            RNP_LOG("no data source for detached signature verification");
            res = RNP_ERROR_READ;
            goto finish;
        }

        while (!datasrc.eof) {
            size_t read = 0;
            if (!src_read(&datasrc, readbuf, PGP_INPUT_CACHE_SIZE, &read)) {
                res = RNP_ERROR_GENERIC;
                break;
            }
            if (read > 0) {
                signed_src_update(ctx.signed_src, readbuf, read);
            }
        }
        src_close(&datasrc);
    } else {
        if (handler->ctx->detached) {
            RNP_LOG("Detached signature expected.");
            res = RNP_ERROR_BAD_STATE;
            goto finish;
        }
        /* file processing case */
        decsrc = &ctx.sources.back();
        char *   filename = NULL;
        uint32_t mtime = 0;

        if (ctx.literal_src) {
            auto *param = static_cast<pgp_source_literal_param_t *>(ctx.literal_src->param);
            filename = param->hdr.fname;
            mtime = param->hdr.timestamp;
        }

        if (!handler->dest_provider ||
            !handler->dest_provider(handler, &outdest, &closeout, filename, mtime)) {
            res = RNP_ERROR_WRITE;
            goto finish;
        }

        /* reading the input */
        while (!decsrc->eof) {
            size_t read = 0;
            if (!src_read(decsrc, readbuf, PGP_INPUT_CACHE_SIZE, &read)) {
                res = RNP_ERROR_GENERIC;
                break;
            }
            if (!read) {
                continue;
            }
            if (ctx.signed_src) {
                signed_src_update(ctx.signed_src, readbuf, read);
            }
            dst_write(outdest, readbuf, read);
            if (outdest->werr != RNP_SUCCESS) {
                RNP_LOG("failed to output data");
                res = RNP_ERROR_WRITE;
                break;
            }
        }
    }

    /* finalizing the input. Signatures are checked on this step */
    if (res == RNP_SUCCESS) {
        for (auto &ctxsrc : ctx.sources) {
            fres = src_finish(&ctxsrc);
            if (fres) {
                res = fres;
            }
        }
    }

    if (closeout && (ctx.msg_type != PGP_MESSAGE_DETACHED)) {
        dst_close(outdest, res != RNP_SUCCESS);
    }

finish:
    free(readbuf);
    return res;
}
