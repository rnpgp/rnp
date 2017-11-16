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
#include "stream-parse.h"
#include "stream-armor.h"
#include "stream-packet.h"
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
#include "crypto/sm2.h"
#include "crypto/ec.h"
#include "crypto/rsa.h"
#include "crypto/eddsa.h"
#include "crypto/ecdsa.h"
#include "signature.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "signature.h"
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
    pgp_parse_handler_t handler;
    pgp_source_t *      signed_src;
    pgp_source_t *      literal_src;
    pgp_message_t       msg_type;
    pgp_dest_t          output;
    DYNARRAY(pgp_source_t *, src); /* pgp sources stack */
} pgp_processing_ctx_t;

/* common fields for encrypted, compressed and literal data */
typedef struct pgp_source_packet_param_t {
    pgp_source_t *readsrc;       /* source to read from, could be partial*/
    pgp_source_t *origsrc;       /* original source passed to init_*_src */
    bool          partial;       /* partial length packet */
    bool          indeterminate; /* indeterminate length packet */
    size_t        hdrlen;        /* length of the header */
    uint64_t      len;           /* packet body length if non-partial and non-indeterminate */
} pgp_source_packet_param_t;

typedef struct pgp_source_encrypted_param_t {
    pgp_source_packet_param_t pkt;          /* underlying packet-related params */
    DYNARRAY(pgp_sk_sesskey_t, symenc);     /* array of sym-encrypted session keys */
    DYNARRAY(pgp_pk_sesskey_pkt_t, pubenc); /* array of pk-encrypted session keys */
    bool        has_mdc;                    /* encrypted with mdc, i.e. tag 18 */
    bool        mdc_validated;              /* mdc was validated already */
    pgp_crypt_t decrypt;                    /* decrypting crypto */
    pgp_hash_t  mdc;                        /* mdc SHA1 hash */
} pgp_source_encrypted_param_t;

#define CT_BUF_LEN 4096

typedef struct pgp_source_signed_param_t {
    pgp_processing_ctx_t *ctx;             /* processing context */
    pgp_source_t *        readsrc;         /* source to read from */
    bool                  detached;        /* detached signature */
    bool                  cleartext;       /* source is cleartext signed */
    bool                  clr_eod;         /* cleartext data is over */
    bool                  clr_noeol;       /* do not hash newline before the next line */
    uint8_t               out[CT_BUF_LEN]; /* cleartext output cache for easier parsing */
    size_t                outlen;          /* total bytes in out */
    size_t                outpos;          /* offset of first available byte in out */
    DYNARRAY(pgp_one_pass_sig_t, onepass); /* array of one-pass singatures */
    DYNARRAY(pgp_signature_t, sig);        /* array of signatures */
    DYNARRAY(pgp_hash_t, hash);            /* hash contexts */
    DYNARRAY(pgp_signature_info_t, info);  /* signature validation info */
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
    pgp_source_packet_param_t pkt;  /* underlying packet-related params */
    bool                      text; /* data is text */
    char                      filename[256];
    uint32_t                  timestamp;
} pgp_source_literal_param_t;

typedef struct pgp_source_partial_param_t {
    pgp_source_t *readsrc; /* source to read from */
    int           type;    /* type of the packet */
    size_t        psize;   /* size of the current part */
    size_t        pleft;   /* bytes left to read from the current part */
    bool          last;    /* current part is last */
} pgp_source_partial_param_t;

static size_t
get_part_len(uint8_t blen)
{
    return 1 << (blen & 0x1f);
}

static bool
stream_intedeterminate_pkt_len(pgp_source_t *src)
{
    uint8_t ptag;
    if (src_peek(src, &ptag, 1) == 1) {
        return !(ptag & PGP_PTAG_NEW_FORMAT) &&
               ((ptag & PGP_PTAG_OF_LENGTH_TYPE_MASK) == PGP_PTAG_OLD_LEN_INDETERMINATE);
    } else {
        return false;
    }
}

static bool
stream_partial_pkt_len(pgp_source_t *src)
{
    uint8_t hdr[2];
    if (src_peek(src, hdr, 2) < 2) {
        return false;
    } else {
        return (hdr[0] & PGP_PTAG_NEW_FORMAT) && (hdr[1] >= 224) && (hdr[1] < 255);
    }
}

static bool
is_pgp_source(pgp_source_t *src)
{
    uint8_t buf[1];
    ssize_t read;
    int     tag;

    if ((read = src_peek(src, buf, sizeof(buf))) < 1) {
        return false;
    }

    tag = get_packet_type(buf[0]);
    switch (tag) {
    case PGP_PTAG_CT_PK_SESSION_KEY:
    case PGP_PTAG_CT_SK_SESSION_KEY:
    case PGP_PTAG_CT_1_PASS_SIG:
    case PGP_PTAG_CT_SIGNATURE:
    case PGP_PTAG_CT_SE_DATA:
    case PGP_PTAG_CT_SE_IP_DATA:
    case PGP_PTAG_CT_COMPRESSED:
    case PGP_PTAG_CT_LITDATA:
        return true;
    default:
        return false;
    }
}

static bool
is_cleartext_source(pgp_source_t *src)
{
    const char clear_start[] = "-----BEGIN PGP SIGNED MESSAGE-----";
    uint8_t    buf[128];
    ssize_t    read;

    read = src_peek(src, buf, sizeof(buf));
    if (read < sizeof(clear_start)) {
        return false;
    }

    buf[read - 1] = 0;
    return !!strstr((char *) buf, clear_start);
}

static ssize_t
partial_pkt_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_partial_param_t *param = src->param;
    uint8_t                     hdr[5];
    ssize_t                     read;
    ssize_t                     write = 0;

    if (src->eof) {
        return 0;
    }

    if (param == NULL) {
        return -1;
    }

    while (len > 0) {
        if (param->pleft == 0) {
            // we have the last chunk
            if (param->last) {
                return write;
            }
            // reading next chunk
            read = src_read(param->readsrc, hdr, 1);
            if (read < 0) {
                RNP_LOG("failed to read header");
                return read;
            } else if (read < 1) {
                RNP_LOG("wrong eof");
                return -1;
            }
            if ((hdr[0] >= 224) && (hdr[0] < 255)) {
                param->psize = get_part_len(hdr[0]);
                param->pleft = param->psize;
            } else {
                if (hdr[0] < 192) {
                    read = hdr[0];
                } else if (hdr[0] < 224) {
                    if (src_read(param->readsrc, &hdr[1], 1) < 1) {
                        RNP_LOG("wrong 2-byte length");
                        return -1;
                    }
                    read = ((ssize_t)(hdr[0] - 192) << 8) + (ssize_t) hdr[1] + 192;
                } else {
                    if (src_read(param->readsrc, &hdr[1], 4) < 4) {
                        RNP_LOG("wrong 4-byte length");
                        return -1;
                    }
                    read = ((ssize_t) hdr[1] << 24) | ((ssize_t) hdr[2] << 16) |
                           ((ssize_t) hdr[3] << 8) | (ssize_t) hdr[4];
                }
                param->psize = read;
                param->pleft = read;
                param->last = true;
            }
        }

        if (param->pleft == 0) {
            return write;
        }

        read = param->pleft > len ? len : param->pleft;
        read = src_read(param->readsrc, buf, read);
        if (read == 0) {
            RNP_LOG("unexpected eof");
            return write;
        } else if (read < 0) {
            RNP_LOG("failed to read data chunk");
            return -1;
        } else {
            write += read;
            len -= read;
            buf = (uint8_t *) buf + read;
            param->pleft -= read;
        }
    }

    return write;
}

static void
partial_pkt_src_close(pgp_source_t *src)
{
    pgp_source_partial_param_t *param = src->param;
    if (param) {
        free(src->param);
        src->param = NULL;
    }
}

static rnp_result_t
init_partial_pkt_src(pgp_source_t *src, pgp_source_t *readsrc)
{
    pgp_source_partial_param_t *param;
    uint8_t                     buf[2];

    if (!stream_partial_pkt_len(readsrc)) {
        RNP_LOG("wrong call on non-partial len packet");
        return RNP_ERROR_BAD_FORMAT;
    }

    if (!init_source_cache(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    /* we are sure that there are 2 bytes in readsrc */
    param = src->param;
    (void) src_read(readsrc, buf, 2);
    param->type = get_packet_type(buf[0]);
    param->psize = get_part_len(buf[1]);
    param->pleft = param->psize;
    param->last = false;
    param->readsrc = readsrc;

    src->read = partial_pkt_src_read;
    src->close = partial_pkt_src_close;
    src->finish = NULL;
    src->type = PGP_STREAM_PARLEN_PACKET;
    src->size = 0;
    src->knownsize = 0;
    src->readb = 0;
    src->eof = 0;

    return RNP_SUCCESS;
}

static ssize_t
literal_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_literal_param_t *param = src->param;
    if (!param) {
        return -1;
    }

    return src_read(param->pkt.readsrc, buf, len);
}

static void
literal_src_close(pgp_source_t *src)
{
    pgp_source_literal_param_t *param = src->param;
    if (param) {
        if (param->pkt.partial) {
            param->pkt.readsrc->close(param->pkt.readsrc);
            free(param->pkt.readsrc);
            param->pkt.readsrc = NULL;
        }

        free(src->param);
        src->param = NULL;
    }
}

static ssize_t
compressed_src_read(pgp_source_t *src, void *buf, size_t len)
{
    ssize_t                        read = 0;
    int                            ret;
    pgp_source_compressed_param_t *param = src->param;

    if (param == NULL) {
        return -1;
    }

    if (src->eof || param->zend) {
        return 0;
    }

    if ((param->alg == PGP_C_ZIP) || (param->alg == PGP_C_ZLIB)) {
        param->z.next_out = buf;
        param->z.avail_out = len;
        param->z.next_in = param->in + param->inpos;
        param->z.avail_in = param->inlen - param->inpos;

        while ((param->z.avail_out > 0) && (!param->zend)) {
            if (param->z.avail_in == 0) {
                read = src_read(param->pkt.readsrc, param->in, sizeof(param->in));
                if (read < 0) {
                    RNP_LOG("failed to read data");
                    return -1;
                }
                param->z.next_in = param->in;
                param->z.avail_in = read;
                param->inlen = read;
                param->inpos = 0;
            }
            ret = inflate(&param->z, Z_SYNC_FLUSH);
            if (ret == Z_STREAM_END) {
                param->zend = true;
                if (param->z.avail_in > 0) {
                    RNP_LOG("data beyond the end of z stream");
                }
            } else if (ret != Z_OK) {
                RNP_LOG("inflate error %d", ret);
                return -1;
            }
        }

        param->inpos = param->z.next_in - param->in;
        return len - param->z.avail_out;
    }
#ifdef HAVE_BZLIB_H
    else if (param->alg == PGP_C_BZIP2) {
        param->bz.next_out = buf;
        param->bz.avail_out = len;
        param->bz.next_in = (char *) (param->in + param->inpos);
        param->bz.avail_in = param->inlen - param->inpos;

        while ((param->bz.avail_out > 0) && (!param->zend)) {
            if (param->bz.avail_in == 0) {
                read = src_read(param->pkt.readsrc, param->in, sizeof(param->in));
                if (read < 0) {
                    RNP_LOG("failed to read data");
                    return -1;
                }
                param->bz.next_in = (char *) param->in;
                param->bz.avail_in = read;
                param->inlen = read;
                param->inpos = 0;
            }
            ret = BZ2_bzDecompress(&param->bz);
            if (ret == BZ_STREAM_END) {
                param->zend = true;
                if (param->bz.avail_in > 0) {
                    RNP_LOG("data beyond the end of z stream");
                }
            } else if (ret != BZ_OK) {
                RNP_LOG("inflate error %d", ret);
                return -1;
            }
        }

        param->inpos = (uint8_t *) param->bz.next_in - param->in;
        return len - param->bz.avail_out;
    }
#endif
    else {
        return -1;
    }
}

static void
compressed_src_close(pgp_source_t *src)
{
    pgp_source_compressed_param_t *param = src->param;
    if (param) {
        if (param->pkt.partial) {
            param->pkt.readsrc->close(param->pkt.readsrc);
            free(param->pkt.readsrc);
            param->pkt.readsrc = NULL;
        }

#ifdef HAVE_BZLIB_H
        if (param->alg == PGP_C_BZIP2) {
            BZ2_bzDecompressEnd(&param->bz);
        } else if ((param->alg == PGP_C_ZIP) || (param->alg == PGP_C_ZLIB))
#endif
        {
            inflateEnd(&param->z);
        }

        free(src->param);
        src->param = NULL;
    }
}

static ssize_t
encrypted_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_encrypted_param_t *param = src->param;
    ssize_t                       read;
    ssize_t                       mdcread;
    ssize_t                       mdcsub;
    bool                          parsemdc = false;
    uint8_t                       mdcbuf[MDC_V1_SIZE];
    uint8_t                       hash[PGP_SHA1_HASH_SIZE];

    if (param == NULL) {
        return -1;
    }

    if (src->eof) {
        return 0;
    }

    read = src_read(param->pkt.readsrc, buf, len);
    if (read <= 0) {
        return read;
    }

    if (param->has_mdc) {
        /* make sure there are always 20 bytes left on input */
        mdcread = src_peek(param->pkt.readsrc, mdcbuf, MDC_V1_SIZE);
        if (mdcread < MDC_V1_SIZE) {
            if ((mdcread < 0) || (mdcread + read < MDC_V1_SIZE)) {
                RNP_LOG("wrong mdc read state");
                return -1;
            }

            mdcsub = MDC_V1_SIZE - mdcread;
            memmove(&mdcbuf[mdcsub], mdcbuf, mdcread);
            memcpy(mdcbuf, (uint8_t *) buf + read - mdcsub, mdcsub);
            read -= mdcsub;
            parsemdc = true;
        }
    }

    pgp_cipher_cfb_decrypt(&param->decrypt, buf, buf, read);

    if (param->has_mdc) {
        pgp_hash_add(&param->mdc, buf, read);

        if (parsemdc) {
            pgp_cipher_cfb_decrypt(&param->decrypt, mdcbuf, mdcbuf, MDC_V1_SIZE);
            pgp_cipher_finish(&param->decrypt);
            pgp_hash_add(&param->mdc, mdcbuf, 2);
            pgp_hash_finish(&param->mdc, hash);

            if ((mdcbuf[0] != MDC_PKT_TAG) || (mdcbuf[1] != MDC_V1_SIZE - 2)) {
                RNP_LOG("mdc header check failed");
                return -1;
            }

            if (memcmp(&mdcbuf[2], hash, PGP_SHA1_HASH_SIZE) != 0) {
                RNP_LOG("mdc hash check failed");
                return -1;
            }

            param->mdc_validated = true;
        }
    }

    return read;
}

static rnp_result_t
encrypted_src_finish(pgp_source_t *src)
{
    pgp_source_encrypted_param_t *param = src->param;

    if (param->has_mdc && !param->mdc_validated) {
        RNP_LOG("mdc was not validated");
        return RNP_ERROR_BAD_STATE;
    }

    return RNP_SUCCESS;
}

static void
encrypted_src_close(pgp_source_t *src)
{
    pgp_source_encrypted_param_t *param = src->param;
    if (param) {
        FREE_ARRAY(param, symenc);
        FREE_ARRAY(param, pubenc);

        if (param->pkt.partial) {
            param->pkt.readsrc->close(param->pkt.readsrc);
            free(param->pkt.readsrc);
            param->pkt.readsrc = NULL;
        }

        free(src->param);
        src->param = NULL;
    }
}

static pgp_hash_t *
signed_get_hash(pgp_source_signed_param_t *param, pgp_hash_alg_t alg)
{
    for (int i = 0; i < param->hashc; i++) {
        if (pgp_hash_alg_type(&param->hashs[i]) == alg) {
            return &param->hashs[i];
        }
    }

    return NULL;
}

static void
signed_add_hash(pgp_source_signed_param_t *param, pgp_hash_alg_t alg)
{
    pgp_hash_t hash = {0};

    if (!signed_get_hash(param, alg)) {
        if (!pgp_hash_create(&hash, alg)) {
            RNP_LOG("failed to initialize hash algorithm %d", (int) alg);
        } else {
            EXPAND_ARRAY_EX(param, hash, 1);
            param->hashs[param->hashc++] = hash;
        }
    }
}

static bool
signed_validate_signature(pgp_source_t *src, pgp_signature_t *sig, pgp_pubkey_t *key)
{
    pgp_hash_t *               hash;
    pgp_hash_t                 shash = {0};
    uint8_t                    trailer[6];
    uint8_t                    hval[PGP_MAX_HASH_SIZE];
    unsigned                   len;
    pgp_source_signed_param_t *param = src->param;
    bool                       ret = false;

    /* Get the hash context */
    if ((hash = signed_get_hash(param, sig->halg)) == NULL) {
        RNP_LOG("hash context %d not found", (int) sig->halg);
        return false;
    }

    if (!pgp_hash_copy(&shash, hash)) {
        RNP_LOG("failed to clone hash context");
        return false;
    }

    /* hash signature fields and trailer */
    pgp_hash_add(&shash, sig->hashed_data, sig->hashed_len);

    if (sig->version > 3) {
        trailer[0] = sig->version;
        trailer[1] = 0xff;
        STORE32BE(&trailer[2], sig->hashed_len);
        pgp_hash_add(&shash, trailer, 6);
    }

    len = pgp_hash_finish(&shash, hval);

    /* validate signature */

    switch (sig->palg) {
    case PGP_PKA_DSA: {
        pgp_dsa_sig_t dsa = {.r = BN_bin2bn(sig->material.dsa.r, sig->material.dsa.rlen, NULL),
                             .s =
                               BN_bin2bn(sig->material.dsa.s, sig->material.dsa.slen, NULL)};
        ret = pgp_dsa_verify(hval, len, &dsa, &key->key.dsa);
        BN_free(dsa.r);
        BN_free(dsa.s);
        break;
    }
    case PGP_PKA_EDDSA: {
        BIGNUM *r = BN_bin2bn(sig->material.ecc.r, sig->material.ecc.rlen, NULL);
        BIGNUM *s = BN_bin2bn(sig->material.ecc.s, sig->material.ecc.slen, NULL);
        ret = pgp_eddsa_verify_hash(r, s, hval, len, &key->key.ecc);
        BN_free(r);
        BN_free(s);
        break;
    }
    case PGP_PKA_SM2: {
        pgp_ecc_sig_t ecc = {.r = BN_bin2bn(sig->material.ecc.r, sig->material.ecc.rlen, NULL),
                             .s =
                               BN_bin2bn(sig->material.ecc.s, sig->material.ecc.slen, NULL)};
        ret = pgp_sm2_verify_hash(&ecc, hval, len, &key->key.ecc) == RNP_SUCCESS;
        BN_free(ecc.r);
        BN_free(ecc.s);
        break;
    }
    case PGP_PKA_RSA: {
        ret = pgp_rsa_pkcs1_verify_hash(
          sig->material.rsa.s, sig->material.rsa.slen, sig->halg, hval, len, &key->key.rsa);
        break;
    }
    case PGP_PKA_ECDSA: {
        pgp_ecc_sig_t ecc = {.r = BN_bin2bn(sig->material.ecc.r, sig->material.ecc.rlen, NULL),
                             .s =
                               BN_bin2bn(sig->material.ecc.s, sig->material.ecc.slen, NULL)};
        ret = pgp_ecdsa_verify_hash(&ecc, hval, len, &key->key.ecc) == RNP_SUCCESS;
        BN_free(ecc.r);
        BN_free(ecc.s);
        break;
    }
    default:
        RNP_LOG("Unknown algorithm");
        return false;
    }

    return ret;
}

static void
signed_src_update(pgp_source_t *src, const void *buf, size_t len)
{
    pgp_source_signed_param_t *param = src->param;

    for (int i = 0; i < param->hashc; i++) {
        pgp_hash_add(&param->hashs[i], buf, len);
    }
}

static ssize_t
signed_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_signed_param_t *param = src->param;

    if (param == NULL) {
        return -1;
    } else {
        return src_read(param->readsrc, buf, len);
    }
}

static void
signed_src_close(pgp_source_t *src)
{
    pgp_source_signed_param_t *param = src->param;

    if (param) {
        FREE_ARRAY(param, onepass);
        for (int i = 0; i < param->hashc; i++) {
            pgp_hash_finish(&param->hashs[i], NULL);
        }
        FREE_ARRAY(param, hash);
        FREE_ARRAY(param, info);
        for (int i = 0; i < param->sigc; i++) {
            free_signature(&param->sigs[i]);
        }
        FREE_ARRAY(param, sig);
        free(src->param);
        src->param = NULL;
    }
}

static rnp_result_t
signed_read_single_signature(pgp_source_signed_param_t *param,
                             pgp_source_t *             readsrc,
                             pgp_signature_t **         sig)
{
    uint8_t         ptag;
    int             ptype;
    pgp_signature_t readsig;

    if (src_peek(readsrc, &ptag, 1) < 1) {
        RNP_LOG("failed to read signature packet header");
        return RNP_ERROR_READ;
    }

    ptype = get_packet_type(ptag);

    if (ptype == PGP_PTAG_CT_SIGNATURE) {
        EXPAND_ARRAY_EX(param, info, 1);
        param->infoc++;
        if (stream_parse_signature(readsrc, &readsig) != RNP_SUCCESS) {
            RNP_LOG("failed to parse signature");
            param->infos[param->infoc - 1].unknown = true;
            if (sig) {
                *sig = NULL;
            }
        } else {
            EXPAND_ARRAY_EX(param, sig, 1);
            param->sigs[param->sigc++] = readsig;
            param->infos[param->infoc - 1].sig = &param->sigs[param->sigc - 1];
            if (sig) {
                *sig = &param->sigs[param->sigc - 1];
            }
        }
    } else {
        RNP_LOG("unexpected packet %d", ptype);
        return RNP_ERROR_BAD_FORMAT;
    }

    return RNP_SUCCESS;
}

static rnp_result_t
signed_read_cleartext_signatures(pgp_source_t *src)
{
    pgp_source_t               armor = {0};
    rnp_result_t               ret = RNP_ERROR_BAD_FORMAT;
    pgp_source_signed_param_t *param = src->param;

    if ((ret = init_armored_src(&armor, param->readsrc)) != RNP_SUCCESS) {
        return ret;
    }

    while (!src_eof(&armor)) {
        if ((ret = signed_read_single_signature(param, &armor, NULL)) != RNP_SUCCESS) {
            goto finish;
        }
    }

    ret = RNP_SUCCESS;

finish:
    src_close(&armor);
    return ret;
}

static rnp_result_t
signed_read_signatures(pgp_source_t *src)
{
    pgp_signature_t *          sig = NULL;
    rnp_result_t               ret;
    pgp_source_signed_param_t *param = src->param;

    /* reading signatures */
    for (int i = 0; i < param->onepassc; i++) {
        if ((ret = signed_read_single_signature(param, src, &sig)) != RNP_SUCCESS) {
            return ret;
        }

        if (!signature_matches_onepass(sig, &param->onepasss[param->onepassc - i - 1])) {
            RNP_LOG("signature %d doesn't match one-pass", (int) i);
            return RNP_ERROR_BAD_FORMAT;
        }
    }

    return RNP_SUCCESS;
}

static rnp_result_t
signed_src_finish(pgp_source_t *src)
{
    pgp_source_signed_param_t *param = src->param;
    pgp_signature_info_t *     sinfo = NULL;
    pgp_key_request_ctx_t      keyctx;
    pgp_key_t *                key = NULL;
    rnp_result_t               ret = RNP_SUCCESS;
    time_t                     now;
    uint32_t                   create, expiry;

    if (param->cleartext) {
        ret = signed_read_cleartext_signatures(src);
    } else {
        ret = signed_read_signatures(src);
    }

    if (ret != RNP_SUCCESS) {
        goto finish;
    }

    if (!src_eof(src)) {
        RNP_LOG("warning: unexpected data on the stream end");
    }

    /* validating signatures */
    keyctx.op = PGP_OP_VERIFY;
    keyctx.secret = false;
    keyctx.stype = PGP_KEY_SEARCH_KEYID;

    for (int i = 0; i < param->infoc; i++) {
        sinfo = &param->infos[i];
        if (!sinfo->sig) {
            continue;
        }

        /* Get the key id */
        if (!signature_get_keyid(sinfo->sig, keyctx.search.id)) {
            RNP_LOG("cannot get signer's key id from signature");
            sinfo->unknown = true;
            continue;
        }

        /* Get the public key */
        if (!pgp_request_key(param->ctx->handler.key_provider, &keyctx, &key)) {
            RNP_LOG("signer's key not found");
            param->infos[i].no_signer = true;
            continue;
        }
        sinfo->signer = &(key->key.pubkey);

        /* Validate signature itself */
        sinfo->valid = signed_validate_signature(src, sinfo->sig, sinfo->signer);

        /* Check signature's expiration time */
        now = time(NULL);
        create = signature_get_creation(sinfo->sig);
        expiry = signature_get_expiration(sinfo->sig);
        if (create > 0) {
            if (create > now) {
                /* signature created later then now */
                sinfo->expired = true;
            }
            if ((expiry > 0) && (create + expiry < now)) {
                /* signature expired */
                sinfo->expired = true;
            }
        }
    }

    /* call the callback with signature infos */
    if (param->ctx->handler.on_signatures) {
        param->ctx->handler.on_signatures(&param->ctx->handler, param->infos, param->infoc);
    }

    for (int i = 0; i < param->infoc; i++) {
        if (!param->infos[i].valid || param->infos[i].expired) {
            ret = RNP_ERROR_SIGNATURE_INVALID;
            break;
        }
    }
finish:
    return ret;
}

static bool
cleartext_parse_headers(pgp_source_t *src)
{
    pgp_source_signed_param_t *param = src->param;
    char                       hdr[1024];
    char *                     hval;
    char *                     hname;
    pgp_hash_alg_t             halg;
    ssize_t                    hdrlen;

    do {
        if ((hdrlen = src_peek_line(param->readsrc, hdr, sizeof(hdr))) < 0) {
            RNP_LOG("failed to peek line");
            return false;
        }

        if (!hdrlen) {
            break;
        }

        if (strncmp(hdr, "Hash: ", 6) == 0) {
            hval = hdr + 6;

            while ((hname = strsep(&hval, ", \t"))) {
                if (!*hname) {
                    continue;
                }

                if ((halg = pgp_str_to_hash_alg(hname)) == PGP_HASH_UNKNOWN) {
                    RNP_LOG("unknown halg: %s", hname);
                }

                signed_add_hash(param, halg);
            }
        } else {
            RNP_LOG("unknown header '%s'", hdr);
        }

        src_skip(param->readsrc, hdrlen);

        if (!src_skip_eol(param->readsrc)) {
            return false;
        }
    } while (1);

    /* we have exactly one empty line after the headers */
    return src_skip_eol(param->readsrc);
}

#define CH_CR ('\r')
#define CH_LF ('\n')
#define CH_DASH ('-')
#define CH_SPACE (' ')
#define CH_TAB ('\t')
#define ST_CRLF ("\r\n")
#define ST_DASHES ("-----")

static void
cleartext_process_line(pgp_source_t *src, const uint8_t *buf, size_t len)
{
    pgp_source_signed_param_t *param = src->param;
    uint8_t *                  bufen = (uint8_t *) buf + len - 1;

    if ((len > 0) && (buf[0] == CH_DASH)) {
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

    if (!param->clr_noeol) {
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

    for (; ((*bufen == CH_SPACE) || (*bufen == CH_TAB)) && (bufen >= buf); bufen--)
        ;

    if ((len = bufen + 1 - buf)) {
        memcpy(param->out + param->outlen, buf, len);
        param->outlen += len;
        signed_src_update(src, buf, len);
    }
}

static ssize_t
cleartext_src_read(pgp_source_t *src, void *buf, size_t len)
{
    uint8_t                    srcb[CT_BUF_LEN];
    uint8_t *                  cur, *en, *bg;
    ssize_t                    read = 0;
    ssize_t                    origlen = len;
    pgp_source_signed_param_t *param = src->param;

    if (param == NULL) {
        return -1;
    }

    read = param->outlen - param->outpos;
    if (read >= len) {
        memcpy(buf, param->out + param->outpos, len);
        param->outpos += len;
        if (param->outpos == param->outlen) {
            param->outpos = param->outlen = 0;
        }
        return len;
    } else if (read > 0) {
        memcpy(buf, param->out + param->outpos, read);
        len -= read;
        buf = (uint8_t *) buf + read;
        param->outpos = param->outlen = 0;
    }

    if (param->clr_eod) {
        return origlen - len;
    }

    cur = srcb;
    bg = srcb;

    do {
        read = src_peek(param->readsrc, cur, sizeof(srcb) - (cur - srcb));
        if (read < 0) {
            return -1;
        } else if (read == 0) {
            break;
        }

        /* processing data line by line, eol could be \n or \r\n */
        for (en = cur + read; cur < en; cur++) {
            if ((*cur == CH_LF) || (*cur == CH_CR && (cur + 1 < en) && *(cur + 1) == CH_LF)) {
                cleartext_process_line(src, bg, cur - bg);
                /* processing eol */
                if (param->clr_eod) {
                    read -= en - bg;
                    break;
                }

                /* processing eol */
                param->clr_noeol = false;
                param->out[param->outlen++] = *cur;
                if (*cur == CH_CR) {
                    param->out[param->outlen++] = *cur++;
                }
                bg = cur + 1;
            }
        }

        /* if line is larger then 4k then just dump it out */
        if ((bg == srcb) && !param->clr_eod) {
            cleartext_process_line(src, bg, en - bg);
            param->clr_noeol = true;
            bg = en;
        }
        src_skip(param->readsrc, read);

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

        /* copy bytes left between bg & en, setup cur and bg */
        memmove(srcb, bg, en - bg);
        cur = srcb + (en - bg);
        bg = srcb;
    } while (1);

    return origlen - len;
}

static bool
encrypted_decrypt_header(pgp_source_t *src, pgp_symm_alg_t alg, uint8_t *key)
{
    pgp_source_encrypted_param_t *param = src->param;
    pgp_crypt_t                   crypt;
    uint8_t                       enchdr[PGP_MAX_BLOCK_SIZE + 2];
    uint8_t                       dechdr[PGP_MAX_BLOCK_SIZE + 2];
    unsigned                      blsize;

    if (!(blsize = pgp_block_size(alg))) {
        return false;
    }

    /* reading encrypted header to check the password validity */
    if (src_peek(param->pkt.readsrc, enchdr, blsize + 2) < blsize + 2) {
        RNP_LOG("failed to read encrypted header");
        return false;
    }

    /* having symmetric key in keybuf let's decrypt blocksize + 2 bytes and check them */
    if (!pgp_cipher_start(&crypt, alg, key, NULL)) {
        RNP_LOG("failed to start cipher");
        return false;
    }

    pgp_cipher_cfb_decrypt(&crypt, dechdr, enchdr, blsize + 2);
    if ((dechdr[blsize] == dechdr[blsize - 2]) && (dechdr[blsize + 1] == dechdr[blsize - 1])) {
        src_skip(param->pkt.readsrc, blsize + 2);
        param->decrypt = crypt;
        /* init mdc if it is here */
        /* RFC 4880, 5.13: Unlike the Symmetrically Encrypted Data Packet, no special CFB
         * resynchronization is done after encrypting this prefix data. */
        if (!param->has_mdc) {
            pgp_cipher_cfb_resync(&param->decrypt, enchdr + 2);
        } else {
            if (!pgp_hash_create(&param->mdc, PGP_HASH_SHA1)) {
                pgp_cipher_finish(&crypt);
                RNP_LOG("cannot create sha1 hash");
                return false;
            }

            pgp_hash_add(&param->mdc, dechdr, blsize + 2);
        }

        return true;
    } else {
        return false;
    }
}

static bool
encrypted_try_key(pgp_source_t *src, pgp_pk_sesskey_pkt_t *sesskey, pgp_seckey_t *seckey)
{
    uint8_t           decbuf[PGP_MPINT_SIZE];
    rnp_result_t      err;
    size_t            declen;
    size_t            keylen;
    pgp_fingerprint_t fingerprint;
    pgp_symm_alg_t    salg;
    unsigned          checksum = 0;
    bool              res = false;
    BIGNUM *          ecdh_p;

    /* Decrypting session key value */
    switch (sesskey->alg) {
    case PGP_PKA_RSA:
        declen = pgp_rsa_decrypt_pkcs1(decbuf,
                                       sizeof(decbuf),
                                       sesskey->params.rsa.m,
                                       sesskey->params.rsa.mlen,
                                       &seckey->key.rsa,
                                       &seckey->pubkey.key.rsa);
        if (declen <= 0) {
            RNP_LOG("RSA decryption failure");
            return false;
        }
        break;
    case PGP_PKA_SM2:
        declen = sizeof(decbuf);
        err = pgp_sm2_decrypt(decbuf,
                              &declen,
                              sesskey->params.sm2.m,
                              sesskey->params.sm2.mlen,
                              &seckey->key.ecc,
                              &seckey->pubkey.key.ecc);

        if (err != RNP_SUCCESS) {
            RNP_LOG("SM2 decryption failure, error %x", (int) err);
            return false;
        }
        break;
    case PGP_PKA_ELGAMAL:
        declen = pgp_elgamal_private_decrypt_pkcs1(decbuf,
                                                   sesskey->params.eg.g,
                                                   sesskey->params.eg.m,
                                                   sesskey->params.eg.mlen,
                                                   &seckey->key.elgamal,
                                                   &seckey->pubkey.key.elgamal);
        if (declen <= 0) {
            RNP_LOG("ElGamal decryption failure");
            return false;
        }
        break;
    case PGP_PKA_ECDH:
        declen = sizeof(decbuf);

        if (!pgp_fingerprint(&fingerprint, &seckey->pubkey)) {
            RNP_LOG("ECDH fingerprint calculation failed");
            return false;
        }
        ecdh_p = BN_bin2bn(sesskey->params.ecdh.p, sesskey->params.ecdh.plen, NULL);

        err = pgp_ecdh_decrypt_pkcs5(decbuf,
                                     &declen,
                                     sesskey->params.ecdh.m,
                                     sesskey->params.ecdh.mlen,
                                     ecdh_p,
                                     &seckey->key.ecc,
                                     &seckey->pubkey.key.ecdh,
                                     &fingerprint);
        BN_free(ecdh_p);

        if (err != RNP_SUCCESS) {
            RNP_LOG("ECDH decryption error %u", err);
            return false;
        }
        break;
    default:
        RNP_LOG("unsupported public key algorithm %d\n", seckey->pubkey.alg);
        return false;
    }

    /* Check algorithm and key length */
    salg = decbuf[0];
    if (!pgp_is_sa_supported(salg)) {
        RNP_LOG("unsupported symmetric algorithm %d", (int) salg);
        return false;
    }

    keylen = pgp_key_size(salg);
    if (declen != keylen + 3) {
        RNP_LOG("invalid symmetric key length");
        return false;
    }

    /* Validate checksum */
    for (int i = 1; i <= keylen; i++) {
        checksum += decbuf[i];
    }

    if ((checksum & 0xffff) != (decbuf[keylen + 2] | ((unsigned) decbuf[keylen + 1] << 8))) {
        RNP_LOG("wrong checksum\n");
        goto finish;
    }

    /* Decrypt header */
    res = encrypted_decrypt_header(src, salg, &decbuf[1]);

finish:
    pgp_forget(&checksum, sizeof(checksum));
    pgp_forget(decbuf, sizeof(decbuf));

    return res;
}

static int
encrypted_try_password(pgp_source_t *src, const char *password)
{
    pgp_source_encrypted_param_t *param = src->param;
    pgp_sk_sesskey_t *            symkey;
    pgp_crypt_t                   crypt;
    pgp_symm_alg_t                alg;
    uint8_t                       keybuf[PGP_MAX_KEY_SIZE + 1];
    int                           keysize;
    int                           blsize;
    bool                          keyavail = false;
    int                           res;

    for (int i = 0; i < param->symencc; i++) {
        /* deriving symmetric key from password */
        symkey = &param->symencs[i];
        keysize = pgp_key_size(symkey->alg);
        if (!keysize || !pgp_s2k_derive_key(&symkey->s2k, password, keybuf, keysize)) {
            continue;
        }

        if (symkey->enckeylen > 0) {
            /* decrypting session key */
            if (!pgp_cipher_start(&crypt, symkey->alg, keybuf, NULL)) {
                continue;
            }

            pgp_cipher_cfb_decrypt(&crypt, keybuf, symkey->enckey, symkey->enckeylen);
            pgp_cipher_finish(&crypt);

            keyavail = true;
            alg = (pgp_symm_alg_t) keybuf[0];
            keysize = pgp_key_size(alg);
            blsize = pgp_block_size(alg);
            if (!keysize || (keysize + 1 != symkey->enckeylen) || !blsize) {
                continue;
            }
            memmove(keybuf, keybuf + 1, keysize);
        } else {
            alg = (pgp_symm_alg_t) symkey->alg;
            blsize = pgp_block_size(alg);
            if (!blsize) {
                continue;
            }
            keyavail = true;
        }

        /* decrypting header and checking key validity */
        if (!encrypted_decrypt_header(src, alg, keybuf)) {
            continue;
        }

        res = 1;
        goto finish;
    }

    if (!keyavail) {
        RNP_LOG("no supported sk available");
        res = -1;
    } else {
        res = 0;
    }

finish:
    pgp_forget(keybuf, sizeof(keybuf));
    return res;
}

/** @brief Initialize common to stream packets params, including partial data source */
static rnp_result_t
init_packet_params(pgp_source_t *src, pgp_source_packet_param_t *param)
{
    pgp_source_t *partsrc;
    rnp_result_t  errcode;
    ssize_t       len;

    param->origsrc = NULL;
    // initialize partial reader if needed
    param->hdrlen = stream_pkt_hdr_len(param->readsrc);
    if (stream_partial_pkt_len(param->readsrc)) {
        if ((partsrc = calloc(1, sizeof(*partsrc))) == NULL) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        errcode = init_partial_pkt_src(partsrc, param->readsrc);
        if (errcode != RNP_SUCCESS) {
            free(partsrc);
            return errcode;
        }
        param->partial = true;
        param->origsrc = param->readsrc;
        param->readsrc = partsrc;
    } else if (stream_intedeterminate_pkt_len(param->readsrc)) {
        param->indeterminate = true;
        (void) src_skip(param->readsrc, 1);
    } else {
        len = stream_read_pkt_len(param->readsrc);
        if (len < 0) {
            RNP_LOG("cannot read pkt len");
            return RNP_ERROR_BAD_FORMAT;
        }
        param->len = len;
    }

    return RNP_SUCCESS;
}

static rnp_result_t
init_literal_src(pgp_processing_ctx_t *ctx, pgp_source_t *src, pgp_source_t *readsrc)
{
    rnp_result_t                errcode = RNP_SUCCESS;
    pgp_source_literal_param_t *param;
    uint8_t                     bt;
    uint8_t                     tstbuf[4];

    if (!init_source_cache(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = src->param;
    param->pkt.readsrc = readsrc;
    src->read = literal_src_read;
    src->close = literal_src_close;
    src->finish = NULL;
    src->type = PGP_STREAM_LITERAL;
    src->size = 0;
    src->knownsize = 0;
    src->readb = 0;
    src->eof = 0;

    /* Reading packet length/checking whether it is partial */
    errcode = init_packet_params(src, &param->pkt);
    if (errcode != RNP_SUCCESS) {
        goto finish;
    }

    /* data format */
    if (src_read(param->pkt.readsrc, &bt, 1) != 1) {
        RNP_LOG("failed to read data format");
        errcode = RNP_ERROR_READ;
        goto finish;
    }

    switch (bt) {
    case 'b':
        param->text = false;
        break;
    case 't':
    case 'u':
    case 'l':
    case '1':
        param->text = true;
        break;
    default:
        RNP_LOG("unknown data format %d", (int) bt);
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }

    /* file name */
    if (src_read(param->pkt.readsrc, &bt, 1) != 1) {
        RNP_LOG("failed to read file name length");
        errcode = RNP_ERROR_READ;
        goto finish;
    }
    if (bt > 0) {
        if (src_read(param->pkt.readsrc, param->filename, bt) < bt) {
            RNP_LOG("failed to read file name");
            errcode = RNP_ERROR_READ;
            goto finish;
        }
    }
    param->filename[bt] = 0;
    /* timestamp */
    if (src_read(param->pkt.readsrc, tstbuf, 4) != 4) {
        RNP_LOG("failed to read file timestamp");
        errcode = RNP_ERROR_READ;
        goto finish;
    }
    param->timestamp = ((uint32_t) tstbuf[0] << 24) | ((uint32_t) tstbuf[1] << 16) |
                       ((uint32_t) tstbuf[2] << 8) | (uint32_t) tstbuf[3];

    if (!param->pkt.indeterminate && !param->pkt.partial) {
        src->size = param->pkt.len - (1 + 1 + bt + 4);
        src->knownsize = 1;
    }

finish:
    if (errcode != RNP_SUCCESS) {
        src_close(src);
    }
    return errcode;
}

static rnp_result_t
init_compressed_src(pgp_processing_ctx_t *ctx, pgp_source_t *src, pgp_source_t *readsrc)
{
    rnp_result_t                   errcode = RNP_SUCCESS;
    pgp_source_compressed_param_t *param;
    uint8_t                        alg;
    int                            zret;

    if (!init_source_cache(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = src->param;
    param->pkt.readsrc = readsrc;
    src->read = compressed_src_read;
    src->close = compressed_src_close;
    src->finish = NULL;
    src->type = PGP_STREAM_COMPRESSED;
    src->size = 0;
    src->knownsize = 0;
    src->readb = 0;
    src->eof = 0;

    /* Reading packet length/checking whether it is partial */
    errcode = init_packet_params(src, &param->pkt);
    if (errcode != RNP_SUCCESS) {
        goto finish;
    }

    /* Reading compression algorithm */
    if (src_read(param->pkt.readsrc, &alg, 1) != 1) {
        RNP_LOG("failed to read compression algorithm");
        errcode = RNP_ERROR_READ;
        goto finish;
    }

    /* Initializing decompression */
    switch (alg) {
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
        RNP_LOG("unknown compression algorithm");
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    param->alg = alg;
    param->inlen = 0;
    param->inpos = 0;

finish:
    if (errcode != RNP_SUCCESS) {
        src_close(src);
    }
    return errcode;
}

static rnp_result_t
init_encrypted_src(pgp_processing_ctx_t *ctx, pgp_source_t *src, pgp_source_t *readsrc)
{
    rnp_result_t                  errcode = RNP_SUCCESS;
    pgp_source_encrypted_param_t *param;
    uint8_t                       ptag;
    uint8_t                       mdcver;
    int                           ptype;
    pgp_sk_sesskey_t              skey = {0};
    pgp_pk_sesskey_pkt_t          pkey = {0};
    pgp_key_t *                   seckey = NULL;
    pgp_key_request_ctx_t         keyctx;
    pgp_seckey_t *                decrypted_seckey = NULL;
    char                          password[MAX_PASSWORD_LENGTH] = {0};
    int                           intres;
    bool                          have_key = false;
    uint64_t                      readb;

    if (!init_source_cache(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    param = src->param;
    param->pkt.readsrc = readsrc;
    src->read = encrypted_src_read;
    src->close = encrypted_src_close;
    src->finish = encrypted_src_finish;
    src->type = PGP_STREAM_ENCRYPTED;
    src->size = 0;
    src->knownsize = 0;
    src->readb = 0;
    src->eof = 0;

    /* Reading pk/sk encrypted session key(s) */
    while (true) {
        if (src_peek(readsrc, &ptag, 1) < 1) {
            RNP_LOG("failed to read packet header");
            errcode = RNP_ERROR_READ;
            goto finish;
        }

        ptype = get_packet_type(ptag);

        if (ptype == PGP_PTAG_CT_SK_SESSION_KEY) {
            errcode = stream_parse_sk_sesskey(readsrc, &skey);
            if (errcode != RNP_SUCCESS) {
                goto finish;
            }
            EXPAND_ARRAY_EX(param, symenc, 1);
            param->symencs[param->symencc++] = skey;
        } else if (ptype == PGP_PTAG_CT_PK_SESSION_KEY) {
            errcode = stream_parse_pk_sesskey(readsrc, &pkey);
            if (errcode != RNP_SUCCESS) {
                goto finish;
            }
            EXPAND_ARRAY_EX(param, pubenc, 1);
            param->pubencs[param->pubencc++] = pkey;
        } else if ((ptype == PGP_PTAG_CT_SE_DATA) || (ptype == PGP_PTAG_CT_SE_IP_DATA)) {
            break;
        } else {
            RNP_LOG("unknown packet type: %d", ptype);
            errcode = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
    }

    /* Reading packet length/checking whether it is partial */
    errcode = init_packet_params(src, &param->pkt);
    if (errcode != RNP_SUCCESS) {
        goto finish;
    }

    /* Reading header of encrypted packet */
    readb = param->pkt.readsrc->readb;

    if (ptype == PGP_PTAG_CT_SE_IP_DATA) {
        if (src_read(param->pkt.readsrc, &mdcver, 1) != 1) {
            errcode = RNP_ERROR_READ;
            goto finish;
        }
        if (mdcver != 1) {
            RNP_LOG("unknown mdc ver: %d", (int) mdcver);
            errcode = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
        param->has_mdc = true;
        param->mdc_validated = false;
    }

    /* Obtaining the symmetric key */
    have_key = false;

    if (!ctx->handler.password_provider) {
        RNP_LOG("no password provider");
        errcode = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* Trying public-key decryption */
    if (param->pubencc > 0) {
        if (!ctx->handler.key_provider) {
            RNP_LOG("no key provider");
            errcode = RNP_ERROR_BAD_PARAMETERS;
            goto finish;
        }

        keyctx.op = PGP_OP_DECRYPT_SYM;
        keyctx.secret = true;
        keyctx.stype = PGP_KEY_SEARCH_KEYID;

        for (int i = 0; i < param->pubencc; i++) {
            memcpy(keyctx.search.id, param->pubencs[i].key_id, sizeof(keyctx.search.id));
            /* Get the key if any */
            if (!pgp_request_key(ctx->handler.key_provider, &keyctx, &seckey)) {
                continue;
            }
            /* Decrypt key */
            if (seckey->key.seckey.encrypted) {
                decrypted_seckey = pgp_decrypt_seckey(
                  seckey,
                  ctx->handler.password_provider,
                  &(pgp_password_ctx_t){.op = PGP_OP_DECRYPT, .key = seckey});
                if (!decrypted_seckey) {
                    continue;
                }
            } else {
                decrypted_seckey = &(seckey->key.seckey);
            }

            /* Try to initialize the decryption */
            if (encrypted_try_key(src, &param->pubencs[i], decrypted_seckey)) {
                have_key = true;
            }

            /* Destroy decrypted key */
            if (seckey->key.seckey.encrypted) {
                pgp_seckey_free(decrypted_seckey);
                free(decrypted_seckey);
                decrypted_seckey = NULL;
            }

            if (have_key) {
                break;
            }
        }
    }

    /* Trying password-based decryption */
    if (!have_key && (param->symencc > 0)) {
        do {
            if (!pgp_request_password(
                  ctx->handler.password_provider,
                  &(pgp_password_ctx_t){.op = PGP_OP_DECRYPT_SYM, .key = NULL},
                  password,
                  sizeof(password))) {
                errcode = RNP_ERROR_BAD_PASSWORD;
                goto finish;
            }

            intres = encrypted_try_password(src, password);
            if (intres > 0) {
                have_key = true;
                break;
            } else if (intres < 0) {
                errcode = RNP_ERROR_NOT_SUPPORTED;
                goto finish;
            } else if (strlen(password) == 0) {
                RNP_LOG("empty password - canceling");
                errcode = RNP_ERROR_BAD_PASSWORD;
                goto finish;
            }
        } while (1);
    }

    if (!have_key) {
        RNP_LOG("failed to obtain decrypting key or password");
        errcode = RNP_ERROR_NO_SUITABLE_KEY;
    }

    if (!param->pkt.partial && !param->pkt.indeterminate) {
        src->knownsize = 1;
        src->size = param->pkt.len - (param->pkt.readsrc->readb - readb);
    }

finish:
    if (errcode != RNP_SUCCESS) {
        src_close(src);
    }
    pgp_forget(password, sizeof(password));

    return errcode;
}

static rnp_result_t
init_cleartext_signed_src(pgp_source_t *src)
{
    const char                 hdr[34] = "-----BEGIN PGP SIGNED MESSAGE-----";
    char                       buf[64];
    pgp_source_signed_param_t *param = src->param;

    /* checking header line */
    if (src_read(param->readsrc, buf, sizeof(hdr)) != sizeof(hdr)) {
        RNP_LOG("failed to read header");
        return RNP_ERROR_READ;
    }

    if (memcmp(hdr, buf, sizeof(hdr))) {
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

    param->clr_noeol = true;

    /* now we are good to go */
    return RNP_SUCCESS;
}

static rnp_result_t
init_signed_src(pgp_processing_ctx_t *ctx, pgp_source_t *src, pgp_source_t *readsrc)
{
    rnp_result_t               errcode = RNP_SUCCESS;
    pgp_source_signed_param_t *param;
    uint8_t                    ptag;
    int                        ptype;
    pgp_one_pass_sig_t         onepass = {0};
    pgp_signature_t *          sig = NULL;
    bool                       cleartext;

    if (!init_source_cache(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    cleartext = is_cleartext_source(readsrc);

    param = src->param;
    param->readsrc = readsrc;
    param->ctx = ctx;
    param->cleartext = cleartext;
    src->read = cleartext ? cleartext_src_read : signed_src_read;
    src->close = signed_src_close;
    src->finish = signed_src_finish;
    src->type = cleartext ? PGP_STREAM_CLEARTEXT : PGP_STREAM_SIGNED;
    src->size = 0;
    src->knownsize = 0;
    src->readb = 0;
    src->eof = 0;

    /* we need key provider to validate signatures */
    if (!ctx->handler.key_provider) {
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
        if (src_peek(readsrc, &ptag, 1) < 1) {
            RNP_LOG("failed to read packet header");
            errcode = RNP_ERROR_READ;
            goto finish;
        }

        ptype = get_packet_type(ptag);

        if (ptype == PGP_PTAG_CT_1_PASS_SIG) {
            errcode = stream_parse_one_pass(readsrc, &onepass);
            if (errcode != RNP_SUCCESS) {
                if (errcode == RNP_ERROR_READ) {
                    goto finish;
                } else {
                    continue;
                }
            }
            EXPAND_ARRAY_EX(param, onepass, 1);
            param->onepasss[param->onepassc++] = onepass;

            /* adding hash context */
            signed_add_hash(param, onepass.halg);

            if (onepass.nested) {
                /* despite the name non-zero value means that it is the last one-pass */
                break;
            }
        } else if (ptype == PGP_PTAG_CT_SIGNATURE) {
            /* no need to check the error here - we already know tag */
            signed_read_single_signature(param, readsrc, &sig);
            /* adding hash context */
            if (sig) {
                signed_add_hash(param, sig->halg);
            }
        } else {
            break;
        }

        /* for detached signature we'll get eof */
        if (src_eof(readsrc)) {
            param->detached = true;
            break;
        }
    }

    /* checking what we have now */
    if (!param->onepassc && !param->sigc) {
        RNP_LOG("no signatures");
        errcode = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    } else if (param->onepassc && param->sigc) {
        RNP_LOG("warning: one-passes are mixed with signatures");
    }

finish:
    if (errcode != RNP_SUCCESS) {
        src_close(src);
    }

    return errcode;
}

static void
init_processing_ctx(pgp_processing_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

static void
free_processing_ctx(pgp_processing_ctx_t *ctx)
{
    for (int i = ctx->srcc - 1; i >= 0; i--) {
        src_close(ctx->srcs[i]);
        free(ctx->srcs[i]);
    }
    FREE_ARRAY(ctx, src);
}

/** @brief build PGP source sequence down to the literal data packet
 *
 **/
static rnp_result_t
init_packet_sequence(pgp_processing_ctx_t *ctx, pgp_source_t *src)
{
    uint8_t       ptag;
    ssize_t       read;
    int           type;
    pgp_source_t *psrc = NULL;
    pgp_source_t *lsrc = src;
    rnp_result_t  ret;

    while (1) {
        read = src_peek(lsrc, &ptag, 1);
        if (read < 1) {
            RNP_LOG("cannot read packet tag");
            return RNP_ERROR_READ;
        }

        type = get_packet_type(ptag);
        if (type < 0) {
            RNP_LOG("wrong pkt tag %d", (int) ptag);
            return RNP_ERROR_BAD_FORMAT;
        }

        if ((psrc = calloc(1, sizeof(*psrc))) == NULL) {
            RNP_LOG("allocation failed");
            return RNP_ERROR_OUT_OF_MEMORY;
        }

        switch (type) {
        case PGP_PTAG_CT_PK_SESSION_KEY:
        case PGP_PTAG_CT_SK_SESSION_KEY:
            ret = init_encrypted_src(ctx, psrc, lsrc);
            break;
        case PGP_PTAG_CT_1_PASS_SIG:
        case PGP_PTAG_CT_SIGNATURE:
            ret = init_signed_src(ctx, psrc, lsrc);
            break;
        case PGP_PTAG_CT_COMPRESSED:
            ret = init_compressed_src(ctx, psrc, lsrc);
            break;
        case PGP_PTAG_CT_LITDATA:
            if ((lsrc->type != PGP_STREAM_ENCRYPTED) && (lsrc->type != PGP_STREAM_SIGNED) &&
                (lsrc->type != PGP_STREAM_COMPRESSED)) {
                RNP_LOG("unexpected literal pkt");
                ret = RNP_ERROR_BAD_FORMAT;
            } else {
                ret = init_literal_src(ctx, psrc, lsrc);
            }
            break;
        default:
            RNP_LOG("unexpected pkt %d", type);
            ret = RNP_ERROR_BAD_FORMAT;
        }

        if (ret == RNP_SUCCESS) {
            EXPAND_ARRAY_EX(ctx, src, 1);
            ctx->srcs[ctx->srcc++] = psrc;
            lsrc = psrc;
            if (lsrc->type == PGP_STREAM_LITERAL) {
                ctx->literal_src = lsrc;
                ctx->msg_type = PGP_MESSAGE_NORMAL;
                return RNP_SUCCESS;
            } else if (lsrc->type == PGP_STREAM_SIGNED) {
                ctx->signed_src = lsrc;
                pgp_source_signed_param_t *param = lsrc->param;
                if (param->detached) {
                    ctx->msg_type = PGP_MESSAGE_DETACHED;
                    return RNP_SUCCESS;
                }
            }
        } else {
            free(psrc);
            return ret;
        }
    }
}

static rnp_result_t
init_cleartext_sequence(pgp_processing_ctx_t *ctx, pgp_source_t *src)
{
    pgp_source_t *clrsrc;
    rnp_result_t  res;

    if ((clrsrc = calloc(1, sizeof(*clrsrc))) == NULL) {
        RNP_LOG("allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    res = init_signed_src(ctx, clrsrc, src);

    if (res == RNP_SUCCESS) {
        EXPAND_ARRAY_EX(ctx, src, 1);
        ctx->srcs[ctx->srcc++] = clrsrc;
        ctx->msg_type = PGP_MESSAGE_CLEARTEXT;
    } else {
        free(clrsrc);
    }

    return res;
}

static rnp_result_t
init_armored_sequence(pgp_processing_ctx_t *ctx, pgp_source_t *src)
{
    pgp_source_t *armorsrc = NULL;
    rnp_result_t  res;

    if ((armorsrc = calloc(1, sizeof(*armorsrc))) == NULL) {
        RNP_LOG("allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    res = init_armored_src(armorsrc, src);

    if (res == RNP_SUCCESS) {
        EXPAND_ARRAY_EX(ctx, src, 1);
        ctx->srcs[ctx->srcc++] = armorsrc;
    } else {
        free(armorsrc);
        return res;
    }

    return init_packet_sequence(ctx, armorsrc);
}

rnp_result_t
process_pgp_source(pgp_parse_handler_t *handler, pgp_source_t *src)
{
    ssize_t              read;
    rnp_result_t         res = RNP_ERROR_BAD_FORMAT;
    rnp_result_t         fres;
    pgp_processing_ctx_t ctx;
    pgp_source_t *       decsrc = NULL;
    pgp_source_t         datasrc = {0};
    pgp_dest_t           outdest;
    uint8_t *            readbuf = NULL;
    char *               filename = NULL;

    init_processing_ctx(&ctx);
    ctx.handler = *handler;

    /* Building readers sequence. Checking whether it is binary data */
    if (is_pgp_source(src)) {
        res = init_packet_sequence(&ctx, src);
    } else {
        /* Trying armored or cleartext data */
        if (is_cleartext_source(src)) {
            /* Initializing cleartext message */
            res = init_cleartext_sequence(&ctx, src);
        } else if (is_armored_source(src)) {
            /* Initializing armored message */
            res = init_armored_sequence(&ctx, src);
        } else {
            RNP_LOG("not an OpenPGP data provided");
            res = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
    }

    if (res != RNP_SUCCESS) {
        goto finish;
    }

    if ((readbuf = calloc(1, PGP_INPUT_CACHE_SIZE)) == NULL) {
        RNP_LOG("allocation failure");
        res = RNP_ERROR_OUT_OF_MEMORY;
        goto finish;
    }

    if (ctx.msg_type == PGP_MESSAGE_DETACHED) {
        /* detached signature case */
        if (!handler->src_provider || !handler->src_provider(handler, &datasrc)) {
            RNP_LOG("no data source for detached signature verification");
            res = RNP_ERROR_READ;
            goto finish;
        }

        while (!datasrc.eof) {
            read = src_read(&datasrc, readbuf, PGP_INPUT_CACHE_SIZE);
            if (read < 0) {
                res = RNP_ERROR_GENERIC;
                break;
            } else if (read > 0) {
                signed_src_update(ctx.signed_src, readbuf, read);
            }
        }

        src_close(&datasrc);
    } else {
        /* file processing case */
        decsrc = ctx.srcs[ctx.srcc - 1];
        if (ctx.literal_src) {
            filename = ((pgp_source_literal_param_t *) ctx.literal_src)->filename;
        }

        memset(&outdest, 0, sizeof(outdest));
        if (!handler->dest_provider || !handler->dest_provider(handler, &outdest, filename)) {
            res = RNP_ERROR_WRITE;
            goto finish;
        }

        /* reading the input */
        while (!decsrc->eof) {
            read = src_read(decsrc, readbuf, PGP_INPUT_CACHE_SIZE);
            if (read < 0) {
                res = RNP_ERROR_GENERIC;
                break;
            } else if (read > 0) {
                if (ctx.signed_src) {
                    signed_src_update(ctx.signed_src, readbuf, read);
                }
                dst_write(&outdest, readbuf, read);
                if (outdest.werr != RNP_SUCCESS) {
                    RNP_LOG("failed to output data");
                    res = RNP_ERROR_WRITE;
                    break;
                }
            }
        }
    }

    /* finalizing the input. Signatures are checked on this step */
    for (int i = ctx.srcc - 1; i >= 0; i--) {
        fres = src_finish(ctx.srcs[i]);
        if (fres != RNP_SUCCESS) {
            res = fres;
        }
    }

    if (ctx.msg_type != PGP_MESSAGE_DETACHED) {
        dst_close(&outdest, res != RNP_SUCCESS);
    }

finish:
    free_processing_ctx(&ctx);
    free(readbuf);
    return res;
}
