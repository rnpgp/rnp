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
#include "signature.h"
#include "misc.h"
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

typedef struct pgp_processing_ctx_t {
    pgp_parse_handler_t handler;
    DYNARRAY(pgp_source_t *, src); /* pgp sources stack */
    pgp_dest_t output;
} pgp_processing_ctx_t;

/* common fields for encrypted, compressed and literal data */
typedef struct pgp_source_packet_param_t {
    pgp_source_t *readsrc;       /* source to read from, could be partial*/
    pgp_source_t *origsrc;       /* original source passed to init_*_src */
    bool          partial;       /* partial length packet */
    bool          indeterminate; /* indeterminate length packet */
} pgp_source_packet_param_t;

typedef struct pgp_source_encrypted_param_t {
    pgp_source_packet_param_t pkt;      /* underlying packet-related params */
    DYNARRAY(pgp_sk_sesskey_t, symenc); /* array of sym-encrypted session keys */
    DYNARRAY(pgp_pk_sesskey_t, pubenc); /* array of pk-encrypted session keys */
    bool        has_mdc;                /* encrypted with mdc, i.e. tag 18 */
    pgp_crypt_t decrypt;                /* decrypting crypto */
    pgp_hash_t  mdc;                    /* mdc SHA1 hash */
} pgp_source_encrypted_param_t;

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

#define ARMOURED_BLOCK_SIZE  (4096)

typedef struct pgp_source_armored_param_t {
    pgp_source_t *     readsrc;   /* source to read from */
    pgp_armoured_msg_t type;      /* message type */
    char *             armourhdr; /* armour header */
    char *             version;   /* Version: header if any */
    char *             comment;   /* Comment: header if any */
    char *             hash;      /* Hash: header if any */
    char *             charset;   /* Charset: header if any */
    uint8_t            rest[ARMOURED_BLOCK_SIZE]; /* unread decoded bytes, makes implementation easier */
    unsigned           restlen; /* number of bytes in rest */
    unsigned           restpos; /* index of first unread byte in rest, restpos <= restlen */
    uint8_t            brest[3]; /* decoded 6-bit tail bytes */
    unsigned           brestlen; /* number of bytes in brest */
    bool               eofb64;  /* end of base64 stream reached */
    unsigned           crc;  /* crc-24 of already read data */
    unsigned           readcrc; /* crc-24 from the armoured data */
} pgp_source_armored_param_t;

static int
stream_packet_type(uint8_t ptag)
{
    if (!(ptag & PGP_PTAG_ALWAYS_SET)) {
        return -1;
    }

    if (ptag & PGP_PTAG_NEW_FORMAT) {
        return (int) (ptag & PGP_PTAG_NF_CONTENT_TAG_MASK);
    } else {
        return (int) ((ptag & PGP_PTAG_OF_CONTENT_TAG_MASK) >> PGP_PTAG_OF_CONTENT_TAG_SHIFT);
    }
}

/** @brief Read packet len for fixed-size (say, small) packet. Returns -1 on error.
 *  We do not allow partial length here as well as large packets (so ignoring possible 32 bit
 *int overflow)
 **/
static ssize_t
stream_read_pkt_len(pgp_source_t *src)
{
    uint8_t buf[6];
    ssize_t read;

    read = src_read(src, buf, 2);
    if ((read < 2) || !(buf[0] & PGP_PTAG_ALWAYS_SET)) {
        return -1;
    }

    if (buf[0] & PGP_PTAG_NEW_FORMAT) {
        if (buf[1] < 192) {
            return (ssize_t) buf[1];
        } else if (buf[1] < 224) {
            if (src_read(src, &buf[2], 1) < 1) {
                return -1;
            }
            return ((ssize_t)(buf[1] - 192) << 8) + (ssize_t) buf[2] + 192;
        } else if (buf[1] < 255) {
            // we do not allow partial length here
            return -1;
        } else {
            if (src_read(src, &buf[2], 4) < 4) {
                return -1;
            } else {
                return ((ssize_t) buf[2] << 24) | ((ssize_t) buf[3] << 16) |
                       ((ssize_t) buf[4] << 8) | (ssize_t) buf[5];
            }
        }
    } else {
        switch (buf[0] & PGP_PTAG_OF_LENGTH_TYPE_MASK) {
        case PGP_PTAG_OLD_LEN_1:
            return (ssize_t) buf[1];
        case PGP_PTAG_OLD_LEN_2:
            if (src_read(src, &buf[2], 1) < 1) {
                return -1;
            }
            return ((ssize_t) buf[1] << 8) | ((ssize_t) buf[2]);
        case PGP_PTAG_OLD_LEN_4:
            if (src_read(src, &buf[2], 3) < 3) {
                return -1;
            }
            return ((ssize_t) buf[1] << 24) | ((ssize_t) buf[2] << 16) |
                   ((ssize_t) buf[3] << 8) | (ssize_t) buf[4];
        default:
            return -1;
        }
    }
}

static size_t
stream_part_len(uint8_t blen)
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

ssize_t
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
                (void) fprintf(stderr, "partial_src_read: failed to read header\n");
                return read;
            } else if (read < 1) {
                (void) fprintf(stderr, "partial_src_read: wrong eof\n");
                return -1;
            }
            if ((hdr[0] >= 224) && (hdr[0] < 255)) {
                param->psize = stream_part_len(hdr[0]);
                param->pleft = param->psize;
            } else {
                if (hdr[0] < 192) {
                    read = hdr[0];
                } else if (hdr[0] < 224) {
                    if (src_read(param->readsrc, &hdr[1], 1) < 1) {
                        (void) fprintf(stderr, "partial_src_read: wrong 2-byte length\n");
                        return -1;
                    }
                    read = ((ssize_t)(hdr[0] - 192) << 8) + (ssize_t) hdr[1] + 192;
                } else {
                    if (src_read(param->readsrc, &hdr[1], 4) < 4) {
                        (void) fprintf(stderr, "partial_src_read: wrong 4-byte length\n");
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
            (void) fprintf(stderr, "partial_src_read: unexpected eof\n");
            return write;
        } else if (read < 0) {
            (void) fprintf(stderr, "partial_src_read: failed to read data chunk\n");
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

void
partial_pkt_src_close(pgp_source_t *src)
{
    pgp_source_partial_param_t *param = src->param;
    if (param) {
        free(src->param);
        src->param = NULL;
    }
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
    }
}

rnp_result_t
init_partial_pkt_src(pgp_source_t *src, pgp_source_t *readsrc)
{
    pgp_source_partial_param_t *param;
    uint8_t                     buf[2];

    if (!stream_partial_pkt_len(readsrc)) {
        (void) fprintf(stderr, "init_partial_src: wrong call on non-partial len packet\n");
        return RNP_ERROR_BAD_FORMAT;
    }

    if (!init_source_cache(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    /* we are sure that there are 2 bytes in readsrc */
    param = src->param;
    (void) src_read(readsrc, buf, 2);
    param->type = stream_packet_type(buf[0]);
    param->psize = stream_part_len(buf[1]);
    param->pleft = param->psize;
    param->last = false;
    param->readsrc = readsrc;

    src->read = partial_pkt_src_read;
    src->close = partial_pkt_src_close;
    src->type = PGP_STREAM_PARLEN_PACKET;
    src->size = 0;
    src->readb = 0;
    src->knownsize = 0;
    src->eof = 0;

    return RNP_SUCCESS;
}

ssize_t
literal_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_literal_param_t *param = src->param;
    if (!param) {
        return -1;
    }

    return src_read(param->pkt.readsrc, buf, len);
}

void
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
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
    }
}

ssize_t
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
                    (void) fprintf(stderr, "compressed_src_read: failed to read data\n");
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
                    (void) fprintf(stderr,
                                   "compressed_src_read: data beyond the end of z stream\n");
                }
            } else if (ret != Z_OK) {
                (void) fprintf(stderr, "compressed_src_read: inflate error %d\n", ret);
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
                    (void) fprintf(stderr, "compressed_src_read: failed to read data\n");
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
                    (void) fprintf(stderr,
                                   "compressed_src_read: data beyond the end of z stream\n");
                }
            } else if (ret != BZ_OK) {
                (void) fprintf(stderr, "compressed_src_read: inflate error %d\n", ret);
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

void
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
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
    }
}

ssize_t
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
                (void) fprintf(stderr, "encrypted_src_read: wrong mdc read state\n");
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
                (void) fprintf(stderr, "encrypted_src_read: mdc header check failed\n");
                return -1;
            }

            if (memcmp(&mdcbuf[2], hash, PGP_SHA1_HASH_SIZE) != 0) {
                (void) fprintf(stderr, "encrypted_src_read: mdc hash check failed\n");
                return -1;
            }
        }
    }

    return read;
}

void
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
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
    }
}

static rnp_result_t
stream_parse_pk_sesskey(pgp_source_t *src, pgp_pk_sesskey_t *pkey)
{
    ssize_t len;

    len = stream_read_pkt_len(src);
    if (len < 0) {
        return RNP_ERROR_READ;
    }

    (void) fprintf(stderr, "skipping public key encrypted session key\n");
    src_skip(src, len);
    return RNP_SUCCESS;
}

static rnp_result_t
stream_parse_sk_sesskey(pgp_source_t *src, pgp_sk_sesskey_t *skey)
{
    uint8_t buf[4];
    ssize_t len;
    ssize_t read;

    // read packet length
    len = stream_read_pkt_len(src);
    if (len < 0) {
        return RNP_ERROR_READ;
    } else if (len < 4) {
        return RNP_ERROR_BAD_FORMAT;
    }

    // version + symalg + s2k type + hash alg
    if ((read = src_read(src, buf, 4)) < 4) {
        return RNP_ERROR_READ;
    }

    // version
    skey->version = buf[0];
    if (skey->version != 4) {
        (void) fprintf(stderr, "stream_parse_sk_sesskey: wrong packet version\n");
        return RNP_ERROR_BAD_FORMAT;
    }

    // symmetric algorithm
    skey->alg = buf[1];

    // s2k
    skey->s2k.specifier = buf[2];
    skey->s2k.hash_alg = buf[3];
    len -= 4;

    switch (skey->s2k.specifier) {
    case PGP_S2KS_SIMPLE:
        break;
    case PGP_S2KS_SALTED:
    case PGP_S2KS_ITERATED_AND_SALTED:
        // salt
        if (len < PGP_SALT_SIZE) {
            return RNP_ERROR_BAD_FORMAT;
        }
        if (src_read(src, skey->s2k.salt, PGP_SALT_SIZE) != PGP_SALT_SIZE) {
            return RNP_ERROR_READ;
        }
        len -= PGP_SALT_SIZE;

        // iterations
        if (skey->s2k.specifier == PGP_S2KS_ITERATED_AND_SALTED) {
            if (len < 1) {
                return RNP_ERROR_BAD_FORMAT;
            }
            if (src_read(src, buf, 1) != 1) {
                return RNP_ERROR_READ;
            }
            skey->s2k.iterations = (unsigned) buf[0];
            len--;
        }
        break;
    default:
        (void) fprintf(stderr, "stream_parse_sk_sesskey: wrong s2k specifier\n");
        return RNP_ERROR_BAD_FORMAT;
    }

    // encrypted session key if present
    if (len > 0) {
        if (len > PGP_MAX_KEY_SIZE + 1) {
            (void) fprintf(stderr,
                           "stream_parse_sk_sesskey: too long encrypted session key\n");
            return RNP_ERROR_BAD_FORMAT;
        }
        if (src_read(src, skey->enckey, len) != len) {
            return RNP_ERROR_READ;
        }
        skey->enckeylen = len;
    } else {
        skey->enckeylen = 0;
    }

    return RNP_SUCCESS;
}

static int
encrypted_check_passphrase(pgp_source_t *src, const char *passphrase)
{
    pgp_source_encrypted_param_t *param = src->param;
    pgp_sk_sesskey_t *            symkey;
    pgp_crypt_t                   crypt;
    pgp_symm_alg_t                alg;
    uint8_t                       keybuf[PGP_MAX_KEY_SIZE + 1];
    uint8_t                       enchdr[PGP_MAX_BLOCK_SIZE + 2];
    int                           keysize;
    int                           blsize;
    bool                          keyavail = false;
    uint8_t *                     saltptr = NULL;
    size_t                        iterations = 1;

    for (int i = 0; i < param->symencc; i++) {
        /* deriving symmetric key from passphrase */
        symkey = &param->symencs[i];
        keysize = pgp_key_size(symkey->alg);
        if (!keysize) {
            continue;
        }

        switch (symkey->s2k.specifier) {
        case PGP_S2KS_SIMPLE:
            break;
        case PGP_S2KS_SALTED:
            saltptr = &symkey->s2k.salt[0];
            break;
        case PGP_S2KS_ITERATED_AND_SALTED:
            saltptr = &symkey->s2k.salt[0];
            iterations = pgp_s2k_decode_iterations(symkey->s2k.iterations);
            break;
        default:
            continue;
        }

        if (pgp_s2k_iterated(
              symkey->s2k.hash_alg, keybuf, keysize, passphrase, saltptr, iterations)) {
            (void) fprintf(stderr, "encrypted_check_passphrase: s2k failed\n");
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

        /* reading encrypted header to check the password validity */
        if (src_peek(param->pkt.readsrc, enchdr, blsize + 2) < blsize + 2) {
            continue;
        }
        /* having symmetric key in keybuf let's decrypt blocksize + 2 bytes and check them */
        if (!pgp_cipher_start(&crypt, alg, keybuf, NULL)) {
            continue;
        }
        pgp_cipher_cfb_decrypt(&crypt, enchdr, enchdr, blsize + 2);
        if ((enchdr[blsize] == enchdr[blsize - 2]) &&
            (enchdr[blsize + 1] == enchdr[blsize - 1])) {
            src_skip(param->pkt.readsrc, blsize + 2);
            param->decrypt = crypt;
            /* init mdc if it is here */
            /* RFC 4880, 5.13: Unlike the Symmetrically Encrypted Data Packet, no special CFB
             * resynchronization is done after encrypting this prefix data. */
            if (!param->has_mdc) {
                pgp_cipher_cfb_resync(&param->decrypt);
            } else {
                if (!pgp_hash_create(&param->mdc, PGP_HASH_SHA1)) {
                    (void) fprintf(stderr,
                                   "encrypted_check_passphrase: cannot create sha1 hash\n");
                    return -1;
                }
                pgp_hash_add(&param->mdc, enchdr, blsize + 2);
            }

            return 1;
        } else {
            pgp_cipher_finish(&crypt);
            continue;
        }
    }

    if (!keyavail) {
        (void) fprintf(stderr, "encrypted_check_passphrase: no supported sk available\n");
        return -1;
    } else {
        return 0;
    }
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
            (void) fprintf(stderr, "init_packet_params: cannot read pkt len\n");
            return RNP_ERROR_BAD_FORMAT;
        }
        src->size = len;
        src->knownsize = 1;
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
    src->type = PGP_STREAM_LITERAL;
    src->size = 0;
    src->readb = 0;
    src->knownsize = 0;
    src->eof = 0;

    /* Reading packet length/checking whether it is partial */
    errcode = init_packet_params(src, &param->pkt);
    if (errcode != RNP_SUCCESS) {
        goto finish;
    }

    /* data format */
    if (src_read(param->pkt.readsrc, &bt, 1) != 1) {
        (void) fprintf(stderr, "init_literal_src: failed to read data format\n");
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
        (void) fprintf(stderr, "init_literal_src: unknown data format %d\n", (int) bt);
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }

    /* file name */
    if (src_read(param->pkt.readsrc, &bt, 1) != 1) {
        (void) fprintf(stderr, "init_literal_src: failed to read file name length\n");
        errcode = RNP_ERROR_READ;
        goto finish;
    }
    if (bt > 0) {
        if (src_read(param->pkt.readsrc, param->filename, bt) < bt) {
            (void) fprintf(stderr, "init_literal_src: failed to read file name\n");
            errcode = RNP_ERROR_READ;
            goto finish;
        }
    }
    param->filename[bt] = 0;
    /* timestamp */
    if (src_read(param->pkt.readsrc, tstbuf, 4) != 4) {
        (void) fprintf(stderr, "init_literal_src: failed to read file timestamp\n");
        errcode = RNP_ERROR_READ;
        goto finish;
    }
    param->timestamp = ((uint32_t) tstbuf[0] << 24) | ((uint32_t) tstbuf[1] << 16) |
                       ((uint32_t) tstbuf[2] << 8) | (uint32_t) tstbuf[3];

finish:
    if (errcode != RNP_SUCCESS) {
        literal_src_close(src);
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
    src->type = PGP_STREAM_COMPRESSED;
    src->size = 0;
    src->readb = 0;
    src->knownsize = 0;
    src->eof = 0;

    /* Reading packet length/checking whether it is partial */
    errcode = init_packet_params(src, &param->pkt);
    if (errcode != RNP_SUCCESS) {
        goto finish;
    }

    /* Reading compression algorithm */
    if (src_read(param->pkt.readsrc, &alg, 1) != 1) {
        (void) fprintf(stderr, "init_compressed_src: failed to read compression algorithm\n");
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
            (void) fprintf(
              stderr, "init_compressed_src: failed to init zlib, error %d\n", zret);
            errcode = RNP_ERROR_READ;
            goto finish;
        }
        break;
#ifdef HAVE_BZLIB_H
    case PGP_C_BZIP2:
        (void) memset(&param->bz, 0x0, sizeof(param->bz));
        zret = BZ2_bzDecompressInit(&param->bz, 0, 0);
        if (zret != BZ_OK) {
            (void) fprintf(stderr, "init_compressed_src: failed to init bz, error %d\n", zret);
            errcode = RNP_ERROR_READ;
            goto finish;
        }
        break;
#endif
    default:
        (void) fprintf(stderr, "init_compressed_src: unknown compression algorithm\n");
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    param->alg = alg;
    param->inlen = 0;
    param->inpos = 0;

finish:
    if (errcode != RNP_SUCCESS) {
        compressed_src_close(src);
    }
    return errcode;
}

static rnp_result_t
init_encrypted_src(pgp_processing_ctx_t *ctx, pgp_source_t *src, pgp_source_t *readsrc)
{
    bool                          sk_read = false;
    rnp_result_t                  errcode = RNP_SUCCESS;
    pgp_source_encrypted_param_t *param;
    uint8_t                       ptag;
    uint8_t                       mdcver;
    int                           ptype;
    pgp_sk_sesskey_t              skey = {0};
    pgp_pk_sesskey_t              pkey = {0};
    char                          passphrase[MAX_PASSPHRASE_LENGTH] = {0};
    int                           intres;

    if (!init_source_cache(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    param = src->param;
    param->pkt.readsrc = readsrc;
    src->read = encrypted_src_read;
    src->close = encrypted_src_close;
    src->type = PGP_STREAM_ENCRYPTED;
    src->size = 0;
    src->readb = 0;
    src->knownsize = 0;
    src->eof = 0;

    /* Reading pk/sk encrypted session key(s) */
    while (!sk_read) {
        if (src_peek(readsrc, &ptag, 1) < 1) {
            (void) fprintf(stderr, "init_encrypted_src: failed to read packet header\n");
            errcode = RNP_ERROR_READ;
            goto finish;
        }

        ptype = stream_packet_type(ptag);

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
        } else if ((ptype == PGP_PTAG_CT_SE_DATA) || (ptype == PGP_PTAG_CT_SE_IP_DATA)) {
            sk_read = true;
            break;
        } else {
            (void) fprintf(
              stderr, "init_encrypted_src: unknown or unsupported packet type: %d\n", ptype);
            errcode = RNP_ERROR_READ;
            goto finish;
        }
    }

    /* Reading packet length/checking whether it is partial */
    errcode = init_packet_params(src, &param->pkt);
    if (errcode != RNP_SUCCESS) {
        goto finish;
    }

    /* Reading header of encrypted packet */
    if (ptype == PGP_PTAG_CT_SE_IP_DATA) {
        if (src_read(param->pkt.readsrc, &mdcver, 1) != 1) {
            errcode = RNP_ERROR_READ;
            goto finish;
        }
        if (mdcver != 1) {
            (void) fprintf(
              stderr, "init_encrypted_src: unknown mdc version: %d\n", (int) mdcver);
            errcode = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
        param->has_mdc = true;
    }

    /* Obtaining the symmetric key */
    if (!ctx->handler.passphrase_provider) {
        (void) fprintf(stderr, "init_encrypted_src: no passphrase provider\n");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (param->symencc > 0) {
        do {
            if (!pgp_request_passphrase(
                  ctx->handler.passphrase_provider,
                  &(pgp_passphrase_ctx_t){.op = PGP_OP_DECRYPT_SYM, .key = NULL},
                  passphrase,
                  sizeof(passphrase))) {
                goto finish;
            }

            intres = encrypted_check_passphrase(src, passphrase);
            if (intres == 1) {
                break;
            } else if (intres == -1) {
                errcode = RNP_ERROR_NOT_SUPPORTED;
                goto finish;
            } else if (strlen(passphrase) == 0) {
                (void) fprintf(stderr, "init_encrypted_src: empty passphrase - canceling\n");
                errcode = RNP_ERROR_BAD_PASSPHRASE;
                goto finish;
            }
        } while (1);
    } else {
        errcode = RNP_ERROR_NOT_SUPPORTED;
    }

finish:
    if (errcode != RNP_SUCCESS) {
        encrypted_src_close(src);
    }
    pgp_forget(passphrase, sizeof(passphrase));

    return errcode;
}

/*
   Table for base64 lookups:
   0xff - wrong character,
   0xfe - '='
   0xfd - eol/whitespace,
   0..0x3f - represented 6-bit number
*/
static const uint8_t b64table[256] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xfd, 0xfd, 0xff, 0xff, 0xfd, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
    /* 128..256 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static unsigned 
armour_crc24(unsigned crc, uint8_t *buf, size_t len)
{
    while (len--) {
        crc ^= (*buf++) << 16;
        for (int i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= 0x1864cfbL;
        }
    }
    return crc & 0xFFFFFFL;
}

static bool 
armour_skip_eol(pgp_source_t *readsrc)
{
    uint8_t eol[2];
    ssize_t read;

    read = src_peek(readsrc, eol, 2);
    if ((read >= 1) && (eol[0] == '\n')) {
        src_skip(readsrc, 1);
        return true;
    } else if ((read == 2) && (eol[0] == '\r') && (eol[0] == '\n')) {
        src_skip(readsrc, 2);
        return true;
    }

    return false;
}

static bool 
armour_peek_line(pgp_source_t *readsrc, char *buf, size_t len, size_t *llen)
{
    size_t  clen = 0;
    ssize_t read;
    
    do {
        read = clen + 64 > len ? len - clen : 64;
        read = src_peek(readsrc, buf, read);
        if (read < 0) {
            return false;
        }
        for (int i = 0; i < read; i++) {
            if (buf[i] == '\n') {
                *llen = clen + i;
                if ((*llen > 0) && (buf[i - 1] == '\r')) {
                    (*llen)--;
                }
                return true;
            }
        }
        clen += read;
    } while (clen < len);

    return false;
}

static int
armour_read_padding(pgp_source_t *src)
{
    char    st[64];
    size_t  stlen;
    pgp_source_armored_param_t *param = src->param;

    if (!armour_peek_line(param->readsrc, st, 12, &stlen)) {
        return -1;
    }

    if ((stlen == 1) || (stlen == 2)) {
        if ((st[0] != '=') || ((stlen == 2) && (st[1] != '='))) {
            return -1;
        }

        src_skip(param->readsrc, stlen);
        armour_skip_eol(param->readsrc);
        return stlen;
    } else if (stlen == 5) {
        return 0;
    }

    return -1;
}

static bool
armour_read_crc(pgp_source_t *src)
{
    uint8_t dec[4];
    char    crc[8];
    size_t  clen;
    pgp_source_armored_param_t *param = src->param;

    if (!armour_peek_line(param->readsrc, crc, sizeof(crc), &clen)) {
        return false;
    }

    if ((clen == 5) && (crc[0] == '=')) {
        for (int i = 0; i < 4; i++) {
            if ((dec[i] = b64table[(int)crc[i + 1]]) >= 64) {
                return false;
            }
        }
    
        param->readcrc = (dec[0] << 18) | (dec[1] << 12) | (dec[2] << 6) | (dec[3]);
        src_skip(param->readsrc, 5);
        armour_skip_eol(param->readsrc);
        return true;
    }

    return false;
}

static bool
armour_read_trailer(pgp_source_t *src)
{
    char    st[64];
    char    str[64];
    size_t  stlen;
    ssize_t read;
    pgp_source_armored_param_t *param = src->param;

    stlen = strlen(param->armourhdr);
    strncpy(st, "-----END", 8);
    strncpy(st + 8, param->armourhdr + 5, stlen - 5);
    strncpy(st + stlen + 3, "-----", 5);
    stlen += 8;
    read = src_peek(param->readsrc, str, stlen);
    if ((read < stlen) || strncmp(str, st, stlen)) {
        return false;
    } 
    src_skip(param->readsrc, stlen);
    return true;
}

static ssize_t
armoured_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_armored_param_t *param = src->param;
    uint8_t  b64buf[ARMOURED_BLOCK_SIZE]; /* input base64 data with spaces and so on */
    uint8_t  decbuf[ARMOURED_BLOCK_SIZE + 4]; /* decoded 6-bit values */
    uint8_t *bufptr = buf; /* for better readability below */
    uint8_t *bptr, *bend; /* pointer to input data in b64buf */
    uint8_t *dptr, *dend; /* pointer to decoded data in decbuf */
    uint8_t  bval;
    uint32_t b24;
    ssize_t  read;
    ssize_t  left = len;
    int      eqcount; /* number of '=' at the end of base64 stream */
    
    if (!param) {
        return -1;
    }

    /* checking whether there are some decoded bytes */
    if (param->restpos < param->restlen) {
        if (param->restlen - param->restpos >= len) {
            memcpy(bufptr, &param->rest[param->restpos], len);
            param->restpos += len;
            return len;
        } else {
            left = len - (param->restlen - param->restpos);
            memcpy(bufptr, &param->rest[param->restpos], len - left);
            param->restpos = param->restlen = 0;
            bufptr += len - left;
        }
    }

    if (param->eofb64) {
        return len - left;
    }

    memcpy(decbuf, param->brest, param->brestlen);
    dptr = decbuf + param->brestlen;

    do {
        read = src_peek(param->readsrc, b64buf, sizeof(b64buf));
        if (read < 0) {
            return read;
        }

        bptr = b64buf;
        bend = b64buf + read;
        /* checking input data, stripping away whitespaces, checking for end of the b64 data */
        while (bptr < bend) {
            if ((bval = b64table[*(bptr++)]) < 64) {
                *(dptr++) = bval;
            } else if (bval == 0xfe) {
                /* '=' means the base64 padding or the beginning of checksum */
                param->eofb64 = true;
                break;
            } else if (bval == 0xff) {
                (void) fprintf(stderr, "armoured_src_read: wrong base64 character %c\n", (char)*(bptr - 1));
                return -1;
            }
        }

        dend = dptr;
        dptr = decbuf;
        /* Processing full 4s which will go directly to the buf.
           After this left < 3 or decbuf has < 4 bytes */
        if ((dend - dptr) / 4 * 3 < left) {
            bend = decbuf + (dend - dptr) / 4 * 4;
            left -= (dend - dptr) / 4 * 3;
        } else {
            bend = decbuf + (left / 3) * 4;
            left -= left / 3 * 3;
        }
        
        /* this one would the most performance-consuming part for large chunks */
        while (dptr < bend) {
            b24 = *dptr++ << 18;
            b24 |= *dptr++ << 12;
            b24 |= *dptr++ << 6;
            b24 |= *dptr++;
            *bufptr++ = b24 >> 16;
            *bufptr++ = b24 >> 8;
            *bufptr++ = b24 & 0xff;
        }

        /* moving rest to the beginning of decbuf */
        memmove(decbuf, dptr, dend - dptr);
        dend = decbuf + (dend - dptr);
        dptr = decbuf;

        if (param->eofb64) {
            /* '=' reached, bptr points on it */
            src_skip(param->readsrc, bptr - b64buf - 1);

            /* reading b64 padding if any */
            if ((eqcount = armour_read_padding(src)) < 0) {
                (void) fprintf(stderr, "armoured_src_read: wrong padding\n");
                return -1;
            }

            /* reading crc */
            if (!armour_read_crc(src)) {
                (void) fprintf(stderr, "armoured_src_read: wrong crc line\n");
                return -1;
            }
            /* reading armour trailing line */
            if (!armour_read_trailer(src)) {
                (void) fprintf(stderr, "armoured_src_read: wrong armour trailer\n");
                return -1;
            }

            break;
        } else {
            /* all input is base64 data or eol/spaces, so skipping it */
            src_skip(param->readsrc, read);
        }
    } while (left >= 3);

    /* process bytes left in decbuf */
    bend = dptr + (dend - dptr) / 4 * 4;
    bptr = param->rest;
    while (dptr < bend) {
        b24 = *dptr++ << 18;
        b24 |= *dptr++ << 12;
        b24 |= *dptr++ << 6;
        b24 |= *dptr++;
        *bptr++ = b24 >> 16;
        *bptr++ = b24 >> 8;
        *bptr++ = b24 & 0xff;
    }

    param->crc = armour_crc24(param->crc, buf, bufptr - (uint8_t*)buf);
    param->crc = armour_crc24(param->crc, param->rest, bptr - param->rest);

    if (param->eofb64) {
        if ((dend - dptr + eqcount) % 4 != 0) {
            (void) fprintf(stderr, "armoured_src_read: wrong padding\n");
            return -1;
        }

        if (eqcount == 1) {
            b24 = (*dptr << 10) | (*(dptr + 1) << 4) | (*(dptr + 2) >> 2);
            *bptr++ = b24 >> 8;
            *bptr++ = b24 & 0xff;
            param->crc = armour_crc24(param->crc, bptr - 2, 2);
        } else if (eqcount == 2) {
            *bptr++ = (*dptr << 2 ) | (*(dptr + 1) >> 4);
            param->crc = armour_crc24(param->crc, bptr - 1, 1);
        }
        
        if (param->crc != param->readcrc) {
            (void) fprintf(stderr, "armoured_src_read: CRC mismatch\n");
            //return -1;
        }
    } else {
        /* few bytes which do not fit to 4 boundary */
        for (int i = 0; i < dend - dptr; i++) {
            param->brest[i] = *(dptr + i);
        }
        param->brestlen = dend - dptr;
    }

    param->restlen = bptr - param->rest;

    /* check whether we have some bytes to add */
    if ((left > 0) && (param->restlen > 0)) {
        read = left > param->restlen ? param->restlen : left;
        memcpy(bufptr, param->rest, read);
        left -= read;
        param->restpos += read;
    }

    return len - left;
}

static void
armoured_src_close(pgp_source_t *src)
{
    pgp_source_armored_param_t *param = src->param;

    if (!param) {
        return;
    }

    free(param->armourhdr);
    free(param->version);
    free(param->comment);
    free(param->hash);
    free(param->charset);
    free(param);
    param = NULL;
}

/** @brief finds armour header position in the buffer, returning beginning of header or NULL. 
 *  hdrlen will contain the length of the header
**/
static const char * 
find_armour_header(const char *buf, size_t len, size_t *hdrlen)
{
    int st = -1;

    for (int i = 0; i < len - 10; i++) {
        if ((buf[i] == '-') && !strncmp(&buf[i + 1], "----", 4)) {
            st = i;
            break;
        }
    }

    if (st < 0) {
        return NULL;
    }

    for (int i = st + 5; i <= len - 5; i++) {
        if ((buf[i] == '-') && !strncmp(&buf[i + 1], "----", 4)) {
            *hdrlen = i + 5 - st;
            return &buf[st];
        }
    }

    return NULL;
}

static pgp_armoured_msg_t
armour_message_type(const char *hdr, size_t len)
{
    if (!strncmp(hdr, "BEGIN PGP MESSAGE", len)) {
        return PGP_ARMOURED_MESSAGE;
    } else if (!strncmp(hdr, "BEGIN PGP PUBLIC KEY BLOCK", len) || !strncmp(hdr, "BEGIN PGP PUBLIC KEY", len))
    {
        return PGP_ARMOURED_PUBLIC_KEY;
    } else if (!strncmp(hdr, "BEGIN PGP SECRET KEY BLOCK", len) || !strncmp(hdr, "BEGIN PGP SECRET KEY", len))
    {
        return PGP_ARMOURED_SECRET_KEY;
    } else if (!strncmp(hdr, "BEGIN PGP SIGNATURE", len)) {
        return PGP_ARMOURED_SIGNATURE;
    } else if (!strncmp(hdr, "BEGIN PGP SIGNED MESSAGE", len)) {
        return PGP_ARMOURED_CLEARTEXT;
    } else {
        return PGP_ARMOURED_UNKNOWN;
    }
}

static bool 
armour_parse_header(pgp_source_t *src)
{
    char    hdr[128];
    const char *  armhdr;
    size_t  armhdrlen;
    ssize_t read;
    pgp_source_armored_param_t *param = src->param;

    read = src_peek(param->readsrc, hdr, sizeof(hdr));
    if (read < 20) {
        return false;
    }
    
    if (!(armhdr = find_armour_header(hdr, read, &armhdrlen))) {
        (void) fprintf(stderr, "parse_armour_header: no armour header\n");
        return false;
    }

    if (armhdr > hdr) {
        (void) fprintf(stderr, "parse_armour_header: extra data before the header line\n");
    }

    param->type = armour_message_type(armhdr + 5, armhdrlen - 10);
    if (param->type == PGP_ARMOURED_UNKNOWN) {
        (void) fprintf(stderr, "parse_armour_header: unknown armour header\n");
        return false;
    }

    if ((param->armourhdr = malloc(armhdrlen - 9)) == NULL) {
        (void) fprintf(stderr, "parse_armour_header: allocation failed\n");
        return false;
    }

    memcpy(param->armourhdr, armhdr + 5, armhdrlen - 10);
    param->armourhdr[armhdrlen - 10] = '\0';
    src_skip(param->readsrc, armhdr - hdr + armhdrlen);
    return true;
}

static bool armour_parse_headers(pgp_source_t *src)
{
    pgp_source_armored_param_t *param = src->param;
    char                        header[1024];
    size_t                      hdrlen;
    char *                      hdrval;
    
    do {
        if (!armour_peek_line(param->readsrc, header, sizeof(header) - 1, &hdrlen)) {
            (void) fprintf(stderr, "armour_parse_headers: failed to peek line\n");
            return false;
        }

        if (hdrlen > 0) {
            if ((hdrval = malloc(hdrlen + 1)) == NULL) {
                (void) fprintf(stderr, "armour_parse_headers: malloc failed\n");
                return false;
            }

            if (strncmp(header, "Version: ", 9) == 0) {
                memcpy(hdrval, header + 9, hdrlen - 9);
                hdrval[hdrlen - 9] = '\0';
                param->version = hdrval;
            } else if (strncmp(header, "Comment: ", 9) == 0) {
                memcpy(hdrval, header + 9, hdrlen - 9);
                hdrval[hdrlen - 9] = '\0';
                param->comment = hdrval;
            } else if (strncmp(header, "Hash: ", 6) == 0) {
                memcpy(hdrval, header + 6, hdrlen - 6);
                hdrval[hdrlen - 6] = '\0';
                param->hash = hdrval;
            } else if (strncmp(header, "Charset: ", 9) == 0) {
                memcpy(hdrval, header + 9, hdrlen - 9);
                hdrval[hdrlen - 9] = '\0';
                param->charset = hdrval;
            } else {
                header[hdrlen] = '\0';
                (void) fprintf(stderr, "armour_parse_headers: unknown header '%s'\n", header);
            }

            src_skip(param->readsrc, hdrlen);
        }

        if (!armour_skip_eol(param->readsrc)) {
            return false;
        }
    } while (hdrlen > 0);

    return true;
}


static rnp_result_t
init_armoured_src(pgp_source_t *src, pgp_source_t *readsrc)
{
    rnp_result_t                errcode = RNP_SUCCESS;
    pgp_source_armored_param_t *param;

    if (!init_source_cache(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = src->param;
    param->readsrc = readsrc;
    param->crc = 0xb704ceL;
    src->read = armoured_src_read;
    src->close = armoured_src_close;
    src->type = PGP_STREAM_ARMOURED;
    src->size = 0;
    src->readb = 0;
    src->knownsize = 0;
    src->eof = 0;

    /* parsing armoured header */
    if (!armour_parse_header(src)) {
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    /* eol */
    if (!armour_skip_eol(param->readsrc)) {
        (void) fprintf(stderr, "init_armored_src: no eol after the armour header\n");
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    /* parsing headers */
    if (!armour_parse_headers(src)) {
        (void) fprintf(stderr, "init_armored_src: failed to parse headers\n");
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }

    /* now we are good to go with base64-encoded data */
    errcode = RNP_SUCCESS;
    goto finish;

    finish:
    if (errcode != RNP_SUCCESS) {
        armoured_src_close(src);
    }
    return  errcode;
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
            (void) fprintf(stderr, "process_packet_sequence: cannot read packet tag\n");
            return RNP_ERROR_READ;
        }

        type = stream_packet_type(ptag);
        if (type < 0) {
            (void) fprintf(stderr, "process_packet_sequence: wrong pkt tag %d\n", (int) ptag);
            return RNP_ERROR_BAD_FORMAT;
        }

        psrc = calloc(1, sizeof(*psrc));

        if ((type == PGP_PTAG_CT_PK_SESSION_KEY) || (type == PGP_PTAG_CT_SK_SESSION_KEY)) {
            ret = init_encrypted_src(ctx, psrc, lsrc);
        } else if (type == PGP_PTAG_CT_1_PASS_SIG) {
            (void) fprintf( stderr, "process_packet_sequence: signed data not implemented\n");
            ret = RNP_ERROR_NOT_IMPLEMENTED;
        } else if (type == PGP_PTAG_CT_COMPRESSED) {
            if ((lsrc->type != PGP_STREAM_ENCRYPTED) && (lsrc->type != PGP_STREAM_SIGNED)) {
                (void) fprintf(stderr, "process_packet_sequence: unexpected compressed pkt\n");
                ret = RNP_ERROR_BAD_FORMAT;
            } else {
                ret = init_compressed_src(ctx, psrc, lsrc);
            }
        } else if (type == PGP_PTAG_CT_LITDATA) {
            if ((lsrc->type != PGP_STREAM_ENCRYPTED) && (lsrc->type != PGP_STREAM_SIGNED) &&
                (lsrc->type != PGP_STREAM_COMPRESSED)) {
                (void) fprintf( stderr, "process_packet_sequence: unexpected literal pkt\n");
                ret = RNP_ERROR_BAD_FORMAT;
            } else {
                ret = init_literal_src(ctx, psrc, lsrc);
            }
        } else {
            (void) fprintf(stderr, "process_packet_sequence: unexpected pkt %d\n", type);
            ret = RNP_ERROR_BAD_FORMAT;
        }

        if (ret == RNP_SUCCESS) {
            EXPAND_ARRAY_EX(ctx, src, 1);
            ctx->srcs[ctx->srcc++] = psrc;
            lsrc = psrc;
            if (lsrc->type == PGP_STREAM_LITERAL) {
                return RNP_SUCCESS;
            }
        } else {
            free(psrc);
            return ret;
        }
    }
}

bool
is_pgp_sequence(uint8_t *buf, int size)
{
    int tag;

    if (size < 1) {
        return false;
    }

    tag = stream_packet_type(buf[0]);
    switch (tag) {
    case PGP_PTAG_CT_PK_SESSION_KEY:
    case PGP_PTAG_CT_SK_SESSION_KEY:
    case PGP_PTAG_CT_1_PASS_SIG:
    case PGP_PTAG_CT_SE_DATA:
    case PGP_PTAG_CT_SE_IP_DATA:
    case PGP_PTAG_CT_COMPRESSED:
    case PGP_PTAG_CT_LITDATA:
        return true;
    default:
        return false;
    }
}

rnp_result_t
process_pgp_source(pgp_parse_handler_t *handler, pgp_source_t *src)
{
    const char                  armor_start[] = "-----BEGIN PGP";
    const char                  clear_start[] = "-----BEGIN PGP SIGNED MESSAGE-----";
    uint8_t                     buf[128];
    ssize_t                     read;
    rnp_result_t                res = RNP_ERROR_BAD_FORMAT;
    pgp_processing_ctx_t        ctx;
    pgp_source_t *              litsrc;
    pgp_source_t *              armorsrc = NULL;
    pgp_source_literal_param_t *litparam;
    pgp_dest_t                  outdest;
    uint8_t *                   readbuf = NULL;

    init_processing_ctx(&ctx);
    ctx.handler = *handler;

    read = src_peek(src, buf, sizeof(buf));
    if (read < 2) {
        (void) fprintf(stderr, "process_pgp_source: can't read enough data from source\n");
        res = RNP_ERROR_READ;
        goto finish;
    }

    /* Building readers sequence.  Checking whether it is binary data */
    if (is_pgp_sequence(buf, read)) {
        if ((res = init_packet_sequence(&ctx, src)) != RNP_SUCCESS) {
            goto finish;
        }
    } else {
        /* Trying armored or cleartext data */
        buf[read - 1] = 0;
        if (strstr((char *) buf, armor_start)) {
            /* checking whether it is cleartext */
            if (strstr((char *) buf, clear_start)) {
                (void) fprintf(stderr, "process_pgp_source: cleartext not supported yet\n");
                goto finish;
            }

            /* initializing armoured message */
            if ((armorsrc = calloc(1, sizeof(*armorsrc))) == NULL) {
                (void) fprintf(stderr, "process_pgp_source: allocation failed\n");
                goto finish;
            }

            res = init_armoured_src(armorsrc, src);

            if (res == RNP_SUCCESS) {
                EXPAND_ARRAY_EX((&ctx), src, 1);
                ctx.srcs[ctx.srcc++] = armorsrc;
            } else {
                free(armorsrc);
                goto finish;
            }

            if ((res = init_packet_sequence(&ctx, armorsrc)) != RNP_SUCCESS) {
                goto finish;
            }
        } else {
            (void) fprintf(stderr, "process_pgp_source: not an OpenPGP data provided\n");
            res = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
    }

    /* Reading data from literal source and writing it to the output */
    if (res == RNP_SUCCESS) {
        litsrc = ctx.srcs[ctx.srcc - 1];
        litparam = litsrc->param;
        if ((readbuf = calloc(1, PGP_INPUT_CACHE_SIZE)) == NULL) {
            (void) fprintf(stderr, "process_pgp_source: allocation failure\n");
            res = RNP_ERROR_OUT_OF_MEMORY;
            goto finish;
        }

        memset(&outdest, 0, sizeof(outdest));
        if (!handler->dest_provider ||
            !handler->dest_provider(handler, &outdest, litparam->filename)) {
            res = RNP_ERROR_WRITE;
            goto finish;
        }

        while (!litsrc->eof) {
            read = src_read(litsrc, readbuf, PGP_INPUT_CACHE_SIZE);
            if (read < 0) {
                res = RNP_ERROR_GENERIC;
                break;
            } else if (read > 0) {
                dst_write(&outdest, readbuf, read);
                if (outdest.werr != RNP_SUCCESS) {
                    (void) fprintf(stderr, "process_pgp_source: failed to output data\n");
                    res = RNP_ERROR_WRITE;
                    break;
                }
            }
        }

        dst_close(&outdest, res != RNP_SUCCESS);
    }

finish:
    free_processing_ctx(&ctx);
    free(readbuf);
    return res;
}

rnp_result_t 
dearmor_pgp_source(pgp_source_t *src, pgp_dest_t *dst)
{
    const char                  armor_start[] = "-----BEGIN PGP";
    const char                  clear_start[] = "-----BEGIN PGP SIGNED MESSAGE-----";
    rnp_result_t                res = RNP_ERROR_BAD_FORMAT;
    pgp_source_t                armorsrc;
    uint8_t                     readbuf[PGP_INPUT_CACHE_SIZE];
    ssize_t                     read;
    
    read = src_peek(src, readbuf, sizeof(clear_start));
    if (read < sizeof(armor_start)) {
        (void) fprintf(stderr, "dearmor_pgp_source: can't read enough data from source\n");
        res = RNP_ERROR_READ;
        goto finish;
    }

    /* Trying armored or cleartext data */
    readbuf[read - 1] = 0;
    if (strstr((char *) readbuf, armor_start)) {
        /* checking whether it is cleartext */
        if (strstr((char *) readbuf, clear_start)) {
            (void) fprintf(stderr, "dearmor_pgp_source: source is cleartext, not armored\n");
            goto finish;
        }

        /* initializing armoured message */
        res = init_armoured_src(&armorsrc, src);

        if (res != RNP_SUCCESS) {
            goto finish;
        }
    } else {
        (void) fprintf(stderr, "dearmor_pgp_source: source is not armored data\n");
        goto finish;
    }

    /* Reading data from armored source and writing it to the output */
    while (!armorsrc.eof) {
        read = src_read(&armorsrc, readbuf, PGP_INPUT_CACHE_SIZE);
        if (read < 0) {
            res = RNP_ERROR_GENERIC;
            break;
        } else if (read > 0) {
            dst_write(dst, readbuf, read);
            if (dst->werr != RNP_SUCCESS) {
                (void) fprintf(stderr, "dearmor_pgp_source: failed to output data\n");
                res = RNP_ERROR_WRITE;
                break;
            }
        }
    }

finish:
    src_close(&armorsrc);
    return res;
}

