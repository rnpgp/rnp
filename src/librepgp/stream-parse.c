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
#include "fingerprint.h"
#include "pgp-key.h"
#include "signature.h"
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
    pgp_source_packet_param_t pkt;          /* underlying packet-related params */
    DYNARRAY(pgp_sk_sesskey_t, symenc);     /* array of sym-encrypted session keys */
    DYNARRAY(pgp_pk_sesskey_pkt_t, pubenc); /* array of pk-encrypted session keys */
    bool        has_mdc;                    /* encrypted with mdc, i.e. tag 18 */
    pgp_crypt_t decrypt;                    /* decrypting crypto */
    pgp_hash_t  mdc;                        /* mdc SHA1 hash */
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
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
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
    src->type = PGP_STREAM_PARLEN_PACKET;
    src->size = 0;
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
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
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
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
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
        }
    }

    return read;
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
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
    }
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
encrypted_try_passphrase(pgp_source_t *src, const char *passphrase)
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
        /* deriving symmetric key from passphrase */
        symkey = &param->symencs[i];
        keysize = pgp_key_size(symkey->alg);
        if (!keysize || !pgp_s2k_derive_key(&symkey->s2k, passphrase, keybuf, keysize)) {
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
        src->size = len;
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
        compressed_src_close(src);
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
    char                          passphrase[MAX_PASSPHRASE_LENGTH] = {0};
    int                           intres;
    bool                          have_key = false;

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
    }

    /* Obtaining the symmetric key */
    have_key = false;

    if (!ctx->handler.passphrase_provider) {
        RNP_LOG("no passphrase provider");
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
                  ctx->handler.passphrase_provider,
                  &(pgp_passphrase_ctx_t){.op = PGP_OP_DECRYPT, .key = seckey});
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
            if (!pgp_request_passphrase(
                  ctx->handler.passphrase_provider,
                  &(pgp_passphrase_ctx_t){.op = PGP_OP_DECRYPT_SYM, .key = NULL},
                  passphrase,
                  sizeof(passphrase))) {
                goto finish;
            }

            intres = encrypted_try_passphrase(src, passphrase);
            if (intres > 0) {
                have_key = true;
                break;
            } else if (intres < 0) {
                errcode = RNP_ERROR_NOT_SUPPORTED;
                goto finish;
            } else if (strlen(passphrase) == 0) {
                RNP_LOG("empty passphrase - canceling");
                errcode = RNP_ERROR_BAD_PASSPHRASE;
                goto finish;
            }
        } while (1);
    }

    if (!have_key) {
        RNP_LOG("failed to obtain decrypting key or password");
        errcode = RNP_ERROR_NO_SUITABLE_KEY;
    }

finish:
    if (errcode != RNP_SUCCESS) {
        encrypted_src_close(src);
    }
    pgp_forget(passphrase, sizeof(passphrase));

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

        psrc = calloc(1, sizeof(*psrc));

        if ((type == PGP_PTAG_CT_PK_SESSION_KEY) || (type == PGP_PTAG_CT_SK_SESSION_KEY)) {
            ret = init_encrypted_src(ctx, psrc, lsrc);
        } else if (type == PGP_PTAG_CT_1_PASS_SIG) {
            RNP_LOG("signed data not implemented");
            ret = RNP_ERROR_NOT_IMPLEMENTED;
        } else if (type == PGP_PTAG_CT_COMPRESSED) {
            if ((lsrc->type != PGP_STREAM_ENCRYPTED) && (lsrc->type != PGP_STREAM_SIGNED)) {
                RNP_LOG("unexpected compressed pkt");
                ret = RNP_ERROR_BAD_FORMAT;
            } else {
                ret = init_compressed_src(ctx, psrc, lsrc);
            }
        } else if (type == PGP_PTAG_CT_LITDATA) {
            if ((lsrc->type != PGP_STREAM_ENCRYPTED) && (lsrc->type != PGP_STREAM_SIGNED) &&
                (lsrc->type != PGP_STREAM_COMPRESSED)) {
                RNP_LOG("unexpected literal pkt");
                ret = RNP_ERROR_BAD_FORMAT;
            } else {
                ret = init_literal_src(ctx, psrc, lsrc);
            }
        } else {
            RNP_LOG("unexpected pkt %d", type);
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

static bool
is_pgp_sequence(uint8_t *buf, int size)
{
    int tag;

    if (size < 1) {
        return false;
    }

    tag = get_packet_type(buf[0]);
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
        RNP_LOG("can't read enough data from source");
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
                RNP_LOG("cleartext not supported yet");
                goto finish;
            }

            /* initializing armored message */
            if ((armorsrc = calloc(1, sizeof(*armorsrc))) == NULL) {
                RNP_LOG("allocation failed");
                goto finish;
            }

            res = init_armored_src(armorsrc, src);

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
            RNP_LOG("not an OpenPGP data provided");
            res = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
    }

    /* Reading data from literal source and writing it to the output */
    if (res == RNP_SUCCESS) {
        litsrc = ctx.srcs[ctx.srcc - 1];
        litparam = litsrc->param;
        if ((readbuf = calloc(1, PGP_INPUT_CACHE_SIZE)) == NULL) {
            RNP_LOG("allocation failure");
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
                    RNP_LOG("failed to output data");
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
