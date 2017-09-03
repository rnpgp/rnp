/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "stream-parse.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <rnp/rnp_def.h>
#include "defs.h"
#include "types.h"
#include "symmetric.h"
#include "crypto/s2k.h"
#include "misc.h"

ssize_t src_read(pgp_source_t *src, void *buf, size_t len)
{
    size_t              left = len;
    ssize_t             read;
    pgp_source_cache_t *cache = src->cache;

    if (src->eof || (len == 0)) {
        return 0;
    }

    // Check whether we have cache and there is data inside
    if (cache && (cache->len > cache->pos)) {
        read = cache->len - cache->pos;
        if (read >= len) {
            memcpy(buf, &cache->buf[cache->pos], len);
            cache->pos += len;
            src->read += len;
            return len;
        } else {
            memcpy(buf, &cache->buf[cache->pos], read);
            cache->pos += read;
            buf = (uint8_t*)buf + read;
            left = len - read;
        }
    }

    // If we got here then we have empty cache or no cache at all
    while (left > 0) {
        if (!cache || (left > sizeof(cache->buf))) {
            // If there is no cache or chunk large then read directly
            read = src->readfunc(src, buf, left);
            if (read > 0) {
                left -= read;
                buf = (uint8_t*)buf + read;
            } else if (read == 0) {
                src->eof = 1;
                src->read += len - left;
                return len - left;
            } else {
                return -1;
            }
        } else {
            // Try to fill the cache to avoid small reads
            read = src->readfunc(src, &cache->buf[0], sizeof(cache->buf));
            if (read == 0) {
                src->eof = 1;
                src->read += len - left;
                return len - left;
            } else if (read < 0) {
                return -1;
            } else if (read < left) {
                memcpy(buf, &cache->buf[0], read);
                left -= read;
                buf = (uint8_t*)buf + read;
            } else {
                memcpy(buf, &cache->buf[0], left);
                cache->pos = left;
                cache->len = read;
                src->read += len;
                return len;
            }
        }
    }
    
    src->read += len;
    return len;
}

ssize_t src_peek(pgp_source_t *src, void *buf, size_t len)
{
    ssize_t             read;
    pgp_source_cache_t *cache = src->cache;

    if (!cache || (len > sizeof(cache->buf))) {
        return -1;
    }

    if (src->eof) {
        return 0;
    }

    if (cache->len - cache->pos >= len) {
        memcpy(buf, &cache->buf[cache->pos], len);
        return len;
    }

    if (cache->pos > 0) {
        memmove(&cache->buf[0], &cache->buf[cache->pos], cache->len - cache->pos);
        cache->len -= cache->pos;
        cache->pos = 0;
    }

    while (cache->len < len) {
        read = src->readfunc(src, &cache->buf[cache->len], sizeof(cache->buf) - cache->len);
        if (read == 0) {
            memcpy(buf, &cache->buf[0], cache->len);
            return cache->len;
        } else if (read < 0) {
            return -1;
        } else {
            cache->len += read;
            if (cache->len >= len) {
                memcpy(buf, &cache->buf[0], len);
                return len;
            }
        }
    }

    return -1;
}

ssize_t src_skip(pgp_source_t *src, size_t len)
{
    ssize_t res;
    void *  buf;
    uint8_t sbuf[16];
     
    if (len < sizeof(sbuf)) {
        return src_read(src, sbuf, len);
    } else {
        buf = calloc(1, len);

        if (buf == NULL) {
            return -1;
        } else {
            res = src_read(src, buf, len);
            free(buf);
            return res;
        }
    }
}

void src_close(pgp_source_t *src)
{
    if (src->closefunc) {
        src->closefunc(src);
    }
}

typedef struct pgp_source_file_param_t {
    int fd;
} pgp_source_file_param_t;

ssize_t file_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_file_param_t *param = src->param;

    if (param == NULL) {
        return -1;
    } else {
        return read(param->fd, buf, len);
    }
}

void file_src_close(pgp_source_t *src)
{
    pgp_source_file_param_t *param = src->param;
    if (param) {
        if (src->type == PGP_SOURCE_FILE) {
            close(param->fd);
        }
        free(src->param);
        src->param = NULL;
    }
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
    }
}

pgp_errcode_t init_file_src(pgp_source_t *src, const char *path)
{
    int                      fd;
    struct stat              st;
    pgp_source_file_param_t *param;

    if (stat(path, &st) != 0) {
        (void) fprintf(stderr, "can't stat \"%s\"\n", path);
        return PGP_E_R_READ_FAILED;
    }

#ifdef O_BINARY
    fd = open(path, O_RDONLY | O_BINARY);
#else
    fd = open(path, O_RDONLY);
#endif
    if (fd < 0) {
        (void) fprintf(stderr, "can't open \"%s\"\n", path);
        return RNP_ERROR_READ;
    }

    if ((src->cache = calloc(1, sizeof(pgp_source_cache_t))) == NULL) {
        close(fd);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if ((param = calloc(1, sizeof(pgp_source_file_param_t))) == NULL) {
        close(fd);
        free(src->cache);
        src->cache = NULL;
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    src->readfunc = file_src_read;
    src->closefunc = file_src_close;
    param->fd = fd;
    src->param = param;
    src->type = PGP_SOURCE_FILE;
    src->size = st.st_size;
    src->read = 0;
    src->knownsize = 1;
    src->eof = 0;

    return RNP_SUCCESS;
}

pgp_errcode_t init_stdin_src(pgp_source_t *src)
{
    pgp_source_file_param_t *param;

    if ((src->cache = calloc(1, sizeof(pgp_source_cache_t))) == NULL) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if ((param = calloc(1, sizeof(pgp_source_file_param_t))) == NULL) {
        free(src->cache);
        src->cache = NULL;
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    src->readfunc = file_src_read;
    src->closefunc = file_src_close;
    param->fd = 0;
    src->param = param;
    src->type = PGP_SOURCE_STDIN;
    src->size = 0;
    src->read = 0;
    src->knownsize = 0;
    src->eof = 0;

    return RNP_SUCCESS;
}

pgp_errcode_t init_mem_src(pgp_source_t *src, void *mem, size_t len)
{
    return RNP_ERROR_GENERIC;
}

typedef struct pgp_processing_ctx_t {
    pgp_operation_handler_t handler;

    pgp_source_t *cleartext;   /* literal data packet or cleartext to read from as it is detected */
} pgp_processing_ctx_t;

typedef struct pgp_source_encrypted_param_t {
    DYNARRAY(pgp_sk_sesskey_t, symenc); /* array of sym-encrypted session keys */
    DYNARRAY(pgp_pk_sesskey_t, pubenc); /* array of pk-encrypted session keys */
    pgp_source_t *readsrc;              /* source to read from, could be partial */
    pgp_source_t *origsrc;              /* original source passed to init_encrypted_src */
    bool          has_mdc;              /* encrypted with mdc, i.e. tag 18 */
    bool          partial;              /* partial length packet */
    pgp_crypt_t   decrypt;              /* decrypting crypto */
} pgp_source_encrypted_param_t;

typedef struct pgp_source_partial_param_t {
    pgp_source_t *readsrc; /* source to read from */
    int           type;    /* type of the packet */
    size_t        psize;   /* size of the current part */
    size_t        pleft;   /* bytes left to read from the current part */
    bool          last;    /* current part is last */
} pgp_source_partial_param_t;

static int stream_packet_type(uint8_t ptag)
{
    if (!(ptag & PGP_PTAG_ALWAYS_SET)) {
        return -1;
    }

    if (ptag & PGP_PTAG_NEW_FORMAT) {
        return (int)(ptag & PGP_PTAG_NF_CONTENT_TAG_MASK);
    } else {
        return (int)((ptag & PGP_PTAG_OF_CONTENT_TAG_MASK) >> PGP_PTAG_OF_CONTENT_TAG_SHIFT);
    }
}

/** @brief Read packet len for fixed-size (say, small) packet. Returns -1 on error.
 *  We do not allow partial length here as well as large packets (so ignoring possible 32 bit int overflow)
 **/
static ssize_t stream_read_pkt_len(pgp_source_t *src)
{
    uint8_t buf[6];
    ssize_t read;

    read = src_read(src, buf, 2);
    if ((read < 2) || !(buf[0] & PGP_PTAG_ALWAYS_SET)) {
        return -1;
    }

    if (buf[0] & PGP_PTAG_NEW_FORMAT) {
        if (buf[1] < 192) {
            return (ssize_t)buf[1];
        } else if (buf[1] < 224) {
            if (read < 3) {
                return -1;
            } else {
                if (src_read(src, &buf[2], 1) < 1) {
                    return -1;
                }
                return ((ssize_t)(buf[1] - 192) << 8) + (ssize_t)buf[2] + 192;
            }
        } else if (buf[1] < 255) {
            // we do not allow partial length here
            return -1;
        } else {
            if (src_read(src, &buf[2], 4) < 4) {
                return -1;
            } else {
                return ((ssize_t)buf[2] << 24) | ((ssize_t)buf[3] << 16) | ((ssize_t)buf[4] << 8) | (ssize_t)buf[5];
            }
        }
    } else {
        switch (buf[0] & PGP_PTAG_OF_LENGTH_TYPE_MASK) {
            case PGP_PTAG_OLD_LEN_1:
                return (ssize_t)buf[1];
            case PGP_PTAG_OLD_LEN_2:
                if (src_read(src, &buf[2], 1) < 1) {
                    return -1;
                } else {
                    return ((ssize_t)buf[1] << 8) | ((ssize_t)buf[2]);
                }
            case PGP_PTAG_OLD_LEN_4:
                if (src_read(src, &buf[2], 3) < 3) {
                    return -1;
                } else {
                    return ((ssize_t)buf[1] << 24) | ((ssize_t)buf[2] << 16) | ((ssize_t)buf[3] << 8) | (ssize_t)buf[4];
                }
            default:
                return -1;
        }
    }
}

static size_t stream_part_len(uint8_t blen)
{
    return 1 << (blen & 0x1f);
}

static bool stream_intedeterminate_pkt_len(pgp_source_t *src)
{
    uint8_t ptag;
    if (src_peek(src, &ptag, 1) == 1) {
        return !(ptag & PGP_PTAG_NEW_FORMAT) && ((ptag & PGP_PTAG_OF_LENGTH_TYPE_MASK) == PGP_PTAG_OLD_LEN_INDETERMINATE);
    } else {
        return false;
    }
}

static bool stream_partial_pkt_len(pgp_source_t *src)
{
    uint8_t hdr[2];
    if (src_peek(src, hdr, 2) < 2) {
        return false;
    } else {
        return (hdr[0] & PGP_PTAG_NEW_FORMAT) && (hdr[1] >= 224) && (hdr[1] < 255);
    }
}

ssize_t partial_pkt_src_read(pgp_source_t *src, void *buf, size_t len)
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
            read = src_peek(param->readsrc, hdr, 1);
            if (read < 0) {
                (void) fprintf(stderr, "partial_src_read: failed to read header\n");
                return read;
            } else if (read < 1) {
                (void) fprintf(stderr, "partial_src_read: wrong eof\n");
                return -1;
            }
            if ((hdr[0] >= 224) && (hdr[0] < 255)) {
                src_skip(param->readsrc, 1);
                param->psize = stream_part_len(hdr[0]);
                param->pleft = param->psize;
            } else {
                if (hdr[0] < 192) {
                    read = hdr[0];
                } else if (hdr[0] < 224) {
                    if (src_read(param->readsrc, hdr, 2) < 2) {
                        (void) fprintf(stderr, "partial_src_read: wrong 2-byte length\n");
                        return -1;
                    }
                    read = ((ssize_t)(hdr[0] - 192) << 8) + (ssize_t)hdr[1] + 192;
                } else {
                    if (src_read(param->readsrc, hdr, 5) < 5) {
                        (void) fprintf(stderr, "partial_src_read: wrong 4-byte length\n");
                        return -1;
                    }
                    read = ((ssize_t)hdr[1] << 24) | ((ssize_t)hdr[2] << 16) | ((ssize_t)hdr[3] << 8) | (ssize_t)hdr[4];
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
            buf = (uint8_t*)buf + read;
            param->pleft -= read;
        }
    }

    return len;
}

void partial_pkt_src_close(pgp_source_t *src)
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

pgp_errcode_t init_partial_pkt_src(pgp_source_t *src, pgp_source_t *readsrc)
{
    pgp_source_partial_param_t *param;
    uint8_t                     buf[2];

    if (!stream_partial_pkt_len(readsrc)) {
        (void) fprintf(stderr, "init_partial_src: wrong call on non-partial len packet\n");
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((src->cache = calloc(1, sizeof(pgp_source_cache_t))) == NULL) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if ((param = calloc(1, sizeof(pgp_source_partial_param_t))) == NULL) {
        free(src->cache);
        src->cache = NULL;
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    // we are sure that there are 2 bytes in readsrc
    (void) src_read(readsrc, buf, 2);
    param->type = stream_packet_type(buf[0]);
    param->psize = stream_part_len(buf[1]);
    param->pleft = param->psize;
    param->last = false;
    param->readsrc = readsrc;

    src->readfunc = partial_pkt_src_read;
    src->closefunc = partial_pkt_src_close;
    src->param = param;
    src->type = PGP_SOURCE_PARLEN_PACKET;
    src->size = 0;
    src->read = 0;
    src->knownsize = 0;
    src->eof = 0;
    
    return RNP_SUCCESS;
}

ssize_t encrypted_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_encrypted_param_t *param = src->param;

    if (param == NULL) {
        return -1;
    } else {
        // not implemented yet
        return -1;
    }
}

void encrypted_src_close(pgp_source_t *src)
{
    pgp_source_encrypted_param_t *param = src->param;
    if (param) {
        FREE_ARRAY(param, symenc);
        FREE_ARRAY(param, pubenc);

        if (param->partial) {
            param->readsrc->closefunc(param->readsrc);
            free(param->readsrc);
            param->readsrc = NULL;
        }

        free(src->param);
        src->param = NULL;
    }
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
    }
}

static pgp_errcode_t stream_parse_pk_sesskey(pgp_source_t *src, pgp_pk_sesskey_t *pkey)
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

static pgp_errcode_t stream_parse_sk_sesskey(pgp_source_t *src, pgp_sk_sesskey_t *skey)
{
    uint8_t           buf[4];
    ssize_t           len;
    ssize_t           read;

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
    skey->s2k_specifier = buf[2];
    skey->hash_alg = buf[3];
    len -= 4;

    switch (skey->s2k_specifier) {
        case PGP_S2KS_SIMPLE:
            break;
        case PGP_S2KS_SALTED:
        case PGP_S2KS_ITERATED_AND_SALTED:
            // salt
            if (len < PGP_SALT_SIZE) {
                return RNP_ERROR_BAD_FORMAT;
            }
            if (src_read(src, skey->salt, PGP_SALT_SIZE) != PGP_SALT_SIZE) {
                return RNP_ERROR_READ;
            }
            len -= PGP_SALT_SIZE;

            // iterations
            if (skey->s2k_specifier == PGP_S2KS_ITERATED_AND_SALTED) {
                if (len < 1) {
                    return RNP_ERROR_BAD_FORMAT;
                }
                if (src_read(src, buf, 1) != 1) {
                    return RNP_ERROR_READ;
                }
                skey->s2k_iterations = (unsigned)buf[0];
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
            (void) fprintf(stderr, "stream_parse_sk_sesskey: too long encrypted session key\n");
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

static int encrypted_check_passphrase(pgp_source_t *src, const char *passphrase)
{
    pgp_source_encrypted_param_t *param = src->param;
    pgp_sk_sesskey_t *            symkey;
    pgp_crypt_t                   crypt;
    pgp_symm_alg_t                alg;
    uint8_t                       keybuf[PGP_MAX_KEY_SIZE + 1];
    uint8_t                       enchdr[PGP_MAX_BLOCK_SIZE + 2];
    uint8_t                       dechdr[PGP_MAX_BLOCK_SIZE + 2];
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

        switch (symkey->s2k_specifier) {
            case PGP_S2KS_SIMPLE:
                break;
            case PGP_S2KS_SALTED:
                saltptr = &symkey->salt[0];
                break;
            case PGP_S2KS_ITERATED_AND_SALTED:
                saltptr = &symkey->salt[0];
                iterations = pgp_s2k_decode_iterations(symkey->s2k_iterations);
                break;
            default:
                continue;
        }

        if (pgp_s2k_iterated(symkey->hash_alg, keybuf, keysize, passphrase, saltptr, iterations)) {
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
            alg = (pgp_symm_alg_t)keybuf[0];
            keysize = pgp_key_size(alg);
            blsize = pgp_block_size(alg);
            if (!keysize || (keysize + 1 != symkey->enckeylen) || !blsize) {
                continue;
            }
            memmove(keybuf, keybuf + 1, keysize);
        } else {
            alg = (pgp_symm_alg_t)symkey->alg;
            blsize = pgp_block_size(alg);
            if (!blsize) {
                continue;
            }
            keyavail = true;
        }

        /* reading encrypted header to check the password validity */
        if (src_peek(param->readsrc, enchdr, blsize + 2) < blsize + 2) {
            continue;
        }
        /* having symmetric key in keybuf let's decrypt blocksize + 2 bytes and check them */
        if (!pgp_cipher_start(&crypt, alg, keybuf, NULL)) {
            continue;
        }
        pgp_cipher_cfb_decrypt(&crypt, dechdr, enchdr, blsize + 2);
        if ((dechdr[blsize] == dechdr[blsize - 2]) && (dechdr[blsize + 1] == dechdr[blsize - 1])) {
            src_skip(param->readsrc, blsize + 2);
            pgp_cipher_cfb_resync_v2(&crypt);
            param->decrypt = crypt;
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

pgp_errcode_t init_encrypted_src(pgp_processing_ctx_t *ctx, pgp_source_t *src, pgp_source_t *readsrc)
{
    bool                          sk_read = false;
    pgp_errcode_t                 errcode;
    pgp_source_encrypted_param_t *param;
    pgp_source_t *                partsrc; 
    uint8_t                       ptag;
    uint8_t                       mdcver;
    int                           ptype;
    pgp_sk_sesskey_t              skey = {0};
    pgp_pk_sesskey_t              pkey = {0};
    char                          passphrase[MAX_PASSPHRASE_LENGTH] = {0};
    int                           intres;

    if ((src->cache = calloc(1, sizeof(pgp_source_cache_t))) == NULL) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if ((param = calloc(1, sizeof(pgp_source_encrypted_param_t))) == NULL) {
        free(src->cache);
        src->cache = NULL;
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param->readsrc = readsrc;
    src->param = param;
    src->readfunc = encrypted_src_read;
    src->closefunc = encrypted_src_close;
    src->type = PGP_SOURCE_ENCRYPTED;
    src->size = 0;
    src->read = 0;
    src->knownsize = 0;
    src->eof = 0;

    // Reading pk/sk encrypted session key(s)
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

            EXPAND_ARRAY(param, symenc);
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
            (void) fprintf(stderr, "init_encrypted_src: unknown or unsupported packet type: %d\n", ptype);
            errcode = RNP_ERROR_READ;
            goto finish;
        }
    }

    param->origsrc = NULL;

    if (stream_partial_pkt_len(readsrc)) {
        // initialize partial reader
        if ((partsrc = calloc(1, sizeof(*partsrc))) == NULL) {
            errcode = RNP_ERROR_OUT_OF_MEMORY;
            goto finish;
        }
        errcode = init_partial_pkt_src(partsrc, readsrc);
        if (errcode != RNP_SUCCESS) {
            free(partsrc);
            goto finish;
        }

        param->partial = true;
        param->origsrc = readsrc;
        param->readsrc = partsrc;
    } else if (stream_intedeterminate_pkt_len(readsrc)) {
        (void) src_skip(readsrc, 1);
    } else {
        if ((src->size = stream_read_pkt_len(readsrc)) < 0) {
            (void) fprintf(stderr, "init_encrypted_src: cannot read pkt len\n");
            return RNP_ERROR_BAD_FORMAT;
        }
        src->knownsize = 1;
    }

    // Reading header of encrypted packet
    if (ptype == PGP_PTAG_CT_SE_IP_DATA) {
        if (src_read(param->readsrc, &mdcver, 1) != 1) {
            errcode = RNP_ERROR_READ;
            goto finish;
        }
        if (mdcver != 1) {
            (void) fprintf(stderr, "init_encrypted_src: unknown mdc version: %d\n", (int)mdcver);
            errcode = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
        param->has_mdc = true;
    }

    // Obtaining the symmetric key
    if (!ctx->handler.passphrase_provider) {
        (void) fprintf(stderr, "init_encrypted_src: no passphrase provider\n");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (param->symencc > 0) {
        do {
            if (!pgp_request_passphrase(ctx->handler.passphrase_provider, &(pgp_passphrase_ctx_t){.op = PGP_OP_DECRYPT_SYM, .pubkey = NULL, .key_type = 0}, passphrase, sizeof(passphrase))) {
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
        goto finish;
    }

    errcode = RNP_ERROR_NOT_IMPLEMENTED;
    // Initializing encryption

    finish:
    if (errcode != RNP_SUCCESS) {
        encrypted_src_close(src);
    }
    pgp_forget(passphrase, sizeof(passphrase));

    return  errcode;
}

/** @brief parse first packet in PGP sequence and decide which content type it is
 **/
static pgp_errcode_t init_packet_sequence(pgp_processing_ctx_t *ctx, pgp_source_t *src)
{
    uint8_t       ptag;
    ssize_t       read;
    int           type;
    pgp_source_t  psrc;
    pgp_errcode_t ret;

    read = src_peek(src, &ptag, 1);
    if (read < 1) {
        (void) fprintf(stderr, "process_packet_sequence: cannot read packet tag\n");
        return RNP_ERROR_READ;
    }

    type = stream_packet_type(ptag);
    if (type < 0) {
        (void) fprintf(stderr, "process_packet_sequence: wrong packet tag %d\n", (int)ptag);
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((type == PGP_PTAG_CT_PK_SESSION_KEY) || (type == PGP_PTAG_CT_SK_SESSION_KEY)) {
        ret = init_encrypted_src(ctx, &psrc, src);
        if (ret != RNP_SUCCESS) {
            return ret;
        }
    } else if (type == PGP_PTAG_CT_1_PASS_SIG) {
        (void) fprintf(stderr, "process_packet_sequence: signed data processing is not implemented yet\n");
        return RNP_ERROR_NOT_IMPLEMENTED;
    } else if (type == PGP_PTAG_CT_COMPRESSED) {
        if ((src->type != PGP_SOURCE_ENCRYPTED) && (src->type != PGP_SOURCE_SIGNED)) {
            (void) fprintf(stderr, "process_packet_sequence: invalid sequence: unexpected compressed packet\n");
            return RNP_ERROR_BAD_FORMAT;
        }
    } else if (type == PGP_PTAG_CT_LITDATA) {
        if ((src->type != PGP_SOURCE_ENCRYPTED) && (src->type != PGP_SOURCE_SIGNED) && (src->type != PGP_SOURCE_COMPRESSED)) {
            (void) fprintf(stderr, "process_packet_sequence: invalid sequence: unexpected literal packet\n");
            return RNP_ERROR_BAD_FORMAT;
        }
    } else {
        (void) fprintf(stderr, "process_packet_sequence: unexpected packet type %d\n", type);
        return RNP_ERROR_BAD_FORMAT;
    }

    return RNP_SUCCESS;
}

pgp_errcode_t process_pgp_source(pgp_operation_handler_t *handler, pgp_source_t *src)
{
    static const char armor_start[] = "-----BEGIN PGP";
    uint8_t              buf[128];
    ssize_t              read;
    pgp_errcode_t        res;
    pgp_processing_ctx_t ctx;

    ctx.handler = *handler;
    ctx.cleartext = NULL;

    read = src_peek(src, buf, sizeof(buf));
    if (read < 2) {
        (void) fprintf(stderr, "process_pgp_source: can't read enough data from source\n");
        return RNP_ERROR_READ;
    }

    // Checking whether it is binary data
    if (buf[0] & PGP_PTAG_ALWAYS_SET) {
        res = init_packet_sequence(&ctx, src);
        if (res != RNP_SUCCESS) {
            return res;
        }
    } else {
        // Trying armored data
        buf[read - 1] = 0;
        if (strstr((char*)buf, armor_start) != NULL) {
            // TODO: push cleartext source or dearmoring source and call process_packet_sequence 
            (void) fprintf(stderr, "process_pgp_source: armored input is not supported yet\n");
            return RNP_ERROR_NOT_IMPLEMENTED;
        } else {
            (void) fprintf(stderr, "process_pgp_source: not an OpenPGP data provided\n");
            return RNP_ERROR_BAD_FORMAT;
        }
    }

    // Processing data

    return RNP_ERROR_NOT_IMPLEMENTED;
}
