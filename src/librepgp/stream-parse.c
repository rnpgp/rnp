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
#include "rnp_def.h"
#include "defs.h"
#include "types.h"

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
            read += len;
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
        read = src->readfunc(src, &cache->buf[0], sizeof(cache->buf) - cache->len);
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
        } else 
        {
            res = src_read(src, buf, len);
            free(buf);
            return res;
        }
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

pgp_errcode_t init_file_src(pgp_source_t *src, char *path)
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

typedef struct pgp_source_encrypted_param_t {
    DYNARRAY(pgp_sk_sesskey_t, symenc);
    DYNARRAY(pgp_pk_sesskey_t, pubenc);
    pgp_source_t *readsrc;

} pgp_source_encrypted_param_t;

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
        free(src->param);
        src->param = NULL;
    }
    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
    }
}

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

    read = src_peek(src, buf, 6);
    if ((read < 2) || !(buf[0] & PGP_PTAG_ALWAYS_SET)) {
        return -1;
    }

    if (buf[0] & PGP_PTAG_NEW_FORMAT) {
        if (buf[1] < 192) {
            src_read(src, buf, 2);
            return (ssize_t)buf[1];
        } else if (buf[1] < 224) {
            if (read < 3) {
                return -1;
            } else {
                src_read(src, buf, 3);
                return ((ssize_t)(buf[1] - 192) << 8) + (ssize_t)buf[2] + 192;
            }
        } else if (buf[1] < 255) {
            // we do not allow partial length here
            return -1;
        } else {
            if (read < 6) {
                return -1;
            } else {
                src_read(src, buf, 6);
                return ((ssize_t)buf[2] << 24) | ((ssize_t)buf[3] << 16) | ((ssize_t)buf[4] << 8) | (ssize_t)buf[5];
            }
        }
    } else {
        switch (buf[0] & PGP_PTAG_OF_LENGTH_TYPE_MASK) {
            case PGP_PTAG_OLD_LEN_1:
                return (ssize_t)buf[1];
            case PGP_PTAG_OLD_LEN_2:
                if (read < 3) {
                    return -1;
                } else {
                    src_read(src, buf, 3);
                    return ((ssize_t)buf[1] << 8) | ((ssize_t)buf[2]);
                }
            case PGP_PTAG_OLD_LEN_4:
                if (read < 5) {
                    return -1;
                } else {
                    src_read(src, buf, 5);
                    return ((ssize_t)buf[1] << 24) | ((ssize_t)buf[2] << 16) | ((ssize_t)buf[3] << 8) | (ssize_t)buf[4];
                }
            default:
                return -1;
        }
    }
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
            if ((read = src_read(src, skey->salt, PGP_SALT_SIZE)) != PGP_SALT_SIZE) {
                return RNP_ERROR_READ;
            }
            len -= PGP_SALT_SIZE;

            // iterations
            if (skey->s2k_specifier == PGP_S2KS_ITERATED_AND_SALTED) {
                if (len < 1) {
                    return RNP_ERROR_BAD_FORMAT;
                }
                if ((read = src_read(src, buf, 1)) != 1) {
                    return RNP_ERROR_READ;
                }
                skey->s2k_iterations = (unsigned)buf[0];
                len--;
            }
        default:
            (void) fprintf(stderr, "stream_parse_sk_sesskey: wrong s2k specifier\n");
            return RNP_ERROR_BAD_FORMAT;
    }

    // encrypted session key if present
    if (len > 0) {
        if (len > PGP_MAX_BLOCK_SIZE + 1) {
            (void) fprintf(stderr, "stream_parse_sk_sesskey: too long encrypted session key\n");
            return RNP_ERROR_BAD_FORMAT;
        }
        if ((read = src_read(src, skey->sesskey, len)) != len) {
            return RNP_ERROR_READ;
        }
    }

    return RNP_SUCCESS;
}

pgp_errcode_t init_encrypted_src(pgp_source_t *src, pgp_source_t *readsrc)
{
    bool                          sk_read = false;
    pgp_errcode_t                 errcode;
    pgp_source_encrypted_param_t *param; 
    uint8_t                       ptag;
    int                           ptype;
    pgp_sk_sesskey_t              skey;

    if ((src->cache = calloc(1, sizeof(pgp_source_cache_t))) == NULL) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if ((param = calloc(1, sizeof(pgp_source_encrypted_param_t))) == NULL) {
        free(src->cache);
        src->cache = NULL;
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param->readsrc = readsrc;

    src->readfunc = encrypted_src_read;
    src->closefunc = encrypted_src_close;
    src->param = param;
    src->type = PGP_SOURCE_ENCRYPTED;
    src->size = 0;
    src->read = 0;
    src->knownsize = 0;
    src->eof = 0;

    // Reading session key(s)
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
            param->symencs[param->symencc] = skey;
        } else if (ptype == PGP_PTAG_CT_SE_DATA) {
            sk_read = true;
            break;
        } else {
            (void) fprintf(stderr, "init_encrypted_src: unknown or unsupported packet type: %d\n", ptype);
            errcode = RNP_ERROR_READ;
            goto finish;
        }
    }

    // Reading header of encrypted packet
    errcode = RNP_ERROR_NOT_IMPLEMENTED;
    // Initializing encryption

    finish:
    if (errcode != RNP_SUCCESS) {
        encrypted_src_close(src);
    }
    return  errcode;
}

/** @brief parse first packet in PGP sequence and decide which content type it is
 **/
static pgp_errcode_t init_packet_sequence(pgp_source_t *src)
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
        ret = init_encrypted_src(&psrc, src);
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

pgp_errcode_t process_pgp_source(pgp_source_t *src)
{
    static const char armor_start[] = "-----BEGIN PGP";
    uint8_t buf[128];
    ssize_t read;
    pgp_errcode_t res;

    read = src_peek(src, buf, sizeof(buf));
    if (read < 2) {
        (void) fprintf(stderr, "process_pgp_source: can't read enough data from source\n");
        return RNP_ERROR_READ;
    }

    // Checking whether it is binary data
    if (buf[0] & PGP_PTAG_ALWAYS_SET) {
        res = init_packet_sequence(src);
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
