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
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#else
#include "uniwin.h"
#endif
#include <string.h>
#include <algorithm>
#include <rnp/rnp_def.h>
#include "stream-def.h"
#include "stream-armor.h"
#include "stream-packet.h"
#include "str-utils.h"
#include "crypto/hash.h"
#include "types.h"
#include "utils.h"

#define ARMORED_BLOCK_SIZE (4096)
#define ARMORED_PEEK_BUF_SIZE 1024
#define ARMORED_MIN_LINE_LENGTH (16)
#define ARMORED_MAX_LINE_LENGTH (76)

typedef struct pgp_source_armored_param_t {
    pgp_source_t *    readsrc;         /* source to read from */
    pgp_armored_msg_t type;            /* type of the message */
    char *            armorhdr;        /* armor header */
    char *            version;         /* Version: header if any */
    char *            comment;         /* Comment: header if any */
    char *            hash;            /* Hash: header if any */
    char *            charset;         /* Charset: header if any */
    uint8_t  rest[ARMORED_BLOCK_SIZE]; /* unread decoded bytes, makes implementation easier */
    unsigned restlen;                  /* number of bytes in rest */
    unsigned restpos;    /* index of first unread byte in rest, restpos <= restlen */
    uint8_t  brest[3];   /* decoded 6-bit tail bytes */
    unsigned brestlen;   /* number of bytes in brest */
    bool     eofb64;     /* end of base64 stream reached */
    uint8_t  readcrc[3]; /* crc-24 from the armored data */
    bool     has_crc;    /* message contains CRC line */
    pgp_hash_t crc_ctx;  /* CTX used to calculate CRC */
} pgp_source_armored_param_t;

typedef struct pgp_dest_armored_param_t {
    pgp_dest_t *      writedst;
    pgp_armored_msg_t type;    /* type of the message */
    bool              usecrlf; /* use CR LF instead of LF as eol */
    unsigned          lout;    /* chars written in current line */
    unsigned          llen;    /* length of the base64 line, defaults to 76 as per RFC */
    uint8_t           tail[2]; /* bytes which didn't fit into 3-byte boundary */
    unsigned          tailc;   /* number of bytes in tail */
    pgp_hash_t        crc_ctx; /* CTX used to calculate CRC */
} pgp_dest_armored_param_t;

/*
   Table for base64 lookups:
   0xff - wrong character,
   0xfe - '='
   0xfd - eol/whitespace,
   0..0x3f - represented 6-bit number
*/
static const uint8_t B64DEC[256] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd, 0xfd, 0xff, 0xff, 0xfd, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff,
  0xff, 0xff, 0x3f, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff,
  0xff, 0xfe, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
  0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
  0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff};

static bool
armor_read_padding(pgp_source_t *src, size_t *read)
{
    char          st[64];
    size_t        stlen = 0;
    pgp_source_t *readsrc = ((pgp_source_armored_param_t *) src->param)->readsrc;

    if (!src_peek_line(readsrc, st, 12, &stlen)) {
        return false;
    }

    if ((stlen == 1) || (stlen == 2)) {
        if ((st[0] != CH_EQ) || ((stlen == 2) && (st[1] != CH_EQ))) {
            return false;
        }

        *read = stlen;
        src_skip(readsrc, stlen);
        return src_skip_eol(readsrc);
    } else if (stlen == 5) {
        *read = 0;
        return true;
    }
    return false;
}

static bool
armor_read_crc(pgp_source_t *src)
{
    uint8_t                     dec[4] = {0};
    char                        crc[8] = {0};
    size_t                      clen = 0;
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;

    if (!src_peek_line(param->readsrc, crc, sizeof(crc), &clen)) {
        return false;
    }

    if ((clen != 5) || (crc[0] != CH_EQ)) {
        return false;
    }

    for (int i = 0; i < 4; i++) {
        if ((dec[i] = B64DEC[(uint8_t) crc[i + 1]]) >= 64) {
            return false;
        }
    }

    param->readcrc[0] = (dec[0] << 2) | ((dec[1] >> 4) & 0x0F);
    param->readcrc[1] = (dec[1] << 4) | ((dec[2] >> 2) & 0x0F);
    param->readcrc[2] = (dec[2] << 6) | dec[3];

    param->has_crc = true;

    src_skip(param->readsrc, 5);
    return src_skip_eol(param->readsrc);
}

static bool
armor_skip_chars(pgp_source_t *src, const char *chars)
{
    uint8_t ch;
    size_t  read;

    do {
        bool found = false;
        if (!src_peek(src, &ch, 1, &read)) {
            return false;
        }
        if (!read) {
            /* return true only if there is no underlying read error */
            return true;
        }
        for (const char *chptr = chars; *chptr; chptr++) {
            if (ch == *chptr) {
                src_skip(src, 1);
                found = true;
                break;
            }
        }
        if (!found) {
            break;
        }
    } while (1);

    return true;
}

static bool
armor_read_trailer(pgp_source_t *src)
{
    char                        st[64];
    char                        str[64];
    size_t                      stlen;
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;

    if (!armor_skip_chars(param->readsrc, "\r\n")) {
        return false;
    }

    stlen = strlen(param->armorhdr);
    if ((stlen > 5) && (stlen + 8 + 1 <= sizeof(st))) {
        memcpy(st, ST_ARMOR_END, 8); /* 8 here is mandatory */
        memcpy(st + 8, param->armorhdr + 5, stlen - 5);
        memcpy(st + stlen + 3, ST_DASHES, 5);
        stlen += 8;
    } else {
        RNP_LOG("Internal error");
        return false;
    }
    if (!src_peek_eq(param->readsrc, str, stlen) || strncmp(str, st, stlen)) {
        return false;
    }
    src_skip(param->readsrc, stlen);
    (void) armor_skip_chars(param->readsrc, "\t ");
    (void) src_skip_eol(param->readsrc);
    return true;
}

static bool
armored_src_read(pgp_source_t *src, void *buf, size_t len, size_t *readres)
{
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;
    uint8_t  b64buf[ARMORED_BLOCK_SIZE];     /* input base64 data with spaces and so on */
    uint8_t  decbuf[ARMORED_BLOCK_SIZE + 4]; /* decoded 6-bit values */
    uint8_t *bufptr = (uint8_t *) buf;       /* for better readability below */
    uint8_t *bptr, *bend;                    /* pointer to input data in b64buf */
    uint8_t *dptr, *dend, *pend; /* pointers to decoded data in decbuf: working pointer, last
                                    available byte, last byte to process */
    uint8_t  bval;
    uint32_t b24;
    size_t   read = 0;
    size_t   left = len;
    size_t   eqcount = 0; /* number of '=' at the end of base64 stream */

    if (!param) {
        return false;
    }

    /* checking whether there are some decoded bytes */
    if (param->restpos < param->restlen) {
        if (param->restlen - param->restpos >= len) {
            memcpy(bufptr, &param->rest[param->restpos], len);
            param->restpos += len;
            pgp_hash_add(&param->crc_ctx, bufptr, len);
            *readres = len;
            return true;
        } else {
            left = len - (param->restlen - param->restpos);
            memcpy(bufptr, &param->rest[param->restpos], len - left);
            param->restpos = param->restlen = 0;
            bufptr += len - left;
        }
    }

    if (param->eofb64) {
        *readres = len - left;
        return true;
    }

    memcpy(decbuf, param->brest, param->brestlen);
    dend = decbuf + param->brestlen;

    do {
        if (!src_peek(param->readsrc, b64buf, sizeof(b64buf), &read)) {
            return false;
        }
        if (!read) {
            RNP_LOG("premature end of armored input");
            return false;
        }

        dptr = dend;
        bptr = b64buf;
        bend = b64buf + read;
        /* checking input data, stripping away whitespaces, checking for end of the b64 data */
        while (bptr < bend) {
            if ((bval = B64DEC[*(bptr++)]) < 64) {
                *(dptr++) = bval;
            } else if (bval == 0xfe) {
                /* '=' means the base64 padding or the beginning of checksum */
                param->eofb64 = true;
                break;
            } else if (bval == 0xff) {
                RNP_LOG("wrong base64 character 0x%02hhX", *(bptr - 1));
                return false;
            }
        }

        dend = dptr;
        dptr = decbuf;
        /* Processing full 4s which will go directly to the buf.
           After this left < 3 or decbuf has < 4 bytes */
        if ((size_t)(dend - dptr) / 4 * 3 < left) {
            pend = decbuf + (dend - dptr) / 4 * 4;
            left -= (dend - dptr) / 4 * 3;
        } else {
            pend = decbuf + (left / 3) * 4;
            left -= left / 3 * 3;
        }

        /* this one would the most performance-consuming part for large chunks */
        while (dptr < pend) {
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

        if (param->eofb64) {
            /* '=' reached, bptr points on it */
            src_skip(param->readsrc, bptr - b64buf - 1);

            /* reading b64 padding if any */
            if (!armor_read_padding(src, &eqcount)) {
                RNP_LOG("wrong padding");
                return false;
            }

            /* reading crc */
            if (!armor_read_crc(src)) {
                RNP_LOG("Warning: missing or malformed CRC line");
            }
            /* reading armor trailing line */
            if (!armor_read_trailer(src)) {
                RNP_LOG("wrong armor trailer");
                return false;
            }

            break;
        } else {
            /* all input is base64 data or eol/spaces, so skipping it */
            src_skip(param->readsrc, read);
        }
    } while (left >= 3);

    /* process bytes left in decbuf */

    dptr = decbuf;
    pend = decbuf + (dend - decbuf) / 4 * 4;
    bptr = param->rest;
    while (dptr < pend) {
        b24 = *dptr++ << 18;
        b24 |= *dptr++ << 12;
        b24 |= *dptr++ << 6;
        b24 |= *dptr++;
        *bptr++ = b24 >> 16;
        *bptr++ = b24 >> 8;
        *bptr++ = b24 & 0xff;
    }

    pgp_hash_add(&param->crc_ctx, buf, bufptr - (uint8_t *) buf);

    if (param->eofb64) {
        if ((dend - dptr + eqcount) % 4 != 0) {
            RNP_LOG("wrong b64 padding");
            return false;
        }

        if (eqcount == 1) {
            b24 = (*dptr << 10) | (*(dptr + 1) << 4) | (*(dptr + 2) >> 2);
            *bptr++ = b24 >> 8;
            *bptr++ = b24 & 0xff;
        } else if (eqcount == 2) {
            *bptr++ = (*dptr << 2) | (*(dptr + 1) >> 4);
        }

        uint8_t crc_fin[5];
        /* Calculate CRC after reading whole input stream */
        pgp_hash_add(&param->crc_ctx, param->rest, bptr - param->rest);
        if (!pgp_hash_finish(&param->crc_ctx, crc_fin)) {
            RNP_LOG("Can't finalize RNP ctx");
            return false;
        }

        if (param->has_crc && memcmp(param->readcrc, crc_fin, 3)) {
            RNP_LOG("Warning: CRC mismatch");
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
        if (!param->eofb64) {
            pgp_hash_add(&param->crc_ctx, bufptr, read);
        }
        left -= read;
        param->restpos += read;
    }

    *readres = len - left;
    return true;
}

static void
armored_src_close(pgp_source_t *src)
{
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;

    if (param) {
        (void) pgp_hash_finish(&param->crc_ctx, NULL);
        free(param->armorhdr);
        free(param->version);
        free(param->comment);
        free(param->hash);
        free(param->charset);
        free(param);
        src->param = NULL;
    }
}

/** @brief finds armor header position in the buffer, returning beginning of header or NULL.
 *  hdrlen will contain the length of the header
 **/
static const char *
find_armor_header(const char *buf, size_t len, size_t *hdrlen)
{
    int st = -1;

    for (unsigned i = 0; i < len - 10; i++) {
        if ((buf[i] == CH_DASH) && !strncmp(&buf[i + 1], ST_DASHES, 4)) {
            st = i;
            break;
        }
    }

    if (st < 0) {
        return NULL;
    }

    for (unsigned i = st + 5; i <= len - 5; i++) {
        if ((buf[i] == CH_DASH) && !strncmp(&buf[i + 1], ST_DASHES, 4)) {
            *hdrlen = i + 5 - st;
            return &buf[st];
        }
    }

    return NULL;
}

static bool
str_equals(const char *str, size_t len, const char *another)
{
    size_t alen = strlen(another);
    return (len == alen) && !memcmp(str, another, alen);
}

static pgp_armored_msg_t
armor_str_to_data_type(const char *str, size_t len)
{
    if (!str) {
        return PGP_ARMORED_UNKNOWN;
    }
    if (str_equals(str, len, "BEGIN PGP MESSAGE")) {
        return PGP_ARMORED_MESSAGE;
    }
    if (str_equals(str, len, "BEGIN PGP PUBLIC KEY BLOCK") ||
        str_equals(str, len, "BEGIN PGP PUBLIC KEY")) {
        return PGP_ARMORED_PUBLIC_KEY;
    }
    if (str_equals(str, len, "BEGIN PGP SECRET KEY BLOCK") ||
        str_equals(str, len, "BEGIN PGP SECRET KEY") ||
        str_equals(str, len, "BEGIN PGP PRIVATE KEY BLOCK") ||
        str_equals(str, len, "BEGIN PGP PRIVATE KEY")) {
        return PGP_ARMORED_SECRET_KEY;
    }
    if (str_equals(str, len, "BEGIN PGP SIGNATURE")) {
        return PGP_ARMORED_SIGNATURE;
    }
    if (str_equals(str, len, "BEGIN PGP SIGNED MESSAGE")) {
        return PGP_ARMORED_CLEARTEXT;
    }
    return PGP_ARMORED_UNKNOWN;
}

pgp_armored_msg_t
rnp_armor_guess_type(pgp_source_t *src)
{
    uint8_t ptag;

    if (!src_peek_eq(src, &ptag, 1)) {
        return PGP_ARMORED_UNKNOWN;
    }

    switch (get_packet_type(ptag)) {
    case PGP_PKT_PK_SESSION_KEY:
    case PGP_PKT_SK_SESSION_KEY:
    case PGP_PKT_ONE_PASS_SIG:
    case PGP_PKT_SE_DATA:
    case PGP_PKT_SE_IP_DATA:
    case PGP_PKT_COMPRESSED:
    case PGP_PKT_LITDATA:
    case PGP_PKT_MARKER:
        return PGP_ARMORED_MESSAGE;
    case PGP_PKT_PUBLIC_KEY:
    case PGP_PKT_PUBLIC_SUBKEY:
        return PGP_ARMORED_PUBLIC_KEY;
    case PGP_PKT_SECRET_KEY:
    case PGP_PKT_SECRET_SUBKEY:
        return PGP_ARMORED_SECRET_KEY;
    case PGP_PKT_SIGNATURE:
        return PGP_ARMORED_SIGNATURE;
    default:
        return PGP_ARMORED_UNKNOWN;
    }
}

static pgp_armored_msg_t
rnp_armored_guess_type_by_readahead(pgp_source_t *src)
{
    if (!src->cache) {
        return PGP_ARMORED_UNKNOWN;
    }

    pgp_source_t armorsrc = {0};
    pgp_source_t memsrc = {0};
    size_t       read;
    // peek as much as the cache can take
    bool cache_res = src_peek(src, NULL, sizeof(src->cache->buf), &read);
    if (!cache_res || !read ||
        init_mem_src(&memsrc,
                     src->cache->buf + src->cache->pos,
                     src->cache->len - src->cache->pos,
                     false)) {
        return PGP_ARMORED_UNKNOWN;
    }
    rnp_result_t res = init_armored_src(&armorsrc, &memsrc);
    if (res) {
        src_close(&memsrc);
        RNP_LOG("failed to parse armored data");
        return PGP_ARMORED_UNKNOWN;
    }
    pgp_armored_msg_t guessed = rnp_armor_guess_type(&armorsrc);
    src_close(&armorsrc);
    src_close(&memsrc);
    return guessed;
}

pgp_armored_msg_t
rnp_armored_get_type(pgp_source_t *src)
{
    pgp_armored_msg_t guessed = rnp_armored_guess_type_by_readahead(src);
    if (guessed != PGP_ARMORED_UNKNOWN) {
        return guessed;
    }

    char        hdr[ARMORED_PEEK_BUF_SIZE];
    const char *armhdr;
    size_t      armhdrlen;
    size_t      read;

    if (!src_peek(src, hdr, sizeof(hdr), &read) || (read < 20)) {
        return PGP_ARMORED_UNKNOWN;
    }
    if (!(armhdr = find_armor_header(hdr, read, &armhdrlen))) {
        return PGP_ARMORED_UNKNOWN;
    }

    return armor_str_to_data_type(armhdr + 5, armhdrlen - 10);
}

static bool
armor_parse_header(pgp_source_t *src)
{
    char                        hdr[ARMORED_PEEK_BUF_SIZE];
    const char *                armhdr;
    size_t                      armhdrlen;
    size_t                      read;
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;

    if (!src_peek(param->readsrc, hdr, sizeof(hdr), &read) || (read < 20)) {
        return false;
    }

    if (!(armhdr = find_armor_header(hdr, read, &armhdrlen))) {
        RNP_LOG("no armor header");
        return false;
    }

    /* if there are non-whitespaces before the armor header then issue warning */
    for (char *ch = hdr; ch < armhdr; ch++) {
        if (B64DEC[(uint8_t) *ch] != 0xfd) {
            RNP_LOG("extra data before the header line");
            break;
        }
    }

    param->type = armor_str_to_data_type(armhdr + 5, armhdrlen - 10);
    if (param->type == PGP_ARMORED_UNKNOWN) {
        RNP_LOG("unknown armor header");
        return false;
    }

    if ((param->armorhdr = (char *) malloc(armhdrlen - 9)) == NULL) {
        RNP_LOG("allocation failed");
        return false;
    }

    memcpy(param->armorhdr, armhdr + 5, armhdrlen - 10);
    param->armorhdr[armhdrlen - 10] = '\0';
    src_skip(param->readsrc, armhdr - hdr + armhdrlen);
    armor_skip_chars(param->readsrc, "\t ");
    return true;
}

static bool
armor_skip_line(pgp_source_t *src)
{
    char header[ARMORED_PEEK_BUF_SIZE] = {0};
    do {
        size_t hdrlen = 0;
        bool   res = src_peek_line(src, header, sizeof(header), &hdrlen);
        if (hdrlen) {
            src_skip(src, hdrlen);
        }
        if (res || (hdrlen < sizeof(header) - 1)) {
            return res;
        }
    } while (1);
}

static bool
armor_parse_headers(pgp_source_t *src)
{
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;
    char                        header[ARMORED_PEEK_BUF_SIZE] = {0};

    do {
        size_t hdrlen = 0;
        if (!src_peek_line(param->readsrc, header, sizeof(header), &hdrlen)) {
            /* if line is too long let's cut it to the reasonable size */
            src_skip(param->readsrc, hdrlen);
            if ((hdrlen != sizeof(header) - 1) || !armor_skip_line(param->readsrc)) {
                RNP_LOG("failed to peek line: unexpected end of data");
                return false;
            }
            RNP_LOG("Too long armor header - truncated.");
            header[hdrlen] = '\0';
        } else if (hdrlen) {
            src_skip(param->readsrc, hdrlen);
            if (rnp_is_blank_line(header, hdrlen)) {
                return src_skip_eol(param->readsrc);
            }
        } else {
            /* empty line - end of the headers */
            return src_skip_eol(param->readsrc);
        }

        char *hdrval = (char *) malloc(hdrlen + 1);
        if (!hdrval) {
            RNP_LOG("malloc failed");
            return false;
        }

        if ((hdrlen >= 9) && !strncmp(header, ST_HEADER_VERSION, 9)) {
            memcpy(hdrval, header + 9, hdrlen - 8);
            free(param->version);
            param->version = hdrval;
        } else if ((hdrlen >= 9) && !strncmp(header, ST_HEADER_COMMENT, 9)) {
            memcpy(hdrval, header + 9, hdrlen - 8);
            free(param->comment);
            param->comment = hdrval;
        } else if ((hdrlen >= 5) && !strncmp(header, ST_HEADER_HASH, 6)) {
            memcpy(hdrval, header + 6, hdrlen - 5);
            free(param->hash);
            param->hash = hdrval;
        } else if ((hdrlen >= 9) && !strncmp(header, ST_HEADER_CHARSET, 9)) {
            memcpy(hdrval, header + 9, hdrlen - 8);
            free(param->charset);
            param->charset = hdrval;
        } else {
            RNP_LOG("unknown header '%s'", header);
            free(hdrval);
        }

        if (!src_skip_eol(param->readsrc)) {
            return false;
        }
    } while (1);
}

rnp_result_t
init_armored_src(pgp_source_t *src, pgp_source_t *readsrc)
{
    rnp_result_t                errcode = RNP_ERROR_GENERIC;
    pgp_source_armored_param_t *param;

    if (!init_src_common(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_source_armored_param_t *) src->param;
    param->readsrc = readsrc;

    if (!pgp_hash_create_crc24(&param->crc_ctx)) {
        RNP_LOG("Internal error");
        return RNP_ERROR_GENERIC;
    }

    src->read = armored_src_read;
    src->close = armored_src_close;
    src->type = PGP_STREAM_ARMORED;

    /* parsing armored header */
    if (!armor_parse_header(src)) {
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    /* eol */
    if (!src_skip_eol(param->readsrc)) {
        RNP_LOG("no eol after the armor header");
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    /* parsing headers */
    if (!armor_parse_headers(src)) {
        RNP_LOG("failed to parse headers");
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }

    /* now we are good to go with base64-encoded data */
    errcode = RNP_SUCCESS;

finish:
    if (errcode != RNP_SUCCESS) {
        src_close(src);
    }
    return errcode;
}

/** @brief Copy armor header of tail to the buffer. Buffer should be at least ~40 chars. */
static bool
armor_message_header(pgp_armored_msg_t type, bool finish, char *buf)
{
    const char *str;
    str = finish ? ST_ARMOR_END : ST_ARMOR_BEGIN;
    memcpy(buf, str, strlen(str));
    buf += strlen(str);
    switch (type) {
    case PGP_ARMORED_MESSAGE:
        str = "MESSAGE";
        break;
    case PGP_ARMORED_PUBLIC_KEY:
        str = "PUBLIC KEY BLOCK";
        break;
    case PGP_ARMORED_SECRET_KEY:
        str = "PRIVATE KEY BLOCK";
        break;
    case PGP_ARMORED_SIGNATURE:
        str = "SIGNATURE";
        break;
    case PGP_ARMORED_CLEARTEXT:
        str = "SIGNED MESSAGE";
        break;
    default:
        return false;
    }

    memcpy(buf, str, strlen(str));
    buf += strlen(str);
    memcpy(buf, ST_DASHES, std::min<size_t>(sizeof(ST_DASHES) - 1, 5));
    buf[5] = '\0';
    return true;
}

static void
armor_write_eol(pgp_dest_armored_param_t *param)
{
    if (param->usecrlf) {
        dst_write(param->writedst, ST_CRLF, 2);
    } else {
        dst_write(param->writedst, ST_LF, 1);
    }
}

/* Base 64 encoded table, quadruplicated to save cycles on use & 0x3f operation  */
static const uint8_t B64ENC[256] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
  'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
  'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
  '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
  's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '+', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', 'A', 'B', 'C', 'D', 'E', 'F',
  'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
  'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '+', '/'};

static void
armored_encode3(uint8_t *out, uint8_t *in)
{
    out[0] = B64ENC[in[0] >> 2];
    out[1] = B64ENC[((in[0] << 4) | (in[1] >> 4)) & 0xff];
    out[2] = B64ENC[((in[1] << 2) | (in[2] >> 6)) & 0xff];
    out[3] = B64ENC[in[2] & 0xff];
}

static rnp_result_t
armored_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    uint8_t                   encbuf[PGP_INPUT_CACHE_SIZE / 2];
    uint8_t *                 encptr = encbuf;
    uint8_t *                 enclast;
    uint8_t                   dec3[3];
    uint8_t *                 bufptr = (uint8_t *) buf;
    uint8_t *                 bufend = bufptr + len;
    uint8_t *                 inlend;
    uint32_t                  t;
    unsigned                  inllen;
    pgp_dest_armored_param_t *param = (pgp_dest_armored_param_t *) dst->param;

    if (!param) {
        RNP_LOG("wrong param");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* update crc */
    pgp_hash_add(&param->crc_ctx, buf, len);

    /* processing tail if any */
    if (len + param->tailc < 3) {
        memcpy(&param->tail[param->tailc], buf, len);
        param->tailc += len;
        return RNP_SUCCESS;
    } else if (param->tailc > 0) {
        memcpy(dec3, param->tail, param->tailc);
        memcpy(&dec3[param->tailc], bufptr, 3 - param->tailc);
        bufptr += 3 - param->tailc;
        param->tailc = 0;
        armored_encode3(encptr, dec3);
        encptr += 4;
        param->lout += 4;
        if (param->lout == param->llen) {
            if (param->usecrlf) {
                *encptr++ = CH_CR;
            }
            *encptr++ = CH_LF;
            param->lout = 0;
        }
    }

    /* this version prints whole chunks, so rounding down to the closest 4 */
    auto adjusted_llen = param->llen & ~3;
    /* number of input bytes to form a whole line of output, param->llen / 4 * 3 */
    inllen = (adjusted_llen >> 2) + (adjusted_llen >> 1);
    /* pointer to the last full line space in encbuf */
    enclast = encbuf + sizeof(encbuf) - adjusted_llen - 2;

    /* processing line chunks, this is the main performance-hitting cycle */
    while (bufptr + 3 <= bufend) {
        /* checking whether we have enough space in encbuf */
        if (encptr > enclast) {
            dst_write(param->writedst, encbuf, encptr - encbuf);
            encptr = encbuf;
        }
        /* setup length of the input to process in this iteration */
        inlend = param->lout == 0 ? bufptr + inllen :
                                    bufptr + ((adjusted_llen - param->lout) >> 2) * 3;
        if (inlend > bufend) {
            /* no enough input for the full line */
            inlend = bufptr + (bufend - bufptr) / 3 * 3;
            param->lout += (inlend - bufptr) / 3 * 4;
        } else {
            /* we have full line of input */
            param->lout = 0;
        }

        /* processing one line */
        while (bufptr < inlend) {
            t = (bufptr[0] << 16) | (bufptr[1] << 8) | (bufptr[2]);
            bufptr += 3;
            *encptr++ = B64ENC[(t >> 18) & 0xff];
            *encptr++ = B64ENC[(t >> 12) & 0xff];
            *encptr++ = B64ENC[(t >> 6) & 0xff];
            *encptr++ = B64ENC[t & 0xff];
        }

        /* adding line ending */
        if (param->lout == 0) {
            if (param->usecrlf) {
                *encptr++ = CH_CR;
            }
            *encptr++ = CH_LF;
        }
    }

    dst_write(param->writedst, encbuf, encptr - encbuf);

    /* saving tail */
    param->tailc = bufend - bufptr;
    memcpy(param->tail, bufptr, param->tailc);

    return RNP_SUCCESS;
}

static rnp_result_t
armored_dst_finish(pgp_dest_t *dst)
{
    uint8_t                   buf[64];
    uint8_t                   crcbuf[3];
    pgp_dest_armored_param_t *param = (pgp_dest_armored_param_t *) dst->param;

    /* writing tail */
    if (param->tailc == 1) {
        buf[0] = B64ENC[param->tail[0] >> 2];
        buf[1] = B64ENC[(param->tail[0] << 4) & 0xff];
        buf[2] = CH_EQ;
        buf[3] = CH_EQ;
        dst_write(param->writedst, buf, 4);
    } else if (param->tailc == 2) {
        buf[0] = B64ENC[(param->tail[0] >> 2)];
        buf[1] = B64ENC[((param->tail[0] << 4) | (param->tail[1] >> 4)) & 0xff];
        buf[2] = B64ENC[(param->tail[1] << 2) & 0xff];
        buf[3] = CH_EQ;
        dst_write(param->writedst, buf, 4);
    }

    /* writing EOL if needed */
    if ((param->tailc > 0) || (param->lout > 0)) {
        armor_write_eol(param);
    }

    /* writing CRC and EOL */
    buf[0] = CH_EQ;

    // At this point crc_ctx is initialized, so call can't fail
    (void) pgp_hash_finish(&param->crc_ctx, crcbuf);
    armored_encode3(&buf[1], crcbuf);
    dst_write(param->writedst, buf, 5);
    armor_write_eol(param);

    /* writing armor header */
    armor_message_header(param->type, true, (char *) buf);
    dst_write(param->writedst, buf, strlen((char *) buf));
    armor_write_eol(param);

    return param->writedst->werr;
}

static void
armored_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_armored_param_t *param = (pgp_dest_armored_param_t *) dst->param;

    if (!param) {
        return;
    }

    /* dst_close may be called without dst_finish on error */
    (void) pgp_hash_finish(&param->crc_ctx, NULL);
    free(param);
    dst->param = NULL;
}

rnp_result_t
init_armored_dst(pgp_dest_t *dst, pgp_dest_t *writedst, pgp_armored_msg_t msgtype)
{
    char                      hdr[64];
    pgp_dest_armored_param_t *param;
    rnp_result_t              ret = RNP_SUCCESS;

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    param = (pgp_dest_armored_param_t *) dst->param;
    dst->write = armored_dst_write;
    dst->finish = armored_dst_finish;
    dst->close = armored_dst_close;
    dst->type = PGP_STREAM_ARMORED;
    dst->writeb = 0;
    dst->clen = 0;

    if (!pgp_hash_create_crc24(&param->crc_ctx)) {
        RNP_LOG("Internal error");
        return RNP_ERROR_GENERIC;
    }

    param->writedst = writedst;
    param->type = msgtype;
    param->usecrlf = true;
    param->llen = 76; /* must be multiple of 4 */

    if (!armor_message_header(param->type, false, hdr)) {
        RNP_LOG("unknown data type");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* armor header */
    dst_write(writedst, hdr, strlen(hdr));
    armor_write_eol(param);
    /* empty line */
    armor_write_eol(param);

finish:
    if (ret != RNP_SUCCESS) {
        armored_dst_close(dst, true);
    }

    return ret;
}

bool
is_armored_dest(pgp_dest_t *dst)
{
    return dst->type == PGP_STREAM_ARMORED;
}

rnp_result_t
armored_dst_set_line_length(pgp_dest_t *dst, size_t llen)
{
    if (!dst || (llen < ARMORED_MIN_LINE_LENGTH) || (llen > ARMORED_MAX_LINE_LENGTH) ||
        !dst->param || !is_armored_dest(dst)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    auto param = (pgp_dest_armored_param_t *) dst->param;
    param->llen = llen;
    return RNP_SUCCESS;
}

bool
is_armored_source(pgp_source_t *src)
{
    uint8_t buf[ARMORED_PEEK_BUF_SIZE];
    size_t  read = 0;

    if (!src_peek(src, buf, sizeof(buf), &read) || (read < strlen(ST_ARMOR_BEGIN) + 1)) {
        return false;
    }
    buf[read - 1] = 0;
    return !!strstr((char *) buf, ST_ARMOR_BEGIN);
}

bool
is_cleartext_source(pgp_source_t *src)
{
    uint8_t buf[ARMORED_PEEK_BUF_SIZE];
    size_t  read = 0;

    if (!src_peek(src, buf, sizeof(buf), &read) || (read < strlen(ST_CLEAR_BEGIN))) {
        return false;
    }
    buf[read - 1] = 0;
    return !!strstr((char *) buf, ST_CLEAR_BEGIN);
}

rnp_result_t
rnp_dearmor_source(pgp_source_t *src, pgp_dest_t *dst)
{
    rnp_result_t res = RNP_ERROR_BAD_FORMAT;
    pgp_source_t armorsrc = {0};

    /* initializing armored message */
    res = init_armored_src(&armorsrc, src);
    if (res) {
        return res;
    }
    /* Reading data from armored source and writing it to the output */
    res = dst_write_src(&armorsrc, dst);
    if (res) {
        RNP_LOG("dearmoring failed");
    }

    src_close(&armorsrc);
    return res;
}

rnp_result_t
rnp_armor_source(pgp_source_t *src, pgp_dest_t *dst, pgp_armored_msg_t msgtype)
{
    pgp_dest_t   armordst = {0};
    rnp_result_t res = init_armored_dst(&armordst, dst, msgtype);
    if (res) {
        return res;
    }

    res = dst_write_src(src, &armordst);
    if (res) {
        RNP_LOG("armoring failed");
    }

    dst_close(&armordst, res != RNP_SUCCESS);
    return res;
}
