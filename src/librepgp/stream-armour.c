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
#include "stream-armour.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <rnp/rnp_def.h>
#include "defs.h"
#include "types.h"
#include "symmetric.h"

#define ARMOURED_BLOCK_SIZE (4096)

typedef struct pgp_source_armored_param_t {
    pgp_source_t *     readsrc;         /* source to read from */
    pgp_armoured_msg_t type;            /* message type */
    char *             armourhdr;       /* armour header */
    char *             version;         /* Version: header if any */
    char *             comment;         /* Comment: header if any */
    char *             hash;            /* Hash: header if any */
    char *             charset;         /* Charset: header if any */
    uint8_t  rest[ARMOURED_BLOCK_SIZE]; /* unread decoded bytes, makes implementation easier */
    unsigned restlen;                   /* number of bytes in rest */
    unsigned restpos;  /* index of first unread byte in rest, restpos <= restlen */
    uint8_t  brest[3]; /* decoded 6-bit tail bytes */
    unsigned brestlen; /* number of bytes in brest */
    bool     eofb64;   /* end of base64 stream reached */
    unsigned crc;      /* crc-24 of already read data */
    unsigned readcrc;  /* crc-24 from the armoured data */
} pgp_source_armored_param_t;

typedef struct pgp_dest_armoured_param_t {
    pgp_dest_t *       writedst;
    pgp_armoured_msg_t type;    /* type of the message */
    bool               usecrlf; /* use CR LF instead of LF as eol */
    unsigned           lout;    /* chars written in current line */
    unsigned           llen;    /* length of the base64 line, defaults to 76 as per RFC */
    uint8_t            tail[2]; /* bytes which didn't fit into 3-byte boundary */
    unsigned           tailc;   /* number of bytes in tail */
    unsigned           crc;
} pgp_dest_armoured_param_t;

static unsigned
armour_crc24(unsigned crc, const uint8_t *buf, size_t len)
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
armour_skip_eol(pgp_source_t *readsrc)
{
    uint8_t eol[2];
    ssize_t read;

    read = src_peek(readsrc, eol, 2);
    if ((read >= 1) && (eol[0] == '\n')) {
        src_skip(readsrc, 1);
        return true;
    } else if ((read == 2) && (eol[0] == '\r') && (eol[1] == '\n')) {
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
    char                        st[64];
    size_t                      stlen;
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
    uint8_t                     dec[4];
    char                        crc[8];
    size_t                      clen;
    pgp_source_armored_param_t *param = src->param;

    if (!armour_peek_line(param->readsrc, crc, sizeof(crc), &clen)) {
        return false;
    }

    if ((clen == 5) && (crc[0] == '=')) {
        for (int i = 0; i < 4; i++) {
            if ((dec[i] = B64DEC[(int) crc[i + 1]]) >= 64) {
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
    char                        st[64];
    char                        str[64];
    size_t                      stlen;
    ssize_t                     read;
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
    uint8_t  b64buf[ARMOURED_BLOCK_SIZE];     /* input base64 data with spaces and so on */
    uint8_t  decbuf[ARMOURED_BLOCK_SIZE + 4]; /* decoded 6-bit values */
    uint8_t *bufptr = buf;                    /* for better readability below */
    uint8_t *bptr, *bend;                     /* pointer to input data in b64buf */
    uint8_t *dptr, *dend, *pend; /* pointers to decoded data in decbuf: working pointer, last
                                    available byte, last byte to process */
    uint8_t  bval;
    uint32_t b24;
    ssize_t  read;
    ssize_t  left = len;
    int      eqcount = 0; /* number of '=' at the end of base64 stream */

    if (!param) {
        return -1;
    }

    /* checking whether there are some decoded bytes */
    if (param->restpos < param->restlen) {
        if (param->restlen - param->restpos >= len) {
            memcpy(bufptr, &param->rest[param->restpos], len);
            param->restpos += len;
            param->crc = armour_crc24(param->crc, bufptr, len);
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
    dend = decbuf + param->brestlen;

    do {
        read = src_peek(param->readsrc, b64buf, sizeof(b64buf));
        if (read < 0) {
            return read;
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
                (void) fprintf(stderr,
                               "armoured_src_read: wrong base64 character %c\n",
                               (char) *(bptr - 1));
                return -1;
            }
        }

        dend = dptr;
        dptr = decbuf;
        /* Processing full 4s which will go directly to the buf.
           After this left < 3 or decbuf has < 4 bytes */
        if ((dend - dptr) / 4 * 3 < left) {
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

    param->crc = armour_crc24(param->crc, buf, bufptr - (uint8_t *) buf);

    if (param->eofb64) {
        if ((dend - dptr + eqcount) % 4 != 0) {
            (void) fprintf(stderr, "armoured_src_read: wrong b64 padding\n");
            return -1;
        }

        if (eqcount == 1) {
            b24 = (*dptr << 10) | (*(dptr + 1) << 4) | (*(dptr + 2) >> 2);
            *bptr++ = b24 >> 8;
            *bptr++ = b24 & 0xff;
        } else if (eqcount == 2) {
            *bptr++ = (*dptr << 2) | (*(dptr + 1) >> 4);
        }

        param->crc = armour_crc24(param->crc, param->rest, bptr - param->rest);

        /* we calculate crc when input stream finished instead of when all data is read */
        if (param->crc != param->readcrc) {
            (void) fprintf(stderr, "armoured_src_read: CRC mismatch\n");
            return -1;
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
            param->crc = armour_crc24(param->crc, bufptr, read);
        }
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
    } else if (!strncmp(hdr, "BEGIN PGP PUBLIC KEY BLOCK", len) ||
               !strncmp(hdr, "BEGIN PGP PUBLIC KEY", len)) {
        return PGP_ARMOURED_PUBLIC_KEY;
    } else if (!strncmp(hdr, "BEGIN PGP SECRET KEY BLOCK", len) ||
               !strncmp(hdr, "BEGIN PGP SECRET KEY", len)) {
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
    char                        hdr[128];
    const char *                armhdr;
    size_t                      armhdrlen;
    ssize_t                     read;
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

static bool
armour_parse_headers(pgp_source_t *src)
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

rnp_result_t
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
    src->eof = 0;

    /* parsing armoured header */
    if (!armour_parse_header(src)) {
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    /* eol */
    if (!armour_skip_eol(param->readsrc)) {
        (void) fprintf(stderr, "init_armoured_src: no eol after the armour header\n");
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    /* parsing headers */
    if (!armour_parse_headers(src)) {
        (void) fprintf(stderr, "init_armoured_src: failed to parse headers\n");
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
    return errcode;
}

/** @brief Copy armour header of tail to the buffer. Buffer should be at least ~40 chars. */
static bool
armour_message_header(pgp_armoured_msg_t type, bool finish, char *buf)
{
    char *str;
    str = finish ? "-----END PGP " : "-----BEGIN PGP ";
    strncpy(buf, str, strlen(str));
    buf += strlen(str);
    switch (type) {
    case PGP_ARMOURED_MESSAGE:
        str = "MESSAGE";
        break;
    case PGP_ARMOURED_PUBLIC_KEY:
        str = "PUBLIC KEY BLOCK";
        break;
    case PGP_ARMOURED_SECRET_KEY:
        str = "SECRET KEY BLOCK";
        break;
    case PGP_ARMOURED_SIGNATURE:
        str = "SIGNATURE";
        break;
    case PGP_ARMOURED_CLEARTEXT:
        str = "SIGNED MESSAGE";
        break;
    default:
        return false;
    }

    strncpy(buf, str, strlen(str));
    buf += strlen(str);
    strncpy(buf, "-----", 5);
    buf[5] = '\0';
    return true;
}

static const uint8_t CR = 0x0d;
static const uint8_t LF = 0x0a;
static const uint8_t EQ = 0x3d;
static const uint8_t CRLF[2] = {0x0d, 0x0a};

static void
armour_write_eol(pgp_dest_armoured_param_t *param)
{
    if (param->usecrlf) {
        dst_write(param->writedst, CRLF, 2);
    } else {
        dst_write(param->writedst, &LF, 1);
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
armoured_encode3(uint8_t *out, uint8_t *in)
{
    out[0] = B64ENC[in[0] >> 2];
    out[1] = B64ENC[((in[0] << 4) | (in[1] >> 4)) & 0xff];
    out[2] = B64ENC[((in[1] << 2) | (in[2] >> 6)) & 0xff];
    out[3] = B64ENC[in[2] & 0xff];
}

static rnp_result_t
armoured_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    uint8_t                    encbuf[PGP_INPUT_CACHE_SIZE / 2];
    uint8_t *                  encptr = encbuf;
    uint8_t *                  enclast;
    uint8_t                    dec3[3];
    uint8_t *                  bufptr = (uint8_t *) buf;
    uint8_t *                  bufend = bufptr + len;
    uint8_t *                  inlend;
    uint32_t                   t;
    unsigned                   inllen;
    pgp_dest_armoured_param_t *param = dst->param;

    if (!param) {
        (void) fprintf(stderr, "armoured_dst_write: wrong param\n");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* update crc */
    param->crc = armour_crc24(param->crc, buf, len);

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
        armoured_encode3(encptr, dec3);
        encptr += 4;
        param->lout += 4;
        if (param->lout == param->llen) {
            if (param->usecrlf) {
                *encptr++ = CR;
            }
            *encptr++ = LF;
            param->lout = 0;
        }
    }

    /* number of input bytes to form a whole line of output, param->llen / 4 * 3 */
    inllen = (param->llen >> 2) + (param->llen >> 1);
    /* pointer to the last full line space in encbuf */
    enclast = encbuf + sizeof(encbuf) - param->llen - 2;

    /* processing line chunks, this is the main performance-hitting cycle */
    while (bufptr + 3 <= bufend) {
        /* checking whether we have enough space in encbuf */
        if (encptr > enclast) {
            dst_write(param->writedst, encbuf, encptr - encbuf);
            encptr = encbuf;
        }
        /* setup length of the input to process in this iteration */
        inlend =
          param->lout == 0 ? bufptr + inllen : bufptr + ((param->llen - param->lout) >> 2) * 3;
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
                *encptr++ = CR;
            }
            *encptr++ = LF;
        }
    }

    dst_write(param->writedst, encbuf, encptr - encbuf);

    /* saving tail */
    param->tailc = bufend - bufptr;
    memcpy(param->tail, bufptr, param->tailc);

    return RNP_SUCCESS;
}

static void
armoured_dst_close(pgp_dest_t *dst, bool discard)
{
    uint8_t                    buf[64];
    uint8_t                    crcbuf[3];
    pgp_dest_armoured_param_t *param = dst->param;

    if (!param) {
        return;
    }

    if (!discard) {
        /* writing tail */
        if (param->tailc == 1) {
            buf[0] = B64ENC[param->tail[0] >> 2];
            buf[1] = B64ENC[(param->tail[0] << 4) & 0xff];
            buf[2] = EQ;
            buf[3] = EQ;
            dst_write(param->writedst, buf, 4);
        } else if (param->tailc == 2) {
            buf[0] = B64ENC[(param->tail[0] >> 2)];
            buf[1] = B64ENC[((param->tail[0] << 4) | (param->tail[1] >> 4)) & 0xff];
            buf[2] = B64ENC[(param->tail[1] << 2) & 0xff];
            buf[3] = EQ;
            dst_write(param->writedst, buf, 4);
        }

        /* writing EOL if needed */
        if ((param->tailc > 0) || (param->lout > 0)) {
            armour_write_eol(param);
        }

        /* writing CRC and EOL */
        buf[0] = EQ;
        crcbuf[0] = (param->crc >> 16) & 0xff;
        crcbuf[1] = (param->crc >> 8) & 0xff;
        crcbuf[2] = param->crc & 0xff;
        armoured_encode3(&buf[1], crcbuf);
        dst_write(param->writedst, buf, 5);
        armour_write_eol(param);

        /* writing armour header */
        armour_message_header(param->type, true, (char *) buf);
        dst_write(param->writedst, buf, strlen((char *) buf));
        armour_write_eol(param);
    }

    free(param);
    dst->param = NULL;
}

rnp_result_t
init_armoured_dst(pgp_dest_t *dst, pgp_dest_t *writedst, pgp_armoured_msg_t msgtype)
{
    char                       hdr[40];
    pgp_dest_armoured_param_t *param;
    rnp_result_t               ret = RNP_SUCCESS;

    if ((param = calloc(1, sizeof(*param))) == NULL) {
        (void) fprintf(stderr, "init_armoured_dst: allocation failed\n");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    dst->write = armoured_dst_write;
    dst->close = armoured_dst_close;
    dst->type = PGP_STREAM_ARMOURED;
    dst->writeb = 0;
    dst->param = param;
    dst->werr = RNP_SUCCESS;
    param->writedst = writedst;
    param->type = msgtype;
    param->usecrlf = true;
    param->crc = 0xb704ceL;
    param->llen = 76; /* must be multiple of 4 */

    if (!armour_message_header(param->type, false, hdr)) {
        (void) fprintf(stderr, "init_armoured_dst: unknown message type\n");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* armour header */
    dst_write(writedst, hdr, strlen(hdr));
    armour_write_eol(param);
    /* version string */
    strncpy(hdr, "Version: " PACKAGE_STRING, sizeof(hdr));
    dst_write(writedst, hdr, strlen(hdr));
    armour_write_eol(param);
    /* empty line */
    armour_write_eol(param);

finish:
    if (ret != RNP_SUCCESS) {
        armoured_dst_close(dst, true);
    }

    return ret;
}

rnp_result_t
rnp_dearmour_source(pgp_source_t *src, pgp_dest_t *dst)
{
    const char   armor_start[] = "-----BEGIN PGP";
    const char   clear_start[] = "-----BEGIN PGP SIGNED MESSAGE-----";
    rnp_result_t res = RNP_ERROR_BAD_FORMAT;
    pgp_source_t armorsrc;
    uint8_t      readbuf[PGP_INPUT_CACHE_SIZE];
    ssize_t      read;

    read = src_peek(src, readbuf, sizeof(clear_start));
    if (read < sizeof(armor_start)) {
        (void) fprintf(stderr, "rnp_dearmour_source: can't read enough data from source\n");
        res = RNP_ERROR_READ;
        goto finish;
    }

    /* Trying armored or cleartext data */
    readbuf[read - 1] = 0;
    if (strstr((char *) readbuf, armor_start)) {
        /* checking whether it is cleartext */
        if (strstr((char *) readbuf, clear_start)) {
            (void) fprintf(stderr, "rnp_dearmour_source: source is cleartext, not armored\n");
            goto finish;
        }

        /* initializing armoured message */
        res = init_armoured_src(&armorsrc, src);

        if (res != RNP_SUCCESS) {
            goto finish;
        }
    } else {
        (void) fprintf(stderr, "rnp_dearmour_source: source is not armored data\n");
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
                (void) fprintf(stderr, "rnp_dearmour_source: failed to output data\n");
                res = RNP_ERROR_WRITE;
                break;
            }
        }
    }

finish:
    src_close(&armorsrc);
    return res;
}

rnp_result_t
rnp_armour_source(pgp_source_t *src, pgp_dest_t *dst, pgp_armoured_msg_t msgtype)
{
    pgp_dest_t   armordst = {0};
    rnp_result_t res = RNP_ERROR_GENERIC;
    uint8_t      readbuf[PGP_INPUT_CACHE_SIZE];
    ssize_t      read;

    res = init_armoured_dst(&armordst, dst, msgtype);
    if (res != RNP_SUCCESS) {
        goto finish;
    }

    while (!src->eof) {
        read = src_read(src, readbuf, PGP_INPUT_CACHE_SIZE);
        if (read < 0) {
            res = RNP_ERROR_READ;
            break;
        } else if (read > 0) {
            dst_write(&armordst, readbuf, read);
            if (armordst.werr != RNP_SUCCESS) {
                (void) fprintf(stderr, "rnp_armour_source: failed to output data\n");
                res = RNP_ERROR_WRITE;
                break;
            }
        }
    }

finish:
    dst_close(&armordst, res != RNP_SUCCESS);
    return res;
}
