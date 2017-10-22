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
#include "utils.h"

#define ARMORED_BLOCK_SIZE (4096)

typedef struct pgp_source_armored_param_t {
    pgp_source_t *    readsrc;         /* source to read from */
    pgp_armored_msg_t type;            /* message type */
    char *            armorhdr;        /* armor header */
    char *            version;         /* Version: header if any */
    char *            comment;         /* Comment: header if any */
    char *            hash;            /* Hash: header if any */
    char *            charset;         /* Charset: header if any */
    uint8_t  rest[ARMORED_BLOCK_SIZE]; /* unread decoded bytes, makes implementation easier */
    unsigned restlen;                  /* number of bytes in rest */
    unsigned restpos;  /* index of first unread byte in rest, restpos <= restlen */
    uint8_t  brest[3]; /* decoded 6-bit tail bytes */
    unsigned brestlen; /* number of bytes in brest */
    bool     eofb64;   /* end of base64 stream reached */
    unsigned crc;      /* crc-24 of already read data */
    unsigned readcrc;  /* crc-24 from the armored data */
} pgp_source_armored_param_t;

typedef struct pgp_dest_armored_param_t {
    pgp_dest_t *      writedst;
    pgp_armored_msg_t type;    /* type of the message */
    bool              usecrlf; /* use CR LF instead of LF as eol */
    unsigned          lout;    /* chars written in current line */
    unsigned          llen;    /* length of the base64 line, defaults to 76 as per RFC */
    uint8_t           tail[2]; /* bytes which didn't fit into 3-byte boundary */
    unsigned          tailc;   /* number of bytes in tail */
    unsigned          crc;
} pgp_dest_armored_param_t;

static const uint32_t CRCTABLE[256] = {
  0x00000000, 0x00864cfb, 0x018ad50d, 0x010c99f6, 0x0393e6e1, 0x0315aa1a, 0x021933ec,
  0x029f7f17, 0x07a18139, 0x0727cdc2, 0x062b5434, 0x06ad18cf, 0x043267d8, 0x04b42b23,
  0x05b8b2d5, 0x053efe2e, 0x0fc54e89, 0x0f430272, 0x0e4f9b84, 0x0ec9d77f, 0x0c56a868,
  0x0cd0e493, 0x0ddc7d65, 0x0d5a319e, 0x0864cfb0, 0x08e2834b, 0x09ee1abd, 0x09685646,
  0x0bf72951, 0x0b7165aa, 0x0a7dfc5c, 0x0afbb0a7, 0x1f0cd1e9, 0x1f8a9d12, 0x1e8604e4,
  0x1e00481f, 0x1c9f3708, 0x1c197bf3, 0x1d15e205, 0x1d93aefe, 0x18ad50d0, 0x182b1c2b,
  0x192785dd, 0x19a1c926, 0x1b3eb631, 0x1bb8faca, 0x1ab4633c, 0x1a322fc7, 0x10c99f60,
  0x104fd39b, 0x11434a6d, 0x11c50696, 0x135a7981, 0x13dc357a, 0x12d0ac8c, 0x1256e077,
  0x17681e59, 0x17ee52a2, 0x16e2cb54, 0x166487af, 0x14fbf8b8, 0x147db443, 0x15712db5,
  0x15f7614e, 0x3e19a3d2, 0x3e9fef29, 0x3f9376df, 0x3f153a24, 0x3d8a4533, 0x3d0c09c8,
  0x3c00903e, 0x3c86dcc5, 0x39b822eb, 0x393e6e10, 0x3832f7e6, 0x38b4bb1d, 0x3a2bc40a,
  0x3aad88f1, 0x3ba11107, 0x3b275dfc, 0x31dced5b, 0x315aa1a0, 0x30563856, 0x30d074ad,
  0x324f0bba, 0x32c94741, 0x33c5deb7, 0x3343924c, 0x367d6c62, 0x36fb2099, 0x37f7b96f,
  0x3771f594, 0x35ee8a83, 0x3568c678, 0x34645f8e, 0x34e21375, 0x2115723b, 0x21933ec0,
  0x209fa736, 0x2019ebcd, 0x228694da, 0x2200d821, 0x230c41d7, 0x238a0d2c, 0x26b4f302,
  0x2632bff9, 0x273e260f, 0x27b86af4, 0x252715e3, 0x25a15918, 0x24adc0ee, 0x242b8c15,
  0x2ed03cb2, 0x2e567049, 0x2f5ae9bf, 0x2fdca544, 0x2d43da53, 0x2dc596a8, 0x2cc90f5e,
  0x2c4f43a5, 0x2971bd8b, 0x29f7f170, 0x28fb6886, 0x287d247d, 0x2ae25b6a, 0x2a641791,
  0x2b688e67, 0x2beec29c, 0x7c3347a4, 0x7cb50b5f, 0x7db992a9, 0x7d3fde52, 0x7fa0a145,
  0x7f26edbe, 0x7e2a7448, 0x7eac38b3, 0x7b92c69d, 0x7b148a66, 0x7a181390, 0x7a9e5f6b,
  0x7801207c, 0x78876c87, 0x798bf571, 0x790db98a, 0x73f6092d, 0x737045d6, 0x727cdc20,
  0x72fa90db, 0x7065efcc, 0x70e3a337, 0x71ef3ac1, 0x7169763a, 0x74578814, 0x74d1c4ef,
  0x75dd5d19, 0x755b11e2, 0x77c46ef5, 0x7742220e, 0x764ebbf8, 0x76c8f703, 0x633f964d,
  0x63b9dab6, 0x62b54340, 0x62330fbb, 0x60ac70ac, 0x602a3c57, 0x6126a5a1, 0x61a0e95a,
  0x649e1774, 0x64185b8f, 0x6514c279, 0x65928e82, 0x670df195, 0x678bbd6e, 0x66872498,
  0x66016863, 0x6cfad8c4, 0x6c7c943f, 0x6d700dc9, 0x6df64132, 0x6f693e25, 0x6fef72de,
  0x6ee3eb28, 0x6e65a7d3, 0x6b5b59fd, 0x6bdd1506, 0x6ad18cf0, 0x6a57c00b, 0x68c8bf1c,
  0x684ef3e7, 0x69426a11, 0x69c426ea, 0x422ae476, 0x42aca88d, 0x43a0317b, 0x43267d80,
  0x41b90297, 0x413f4e6c, 0x4033d79a, 0x40b59b61, 0x458b654f, 0x450d29b4, 0x4401b042,
  0x4487fcb9, 0x461883ae, 0x469ecf55, 0x479256a3, 0x47141a58, 0x4defaaff, 0x4d69e604,
  0x4c657ff2, 0x4ce33309, 0x4e7c4c1e, 0x4efa00e5, 0x4ff69913, 0x4f70d5e8, 0x4a4e2bc6,
  0x4ac8673d, 0x4bc4fecb, 0x4b42b230, 0x49ddcd27, 0x495b81dc, 0x4857182a, 0x48d154d1,
  0x5d26359f, 0x5da07964, 0x5cace092, 0x5c2aac69, 0x5eb5d37e, 0x5e339f85, 0x5f3f0673,
  0x5fb94a88, 0x5a87b4a6, 0x5a01f85d, 0x5b0d61ab, 0x5b8b2d50, 0x59145247, 0x59921ebc,
  0x589e874a, 0x5818cbb1, 0x52e37b16, 0x526537ed, 0x5369ae1b, 0x53efe2e0, 0x51709df7,
  0x51f6d10c, 0x50fa48fa, 0x507c0401, 0x5542fa2f, 0x55c4b6d4, 0x54c82f22, 0x544e63d9,
  0x56d11cce, 0x56575035, 0x575bc9c3, 0x57dd8538};

static unsigned
armor_crc24(unsigned crc, const uint8_t *buf, size_t len)
{
    for (; len; buf++, len--) {
        crc = (crc << 8) ^ CRCTABLE[((crc >> 16) & 0xff) ^ *buf];
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
armor_skip_eol(pgp_source_t *readsrc)
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
armor_peek_line(pgp_source_t *readsrc, char *buf, size_t len, size_t *llen)
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
armor_read_padding(pgp_source_t *src)
{
    char                        st[64];
    size_t                      stlen;
    pgp_source_armored_param_t *param = src->param;

    if (!armor_peek_line(param->readsrc, st, 12, &stlen)) {
        return -1;
    }

    if ((stlen == 1) || (stlen == 2)) {
        if ((st[0] != '=') || ((stlen == 2) && (st[1] != '='))) {
            return -1;
        }

        src_skip(param->readsrc, stlen);
        armor_skip_eol(param->readsrc);
        return stlen;
    } else if (stlen == 5) {
        return 0;
    }

    return -1;
}

static bool
armor_read_crc(pgp_source_t *src)
{
    uint8_t                     dec[4];
    char                        crc[8];
    size_t                      clen;
    pgp_source_armored_param_t *param = src->param;

    if (!armor_peek_line(param->readsrc, crc, sizeof(crc), &clen)) {
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
        armor_skip_eol(param->readsrc);
        return true;
    }

    return false;
}

static bool
armor_read_trailer(pgp_source_t *src)
{
    char                        st[64];
    char                        str[64];
    size_t                      stlen;
    ssize_t                     read;
    pgp_source_armored_param_t *param = src->param;

    stlen = strlen(param->armorhdr);
    strncpy(st, "-----END", 8);
    strncpy(st + 8, param->armorhdr + 5, stlen - 5);
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
armored_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_armored_param_t *param = src->param;
    uint8_t  b64buf[ARMORED_BLOCK_SIZE];     /* input base64 data with spaces and so on */
    uint8_t  decbuf[ARMORED_BLOCK_SIZE + 4]; /* decoded 6-bit values */
    uint8_t *bufptr = buf;                   /* for better readability below */
    uint8_t *bptr, *bend;                    /* pointer to input data in b64buf */
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
            param->crc = armor_crc24(param->crc, bufptr, len);
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
                RNP_LOG("wrong base64 character %c", (char) *(bptr - 1));
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
            if ((eqcount = armor_read_padding(src)) < 0) {
                RNP_LOG("wrong padding");
                return -1;
            }

            /* reading crc */
            if (!armor_read_crc(src)) {
                RNP_LOG("wrong crc line");
                return -1;
            }
            /* reading armor trailing line */
            if (!armor_read_trailer(src)) {
                RNP_LOG("armored_src_read: wrong armor trailer");
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

    param->crc = armor_crc24(param->crc, buf, bufptr - (uint8_t *) buf);

    if (param->eofb64) {
        if ((dend - dptr + eqcount) % 4 != 0) {
            RNP_LOG("wrong b64 padding");
            return -1;
        }

        if (eqcount == 1) {
            b24 = (*dptr << 10) | (*(dptr + 1) << 4) | (*(dptr + 2) >> 2);
            *bptr++ = b24 >> 8;
            *bptr++ = b24 & 0xff;
        } else if (eqcount == 2) {
            *bptr++ = (*dptr << 2) | (*(dptr + 1) >> 4);
        }

        param->crc = armor_crc24(param->crc, param->rest, bptr - param->rest);

        /* we calculate crc when input stream finished instead of when all data is read */
        if (param->crc != param->readcrc) {
            RNP_LOG("CRC mismatch");
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
            param->crc = armor_crc24(param->crc, bufptr, read);
        }
        left -= read;
        param->restpos += read;
    }

    return len - left;
}

static void
armored_src_close(pgp_source_t *src)
{
    pgp_source_armored_param_t *param = src->param;

    if (!param) {
        return;
    }

    free(param->armorhdr);
    free(param->version);
    free(param->comment);
    free(param->hash);
    free(param->charset);
    free(param);
    param = NULL;
}

/** @brief finds armor header position in the buffer, returning beginning of header or NULL.
 *  hdrlen will contain the length of the header
**/
static const char *
find_armor_header(const char *buf, size_t len, size_t *hdrlen)
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

pgp_armored_msg_t
armor_str_to_data_type(const char *str, size_t len)
{
    if (!str) {
        return PGP_ARMORED_UNKNOWN;
    }

    if (!strncmp(str, "BEGIN PGP MESSAGE", len) || !strncmp("msg", str, len)) {
        return PGP_ARMORED_MESSAGE;
    }

    if (!strncmp(str, "BEGIN PGP PUBLIC KEY BLOCK", len) ||
        !strncmp(str, "BEGIN PGP PUBLIC KEY", len) || !strncmp("pubkey", str, len)) {
        return PGP_ARMORED_PUBLIC_KEY;
    }

    if (!strncmp(str, "BEGIN PGP SECRET KEY BLOCK", len) ||
        !strncmp(str, "BEGIN PGP SECRET KEY", len) || !strncmp("seckey", str, len)) {
        return PGP_ARMORED_SECRET_KEY;
    }

    if (!strncmp(str, "BEGIN PGP SIGNATURE", len) || !strncmp("sign", str, len)) {
        return PGP_ARMORED_SIGNATURE;
    }

    if (!strncmp(str, "BEGIN PGP SIGNED MESSAGE", len)) {
        return PGP_ARMORED_CLEARTEXT;
    }
    return PGP_ARMORED_UNKNOWN;
}

static bool
armor_parse_header(pgp_source_t *src)
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

    if (!(armhdr = find_armor_header(hdr, read, &armhdrlen))) {
        RNP_LOG("no armor header");
        return false;
    }

    if (armhdr > hdr) {
        RNP_LOG("extra data before the header line");
    }

    param->type = armor_str_to_data_type(armhdr + 5, armhdrlen - 10);
    if (param->type == PGP_ARMORED_UNKNOWN) {
        RNP_LOG("unknown armor header");
        return false;
    }

    if ((param->armorhdr = malloc(armhdrlen - 9)) == NULL) {
        RNP_LOG("allocation failed");
        return false;
    }

    memcpy(param->armorhdr, armhdr + 5, armhdrlen - 10);
    param->armorhdr[armhdrlen - 10] = '\0';
    src_skip(param->readsrc, armhdr - hdr + armhdrlen);
    return true;
}

static bool
armor_parse_headers(pgp_source_t *src)
{
    pgp_source_armored_param_t *param = src->param;
    char                        header[1024];
    size_t                      hdrlen;
    char *                      hdrval;

    do {
        if (!armor_peek_line(param->readsrc, header, sizeof(header) - 1, &hdrlen)) {
            RNP_LOG("failed to peek line");
            return false;
        }

        if (hdrlen > 0) {
            if ((hdrval = malloc(hdrlen + 1)) == NULL) {
                RNP_LOG("malloc failed");
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
                RNP_LOG("unknown header '%s'", header);
            }

            src_skip(param->readsrc, hdrlen);
        }

        if (!armor_skip_eol(param->readsrc)) {
            return false;
        }
    } while (hdrlen > 0);

    return true;
}

rnp_result_t
init_armored_src(pgp_source_t *src, pgp_source_t *readsrc)
{
    rnp_result_t                errcode = RNP_SUCCESS;
    pgp_source_armored_param_t *param;

    if (!init_source_cache(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = src->param;
    param->readsrc = readsrc;
    param->crc = 0xb704ceL;
    src->read = armored_src_read;
    src->close = armored_src_close;
    src->type = PGP_STREAM_ARMORED;
    src->size = 0;
    src->readb = 0;
    src->eof = 0;

    /* parsing armored header */
    if (!armor_parse_header(src)) {
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    /* eol */
    if (!armor_skip_eol(param->readsrc)) {
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
    goto finish;

finish:
    if (errcode != RNP_SUCCESS) {
        armored_src_close(src);
    }
    return errcode;
}

/** @brief Copy armor header of tail to the buffer. Buffer should be at least ~40 chars. */
static bool
armor_message_header(pgp_armored_msg_t type, bool finish, char *buf)
{
    char *str;
    str = finish ? "-----END PGP " : "-----BEGIN PGP ";
    strncpy(buf, str, strlen(str));
    buf += strlen(str);
    switch (type) {
    case PGP_ARMORED_MESSAGE:
        str = "MESSAGE";
        break;
    case PGP_ARMORED_PUBLIC_KEY:
        str = "PUBLIC KEY BLOCK";
        break;
    case PGP_ARMORED_SECRET_KEY:
        str = "SECRET KEY BLOCK";
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
armor_write_eol(pgp_dest_armored_param_t *param)
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
    pgp_dest_armored_param_t *param = dst->param;

    if (!param) {
        RNP_LOG("wrong param");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* update crc */
    param->crc = armor_crc24(param->crc, buf, len);

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
armored_dst_close(pgp_dest_t *dst, bool discard)
{
    uint8_t                   buf[64];
    uint8_t                   crcbuf[3];
    pgp_dest_armored_param_t *param = dst->param;

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
            armor_write_eol(param);
        }

        /* writing CRC and EOL */
        buf[0] = EQ;
        crcbuf[0] = (param->crc >> 16) & 0xff;
        crcbuf[1] = (param->crc >> 8) & 0xff;
        crcbuf[2] = param->crc & 0xff;
        armored_encode3(&buf[1], crcbuf);
        dst_write(param->writedst, buf, 5);
        armor_write_eol(param);

        /* writing armor header */
        armor_message_header(param->type, true, (char *) buf);
        dst_write(param->writedst, buf, strlen((char *) buf));
        armor_write_eol(param);
    }

    free(param);
    dst->param = NULL;
}

rnp_result_t
init_armored_dst(pgp_dest_t *dst, pgp_dest_t *writedst, pgp_armored_msg_t msgtype)
{
    char                      hdr[40];
    pgp_dest_armored_param_t *param;
    rnp_result_t              ret = RNP_SUCCESS;

    if ((param = calloc(1, sizeof(*param))) == NULL) {
        RNP_LOG("allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    dst->write = armored_dst_write;
    dst->close = armored_dst_close;
    dst->type = PGP_STREAM_ARMORED;
    dst->writeb = 0;
    dst->clen = 0;
    dst->param = param;
    dst->werr = RNP_SUCCESS;
    param->writedst = writedst;
    param->type = msgtype;
    param->usecrlf = true;
    param->crc = 0xb704ceL;
    param->llen = 76; /* must be multiple of 4 */

    if (!armor_message_header(param->type, false, hdr)) {
        RNP_LOG("unknown data type");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* armor header */
    dst_write(writedst, hdr, strlen(hdr));
    armor_write_eol(param);
    /* version string */
    strncpy(hdr, "Version: " PACKAGE_STRING, sizeof(hdr));
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

rnp_result_t
rnp_dearmor_source(pgp_source_t *src, pgp_dest_t *dst)
{
    static const char armor_start[] = "-----BEGIN PGP";
    static const char clear_start[] = "-----BEGIN PGP SIGNED MESSAGE-----";
    rnp_result_t      res = RNP_ERROR_BAD_FORMAT;
    pgp_source_t      armorsrc;
    uint8_t           readbuf[PGP_INPUT_CACHE_SIZE];
    ssize_t           read;

    read = src_peek(src, readbuf, sizeof(clear_start));
    if (read < sizeof(armor_start)) {
        RNP_LOG("can't read enough data from source");
        res = RNP_ERROR_READ;
        goto finish;
    }

    /* Trying armored or cleartext data */
    readbuf[read - 1] = 0;
    if (strstr((char *) readbuf, armor_start)) {
        /* checking whether it is cleartext */
        if (strstr((char *) readbuf, clear_start)) {
            RNP_LOG("source is cleartext, not armored");
            goto finish;
        }

        /* initializing armored message */
        res = init_armored_src(&armorsrc, src);

        if (res != RNP_SUCCESS) {
            goto finish;
        }
    } else {
        RNP_LOG("source is not armored data");
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
                RNP_LOG("failed to output data");
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
rnp_armor_source(pgp_source_t *src, pgp_dest_t *dst, pgp_armored_msg_t msgtype)
{
    pgp_dest_t   armordst = {0};
    rnp_result_t res = RNP_ERROR_GENERIC;
    uint8_t      readbuf[PGP_INPUT_CACHE_SIZE];
    ssize_t      read;

    res = init_armored_dst(&armordst, dst, msgtype);
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
                RNP_LOG("failed to output data");
                res = RNP_ERROR_WRITE;
                break;
            }
        }
    }

finish:
    dst_close(&armordst, res != RNP_SUCCESS);
    return res;
}
