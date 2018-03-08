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
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <rnp/rnp_def.h>
#include "defs.h"
#include "types.h"
#include "symmetric.h"
#include "crypto/s2k.h"
#include "stream-packet.h"

static uint32_t
read_uint32(uint8_t *buf)
{
    return ((uint32_t) buf[0] << 24) | ((uint32_t) buf[1] << 16) | ((uint32_t) buf[2] << 8) |
           (uint32_t) buf[3];
}

static uint16_t
read_uint16(uint8_t *buf)
{
    return ((uint16_t) buf[0] << 8) | buf[1];
}

static void
write_uint16(uint8_t *buf, uint16_t val)
{
    buf[0] = val >> 8;
    buf[1] = val & 0xff;
}

size_t
write_packet_len(uint8_t *buf, size_t len)
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
        STORE32BE(&buf[1], len);
        return 5;
    }
}

int
get_packet_type(uint8_t ptag)
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

ssize_t
stream_pkt_hdr_len(pgp_source_t *src)
{
    uint8_t buf[2];
    ssize_t read;

    read = src_peek(src, buf, 2);
    if ((read < 2) || !(buf[0] & PGP_PTAG_ALWAYS_SET)) {
        return -1;
    }

    if (buf[0] & PGP_PTAG_NEW_FORMAT) {
        if (buf[1] < 192) {
            return 2;
        } else if (buf[1] < 224) {
            return 3;
        } else if (buf[1] < 255) {
            return 2;
        } else {
            return 6;
        }
    } else {
        switch (buf[0] & PGP_PTAG_OF_LENGTH_TYPE_MASK) {
        case PGP_PTAG_OLD_LEN_1:
            return 2;
        case PGP_PTAG_OLD_LEN_2:
            return 3;
        case PGP_PTAG_OLD_LEN_4:
            return 5;
        case PGP_PTAG_OLD_LEN_INDETERMINATE:
            return 1;
        default:
            return -1;
        }
    }
}

ssize_t
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
                return read_uint32(&buf[2]);
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
            return read_uint16(&buf[1]);
        case PGP_PTAG_OLD_LEN_4:
            if (src_read(src, &buf[2], 3) < 3) {
                return -1;
            }
            return read_uint32(&buf[1]);
        default:
            return -1;
        }
    }
}

/** @brief read mpi from the source
 *  @param src source to read from
 *  @param mpi preallocated mpi body buffer of PGP_MPINT_SIZE bytes
 *  @param maxlen maximum length of the MPI (including header), or zero if we should not care
 *  @return number of bytes in mpi body or -1 on error
 **/
static ssize_t
stream_read_mpi(pgp_source_t *src, uint8_t *mpi, size_t maxlen)
{
    uint8_t  hdr[2];
    unsigned bits;
    unsigned bytes;
    unsigned hbits;
    ssize_t  read;

    if ((maxlen > 0) && (maxlen < 2)) {
        return -1;
    }

    if ((read = src_read(src, hdr, 2)) < 2) {
        return -1;
    }

    bits = read_uint16(hdr);
    if (!bits || (bits > PGP_MPINT_BITS)) {
        RNP_LOG("too large or zero mpi, %d bits", bits);
        return -1;
    }

    bytes = (bits + 7) >> 3;
    if ((maxlen > 0) && (bytes > maxlen - 2)) {
        RNP_LOG("mpi out of bounds");
        return -1;
    }

    if ((read = src_read(src, mpi, bytes)) < bytes) {
        return -1;
    }

    hbits = bits & 7 ? bits & 7 : 8;
    if ((((unsigned) mpi[0] >> hbits) != 0) || !((unsigned) mpi[0] & (1U << (hbits - 1)))) {
        RNP_LOG("wrong mpi bit count");
        return -1;
    }

    return bytes;
}

bool
init_packet_body(pgp_packet_body_t *body, int tag)
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

bool
add_packet_body(pgp_packet_body_t *body, void *data, size_t len)
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

bool
add_packet_body_byte(pgp_packet_body_t *body, uint8_t byte)
{
    if (body->len < body->allocated) {
        body->data[body->len++] = byte;
        return true;
    } else {
        return add_packet_body(body, &byte, 1);
    }
}

bool
add_packet_body_uint16(pgp_packet_body_t *body, uint16_t val)
{
    uint8_t bytes[2];

    write_uint16(bytes, val);
    return add_packet_body(body, bytes, 2);
}

bool
add_packet_body_uint32(pgp_packet_body_t *body, uint32_t val)
{
    uint8_t bytes[4];

    STORE32BE(bytes, val);
    return add_packet_body(body, bytes, 4);
}

bool
add_packet_body_mpi(pgp_packet_body_t *body, uint8_t *mpi, unsigned len)
{
    unsigned bits;
    unsigned idx = 0;
    unsigned hibyte;
    uint8_t  hdr[2];

    if (!len) {
        return false;
    }

    while ((idx < len - 1) && (mpi[idx] == 0)) {
        idx++;
    }

    bits = (len - idx - 1) << 3;
    hibyte = mpi[idx];
    while (hibyte > 0) {
        bits++;
        hibyte = hibyte >> 1;
    }

    hdr[0] = bits >> 8;
    hdr[1] = bits & 0xff;
    return add_packet_body(body, hdr, 2) && add_packet_body(body, mpi + idx, len - idx);
}

static bool
add_packet_body_key_curve(pgp_packet_body_t *body, const pgp_curve_t curve)
{
    const ec_curve_desc_t *desc = NULL;

    return (desc = get_curve_desc(curve)) &&
           add_packet_body_byte(body, (uint8_t) desc->OIDhex_len) &&
           add_packet_body(body, (void*) desc->OIDhex, desc->OIDhex_len);
}

bool
add_packet_body_subpackets(pgp_packet_body_t *body, pgp_signature_t *sig, bool hashed)
{
    pgp_packet_body_t spbody;
    pgp_sig_subpkt_t *subpkt;
    size_t            lenlen;
    uint8_t           splen[6];
    bool              res;

    if (!init_packet_body(&spbody, 0)) {
        return false;
    }

    /* add space for subpackets length */
    res = add_packet_body_uint16(&spbody, 0);

    for (list_item *sp = list_front(sig->subpkts); sp; sp = list_next(sp)) {
        subpkt = (pgp_sig_subpkt_t *) sp;

        if (subpkt->hashed != hashed) {
            continue;
        }

        lenlen = write_packet_len(splen, subpkt->len + 1);
        res &= add_packet_body(&spbody, splen, lenlen) &&
               add_packet_body_byte(&spbody, subpkt->type | (subpkt->critical << 7)) &&
               add_packet_body(&spbody, subpkt->data, subpkt->len);
    }

    if (res) {
        /* now we know subpackets length */
        write_uint16(spbody.data, spbody.len - 2);
        res = add_packet_body(body, spbody.data, spbody.len);
    }

    free_packet_body(&spbody);
    return res;
}

bool
get_packet_body_byte(pgp_packet_body_t *body, uint8_t *val)
{
    if (body->pos >= body->len) {
        return false;
    }

    *val = body->data[body->pos++];
    return true;
}

bool
get_packet_body_uint16(pgp_packet_body_t *body, uint16_t *val)
{
    if (body->pos + 2 > body->len) {
        return false;
    }

    *val = read_uint16(body->data + body->pos);
    body->pos += 2;
    return true;
}

bool
get_packet_body_uint32(pgp_packet_body_t *body, uint32_t *val)
{
    if (body->pos + 4 > body->len) {
        return false;
    }

    *val = read_uint32(body->data + body->pos);
    body->pos += 4;
    return true;
}

bool
get_packet_body_buf(pgp_packet_body_t *body, uint8_t *val, size_t len)
{
    if (body->pos + len < body->len) {
        return false;
    }

    memcpy(val, body->data + body->pos, len);
    body->pos += len;
    return true;
}

bool
get_packet_body_mpi(pgp_packet_body_t *body, uint8_t *val, size_t *len)
{
    uint16_t bits;

    if (!get_packet_body_uint16(body, &bits)) {
        return false;
    }

    if ((*len = (bits + 7) >> 3) > PGP_MPINT_SIZE) {
        RNP_LOG("too large mpi");
        return false;
    }

    if (*len == 0) {
        RNP_LOG("0 mpi");
        return false;
    }

    if (!get_packet_body_buf(body, val, *len)) {
        return false;
    }

    /* check the mpi bit count */
    unsigned hbits = bits & 7 ? bits & 7 : 8;
    if ((((unsigned) val[0] >> hbits) != 0) || !((unsigned) val[0] & (1U << (hbits - 1)))) {
        RNP_LOG("wrong mpi bit count");
        return false;
    }

    return true;
}

/* @brief Read ECC key curve and convert it to pgp_curve_t */
static bool
get_packet_body_key_curve(pgp_packet_body_t *body, pgp_curve_t *val)
{
    uint8_t     oid[MAX_CURVE_OID_HEX_LEN] = {0};
    uint8_t     oidlen;
    pgp_curve_t res;

    if (!get_packet_body_byte(body, &oidlen)) {
        return false;
    }

    if ((oidlen == 0) || (oidlen == 0xff) || (oidlen > sizeof(oid))) {
        RNP_LOG("unsupported curve oid len: %d", (int) oidlen);
        return false;
    }

    if (!get_packet_body_buf(body, oid, oidlen)) {
        return false;
    }

    if ((res = find_curve_by_OID(oid, oidlen)) == PGP_CURVE_MAX) {
        RNP_LOG("unsupported curve");
        return false;
    }

    *val = res;
    return true;
}

void
free_packet_body(pgp_packet_body_t *body)
{
    free(body->data);
    body->data = NULL;
}

void
stream_flush_packet_body(pgp_packet_body_t *body, pgp_dest_t *dst)
{
    uint8_t hdr[6];
    size_t  hlen;

    hdr[0] = body->tag | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
    hlen = 1 + write_packet_len(&hdr[1], body->len);
    dst_write(dst, hdr, hlen);
    dst_write(dst, body->data, body->len);
    free(body->data);
}

rnp_result_t
stream_read_packet_body(pgp_source_t *src, pgp_packet_body_t *body)
{
    ssize_t len;
    ssize_t read;

    memset(body, 0, sizeof(*body));

    /* Read the packet header and length */
    if ((len = stream_pkt_hdr_len(src)) < 0) {
        return RNP_ERROR_BAD_FORMAT;
    }

    if (src_peek(src, body->hdr, len) != len) {
        return RNP_ERROR_READ;
    }

    body->hdr_len = len;

    if ((body->tag = get_packet_type(body->hdr[0])) < 0) {
        return RNP_ERROR_BAD_FORMAT;
    }

    len = stream_read_pkt_len(src);
    if (len <= 0) {
        return RNP_ERROR_READ;
    } else if (len > PGP_MAX_PKT_SIZE) {
        RNP_LOG("too large packet");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* Read the packet contents */
    if (!(body->data = malloc(len))) {
        RNP_LOG("malloc of %d bytes failed", (int) len);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if ((read = src_read(src, body->data, len)) != len) {
        RNP_LOG("read %d instead of %d", (int) read, (int) len);
        free(body->data);
        body->data = NULL;
        return RNP_ERROR_READ;
    }

    body->allocated = len;
    body->len = len;
    body->pos = 0;

    return RNP_SUCCESS;
}

bool
stream_write_sk_sesskey(pgp_sk_sesskey_t *skey, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;

    if (!init_packet_body(&pktbody, PGP_PTAG_CT_SK_SESSION_KEY)) {
        return false;
    }

    /* version and algorithm fields */
    res = add_packet_body_byte(&pktbody, skey->version) &&
          add_packet_body_byte(&pktbody, skey->alg);

    if (skey->version == PGP_SKSK_V5) {
        res = res && add_packet_body_byte(&pktbody, skey->aalg);
    }

    /* S2K specifier */
    res = res && add_packet_body_byte(&pktbody, skey->s2k.specifier) &&
          add_packet_body_byte(&pktbody, skey->s2k.hash_alg);

    switch (skey->s2k.specifier) {
    case PGP_S2KS_SIMPLE:
        break;
    case PGP_S2KS_SALTED:
        res = res && add_packet_body(&pktbody, skey->s2k.salt, sizeof(skey->s2k.salt));
        break;
    case PGP_S2KS_ITERATED_AND_SALTED:
        res = res && add_packet_body(&pktbody, skey->s2k.salt, sizeof(skey->s2k.salt)) &&
              add_packet_body_byte(&pktbody, skey->s2k.iterations);
        break;
    }

    /* v5 : iv */
    if (skey->version == PGP_SKSK_V5) {
        res = res && add_packet_body(&pktbody, skey->iv, skey->ivlen);
    }

    /* encrypted key and auth tag for v5 */
    if (skey->enckeylen > 0) {
        res = res && add_packet_body(&pktbody, skey->enckey, skey->enckeylen);
    }

    if (res) {
        stream_flush_packet_body(&pktbody, dst);
        return true;
    }

    free_packet_body(&pktbody);
    return false;
}

bool
stream_write_pk_sesskey(pgp_pk_sesskey_pkt_t *pkey, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;

    if (!init_packet_body(&pktbody, PGP_PTAG_CT_PK_SESSION_KEY)) {
        return false;
    }

    res = add_packet_body_byte(&pktbody, pkey->version) &&
          add_packet_body(&pktbody, pkey->key_id, sizeof(pkey->key_id)) &&
          add_packet_body_byte(&pktbody, pkey->alg);

    switch (pkey->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
        res = res && add_packet_body_mpi(&pktbody, pkey->params.rsa.m, pkey->params.rsa.mlen);
        break;
    case PGP_PKA_SM2:
        res = res && add_packet_body_mpi(&pktbody, pkey->params.sm2.m, pkey->params.sm2.mlen);
        break;
    case PGP_PKA_ECDH:
        res = res &&
              add_packet_body_mpi(&pktbody, pkey->params.ecdh.p, pkey->params.ecdh.plen) &&
              add_packet_body_byte(&pktbody, pkey->params.ecdh.mlen) &&
              add_packet_body(&pktbody, pkey->params.ecdh.m, pkey->params.ecdh.mlen);
        break;
    case PGP_PKA_ELGAMAL:
        res = res && add_packet_body_mpi(&pktbody, pkey->params.eg.g, pkey->params.eg.glen) &&
              add_packet_body_mpi(&pktbody, pkey->params.eg.m, pkey->params.eg.mlen);
        break;
    default:
        res = false;
    }

    if (res) {
        stream_flush_packet_body(&pktbody, dst);
        return true;
    } else {
        free_packet_body(&pktbody);
        return false;
    }
}

bool
stream_write_one_pass(pgp_one_pass_sig_t *onepass, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;

    if (!init_packet_body(&pktbody, PGP_PTAG_CT_1_PASS_SIG)) {
        return false;
    }

    res = add_packet_body_byte(&pktbody, onepass->version) &&
          add_packet_body_byte(&pktbody, onepass->type) &&
          add_packet_body_byte(&pktbody, onepass->halg) &&
          add_packet_body_byte(&pktbody, onepass->palg) &&
          add_packet_body(&pktbody, onepass->keyid, PGP_KEY_ID_SIZE) &&
          add_packet_body_byte(&pktbody, onepass->nested);

    if (res) {
        stream_flush_packet_body(&pktbody, dst);
        return true;
    } else {
        free_packet_body(&pktbody);
        return false;
    }
}

bool
stream_write_signature(pgp_signature_t *sig, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;

    if ((sig->version < PGP_V2) || (sig->version > PGP_V4)) {
        RNP_LOG("don't know version %d", (int) sig->version);
        return false;
    }

    if (!init_packet_body(&pktbody, PGP_PTAG_CT_SIGNATURE)) {
        RNP_LOG("allocation failed");
        return false;
    }

    if (sig->version < PGP_V4) {
        /* for v3 signatures hashed data includes only type + creation_time */
        res = add_packet_body_byte(&pktbody, sig->version) &&
              add_packet_body_byte(&pktbody, sig->hashed_len) &&
              add_packet_body(&pktbody, sig->hashed_data, sig->hashed_len) &&
              add_packet_body(&pktbody, sig->signer, PGP_KEY_ID_SIZE) &&
              add_packet_body_byte(&pktbody, sig->palg) &&
              add_packet_body_byte(&pktbody, sig->halg);
    } else {
        /* for v4 sig->hashed_data must contain most of signature fields */
        res = add_packet_body(&pktbody, sig->hashed_data, sig->hashed_len) &&
              add_packet_body_subpackets(&pktbody, sig, false);
    }

    res &= add_packet_body(&pktbody, sig->lbits, 2);

    /* write mpis */
    switch (sig->palg) {
    case PGP_PKA_RSA:
        res &= add_packet_body_mpi(&pktbody, sig->material.rsa.s, sig->material.rsa.slen);
        break;
    case PGP_PKA_DSA:
        res &= add_packet_body_mpi(&pktbody, sig->material.dsa.r, sig->material.dsa.rlen) &&
               add_packet_body_mpi(&pktbody, sig->material.dsa.s, sig->material.dsa.slen);
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        res &= add_packet_body_mpi(&pktbody, sig->material.ecc.r, sig->material.ecc.rlen) &&
               add_packet_body_mpi(&pktbody, sig->material.ecc.s, sig->material.ecc.slen);
        break;
    default:
        RNP_LOG("Unknown pk algorithm : %d", (int) sig->palg);
        res = false;
    }

    if (res) {
        stream_flush_packet_body(&pktbody, dst);
        return dst->werr == RNP_SUCCESS;
    }

    free_packet_body(&pktbody);
    return false;
}

rnp_result_t
stream_parse_sk_sesskey(pgp_source_t *src, pgp_sk_sesskey_t *skey)
{
    uint8_t  buf[5];
    ssize_t  len;
    ssize_t  read;
    unsigned idx = 0;

    /* read packet length */
    len = stream_read_pkt_len(src);
    if (len < 0) {
        return RNP_ERROR_READ;
    } else if (len < 4) {
        return RNP_ERROR_BAD_FORMAT;
    }

    /* version + symalg + s2k type + hash alg for v4 */
    if ((read = src_read(src, buf, 4)) < 4) {
        return RNP_ERROR_READ;
    }

    /* version */
    skey->version = buf[idx++];
    if ((skey->version != PGP_SKSK_V4) && (skey->version != PGP_SKSK_V5)) {
        RNP_LOG("wrong packet version");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* symmetric algorithm */
    skey->alg = buf[idx++];

    if (skey->version == PGP_SKSK_V5) {
        /* aead algorithm */
        skey->aalg = buf[idx++];
        if ((skey->aalg != PGP_AEAD_EAX) && (skey->aalg != PGP_AEAD_OCB)) {
            RNP_LOG("unsupported AEAD algorithm : %d", (int) skey->aalg);
            return RNP_ERROR_BAD_PARAMETERS;
        }
        if (len < 5) {
            return RNP_ERROR_BAD_FORMAT;
        }
        if (src_read(src, buf + 4, 1) != 1) {
            return RNP_ERROR_READ;
        }
    }

    /* s2k */
    skey->s2k.specifier = buf[idx++];
    skey->s2k.hash_alg = buf[idx++];
    len -= idx;

    switch (skey->s2k.specifier) {
    case PGP_S2KS_SIMPLE:
        break;
    case PGP_S2KS_SALTED:
    case PGP_S2KS_ITERATED_AND_SALTED:
        /* salt */
        if (len < PGP_SALT_SIZE) {
            return RNP_ERROR_BAD_FORMAT;
        }
        if (src_read(src, skey->s2k.salt, PGP_SALT_SIZE) != PGP_SALT_SIZE) {
            return RNP_ERROR_READ;
        }
        len -= PGP_SALT_SIZE;

        /* iterations */
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
        RNP_LOG("wrong s2k specifier");
        return RNP_ERROR_BAD_FORMAT;
    }

    if (skey->version == PGP_SKSK_V5) {
        /* v5: iv + esk + tag. For both EAX and OCB ivlen and taglen are 16 octets */
        ssize_t ivlen = pgp_cipher_aead_nonce_len(skey->aalg);
        ssize_t taglen = pgp_cipher_aead_tag_len(skey->aalg);
        if (len > ivlen + taglen + PGP_MAX_KEY_SIZE) {
            RNP_LOG("too long esk");
            return RNP_ERROR_BAD_FORMAT;
        }
        if (len < ivlen + taglen + 8) {
            RNP_LOG("too short esk");
            return RNP_ERROR_BAD_FORMAT;
        }

        /* iv */
        if (src_read(src, skey->iv, ivlen) != ivlen) {
            return RNP_ERROR_READ;
        }
        skey->ivlen = ivlen;

        /* key */
        read = len - ivlen;
        if (src_read(src, skey->enckey, read) != read) {
            return RNP_ERROR_READ;
        }
        skey->enckeylen = read;
    } else {
        /* v4: encrypted session key if present */
        if (len > 0) {
            if (len > PGP_MAX_KEY_SIZE + 1) {
                RNP_LOG("too long esk");
                return RNP_ERROR_BAD_FORMAT;
            }
            if (src_read(src, skey->enckey, len) != len) {
                return RNP_ERROR_READ;
            }
        }

        skey->enckeylen = len;
    }

    return RNP_SUCCESS;
}

rnp_result_t
stream_parse_pk_sesskey(pgp_source_t *src, pgp_pk_sesskey_pkt_t *pkey)
{
    ssize_t len;
    ssize_t read;
    uint8_t buf[10];
    uint8_t mpi[PGP_MPINT_SIZE];

    len = stream_read_pkt_len(src);
    if (len < 0) {
        return RNP_ERROR_READ;
    } else if (len < 10) {
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((read = src_read(src, buf, 10)) < 10) {
        return RNP_ERROR_READ;
    }

    /* version */
    if (buf[0] != PGP_PKSK_V3) {
        RNP_LOG("wrong packet version");
        return RNP_ERROR_BAD_FORMAT;
    }
    pkey->version = buf[0];

    /* key id */
    memcpy(pkey->key_id, &buf[1], 8);

    /* pk alg */
    pkey->alg = buf[9];

    len -= 10;

    /* all algos have first mpi, so let's save some code lines */
    if ((read = stream_read_mpi(src, mpi, len)) < 0) {
        return RNP_ERROR_BAD_FORMAT;
    }
    len -= read + 2;

    switch (pkey->alg) {
    case PGP_PKA_RSA:
        /* RSA m */
        pkey->params.rsa.mlen = read;
        memcpy(pkey->params.rsa.m, mpi, read);
        break;
    case PGP_PKA_ELGAMAL:
        /* ElGamal g */
        pkey->params.eg.glen = read;
        memcpy(pkey->params.eg.g, mpi, read);
        /* ElGamal m */
        if ((read = stream_read_mpi(src, pkey->params.eg.m, len)) < 0) {
            return RNP_ERROR_BAD_FORMAT;
        }
        pkey->params.eg.mlen = read;
        len -= read + 2;
        break;
    case PGP_PKA_SM2:
        /* SM2 m */
        pkey->params.sm2.mlen = read;
        memcpy(pkey->params.sm2.m, mpi, read);
        break;
    case PGP_PKA_ECDH:
        /* ECDH ephemeral point */
        pkey->params.ecdh.plen = read;
        memcpy(pkey->params.ecdh.p, mpi, read);
        /* ECDH m */
        if ((len < 1) || ((read = src_read(src, buf, 1)) < 1)) {
            return RNP_ERROR_READ;
        }
        len--;
        if ((buf[0] > ECDH_WRAPPED_KEY_SIZE) || (len < buf[0])) {
            return RNP_ERROR_BAD_FORMAT;
        }
        pkey->params.ecdh.mlen = buf[0];

        if ((read = src_read(src, pkey->params.ecdh.m, buf[0])) < buf[0]) {
            return RNP_ERROR_READ;
        }
        len -= buf[0];

        break;
    default:
        RNP_LOG("unknown pk alg %d", (int) pkey->alg);
        return RNP_ERROR_BAD_FORMAT;
    }

    if (len > 0) {
        RNP_LOG("extra %d bytes", (int) len);
        return RNP_ERROR_BAD_FORMAT;
    }

    return RNP_SUCCESS;
}

rnp_result_t
stream_parse_one_pass(pgp_source_t *src, pgp_one_pass_sig_t *onepass)
{
    ssize_t len;
    ssize_t read;
    uint8_t buf[13];

    len = stream_read_pkt_len(src);

    if (len < 0) {
        return RNP_ERROR_READ;
    } else if (len != 13) {
        read = src_skip(src, len);

        if (read == len) {
            return RNP_ERROR_BAD_FORMAT;
        } else {
            return RNP_ERROR_READ;
        }
    }

    read = src_read(src, buf, 13);
    if (read != 13) {
        return RNP_ERROR_READ;
    }

    /* vesion */
    if (buf[0] != 3) {
        RNP_LOG("wrong packet version");
        return RNP_ERROR_BAD_FORMAT;
    }
    onepass->version = buf[0];

    /* signature type */
    onepass->type = buf[1];

    /* hash algorithm */
    onepass->halg = buf[2];

    /* pk algorithm */
    onepass->palg = buf[3];

    /* key id */
    memcpy(onepass->keyid, &buf[4], PGP_KEY_ID_SIZE);

    /* nested flag */
    onepass->nested = !!buf[12];

    return RNP_SUCCESS;
}

/* parse v3-specific fields, not the whole signature */
static rnp_result_t
signature_read_v3(pgp_source_t *src, pgp_signature_t *sig, size_t len)
{
    uint8_t buf[16];

    if (len < 16) {
        RNP_LOG("wrong packet length");
        return RNP_ERROR_BAD_FORMAT;
    }

    if (src_read(src, buf, 16) != 16) {
        RNP_LOG("read failed");
        return RNP_ERROR_READ;
    }

    /* length of hashed data, 5 */
    if (buf[0] != 5) {
        RNP_LOG("wrong length of hashed data");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* hashed data */
    if ((sig->hashed_data = malloc(5)) == NULL) {
        RNP_LOG("allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    memcpy(sig->hashed_data, &buf[1], 5);
    sig->hashed_len = 5;

    /* signature type */
    sig->type = buf[1];

    /* creation time */
    sig->creation_time = read_uint32(&buf[2]);

    /* signer's key id */
    memcpy(sig->signer, &buf[6], PGP_KEY_ID_SIZE);

    /* public key algorithm */
    sig->palg = buf[14];

    /* hash algorithm */
    sig->halg = buf[15];

    return RNP_SUCCESS;
}

/* check the signature's subpacket for validity */
static bool
signature_parse_subpacket(pgp_sig_subpkt_t *subpkt)
{
    bool oklen = true;
    bool checked = true;

    switch (subpkt->type) {
    case PGP_SIG_SUBPKT_CREATION_TIME:
        if (!subpkt->hashed) {
            RNP_LOG("creation time subpacket must be hashed");
            checked = false;
        }
        if ((oklen = subpkt->len == 4)) {
            subpkt->fields.create = read_uint32(subpkt->data);
        }
        break;
    case PGP_SIG_SUBPKT_EXPIRATION_TIME:
    case PGP_SIG_SUBPKT_KEY_EXPIRY:
        if ((oklen = subpkt->len == 4)) {
            subpkt->fields.expiry = read_uint32(subpkt->data);
        }
        break;
    case PGP_SIG_SUBPKT_EXPORT_CERT:
        if ((oklen = subpkt->len == 1)) {
            subpkt->fields.exportable = subpkt->data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_TRUST:
        if ((oklen = subpkt->len == 2)) {
            subpkt->fields.trust.level = subpkt->data[0];
            subpkt->fields.trust.amount = subpkt->data[1];
        }
        break;
    case PGP_SIG_SUBPKT_REGEXP:
        subpkt->fields.regexp.str = (const char *) subpkt->data;
        subpkt->fields.regexp.len = subpkt->len;
        break;
    case PGP_SIG_SUBPKT_REVOCABLE:
        if ((oklen = subpkt->len == 1)) {
            subpkt->fields.revocable = subpkt->data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_PREFERRED_SKA:
    case PGP_SIG_SUBPKT_PREFERRED_HASH:
    case PGP_SIG_SUBPKT_PREF_COMPRESS:
    case PGP_SIG_SUBPKT_PREFERRED_AEAD:
        subpkt->fields.preferred.arr = subpkt->data;
        subpkt->fields.preferred.len = subpkt->len;
        break;
    case PGP_SIG_SUBPKT_REVOCATION_KEY:
        if ((oklen = subpkt->len == 22)) {
            subpkt->fields.revocation_key.class = subpkt->data[0];
            subpkt->fields.revocation_key.pkalg = subpkt->data[1];
            subpkt->fields.revocation_key.fp = &subpkt->data[2];
        }
        break;
    case PGP_SIG_SUBPKT_ISSUER_KEY_ID:
        if ((oklen = subpkt->len == 8)) {
            subpkt->fields.issuer = subpkt->data;
        }
        break;
    case PGP_SIG_SUBPKT_NOTATION_DATA:
        if ((oklen = subpkt->len >= 8)) {
            subpkt->fields.notation.nlen = read_uint16(&subpkt->data[4]);
            subpkt->fields.notation.vlen = read_uint16(&subpkt->data[6]);

            if (subpkt->len !=
                8 + subpkt->fields.notation.nlen + subpkt->fields.notation.vlen) {
                oklen = false;
            } else {
                subpkt->fields.notation.name = (const char *) &subpkt->data[8];
                subpkt->fields.notation.value =
                  (const char *) &subpkt->data[8 + subpkt->fields.notation.nlen];
            }
        }
        break;
    case PGP_SIG_SUBPKT_KEYSERV_PREFS:
        if ((oklen = subpkt->len >= 1)) {
            subpkt->fields.ks_prefs.no_modify = (subpkt->data[0] & 0x80) != 0;
        }
        break;
    case PGP_SIG_SUBPKT_PREF_KEYSERV:
        subpkt->fields.preferred_ks.uri = (const char *) subpkt->data;
        subpkt->fields.preferred_ks.len = subpkt->len;
        break;
    case PGP_SIG_SUBPKT_PRIMARY_USER_ID:
        if ((oklen = subpkt->len == 1)) {
            subpkt->fields.primary_uid = subpkt->data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_POLICY_URI:
        subpkt->fields.policy.uri = (const char *) subpkt->data;
        subpkt->fields.policy.len = subpkt->len;
        break;
    case PGP_SIG_SUBPKT_KEY_FLAGS:
        if ((oklen = subpkt->len >= 1)) {
            subpkt->fields.key_flags = subpkt->data[0];
        }
        break;
    case PGP_SIG_SUBPKT_SIGNERS_USER_ID:
        subpkt->fields.signer.uid = (const char *) subpkt->data;
        subpkt->fields.signer.len = subpkt->len;
        break;
    case PGP_SIG_SUBPKT_REVOCATION_REASON:
        if ((oklen = subpkt->len >= 1)) {
            subpkt->fields.revocation_reason.code = subpkt->data[0];
            subpkt->fields.revocation_reason.str = (const char *) &subpkt->data[1];
            subpkt->fields.revocation_reason.len = subpkt->len - 1;
        }
        break;
    case PGP_SIG_SUBPKT_FEATURES:
        if ((oklen = subpkt->len >= 1)) {
            subpkt->fields.features.mdc = subpkt->data[0] & 0x01;
            subpkt->fields.features.aead = subpkt->data[0] & 0x02;
            subpkt->fields.features.key_v5 = subpkt->data[0] & 0x04;
        }
        break;
    case PGP_SIG_SUBPKT_SIGNATURE_TARGET:
        if ((oklen = subpkt->len >= 18)) {
            subpkt->fields.sig_target.pkalg = subpkt->data[0];
            subpkt->fields.sig_target.halg = subpkt->data[1];
            subpkt->fields.sig_target.hash = &subpkt->data[2];
            subpkt->fields.sig_target.hlen = subpkt->len - 2;
        }
        break;
    case PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE:
        /* no special processing - we have data and len already */
        break;
    case PGP_SIG_SUBPKT_ISSUER_FPR:
        if ((oklen = subpkt->len >= 21)) {
            subpkt->fields.issuer_fp.version = subpkt->data[0];
            subpkt->fields.issuer_fp.fp = &subpkt->data[1];
            subpkt->fields.issuer_fp.len = subpkt->len - 1;
        }
        break;
    default:
        RNP_LOG("unknown subpacket : %d", (int) subpkt->type);
        return !subpkt->critical;
    }

    if (!oklen) {
        RNP_LOG("wrong len %d of subpacket type %d", (int) subpkt->len, (int) subpkt->type);
    }

    if (oklen) {
        subpkt->parsed = 1;
    }

    return oklen && checked;
}

/* parse signature subpackets */
static bool
signature_parse_subpackets(pgp_signature_t *sig, uint8_t *buf, size_t len, bool hashed)
{
    pgp_sig_subpkt_t subpkt;
    size_t           splen;
    bool             res = true;

    while (len > 0) {
        if (len < 2) {
            RNP_LOG("got single byte %d", (int) *buf);
            return false;
        }

        /* subpacket length */
        if (*buf < 192) {
            splen = *buf;
            buf++;
            len--;
        } else if (*buf < 255) {
            splen = ((buf[0] - 192) << 8) + buf[1] + 192;
            buf += 2;
            len -= 2;
        } else {
            if (len < 5) {
                RNP_LOG("got 4-byte len but only %d bytes in buffer", (int) len);
                return false;
            }
            splen = read_uint32(&buf[1]);
            buf += 5;
            len -= 5;
        }

        if (splen < 1) {
            RNP_LOG("got subpacket with 0 length, skipping");
            continue;
        }

        /* subpacket data */
        if (len < splen) {
            RNP_LOG("got subpacket len %d, while only %d bytes left", (int) splen, (int) len);
            return false;
        }

        memset(&subpkt, 0, sizeof(subpkt));

        if ((subpkt.data = malloc(splen - 1)) == NULL) {
            RNP_LOG("subpacket data allocation failed");
            return false;
        }

        subpkt.type = *buf & 0x7f;
        subpkt.critical = !!(*buf & 0x80);
        subpkt.hashed = hashed;
        subpkt.parsed = 0;
        memcpy(subpkt.data, buf + 1, splen - 1);
        subpkt.len = splen - 1;

        res = res && signature_parse_subpacket(&subpkt);

        if (!list_append(&sig->subpkts, &subpkt, sizeof(subpkt))) {
            RNP_LOG("allocation failed");
            return false;
        }

        len -= splen;
        buf += splen;
    }

    return res;
}

/* parse v4-specific fields, not the whole signature */
static rnp_result_t
signature_read_v4(pgp_source_t *src, pgp_signature_t *sig, size_t len)
{
    uint8_t  buf[5];
    uint8_t *spbuf;
    size_t   splen;

    if (len < 5) {
        RNP_LOG("wrong packet length, less then 5");
        return RNP_ERROR_BAD_FORMAT;
    }

    if (src_read(src, buf, 5) != 5) {
        RNP_LOG("read of 5 bytes failed");
        return RNP_ERROR_READ;
    }
    len -= 5;

    /* signature type */
    sig->type = buf[0];

    /* public key algorithm */
    sig->palg = buf[1];

    /* hash algorithm */
    sig->halg = buf[2];

    /* hashed subpackets length */
    splen = read_uint16(&buf[3]);

    /* hashed subpackets length + 2 bytes of length of unhashed subpackets */
    if (len < splen + 2) {
        RNP_LOG("wrong packet or hashed subpackets length");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* building hashed data */
    if ((sig->hashed_data = malloc(splen + 6)) == NULL) {
        RNP_LOG("allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    sig->hashed_data[0] = sig->version;
    memcpy(sig->hashed_data + 1, buf, 5);

    if (src_read(src, sig->hashed_data + 6, splen) != (ssize_t) splen) {
        RNP_LOG("read of hashed subpackets failed");
        return RNP_ERROR_READ;
    }
    sig->hashed_len = splen + 6;
    len -= splen;

    /* parsing hashed subpackets */
    if (!signature_parse_subpackets(sig, sig->hashed_data + 6, splen, true)) {
        RNP_LOG("failed to parse hashed subpackets");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* reading unhashed subpackets */
    if (src_read(src, buf, 2) != 2) {
        RNP_LOG("read of unhashed len failed");
        return RNP_ERROR_READ;
    }
    len -= 2;

    splen = read_uint16(buf);
    if (len < splen) {
        RNP_LOG("not enough data for unhashed subpackets");
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((spbuf = malloc(splen)) == NULL) {
        RNP_LOG("allocation of unhashed subpackets failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (src_read(src, spbuf, splen) != (ssize_t) splen) {
        RNP_LOG("read of unhashed subpackets failed");
        return RNP_ERROR_READ;
    }
    len -= splen;

    if (!signature_parse_subpackets(sig, spbuf, splen, false)) {
        RNP_LOG("failed to parse unhashed subpackets");
        free(spbuf);
        return RNP_ERROR_BAD_FORMAT;
    }

    free(spbuf);
    return RNP_SUCCESS;
}

rnp_result_t
stream_parse_signature(pgp_source_t *src, pgp_signature_t *sig)
{
    ssize_t      len;
    ssize_t      read;
    ssize_t      read2;
    uint8_t      ver;
    uint64_t     pktend;
    rnp_result_t res = RNP_SUCCESS;

    memset(sig, 0, sizeof(*sig));

    len = stream_read_pkt_len(src);

    if (len < 0) {
        return RNP_ERROR_READ;
    } else if (len < 1) {
        return RNP_ERROR_BAD_FORMAT;
    }
    pktend = src->readb + len;

    /* version */
    if ((read = src_read(src, &ver, 1)) != 1) {
        return RNP_ERROR_READ;
    }
    len--;
    sig->version = ver;

    /* parsing version-specific fields */
    if ((ver == PGP_V2) || (ver == PGP_V3)) {
        res = signature_read_v3(src, sig, len);
    } else if (ver == PGP_V4) {
        res = signature_read_v4(src, sig, len);
    } else {
        RNP_LOG("unknown signature version: %d", (int) ver);
        res = RNP_ERROR_BAD_FORMAT;
        read = 0;
    }

    /* skipping the packet and returning error */
    if (res != RNP_SUCCESS) {
        goto finish;
    }

    /* left 16 bits of the hash */
    if (pktend - src->readb < 2) {
        RNP_LOG("not enough data for hash left bits");
        goto finish;
    }

    if (src_read(src, sig->lbits, 2) != 2) {
        res = RNP_ERROR_READ;
        goto finish;
    }

    /* signature MPIs */
    switch (sig->palg) {
    case PGP_PKA_RSA:
        if ((read = stream_read_mpi(src, sig->material.rsa.s, pktend - src->readb)) < 0) {
            res = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
        sig->material.rsa.slen = read;
        break;
    case PGP_PKA_DSA:
        if (((read = stream_read_mpi(src, sig->material.dsa.r, pktend - src->readb)) < 0) ||
            ((read2 = stream_read_mpi(src, sig->material.dsa.s, pktend - src->readb)) < 0)) {
            res = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
        sig->material.dsa.rlen = read;
        sig->material.dsa.slen = read2;
        break;
    case PGP_PKA_EDDSA:
        if (sig->version < 4) {
            RNP_LOG("Warning! v3 EdDSA signature.");
        }
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        if (((read = stream_read_mpi(src, sig->material.ecc.r, pktend - src->readb)) < 0) ||
            ((read2 = stream_read_mpi(src, sig->material.ecc.s, pktend - src->readb)) < 0)) {
            res = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
        sig->material.ecc.rlen = read;
        sig->material.ecc.slen = read2;
        break;
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (((read = stream_read_mpi(src, sig->material.eg.r, pktend - src->readb)) < 0) ||
            ((read2 = stream_read_mpi(src, sig->material.eg.s, pktend - src->readb)) < 0)) {
            res = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
        sig->material.eg.rlen = read;
        sig->material.eg.slen = read2;
        break;
    default:
        RNP_LOG("Unknown pk algorithm : %d", (int) sig->palg);
        res = RNP_ERROR_BAD_FORMAT;
    }

    if (pktend > src->readb) {
        RNP_LOG("Warning! %d bytes beyond of signature.", (int) len);
    }

finish:
    /* skipping rest of the packet in case of non-read error */
    if (res != RNP_SUCCESS) {
        free_signature(sig);
        if (res != RNP_ERROR_READ) {
            src_skip(src, pktend - src->readb);
        }
    }

    return res;
}

void
free_signature(pgp_signature_t *sig)
{
    free(sig->hashed_data);
    for (list_item *sp = list_front(sig->subpkts); sp; sp = list_next(sp)) {
        free(((pgp_sig_subpkt_t *) sp)->data);
    }
    list_destroy(&sig->subpkts);
}

/* @brief Fills the hashed (signed) data part of the key packet. Must be called before
          stream_write_key() on the newly generated key
 */
static bool
key_fill_hashed_data(pgp_key_pkt_t *key)
{
    pgp_packet_body_t hbody;
    bool              res = false;

    /* we don't have a need to write v2-v3 signatures */
    if (key->version != PGP_V4) {
        RNP_LOG("unknown key version %d", (int) key->version);
        return false;
    }

    if (!init_packet_body(&hbody, 0)) {
        RNP_LOG("allocation failed");
        return false;
    }

    res = add_packet_body_byte(&hbody, key->version) &&
          add_packet_body_uint32(&hbody, key->creation_time) &&
          add_packet_body_byte(&hbody, key->alg);

    if (!res) {
        goto error;
    }

    /* Algorithm specific fields */
    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        res = add_packet_body_mpi(&hbody, key->material.rsa.n, key->material.rsa.nlen) &&
              add_packet_body_mpi(&hbody, key->material.rsa.e, key->material.rsa.elen);
        break;
    case PGP_PKA_DSA:
        res = add_packet_body_mpi(&hbody, key->material.dsa.p, key->material.dsa.plen) &&
              add_packet_body_mpi(&hbody, key->material.dsa.q, key->material.dsa.qlen) &&
              add_packet_body_mpi(&hbody, key->material.dsa.g, key->material.dsa.glen) &&
              add_packet_body_mpi(&hbody, key->material.dsa.y, key->material.dsa.ylen);
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        res = add_packet_body_mpi(&hbody, key->material.eg.p, key->material.eg.plen) &&
              add_packet_body_mpi(&hbody, key->material.eg.g, key->material.eg.glen) &&
              add_packet_body_mpi(&hbody, key->material.eg.y, key->material.eg.ylen);
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        res = add_packet_body_key_curve(&hbody, key->material.ecc.curve) &&
              add_packet_body_mpi(&hbody, key->material.ecc.p, key->material.ecc.plen);
        break;
    case PGP_PKA_ECDH: 
        res = add_packet_body_key_curve(&hbody, key->material.ecc.curve) &&
              add_packet_body_mpi(&hbody, key->material.ecc.p, key->material.ecc.plen) &&
              add_packet_body_byte(&hbody, 3) &&
              add_packet_body_byte(&hbody, 1) &&
              add_packet_body_byte(&hbody, key->material.ecdh.kdf_hash_alg) &&
              add_packet_body_byte(&hbody, key->material.ecdh.key_wrap_alg);
        break;
    default:
        RNP_LOG("unknown key algorithm: %d", (int) key->alg);
        res = false;
    }

    /* get ownership on written data on success*/
    if (res) {
        key->hashed_data = hbody.data;
        key->hashed_len = hbody.len;
        return true;
    }
error:
    free_packet_body(&hbody);
    return false;
}

bool
stream_write_key(pgp_key_pkt_t *key, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;

    if ((key->tag != PGP_PTAG_CT_PUBLIC_KEY) && (key->tag != PGP_PTAG_CT_PUBLIC_SUBKEY)) {
        RNP_LOG("wrong key tag");
        return false;
    }

    if (!key->hashed_data && !key_fill_hashed_data(key)) {
        return false;
    }

    if (!init_packet_body(&pktbody, key->tag)) {
        RNP_LOG("allocation failed");
        return false;
    }

    /* all public key data is written in hashed_data */
    res = add_packet_body(&pktbody, key->hashed_data, key->hashed_len);

    if (res) {
        stream_flush_packet_body(&pktbody, dst);
        res = dst->werr == RNP_SUCCESS;
    }

    free_packet_body(&pktbody);
    return res;
}

rnp_result_t
stream_parse_key(pgp_source_t *src, pgp_key_pkt_t *key)
{
    pgp_packet_body_t pkt;
    rnp_result_t      res;

    /* Read the packet into memory */
    if ((res = stream_read_packet_body(src, &pkt))) {
        return res;
    }

    res = RNP_ERROR_BAD_FORMAT;

    /* check the key tag */
    if ((pkt.tag != PGP_PTAG_CT_PUBLIC_KEY) && (pkt.tag != PGP_PTAG_CT_PUBLIC_SUBKEY) &&
        (pkt.tag != PGP_PTAG_CT_SECRET_KEY) && (pkt.tag != PGP_PTAG_CT_SECRET_SUBKEY)) {
        RNP_LOG("wrong key tag: %d", pkt.tag);
        goto finish;
    }

    memset(key, 0, sizeof(*key));

    /* key type, i.e. tag */
    key->tag = pkt.tag;

    /* version */
    if (!get_packet_body_byte(&pkt, (uint8_t *) &key->version) || (key->version < PGP_V2) ||
        (key->version > PGP_V4)) {
        RNP_LOG("wrong key packet version");
        goto finish;
    }

    /* creation time */
    if (!get_packet_body_uint32(&pkt, &key->creation_time)) {
        goto finish;
    }

    /* v3: validity days */
    if ((key->version < PGP_V4) && !get_packet_body_uint16(&pkt, &key->v3_days)) {
        goto finish;
    }

    /* key algorithm */
    if (!get_packet_body_byte(&pkt, (uint8_t *) &key->alg)) {
        goto finish;
    }

    /* v3 keys must be RSA-only */
    if ((key->version < PGP_V4) && (key->alg != PGP_PKA_RSA)) {
        RNP_LOG("wrong v3 pk algorithm");
        goto finish;
    }

    /* algorithm specific fields */
    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!get_packet_body_mpi(&pkt, key->material.rsa.n, &key->material.rsa.nlen) ||
            !get_packet_body_mpi(&pkt, key->material.rsa.e, &key->material.rsa.elen)) {
            goto finish;
        }
        break;
    case PGP_PKA_DSA:
        if (!get_packet_body_mpi(&pkt, key->material.dsa.p, &key->material.dsa.plen) ||
            !get_packet_body_mpi(&pkt, key->material.dsa.q, &key->material.dsa.qlen) ||
            !get_packet_body_mpi(&pkt, key->material.dsa.g, &key->material.dsa.glen) ||
            !get_packet_body_mpi(&pkt, key->material.dsa.y, &key->material.dsa.ylen)) {
            goto finish;
        }
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (!get_packet_body_mpi(&pkt, key->material.eg.p, &key->material.eg.plen) ||
            !get_packet_body_mpi(&pkt, key->material.eg.g, &key->material.eg.glen) ||
            !get_packet_body_mpi(&pkt, key->material.eg.y, &key->material.eg.ylen)) {
            goto finish;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        if (!get_packet_body_key_curve(&pkt, &key->material.ecc.curve) ||
            !get_packet_body_mpi(&pkt, key->material.ecc.p, &key->material.ecc.plen)) {
            goto finish;
        }
        break;
    case PGP_PKA_ECDH: {
        if (!get_packet_body_key_curve(&pkt, &key->material.ecdh.curve) ||
            !get_packet_body_mpi(&pkt, key->material.ecdh.p, &key->material.ecdh.plen)) {
            goto finish;
        }

        /* read KDF parameters. At the moment should be 0x03 0x01 halg ealg */
        uint8_t len;
        if (!get_packet_body_byte(&pkt, &len) || (len != 3)) {
            goto finish;
        }
        if (!get_packet_body_byte(&pkt, &len) || (len != 1)) {
            goto finish;
        }
        if (!get_packet_body_byte(&pkt, (uint8_t *) &key->material.ecdh.kdf_hash_alg) ||
            !get_packet_body_byte(&pkt, (uint8_t *) &key->material.ecdh.key_wrap_alg)) {
            goto finish;
        }
        break;
    }
    default:
        RNP_LOG("unknown key algorithm: %d", (int) key->alg);
        goto finish;
    }

    /* fill hashed data used for signatures */
    if (!(key->hashed_data = malloc(pkt.pos))) {
        RNP_LOG("allocation failed");
        res = RNP_ERROR_OUT_OF_MEMORY;
        goto finish;
    }
    memcpy(key->hashed_data, pkt.data, pkt.pos);
    key->hashed_len = pkt.pos;

    /* secret key fields if any */
    if ((key->tag == PGP_PTAG_CT_SECRET_KEY) || (key->tag == PGP_PTAG_CT_SECRET_SUBKEY)) {
        res = RNP_ERROR_NOT_IMPLEMENTED;
        goto finish;
    }

    if (pkt.pos < pkt.len) {
        RNP_LOG("extra %d bytes in key packet", (int) (pkt.len - pkt.pos));
        goto finish;
    }

    res = RNP_SUCCESS;

finish:
    free_packet_body(&pkt);
    if (res) {
        free_key_pkt(key);
    }
    return res;
}

void
free_key_pkt(pgp_key_pkt_t *key)
{
    free(key->hashed_data);
    if (key->sec_data) {
        pgp_forget(key->sec_data, key->sec_len);
        free(key->sec_data);
    }
}
