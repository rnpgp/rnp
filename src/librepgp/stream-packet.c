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
#include "signature.h"
#include "stream-packet.h"

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

    bits = ((unsigned) hdr[0] << 8) | hdr[1];
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
add_packet_body_mpi(pgp_packet_body_t *body, uint8_t *mpi, unsigned len)
{
    unsigned bits;
    unsigned idx = 0;
    unsigned hibyte;
    uint8_t  hdr[2];

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
    uint8_t buf[6];
    ssize_t len;
    ssize_t read;

    read = src_peek(src, buf, 1);
    if (read < 1) {
        return RNP_ERROR_READ;
    }

    if ((body->tag = get_packet_type(buf[0])) < 0) {
        return RNP_ERROR_BAD_FORMAT;
    }

    len = stream_read_pkt_len(src);
    if (len <= 0) {
        return RNP_ERROR_READ;
    } else if (len > PGP_MAX_PKT_SIZE) {
        return RNP_ERROR_BAD_FORMAT;
    }

    if (!(body->data = malloc(len))) {
        RNP_LOG("malloc of %d bytes failed", (int) len);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if ((read = src_read(src, body->data, read)) < len) {
        RNP_LOG("read %d instead of %d", (int) read, (int) len);
        free(body->data);
        body->data = NULL;
        return RNP_ERROR_READ;
    }

    body->allocated = len;
    body->len = len;
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

    res = add_packet_body_byte(&pktbody, skey->version) &&
          add_packet_body_byte(&pktbody, skey->alg) &&
          add_packet_body_byte(&pktbody, skey->s2k.specifier) &&
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

    if (skey->enckeylen > 0) {
        res = res && add_packet_body(&pktbody, skey->enckey, skey->enckeylen);
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
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
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
          add_packet_body_byte(&pktbody, onepass->sig_type) &&
          add_packet_body_byte(&pktbody, onepass->hash_alg) &&
          add_packet_body_byte(&pktbody, onepass->key_alg) &&
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
    return false;
}

rnp_result_t
stream_parse_sk_sesskey(pgp_source_t *src, pgp_sk_sesskey_t *skey)
{
    uint8_t buf[4];
    ssize_t len;
    ssize_t read;

    /* read packet length */
    len = stream_read_pkt_len(src);
    if (len < 0) {
        return RNP_ERROR_READ;
    } else if (len < 4) {
        return RNP_ERROR_BAD_FORMAT;
    }

    /* version + symalg + s2k type + hash alg */
    if ((read = src_read(src, buf, 4)) < 4) {
        return RNP_ERROR_READ;
    }

    /* version */
    skey->version = buf[0];
    if (skey->version != 4) {
        RNP_LOG("wrong packet version");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* symmetric algorithm */
    skey->alg = buf[1];

    /* s2k */
    skey->s2k.specifier = buf[2];
    skey->s2k.hash_alg = buf[3];
    len -= 4;

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

    /* encrypted session key if present */
    if (len > 0) {
        if (len > PGP_MAX_KEY_SIZE + 1) {
            RNP_LOG("too long esk");
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
        return RNP_ERROR_BAD_FORMAT;
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
    onepass->sig_type = buf[1];

    /* hash algorithm */
    onepass->hash_alg = buf[2];

    /* pk algorithm */
    onepass->key_alg = buf[3];

    /* key id */
    memcpy(onepass->keyid, &buf[4], PGP_KEY_ID_SIZE);

    /* nested flag */
    onepass->nested = !!buf[12];

    return RNP_SUCCESS;
}

rnp_result_t
stream_parse_signature(pgp_source_t *src, pgp_signature_t *sig)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}
