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
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#else
#include "uniwin.h"
#endif
#include <string.h>
#include <inttypes.h>
#include <rnp/rnp_def.h>
#include "types.h"
#include "crypto.h"
#include "stream-packet.h"
#include "stream-key.h"
#include <algorithm>

uint32_t
read_uint32(const uint8_t *buf)
{
    return ((uint32_t) buf[0] << 24) | ((uint32_t) buf[1] << 16) | ((uint32_t) buf[2] << 8) |
           (uint32_t) buf[3];
}

uint16_t
read_uint16(const uint8_t *buf)
{
    return ((uint16_t) buf[0] << 8) | buf[1];
}

void
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

int
stream_pkt_type(pgp_source_t *src)
{
    if (src_eof(src)) {
        return 0;
    }
    size_t hdrneed = 0;
    if (!stream_pkt_hdr_len(src, &hdrneed)) {
        return -1;
    }
    uint8_t hdr[PGP_MAX_HEADER_SIZE];
    if (!src_peek_eq(src, hdr, hdrneed)) {
        return -1;
    }
    return get_packet_type(hdr[0]);
}

bool
stream_pkt_hdr_len(pgp_source_t *src, size_t *hdrlen)
{
    uint8_t buf[2];

    if (!src_peek_eq(src, buf, 2) || !(buf[0] & PGP_PTAG_ALWAYS_SET)) {
        return false;
    }

    if (buf[0] & PGP_PTAG_NEW_FORMAT) {
        if (buf[1] < 192) {
            *hdrlen = 2;
        } else if (buf[1] < 224) {
            *hdrlen = 3;
        } else if (buf[1] < 255) {
            *hdrlen = 2;
        } else {
            *hdrlen = 6;
        }
        return true;
    }

    switch (buf[0] & PGP_PTAG_OF_LENGTH_TYPE_MASK) {
    case PGP_PTAG_OLD_LEN_1:
        *hdrlen = 2;
        return true;
    case PGP_PTAG_OLD_LEN_2:
        *hdrlen = 3;
        return true;
    case PGP_PTAG_OLD_LEN_4:
        *hdrlen = 5;
        return true;
    case PGP_PTAG_OLD_LEN_INDETERMINATE:
        *hdrlen = 1;
        return true;
    default:
        return false;
    }
}

static bool
get_pkt_len(uint8_t *hdr, size_t *pktlen)
{
    if (hdr[0] & PGP_PTAG_NEW_FORMAT) {
        // 1-byte length
        if (hdr[1] < 192) {
            *pktlen = hdr[1];
            return true;
        }
        // 2-byte length
        if (hdr[1] < 224) {
            *pktlen = ((size_t)(hdr[1] - 192) << 8) + (size_t) hdr[2] + 192;
            return true;
        }
        // partial length - we do not allow it here
        if (hdr[1] < 255) {
            return false;
        }
        // 4-byte length
        *pktlen = read_uint32(&hdr[2]);
        return true;
    }

    switch (hdr[0] & PGP_PTAG_OF_LENGTH_TYPE_MASK) {
    case PGP_PTAG_OLD_LEN_1:
        *pktlen = hdr[1];
        return true;
    case PGP_PTAG_OLD_LEN_2:
        *pktlen = read_uint16(&hdr[1]);
        return true;
    case PGP_PTAG_OLD_LEN_4:
        *pktlen = read_uint32(&hdr[1]);
        return true;
    default:
        return false;
    }
}

bool
stream_read_pkt_len(pgp_source_t *src, size_t *pktlen)
{
    uint8_t buf[6] = {};
    size_t  read = 0;

    if (!stream_pkt_hdr_len(src, &read)) {
        return false;
    }

    if (!src_read_eq(src, buf, read)) {
        return false;
    }

    return get_pkt_len(buf, pktlen);
}

bool
stream_read_partial_chunk_len(pgp_source_t *src, size_t *clen, bool *last)
{
    uint8_t hdr[5] = {};
    size_t  read = 0;

    if (!src_read(src, hdr, 1, &read)) {
        RNP_LOG("failed to read header");
        return false;
    }
    if (read < 1) {
        RNP_LOG("wrong eof");
        return false;
    }

    *last = true;
    // partial length
    if ((hdr[0] >= 224) && (hdr[0] < 255)) {
        *last = false;
        *clen = get_partial_pkt_len(hdr[0]);
        return true;
    }
    // 1-byte length
    if (hdr[0] < 192) {
        *clen = hdr[0];
        return true;
    }
    // 2-byte length
    if (hdr[0] < 224) {
        if (!src_read_eq(src, &hdr[1], 1)) {
            RNP_LOG("wrong 2-byte length");
            return false;
        }
        *clen = ((size_t)(hdr[0] - 192) << 8) + (size_t) hdr[1] + 192;
        return true;
    }
    // 4-byte length
    if (!src_read_eq(src, &hdr[1], 4)) {
        RNP_LOG("wrong 4-byte length");
        return false;
    }
    *clen = ((size_t) hdr[1] << 24) | ((size_t) hdr[2] << 16) | ((size_t) hdr[3] << 8) |
            (size_t) hdr[4];
    return true;
}

bool
stream_old_indeterminate_pkt_len(pgp_source_t *src)
{
    uint8_t ptag = 0;
    if (!src_peek_eq(src, &ptag, 1)) {
        return false;
    }
    return !(ptag & PGP_PTAG_NEW_FORMAT) &&
           ((ptag & PGP_PTAG_OF_LENGTH_TYPE_MASK) == PGP_PTAG_OLD_LEN_INDETERMINATE);
}

bool
stream_partial_pkt_len(pgp_source_t *src)
{
    uint8_t hdr[2] = {};
    if (!src_peek_eq(src, hdr, 2)) {
        return false;
    }
    return (hdr[0] & PGP_PTAG_NEW_FORMAT) && (hdr[1] >= 224) && (hdr[1] < 255);
}

size_t
get_partial_pkt_len(uint8_t blen)
{
    return 1 << (blen & 0x1f);
}

rnp_result_t
stream_peek_packet_hdr(pgp_source_t *src, pgp_packet_hdr_t *hdr)
{
    size_t hlen = 0;
    memset(hdr, 0, sizeof(*hdr));
    if (!stream_pkt_hdr_len(src, &hlen)) {
        uint8_t hdr2[2] = {0};
        if (!src_peek_eq(src, hdr2, 2)) {
            RNP_LOG("pkt header read failed");
            return RNP_ERROR_READ;
        }

        RNP_LOG("bad packet header: 0x%02x%02x", hdr2[0], hdr2[1]);
        return RNP_ERROR_BAD_FORMAT;
    }

    if (!src_peek_eq(src, hdr->hdr, hlen)) {
        RNP_LOG("failed to read pkt header");
        return RNP_ERROR_READ;
    }

    hdr->hdr_len = hlen;
    hdr->tag = (pgp_pkt_type_t) get_packet_type(hdr->hdr[0]);

    if (stream_partial_pkt_len(src)) {
        hdr->partial = true;
    } else if (stream_old_indeterminate_pkt_len(src)) {
        hdr->indeterminate = true;
    } else {
        (void) get_pkt_len(hdr->hdr, &hdr->pkt_len);
    }

    return RNP_SUCCESS;
}

static rnp_result_t
stream_read_packet_partial(pgp_source_t *src, pgp_dest_t *dst)
{
    uint8_t hdr = 0;
    if (!src_read_eq(src, &hdr, 1)) {
        return RNP_ERROR_READ;
    }

    bool   last = false;
    size_t partlen = 0;
    if (!stream_read_partial_chunk_len(src, &partlen, &last)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    uint8_t *buf = (uint8_t *) malloc(PGP_INPUT_CACHE_SIZE);
    if (!buf) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    while (partlen > 0) {
        size_t read = std::min(partlen, (size_t) PGP_INPUT_CACHE_SIZE);
        if (!src_read_eq(src, buf, read)) {
            free(buf);
            return RNP_ERROR_READ;
        }
        if (dst) {
            dst_write(dst, buf, read);
        }
        partlen -= read;
        if (partlen > 0) {
            continue;
        }
        if (last) {
            break;
        }
        if (!stream_read_partial_chunk_len(src, &partlen, &last)) {
            free(buf);
            return RNP_ERROR_BAD_FORMAT;
        }
    }
    free(buf);
    return RNP_SUCCESS;
}

rnp_result_t
stream_read_packet(pgp_source_t *src, pgp_dest_t *dst)
{
    if (stream_old_indeterminate_pkt_len(src)) {
        return dst_write_src(src, dst, PGP_MAX_OLD_LEN_INDETERMINATE_PKT_SIZE);
    }

    if (stream_partial_pkt_len(src)) {
        return stream_read_packet_partial(src, dst);
    }

    try {
        pgp_packet_body_t body(PGP_PKT_RESERVED);
        rnp_result_t      ret = body.read(*src);
        if (dst) {
            body.write(*dst, false);
        }
        return ret;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_GENERIC;
    }
}

rnp_result_t
stream_skip_packet(pgp_source_t *src)
{
    return stream_read_packet(src, NULL);
}

bool
stream_write_sk_sesskey(const pgp_sk_sesskey_t *skey, pgp_dest_t *dst)
{
    try {
        pgp_packet_body_t pktbody(PGP_PKT_SK_SESSION_KEY);
        /* version and algorithm fields */
        pktbody.add_byte(skey->version);
        pktbody.add_byte(skey->alg);
        if (skey->version == PGP_SKSK_V5) {
            pktbody.add_byte(skey->aalg);
        }
        /* S2K specifier */
        pktbody.add_byte(skey->s2k.specifier);
        pktbody.add_byte(skey->s2k.hash_alg);

        switch (skey->s2k.specifier) {
        case PGP_S2KS_SIMPLE:
            break;
        case PGP_S2KS_SALTED:
            pktbody.add(skey->s2k.salt, sizeof(skey->s2k.salt));
            break;
        case PGP_S2KS_ITERATED_AND_SALTED:
            pktbody.add(skey->s2k.salt, sizeof(skey->s2k.salt));
            pktbody.add_byte(skey->s2k.iterations);
            break;
        default:
            RNP_LOG("Unexpected s2k specifier: %d", (int) skey->s2k.specifier);
            return false;
        }
        /* v5 : iv */
        if (skey->version == PGP_SKSK_V5) {
            pktbody.add(skey->iv, skey->ivlen);
        }
        /* encrypted key and auth tag for v5 */
        if (skey->enckeylen > 0) {
            pktbody.add(skey->enckey, skey->enckeylen);
        }
        /* write packet */
        pktbody.write(*dst);
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

bool
stream_write_pk_sesskey(const pgp_pk_sesskey_t *pkey, pgp_dest_t *dst)
{
    try {
        pgp_packet_body_t pktbody(PGP_PKT_PK_SESSION_KEY);
        pktbody.add_byte(pkey->version);
        pktbody.add(pkey->key_id);
        pktbody.add_byte(pkey->alg);

        switch (pkey->alg) {
        case PGP_PKA_RSA:
        case PGP_PKA_RSA_ENCRYPT_ONLY:
            pktbody.add(pkey->material.rsa.m);
            break;
        case PGP_PKA_SM2:
            pktbody.add(pkey->material.sm2.m);
            break;
        case PGP_PKA_ECDH:
            pktbody.add(pkey->material.ecdh.p);
            pktbody.add_byte(pkey->material.ecdh.mlen);
            pktbody.add(pkey->material.ecdh.m, pkey->material.ecdh.mlen);
            break;
        case PGP_PKA_ELGAMAL:
            pktbody.add(pkey->material.eg.g);
            pktbody.add(pkey->material.eg.m);
            break;
        default:
            RNP_LOG("Unknown pk alg: %d", (int) pkey->alg);
            return false;
        }
        pktbody.write(*dst);
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

bool
stream_write_one_pass(const pgp_one_pass_sig_t *onepass, pgp_dest_t *dst)
{
    try {
        pgp_packet_body_t pktbody(PGP_PKT_ONE_PASS_SIG);
        pktbody.add_byte(onepass->version);
        pktbody.add_byte(onepass->type);
        pktbody.add_byte(onepass->halg);
        pktbody.add_byte(onepass->palg);
        pktbody.add(onepass->keyid);
        pktbody.add_byte(onepass->nested);
        pktbody.write(*dst);
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

bool
write_signature_material(pgp_signature_t &sig, const pgp_signature_material_t &material)
{
    try {
        pgp_packet_body_t pktbody(PGP_PKT_SIGNATURE);
        switch (sig.palg) {
        case PGP_PKA_RSA:
        case PGP_PKA_RSA_SIGN_ONLY:
            pktbody.add(material.rsa.s);
            break;
        case PGP_PKA_DSA:
            pktbody.add(material.dsa.r);
            pktbody.add(material.dsa.s);
            break;
        case PGP_PKA_EDDSA:
        case PGP_PKA_ECDSA:
        case PGP_PKA_SM2:
        case PGP_PKA_ECDH:
            pktbody.add(material.ecc.r);
            pktbody.add(material.ecc.s);
            break;
        case PGP_PKA_ELGAMAL: /* we support writing it but will not generate */
        case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
            pktbody.add(material.eg.r);
            pktbody.add(material.eg.s);
            break;
        default:
            RNP_LOG("Unknown pk algorithm : %d", (int) sig.palg);
            return false;
        }
        free(sig.material_buf);
        sig.material_buf = (uint8_t *) malloc(pktbody.size());
        if (!sig.material_buf) {
            RNP_LOG("allocation failed");
            return false;
        }
        memcpy(sig.material_buf, pktbody.data(), pktbody.size());
        sig.material_len = pktbody.size();
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

bool
stream_write_signature(const pgp_signature_t *sig, pgp_dest_t *dst)
{
    if ((sig->version < PGP_V2) || (sig->version > PGP_V4)) {
        RNP_LOG("don't know version %d", (int) sig->version);
        return false;
    }

    try {
        pgp_packet_body_t pktbody(PGP_PKT_SIGNATURE);

        if (sig->version < PGP_V4) {
            /* for v3 signatures hashed data includes only type + creation_time */
            pktbody.add_byte(sig->version);
            pktbody.add_byte(sig->hashed_len);
            pktbody.add(sig->hashed_data, sig->hashed_len);
            pktbody.add(sig->signer);
            pktbody.add_byte(sig->palg);
            pktbody.add_byte(sig->halg);
        } else {
            /* for v4 sig->hashed_data must contain most of signature fields */
            pktbody.add(sig->hashed_data, sig->hashed_len);
            pktbody.add_subpackets(*sig, false);
        }
        pktbody.add(sig->lbits, 2);
        /* write mpis */
        pktbody.add(sig->material_buf, sig->material_len);
        pktbody.write(*dst);
        return dst->werr == RNP_SUCCESS;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

rnp_result_t
stream_parse_marker(pgp_source_t &src)
{
    try {
        pgp_packet_body_t pkt(PGP_PKT_MARKER);
        rnp_result_t      res = pkt.read(src);
        if (res) {
            return res;
        }
        if ((pkt.size() != PGP_MARKER_LEN) ||
            memcmp(pkt.data(), PGP_MARKER_CONTENTS, PGP_MARKER_LEN)) {
            return RNP_ERROR_BAD_FORMAT;
        }
        return RNP_SUCCESS;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
}

rnp_result_t
stream_parse_pk_sesskey(pgp_source_t *src, pgp_pk_sesskey_t *pkey)
{
    try {
        pgp_packet_body_t pkt(PGP_PKT_PK_SESSION_KEY);
        rnp_result_t      res = pkt.read(*src);
        if (res) {
            return res;
        }
        /* version */
        uint8_t bt = 0;
        if (!pkt.get(bt) || (bt != PGP_PKSK_V3)) {
            RNP_LOG("wrong packet version");
            return RNP_ERROR_BAD_FORMAT;
        }
        pkey->version = bt;
        /* key id */
        if (!pkt.get(pkey->key_id)) {
            RNP_LOG("failed to get key id");
            return RNP_ERROR_BAD_FORMAT;
        }
        /* public key algorithm */
        if (!pkt.get(bt)) {
            RNP_LOG("failed to get palg");
            return RNP_ERROR_BAD_FORMAT;
        }
        pkey->alg = (pgp_pubkey_alg_t) bt;

        switch (pkey->alg) {
        case PGP_PKA_RSA:
        case PGP_PKA_RSA_ENCRYPT_ONLY:
            /* RSA m */
            if (!pkt.get(pkey->material.rsa.m)) {
                RNP_LOG("failed to get rsa m");
                return RNP_ERROR_BAD_FORMAT;
            }
            break;
        case PGP_PKA_ELGAMAL:
        case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
            /* ElGamal g, m */
            if (!pkt.get(pkey->material.eg.g) || !pkt.get(pkey->material.eg.m)) {
                RNP_LOG("failed to get elgamal mpis");
                return RNP_ERROR_BAD_FORMAT;
            }
            break;
        case PGP_PKA_SM2:
            /* SM2 m */
            if (!pkt.get(pkey->material.sm2.m)) {
                RNP_LOG("failed to get sm2 m");
                return RNP_ERROR_BAD_FORMAT;
            }
            break;
        case PGP_PKA_ECDH:
            /* ECDH ephemeral point */
            if (!pkt.get(pkey->material.ecdh.p)) {
                RNP_LOG("failed to get ecdh p");
                return RNP_ERROR_BAD_FORMAT;
            }
            /* ECDH m */
            if (!pkt.get(bt)) {
                RNP_LOG("failed to get ecdh m len");
                return RNP_ERROR_BAD_FORMAT;
            }
            if (bt > ECDH_WRAPPED_KEY_SIZE) {
                RNP_LOG("wrong ecdh m len");
                return RNP_ERROR_BAD_FORMAT;
            }
            pkey->material.ecdh.mlen = bt;
            if (!pkt.get(pkey->material.ecdh.m, bt)) {
                RNP_LOG("failed to get ecdh m len");
                return RNP_ERROR_BAD_FORMAT;
            }
            break;
        default:
            RNP_LOG("unknown pk alg %d", (int) pkey->alg);
            return RNP_ERROR_BAD_FORMAT;
        }

        if (pkt.left()) {
            RNP_LOG("extra %d bytes in pk packet", (int) pkt.left());
            return RNP_ERROR_BAD_FORMAT;
        }
        return RNP_SUCCESS;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_GENERIC;
    }
}

rnp_result_t
stream_parse_one_pass(pgp_source_t *src, pgp_one_pass_sig_t *onepass)
{
    try {
        pgp_packet_body_t pkt(PGP_PKT_ONE_PASS_SIG);
        /* Read the packet into memory */
        rnp_result_t res = pkt.read(*src);
        if (res) {
            return res;
        }

        uint8_t buf[13] = {0};
        bool    ok = (pkt.size() == 13) && pkt.get(buf, 13);
        if (!ok) {
            return RNP_ERROR_BAD_FORMAT;
        }
        /* version */
        if (buf[0] != 3) {
            RNP_LOG("wrong packet version");
            return RNP_ERROR_BAD_FORMAT;
        }
        onepass->version = buf[0];
        /* signature type */
        onepass->type = (pgp_sig_type_t) buf[1];
        /* hash algorithm */
        onepass->halg = (pgp_hash_alg_t) buf[2];
        /* pk algorithm */
        onepass->palg = (pgp_pubkey_alg_t) buf[3];
        /* key id */
        static_assert(std::tuple_size<decltype(onepass->keyid)>::value == PGP_KEY_ID_SIZE,
                      "pgp_one_pass_sig_t.keyid size mismatch");
        memcpy(onepass->keyid.data(), &buf[4], PGP_KEY_ID_SIZE);
        /* nested flag */
        onepass->nested = !!buf[12];
        return RNP_SUCCESS;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_GENERIC;
    }
}

/* parse v3-specific fields, not the whole signature */
static rnp_result_t
signature_read_v3(pgp_packet_body_t &pkt, pgp_signature_t &sig)
{
    uint8_t buf[16] = {};
    if (!pkt.get(buf, 16)) {
        RNP_LOG("cannot get enough bytes");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* length of hashed data, 5 */
    if (buf[0] != 5) {
        RNP_LOG("wrong length of hashed data");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* hashed data */
    if (!(sig.hashed_data = (uint8_t *) malloc(5))) {
        RNP_LOG("allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    memcpy(sig.hashed_data, &buf[1], 5);
    sig.hashed_len = 5;
    /* signature type */
    sig.set_type((pgp_sig_type_t) buf[1]);
    /* creation time */
    sig.creation_time = read_uint32(&buf[2]);
    /* signer's key id */
    static_assert(std::tuple_size<decltype(sig.signer)>::value == PGP_KEY_ID_SIZE,
                  "v3 signer field size mismatch");
    memcpy(sig.signer.data(), &buf[6], PGP_KEY_ID_SIZE);
    /* public key algorithm */
    sig.palg = (pgp_pubkey_alg_t) buf[14];
    /* hash algorithm */
    sig.halg = (pgp_hash_alg_t) buf[15];
    return RNP_SUCCESS;
}

static rnp_result_t stream_parse_signature_body(pgp_packet_body_t &pkt, pgp_signature_t &sig);

/* check the signature's subpacket for validity */
bool
signature_parse_subpacket(pgp_sig_subpkt_t &subpkt)
{
    bool oklen = true;
    bool checked = true;

    switch (subpkt.type) {
    case PGP_SIG_SUBPKT_CREATION_TIME:
        if (!subpkt.hashed) {
            RNP_LOG("creation time subpacket must be hashed");
            checked = false;
        }
        if ((oklen = subpkt.len == 4)) {
            subpkt.fields.create = read_uint32(subpkt.data);
        }
        break;
    case PGP_SIG_SUBPKT_EXPIRATION_TIME:
    case PGP_SIG_SUBPKT_KEY_EXPIRY:
        if ((oklen = subpkt.len == 4)) {
            subpkt.fields.expiry = read_uint32(subpkt.data);
        }
        break;
    case PGP_SIG_SUBPKT_EXPORT_CERT:
        if ((oklen = subpkt.len == 1)) {
            subpkt.fields.exportable = subpkt.data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_TRUST:
        if ((oklen = subpkt.len == 2)) {
            subpkt.fields.trust.level = subpkt.data[0];
            subpkt.fields.trust.amount = subpkt.data[1];
        }
        break;
    case PGP_SIG_SUBPKT_REGEXP:
        subpkt.fields.regexp.str = (const char *) subpkt.data;
        subpkt.fields.regexp.len = subpkt.len;
        break;
    case PGP_SIG_SUBPKT_REVOCABLE:
        if ((oklen = subpkt.len == 1)) {
            subpkt.fields.revocable = subpkt.data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_PREFERRED_SKA:
    case PGP_SIG_SUBPKT_PREFERRED_HASH:
    case PGP_SIG_SUBPKT_PREF_COMPRESS:
    case PGP_SIG_SUBPKT_PREFERRED_AEAD:
        subpkt.fields.preferred.arr = subpkt.data;
        subpkt.fields.preferred.len = subpkt.len;
        break;
    case PGP_SIG_SUBPKT_REVOCATION_KEY:
        if ((oklen = subpkt.len == 22)) {
            subpkt.fields.revocation_key.klass = subpkt.data[0];
            subpkt.fields.revocation_key.pkalg = (pgp_pubkey_alg_t) subpkt.data[1];
            subpkt.fields.revocation_key.fp = &subpkt.data[2];
        }
        break;
    case PGP_SIG_SUBPKT_ISSUER_KEY_ID:
        if ((oklen = subpkt.len == 8)) {
            subpkt.fields.issuer = subpkt.data;
        }
        break;
    case PGP_SIG_SUBPKT_NOTATION_DATA:
        if ((oklen = subpkt.len >= 8)) {
            memcpy(subpkt.fields.notation.flags, subpkt.data, 4);
            subpkt.fields.notation.nlen = read_uint16(&subpkt.data[4]);
            subpkt.fields.notation.vlen = read_uint16(&subpkt.data[6]);

            if (subpkt.len != 8 + subpkt.fields.notation.nlen + subpkt.fields.notation.vlen) {
                oklen = false;
            } else {
                subpkt.fields.notation.name = (const char *) &subpkt.data[8];
                subpkt.fields.notation.value =
                  (const char *) &subpkt.data[8 + subpkt.fields.notation.nlen];
            }
        }
        break;
    case PGP_SIG_SUBPKT_KEYSERV_PREFS:
        if ((oklen = subpkt.len >= 1)) {
            subpkt.fields.ks_prefs.no_modify = (subpkt.data[0] & 0x80) != 0;
        }
        break;
    case PGP_SIG_SUBPKT_PREF_KEYSERV:
        subpkt.fields.preferred_ks.uri = (const char *) subpkt.data;
        subpkt.fields.preferred_ks.len = subpkt.len;
        break;
    case PGP_SIG_SUBPKT_PRIMARY_USER_ID:
        if ((oklen = subpkt.len == 1)) {
            subpkt.fields.primary_uid = subpkt.data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_POLICY_URI:
        subpkt.fields.policy.uri = (const char *) subpkt.data;
        subpkt.fields.policy.len = subpkt.len;
        break;
    case PGP_SIG_SUBPKT_KEY_FLAGS:
        if ((oklen = subpkt.len >= 1)) {
            subpkt.fields.key_flags = subpkt.data[0];
        }
        break;
    case PGP_SIG_SUBPKT_SIGNERS_USER_ID:
        subpkt.fields.signer.uid = (const char *) subpkt.data;
        subpkt.fields.signer.len = subpkt.len;
        break;
    case PGP_SIG_SUBPKT_REVOCATION_REASON:
        if ((oklen = subpkt.len >= 1)) {
            subpkt.fields.revocation_reason.code = (pgp_revocation_type_t) subpkt.data[0];
            subpkt.fields.revocation_reason.str = (const char *) &subpkt.data[1];
            subpkt.fields.revocation_reason.len = subpkt.len - 1;
        }
        break;
    case PGP_SIG_SUBPKT_FEATURES:
        if ((oklen = subpkt.len >= 1)) {
            subpkt.fields.features = subpkt.data[0];
        }
        break;
    case PGP_SIG_SUBPKT_SIGNATURE_TARGET:
        if ((oklen = subpkt.len >= 18)) {
            subpkt.fields.sig_target.pkalg = (pgp_pubkey_alg_t) subpkt.data[0];
            subpkt.fields.sig_target.halg = (pgp_hash_alg_t) subpkt.data[1];
            subpkt.fields.sig_target.hash = &subpkt.data[2];
            subpkt.fields.sig_target.hlen = subpkt.len - 2;
        }
        break;
    case PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE:
        try {
            /* parse signature */
            pgp_packet_body_t pkt(subpkt.data, subpkt.len);
            pgp_signature_t   sig;
            oklen = checked = !stream_parse_signature_body(pkt, sig);
            if (checked) {
                subpkt.fields.sig = new pgp_signature_t(std::move(sig));
            }
            break;
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }
    case PGP_SIG_SUBPKT_ISSUER_FPR:
        if ((oklen = subpkt.len >= 21)) {
            subpkt.fields.issuer_fp.version = subpkt.data[0];
            subpkt.fields.issuer_fp.fp = &subpkt.data[1];
            subpkt.fields.issuer_fp.len = subpkt.len - 1;
        }
        break;
    case PGP_SIG_SUBPKT_PRIVATE_100:
    case PGP_SIG_SUBPKT_PRIVATE_101:
    case PGP_SIG_SUBPKT_PRIVATE_102:
    case PGP_SIG_SUBPKT_PRIVATE_103:
    case PGP_SIG_SUBPKT_PRIVATE_104:
    case PGP_SIG_SUBPKT_PRIVATE_105:
    case PGP_SIG_SUBPKT_PRIVATE_106:
    case PGP_SIG_SUBPKT_PRIVATE_107:
    case PGP_SIG_SUBPKT_PRIVATE_108:
    case PGP_SIG_SUBPKT_PRIVATE_109:
    case PGP_SIG_SUBPKT_PRIVATE_110:
        oklen = true;
        checked = !subpkt.critical;
        if (!checked) {
            RNP_LOG("unknown critical private subpacket %d", (int) subpkt.type);
        }
        break;
    case PGP_SIG_SUBPKT_RESERVED_1:
    case PGP_SIG_SUBPKT_RESERVED_8:
    case PGP_SIG_SUBPKT_PLACEHOLDER:
    case PGP_SIG_SUBPKT_RESERVED_13:
    case PGP_SIG_SUBPKT_RESERVED_14:
    case PGP_SIG_SUBPKT_RESERVED_15:
    case PGP_SIG_SUBPKT_RESERVED_17:
    case PGP_SIG_SUBPKT_RESERVED_18:
    case PGP_SIG_SUBPKT_RESERVED_19:
        /* do not report reserved/placeholder subpacket */
        return !subpkt.critical;
    default:
        RNP_LOG("unknown subpacket : %d", (int) subpkt.type);
        return !subpkt.critical;
    }

    if (!oklen) {
        RNP_LOG("wrong len %d of subpacket type %d", (int) subpkt.len, (int) subpkt.type);
    } else {
        subpkt.parsed = 1;
    }

    return oklen && checked;
}

/* parse signature subpackets */
static bool
signature_parse_subpackets(pgp_signature_t &sig, uint8_t *buf, size_t len, bool hashed)
{
    bool res = true;

    while (len > 0) {
        if (len < 2) {
            RNP_LOG("got single byte %d", (int) *buf);
            return false;
        }

        /* subpacket length */
        size_t splen;
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

        pgp_sig_subpkt_t subpkt;
        if (!(subpkt.data = (uint8_t *) malloc(splen - 1))) {
            RNP_LOG("subpacket data allocation failed");
            return false;
        }

        subpkt.type = (pgp_sig_subpacket_type_t)(*buf & 0x7f);
        subpkt.critical = !!(*buf & 0x80);
        subpkt.hashed = hashed;
        subpkt.parsed = 0;
        memcpy(subpkt.data, buf + 1, splen - 1);
        subpkt.len = splen - 1;

        res = res && signature_parse_subpacket(subpkt);
        try {
            sig.subpkts.emplace_back(subpkt);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }
        len -= splen;
        buf += splen;
    }

    return res;
}

/* parse v4-specific fields, not the whole signature */
static rnp_result_t
signature_read_v4(pgp_packet_body_t &pkt, pgp_signature_t &sig)
{
    uint8_t buf[5];
    if (!pkt.get(buf, 5)) {
        RNP_LOG("cannot get first 5 bytes");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* signature type */
    sig.set_type((pgp_sig_type_t) buf[0]);
    /* public key algorithm */
    sig.palg = (pgp_pubkey_alg_t) buf[1];
    /* hash algorithm */
    sig.halg = (pgp_hash_alg_t) buf[2];
    /* hashed subpackets length */
    uint16_t splen = read_uint16(&buf[3]);
    /* hashed subpackets length + 2 bytes of length of unhashed subpackets */
    if (pkt.left() < splen + 2) {
        RNP_LOG("wrong packet or hashed subpackets length");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* building hashed data */
    if (!(sig.hashed_data = (uint8_t *) malloc(splen + 6))) {
        RNP_LOG("allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    sig.hashed_data[0] = sig.version;
    memcpy(sig.hashed_data + 1, buf, 5);

    if (!pkt.get(sig.hashed_data + 6, splen)) {
        RNP_LOG("cannot get hashed subpackets data");
        return RNP_ERROR_BAD_FORMAT;
    }
    sig.hashed_len = splen + 6;
    /* parsing hashed subpackets */
    if (!signature_parse_subpackets(sig, sig.hashed_data + 6, splen, true)) {
        RNP_LOG("failed to parse hashed subpackets");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* reading unhashed subpackets */
    if (!pkt.get(splen)) {
        RNP_LOG("cannot get unhashed len");
        return RNP_ERROR_BAD_FORMAT;
    }
    if (pkt.left() < splen) {
        RNP_LOG("not enough data for unhashed subpackets");
        return RNP_ERROR_BAD_FORMAT;
    }
    uint8_t *spbuf = (uint8_t *) malloc(splen);
    if (!spbuf) {
        RNP_LOG("allocation of unhashed subpackets failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!pkt.get(spbuf, splen)) {
        RNP_LOG("read of unhashed subpackets failed");
        free(spbuf);
        return RNP_ERROR_READ;
    }
    if (!signature_parse_subpackets(sig, spbuf, splen, false)) {
        RNP_LOG("failed to parse unhashed subpackets");
        free(spbuf);
        return RNP_ERROR_BAD_FORMAT;
    }
    free(spbuf);
    return RNP_SUCCESS;
}

bool
parse_signature_material(const pgp_signature_t &sig, pgp_signature_material_t &material)
{
    try {
        pgp_packet_body_t pkt(sig.material_buf, sig.material_len);

        switch (sig.palg) {
        case PGP_PKA_RSA:
        case PGP_PKA_RSA_SIGN_ONLY:
            if (!pkt.get(material.rsa.s)) {
                return false;
            }
            break;
        case PGP_PKA_DSA:
            if (!pkt.get(material.dsa.r) || !pkt.get(material.dsa.s)) {
                return false;
            }
            break;
        case PGP_PKA_EDDSA:
            if (sig.version < PGP_V4) {
                RNP_LOG("Warning! v3 EdDSA signature.");
            }
            /* FALLTHROUGH */
        case PGP_PKA_ECDSA:
        case PGP_PKA_SM2:
        case PGP_PKA_ECDH:
            if (!pkt.get(material.ecc.r) || !pkt.get(material.ecc.s)) {
                return false;
            }
            break;
        case PGP_PKA_ELGAMAL: /* we support reading it but will not validate */
        case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
            if (!pkt.get(material.eg.r) || !pkt.get(material.eg.s)) {
                return false;
            }
            break;
        default:
            RNP_LOG("Unknown pk algorithm : %d", (int) sig.palg);
            return false;
        }

        if (pkt.left()) {
            RNP_LOG("extra %d bytes in signature packet", (int) pkt.left());
            return false;
        }
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

static rnp_result_t
stream_parse_signature_body(pgp_packet_body_t &pkt, pgp_signature_t &sig)
{
    uint8_t ver = 0;
    if (!pkt.get(ver)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    sig.version = (pgp_version_t) ver;

    /* v3 or v4 signature body */
    rnp_result_t res;
    if ((ver == PGP_V2) || (ver == PGP_V3)) {
        res = signature_read_v3(pkt, sig);
    } else if (ver == PGP_V4) {
        res = signature_read_v4(pkt, sig);
    } else {
        RNP_LOG("unknown signature version: %d", (int) ver);
        res = RNP_ERROR_BAD_FORMAT;
    }

    if (res) {
        return res;
    }

    /* left 16 bits of the hash */
    if (!pkt.get(sig.lbits, 2)) {
        RNP_LOG("not enough data for hash left bits");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* raw signature material */
    sig.material_len = pkt.left();
    if (!sig.material_len) {
        RNP_LOG("No signature material");
        return RNP_ERROR_BAD_FORMAT;
    }
    sig.material_buf = (uint8_t *) malloc(sig.material_len);
    if (!sig.material_buf) {
        RNP_LOG("Allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    /* we cannot fail here */
    if (!pkt.get(sig.material_buf, sig.material_len)) {
        return RNP_ERROR_BAD_STATE;
    }
    /* check whether it can be parsed */
    pgp_signature_material_t material = {};
    if (!parse_signature_material(sig, material)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    return RNP_SUCCESS;
}

rnp_result_t
stream_parse_signature(pgp_source_t *src, pgp_signature_t *sig)
{
    try {
        pgp_packet_body_t pkt(PGP_PKT_SIGNATURE);
        rnp_result_t      res = pkt.read(*src);
        if (res) {
            return res;
        }
        return stream_parse_signature_body(pkt, *sig);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_GENERIC;
    }
}

bool
is_key_pkt(int tag)
{
    switch (tag) {
    case PGP_PKT_PUBLIC_KEY:
    case PGP_PKT_PUBLIC_SUBKEY:
    case PGP_PKT_SECRET_KEY:
    case PGP_PKT_SECRET_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
is_subkey_pkt(int tag)
{
    return (tag == PGP_PKT_PUBLIC_SUBKEY) || (tag == PGP_PKT_SECRET_SUBKEY);
}

bool
is_primary_key_pkt(int tag)
{
    return (tag == PGP_PKT_PUBLIC_KEY) || (tag == PGP_PKT_SECRET_KEY);
}

bool
is_public_key_pkt(int tag)
{
    switch (tag) {
    case PGP_PKT_PUBLIC_KEY:
    case PGP_PKT_PUBLIC_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
is_secret_key_pkt(int tag)
{
    switch (tag) {
    case PGP_PKT_SECRET_KEY:
    case PGP_PKT_SECRET_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
is_rsa_key_alg(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return true;
    default:
        return false;
    }
}

/* @brief Fills the hashed (signed) data part of the key packet. Must be called before
          stream_write_key() on the newly generated key
 */
bool
key_fill_hashed_data(pgp_key_pkt_t *key)
{
    /* we don't have a need to write v2-v3 signatures */
    if (key->version != PGP_V4) {
        RNP_LOG("unknown key version %d", (int) key->version);
        return false;
    }

    try {
        pgp_packet_body_t hbody(PGP_PKT_RESERVED);
        hbody.add_byte(key->version);
        hbody.add_uint32(key->creation_time);
        hbody.add_byte(key->alg);
        /* Algorithm specific fields */
        switch (key->alg) {
        case PGP_PKA_RSA:
        case PGP_PKA_RSA_ENCRYPT_ONLY:
        case PGP_PKA_RSA_SIGN_ONLY:
            hbody.add(key->material.rsa.n);
            hbody.add(key->material.rsa.e);
            break;
        case PGP_PKA_DSA:
            hbody.add(key->material.dsa.p);
            hbody.add(key->material.dsa.q);
            hbody.add(key->material.dsa.g);
            hbody.add(key->material.dsa.y);
            break;
        case PGP_PKA_ELGAMAL:
        case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
            hbody.add(key->material.eg.p);
            hbody.add(key->material.eg.g);
            hbody.add(key->material.eg.y);
            break;
        case PGP_PKA_ECDSA:
        case PGP_PKA_EDDSA:
        case PGP_PKA_SM2:
            hbody.add(key->material.ec.curve);
            hbody.add(key->material.ec.p);
            break;
        case PGP_PKA_ECDH:
            hbody.add(key->material.ec.curve);
            hbody.add(key->material.ec.p);
            hbody.add_byte(3);
            hbody.add_byte(1);
            hbody.add_byte(key->material.ec.kdf_hash_alg);
            hbody.add_byte(key->material.ec.key_wrap_alg);
            break;
        default:
            RNP_LOG("unknown key algorithm: %d", (int) key->alg);
            return false;
        }

        key->hashed_data = (uint8_t *) malloc(hbody.size());
        if (!key->hashed_data) {
            RNP_LOG("allocation failed");
            return false;
        }
        memcpy(key->hashed_data, hbody.data(), hbody.size());
        key->hashed_len = hbody.size();
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

bool
stream_write_key(pgp_key_pkt_t *key, pgp_dest_t *dst)
{
    if (!is_key_pkt(key->tag)) {
        RNP_LOG("wrong key tag");
        return false;
    }

    if (!key->hashed_data && !key_fill_hashed_data(key)) {
        return false;
    }

    try {
        pgp_packet_body_t pktbody(key->tag);
        /* all public key data is written in hashed_data */
        pktbody.add(key->hashed_data, key->hashed_len);
        /* if we have public key then we do not need further processing */
        if (!is_secret_key_pkt(key->tag)) {
            pktbody.write(*dst);
            return dst->werr == RNP_SUCCESS;
        }

        /* secret key fields should be pre-populated in sec_data field */
        if ((key->sec_protection.s2k.specifier != PGP_S2KS_EXPERIMENTAL) &&
            (!key->sec_data || !key->sec_len)) {
            RNP_LOG("secret key data is not populated");
            return false;
        }
        pktbody.add_byte(key->sec_protection.s2k.usage);

        switch (key->sec_protection.s2k.usage) {
        case PGP_S2KU_NONE:
            break;
        case PGP_S2KU_ENCRYPTED_AND_HASHED:
        case PGP_S2KU_ENCRYPTED: {
            pktbody.add_byte(key->sec_protection.symm_alg);
            pktbody.add(key->sec_protection.s2k);
            if (key->sec_protection.s2k.specifier != PGP_S2KS_EXPERIMENTAL) {
                size_t blsize = pgp_block_size(key->sec_protection.symm_alg);
                if (!blsize) {
                    RNP_LOG("wrong block size");
                    return false;
                }
                pktbody.add(key->sec_protection.iv, blsize);
            }
            break;
        }
        default:
            RNP_LOG("wrong s2k usage");
            return false;
        }
        if (key->sec_len) {
            /* if key is stored on card, or exported via gpg --export-secret-subkeys, then
             * sec_data is empty */
            pktbody.add(key->sec_data, key->sec_len);
        }
        pktbody.write(*dst);
        return dst->werr == RNP_SUCCESS;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

rnp_result_t
stream_parse_key(pgp_source_t *src, pgp_key_pkt_t *retkey)
{
    /* check the key tag */
    int tag = stream_pkt_type(src);
    if (!is_key_pkt(tag)) {
        RNP_LOG("wrong key packet tag: %d", tag);
        return RNP_ERROR_BAD_FORMAT;
    }

    try {
        pgp_packet_body_t pkt((pgp_pkt_type_t) tag);
        /* Read the packet into memory */
        rnp_result_t res = pkt.read(*src);
        if (res) {
            return res;
        }
        pgp_key_pkt_t key;
        /* key type, i.e. tag */
        key.tag = (pgp_pkt_type_t) tag;
        /* version */
        uint8_t ver = 0;
        if (!pkt.get(ver) || (ver < PGP_V2) || (ver > PGP_V4)) {
            RNP_LOG("wrong key packet version");
            return RNP_ERROR_BAD_FORMAT;
        }
        key.version = (pgp_version_t) ver;
        /* creation time */
        if (!pkt.get(key.creation_time)) {
            return RNP_ERROR_BAD_FORMAT;
        }
        /* v3: validity days */
        if ((key.version < PGP_V4) && !pkt.get(key.v3_days)) {
            return RNP_ERROR_BAD_FORMAT;
        }
        /* key algorithm */
        uint8_t alg = 0;
        if (!pkt.get(alg)) {
            return RNP_ERROR_BAD_FORMAT;
        }
        key.alg = (pgp_pubkey_alg_t) alg;
        key.material.alg = (pgp_pubkey_alg_t) alg;
        /* v3 keys must be RSA-only */
        if ((key.version < PGP_V4) && !is_rsa_key_alg(key.alg)) {
            RNP_LOG("wrong v3 pk algorithm");
            return RNP_ERROR_BAD_FORMAT;
        }
        /* algorithm specific fields */
        switch (key.alg) {
        case PGP_PKA_RSA:
        case PGP_PKA_RSA_ENCRYPT_ONLY:
        case PGP_PKA_RSA_SIGN_ONLY:
            if (!pkt.get(key.material.rsa.n) || !pkt.get(key.material.rsa.e)) {
                return RNP_ERROR_BAD_FORMAT;
            }
            break;
        case PGP_PKA_DSA:
            if (!pkt.get(key.material.dsa.p) || !pkt.get(key.material.dsa.q) ||
                !pkt.get(key.material.dsa.g) || !pkt.get(key.material.dsa.y)) {
                return RNP_ERROR_BAD_FORMAT;
            }
            break;
        case PGP_PKA_ELGAMAL:
        case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
            if (!pkt.get(key.material.eg.p) || !pkt.get(key.material.eg.g) ||
                !pkt.get(key.material.eg.y)) {
                return RNP_ERROR_BAD_FORMAT;
            }
            break;
        case PGP_PKA_ECDSA:
        case PGP_PKA_EDDSA:
        case PGP_PKA_SM2:
            if (!pkt.get(key.material.ec.curve) || !pkt.get(key.material.ec.p)) {
                return RNP_ERROR_BAD_FORMAT;
            }
            break;
        case PGP_PKA_ECDH: {
            if (!pkt.get(key.material.ec.curve) || !pkt.get(key.material.ec.p)) {
                return RNP_ERROR_BAD_FORMAT;
            }
            /* read KDF parameters. At the moment should be 0x03 0x01 halg ealg */
            uint8_t len = 0, halg = 0, walg = 0;
            if (!pkt.get(len) || (len != 3)) {
                return RNP_ERROR_BAD_FORMAT;
            }
            if (!pkt.get(len) || (len != 1)) {
                return RNP_ERROR_BAD_FORMAT;
            }
            if (!pkt.get(halg) || !pkt.get(walg)) {
                return RNP_ERROR_BAD_FORMAT;
            }
            key.material.ec.kdf_hash_alg = (pgp_hash_alg_t) halg;
            key.material.ec.key_wrap_alg = (pgp_symm_alg_t) walg;
            break;
        }
        default:
            RNP_LOG("unknown key algorithm: %d", (int) key.alg);
            return RNP_ERROR_BAD_FORMAT;
        }
        /* fill hashed data used for signatures */
        if (!(key.hashed_data = (uint8_t *) malloc(pkt.size() - pkt.left()))) {
            RNP_LOG("allocation failed");
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        memcpy(key.hashed_data, pkt.data(), pkt.size() - pkt.left());
        key.hashed_len = pkt.size() - pkt.left();

        /* secret key fields if any */
        if (is_secret_key_pkt(key.tag)) {
            uint8_t usage = 0;
            if (!pkt.get(usage)) {
                RNP_LOG("failed to read key protection");
                return RNP_ERROR_BAD_FORMAT;
            }
            key.sec_protection.s2k.usage = (pgp_s2k_usage_t) usage;
            key.sec_protection.cipher_mode = PGP_CIPHER_MODE_CFB;

            switch (key.sec_protection.s2k.usage) {
            case PGP_S2KU_NONE:
                break;
            case PGP_S2KU_ENCRYPTED:
            case PGP_S2KU_ENCRYPTED_AND_HASHED: {
                /* we have s2k */
                uint8_t salg = 0;
                if (!pkt.get(salg) || !pkt.get(key.sec_protection.s2k)) {
                    RNP_LOG("failed to read key protection");
                    return RNP_ERROR_BAD_FORMAT;
                }
                key.sec_protection.symm_alg = (pgp_symm_alg_t) salg;
                break;
            }
            default:
                /* old-style: usage is symmetric algorithm identifier */
                key.sec_protection.symm_alg = (pgp_symm_alg_t) usage;
                key.sec_protection.s2k.usage = PGP_S2KU_ENCRYPTED;
                key.sec_protection.s2k.specifier = PGP_S2KS_SIMPLE;
                key.sec_protection.s2k.hash_alg = PGP_HASH_MD5;
                break;
            }

            /* iv */
            if (key.sec_protection.s2k.usage &&
                (key.sec_protection.s2k.specifier != PGP_S2KS_EXPERIMENTAL)) {
                size_t bl_size = pgp_block_size(key.sec_protection.symm_alg);
                if (!bl_size || !pkt.get(key.sec_protection.iv, bl_size)) {
                    RNP_LOG("failed to read iv");
                    return RNP_ERROR_BAD_FORMAT;
                }
            }

            /* encrypted/cleartext secret MPIs are left */
            size_t sec_len = pkt.left();
            if (!sec_len) {
                key.sec_data = NULL;
            } else {
                if (!(key.sec_data = (uint8_t *) calloc(1, sec_len))) {
                    return RNP_ERROR_OUT_OF_MEMORY;
                }
                if (!pkt.get(key.sec_data, sec_len)) {
                    return RNP_ERROR_BAD_STATE;
                }
            }
            key.sec_len = sec_len;
        }

        if (pkt.left()) {
            RNP_LOG("extra %d bytes in key packet", (int) pkt.left());
            return RNP_ERROR_BAD_FORMAT;
        }
        *retkey = std::move(key);
        return RNP_SUCCESS;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_GENERIC;
    }
}

bool
key_pkt_equal(const pgp_key_pkt_t *key1, const pgp_key_pkt_t *key2, bool pubonly)
{
    /* check tag. We allow public/secret key comparision here */
    if (pubonly) {
        if (is_subkey_pkt(key1->tag) && !is_subkey_pkt(key2->tag)) {
            return false;
        }
        if (is_key_pkt(key1->tag) && !is_key_pkt(key2->tag)) {
            return false;
        }
    } else if (key1->tag != key2->tag) {
        return false;
    }

    /* check basic fields */
    if ((key1->version != key2->version) || (key1->alg != key2->alg) ||
        (key1->creation_time != key2->creation_time)) {
        return false;
    }

    /* check key material */
    return key_material_equal(&key1->material, &key2->material);
}

bool
stream_write_userid(const pgp_userid_pkt_t *userid, pgp_dest_t *dst)
{
    if ((userid->tag != PGP_PKT_USER_ID) && (userid->tag != PGP_PKT_USER_ATTR)) {
        RNP_LOG("wrong userid tag");
        return false;
    }
    if (userid->uid_len && !userid->uid) {
        RNP_LOG("null but non-empty userid");
        return false;
    }

    try {
        pgp_packet_body_t pktbody(userid->tag);
        if (userid->uid) {
            pktbody.add(userid->uid, userid->uid_len);
        }
        pktbody.write(*dst);
        return dst->werr == RNP_SUCCESS;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

rnp_result_t
stream_parse_userid(pgp_source_t *src, pgp_userid_pkt_t *userid)
{
    /* check the tag */
    int tag = stream_pkt_type(src);
    if ((tag != PGP_PKT_USER_ID) && (tag != PGP_PKT_USER_ATTR)) {
        RNP_LOG("wrong userid tag: %d", tag);
        return RNP_ERROR_BAD_FORMAT;
    }

    try {
        pgp_packet_body_t pkt(PGP_PKT_RESERVED);
        rnp_result_t      res = pkt.read(*src);
        if (res) {
            return res;
        }

        /* userid type, i.e. tag */
        userid->tag = (pgp_pkt_type_t) tag;
        userid->uid = (uint8_t *) malloc(pkt.size());
        if (!userid->uid) {
            RNP_LOG("allocation failed");
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        memcpy(userid->uid, pkt.data(), pkt.size());
        userid->uid_len = pkt.size();
        return RNP_SUCCESS;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_GENERIC;
    }
}

pgp_packet_body_t::pgp_packet_body_t(pgp_pkt_type_t tag)
{
    data_.reserve(16);
    tag_ = tag;
    secure_ = is_secret_key_pkt(tag);
}

pgp_packet_body_t::pgp_packet_body_t(const uint8_t *data, size_t len)
{
    data_.assign(data, data + len);
    tag_ = PGP_PKT_RESERVED;
    secure_ = false;
}

pgp_packet_body_t::~pgp_packet_body_t()
{
    if (secure_) {
        pgp_forget(data_.data(), data_.size());
    }
}

uint8_t *
pgp_packet_body_t::data() noexcept
{
    return data_.data();
}

size_t
pgp_packet_body_t::size() const noexcept
{
    return data_.size();
}

size_t
pgp_packet_body_t::left() const noexcept
{
    return data_.size() - pos_;
}

bool
pgp_packet_body_t::get(uint8_t &val) noexcept
{
    if (pos_ >= data_.size()) {
        return false;
    }
    val = data_[pos_++];
    return true;
}

bool
pgp_packet_body_t::get(uint16_t &val) noexcept
{
    if (pos_ + 2 > data_.size()) {
        return false;
    }
    val = read_uint16(data_.data() + pos_);
    pos_ += 2;
    return true;
}

bool
pgp_packet_body_t::get(uint32_t &val) noexcept
{
    if (pos_ + 4 > data_.size()) {
        return false;
    }
    val = read_uint32(data_.data() + pos_);
    pos_ += 4;
    return true;
}

bool
pgp_packet_body_t::get(uint8_t *val, size_t len) noexcept
{
    if (pos_ + len > data_.size()) {
        return false;
    }
    memcpy(val, data_.data() + pos_, len);
    pos_ += len;
    return true;
}

bool
pgp_packet_body_t::get(pgp_key_id_t &val) noexcept
{
    static_assert(std::tuple_size<pgp_key_id_t>::value == PGP_KEY_ID_SIZE,
                  "pgp_key_id_t size mismatch");
    return get(val.data(), val.size());
}

bool
pgp_packet_body_t::get(pgp_mpi_t &val) noexcept
{
    uint16_t bits;
    if (!get(bits)) {
        return false;
    }
    size_t len = (bits + 7) >> 3;
    if (len > PGP_MPINT_SIZE) {
        RNP_LOG("too large mpi");
        return false;
    }
    if (!len) {
        RNP_LOG("0 mpi");
        return false;
    }
    if (!get(val.mpi, len)) {
        RNP_LOG("failed to read mpi body");
        return false;
    }
    /* check the mpi bit count */
    unsigned hbits = bits & 7 ? bits & 7 : 8;
    if ((((unsigned) val.mpi[0] >> hbits) != 0) ||
        !((unsigned) val.mpi[0] & (1U << (hbits - 1)))) {
        RNP_LOG("Warning! Wrong mpi bit count: got %" PRIu16 ", but high byte is %" PRIu8,
                bits,
                val.mpi[0]);
    }
    val.len = len;
    return true;
}

bool
pgp_packet_body_t::get(pgp_curve_t &val) noexcept
{
    uint8_t oidlen = 0;
    if (!get(oidlen)) {
        return false;
    }
    uint8_t oid[MAX_CURVE_OID_HEX_LEN] = {0};
    if (!oidlen || (oidlen == 0xff) || (oidlen > sizeof(oid))) {
        RNP_LOG("unsupported curve oid len: %" PRIu8, oidlen);
        return false;
    }
    if (!get(oid, oidlen)) {
        return false;
    }
    pgp_curve_t res = find_curve_by_OID(oid, oidlen);
    if (res == PGP_CURVE_MAX) {
        RNP_LOG("unsupported curve");
        return false;
    }
    val = res;
    return true;
}

bool
pgp_packet_body_t::get(pgp_s2k_t &s2k) noexcept
{
    uint8_t spec = 0, halg = 0;
    if (!get(spec) || !get(halg)) {
        return false;
    }
    s2k.specifier = (pgp_s2k_specifier_t) spec;
    s2k.hash_alg = (pgp_hash_alg_t) halg;

    switch (s2k.specifier) {
    case PGP_S2KS_SIMPLE:
        return true;
    case PGP_S2KS_SALTED:
        return get(s2k.salt, PGP_SALT_SIZE);
    case PGP_S2KS_ITERATED_AND_SALTED: {
        uint8_t iter = 0;
        if (!get(s2k.salt, PGP_SALT_SIZE) || !get(iter)) {
            return false;
        }
        s2k.iterations = iter;
        return true;
    }
    case PGP_S2KS_EXPERIMENTAL: {
        try {
            s2k.experimental = {data_.begin() + pos_, data_.end()};
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }
        uint8_t gnu[3] = {0};
        if (!get(gnu, 3) || memcmp(gnu, "GNU", 3)) {
            RNP_LOG("Unknown experimental s2k. Skipping.");
            pos_ = data_.size();
            s2k.gpg_ext_num = PGP_S2K_GPG_NONE;
            return true;
        }
        uint8_t ext_num = 0;
        if (!get(ext_num)) {
            return false;
        }
        if ((ext_num != PGP_S2K_GPG_NO_SECRET) && (ext_num != PGP_S2K_GPG_SMARTCARD)) {
            RNP_LOG("Unsupported gpg extension num: %" PRIu8 ", skipping", ext_num);
            pos_ = data_.size();
            s2k.gpg_ext_num = PGP_S2K_GPG_NONE;
            return true;
        }
        s2k.gpg_ext_num = (pgp_s2k_gpg_extension_t) ext_num;
        if (s2k.gpg_ext_num == PGP_S2K_GPG_NO_SECRET) {
            return true;
        }
        if (!get(s2k.gpg_serial_len)) {
            RNP_LOG("Failed to get GPG serial len");
            return false;
        }
        size_t len = s2k.gpg_serial_len;
        if (s2k.gpg_serial_len > 16) {
            RNP_LOG("Warning: gpg_serial_len is %d", (int) len);
            len = 16;
        }
        if (!get(s2k.gpg_serial, len)) {
            RNP_LOG("Failed to get GPG serial");
            return false;
        }
        return true;
    }
    default:
        RNP_LOG("unknown s2k specifier: %d", (int) s2k.specifier);
        return false;
    }
}

void
pgp_packet_body_t::add(const void *data, size_t len)
{
    data_.insert(data_.end(), (uint8_t *) data, (uint8_t *) data + len);
}

void
pgp_packet_body_t::add_byte(uint8_t bt)
{
    data_.push_back(bt);
}

void
pgp_packet_body_t::add_uint16(uint16_t val)
{
    uint8_t bytes[2];
    write_uint16(bytes, val);
    add(bytes, 2);
}

void
pgp_packet_body_t::add_uint32(uint32_t val)
{
    uint8_t bytes[4];
    STORE32BE(bytes, val);
    add(bytes, 4);
}

void
pgp_packet_body_t::add(const pgp_key_id_t &val)
{
    add(val.data(), val.size());
}

void
pgp_packet_body_t::add(const pgp_mpi_t &val)
{
    if (!val.len) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    unsigned idx = 0;
    while ((idx < val.len - 1) && (!val.mpi[idx])) {
        idx++;
    }

    unsigned bits = (val.len - idx - 1) << 3;
    unsigned hibyte = val.mpi[idx];
    while (hibyte) {
        bits++;
        hibyte = hibyte >> 1;
    }

    uint8_t hdr[2] = {(uint8_t)(bits >> 8), (uint8_t)(bits & 0xff)};
    add(hdr, 2);
    add(val.mpi + idx, val.len - idx);
}

void
pgp_packet_body_t::add_subpackets(const pgp_signature_t &sig, bool hashed)
{
    pgp_packet_body_t spbody(PGP_PKT_RESERVED);

    for (auto &subpkt : sig.subpkts) {
        if (subpkt.hashed != hashed) {
            continue;
        }

        uint8_t splen[6];
        size_t  lenlen = write_packet_len(splen, subpkt.len + 1);
        spbody.add(splen, lenlen);
        spbody.add_byte(subpkt.type | (subpkt.critical << 7));
        spbody.add(subpkt.data, subpkt.len);
    }

    if (spbody.data_.size() > 0xffff) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    add_uint16(spbody.data_.size());
    add(spbody.data_.data(), spbody.data_.size());
}

void
pgp_packet_body_t::add(const pgp_curve_t curve)
{
    const ec_curve_desc_t *desc = get_curve_desc(curve);
    if (!desc) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    add_byte((uint8_t) desc->OIDhex_len);
    add(desc->OIDhex, (uint8_t) desc->OIDhex_len);
}

void
pgp_packet_body_t::add(const pgp_s2k_t &s2k)
{
    add_byte(s2k.specifier);
    add_byte(s2k.hash_alg);

    switch (s2k.specifier) {
    case PGP_S2KS_SIMPLE:
        return;
    case PGP_S2KS_SALTED:
        add(s2k.salt, PGP_SALT_SIZE);
        return;
    case PGP_S2KS_ITERATED_AND_SALTED: {
        unsigned iter = s2k.iterations;
        if (iter > 255) {
            iter = pgp_s2k_encode_iterations(iter);
        }
        add(s2k.salt, PGP_SALT_SIZE);
        add_byte(iter);
        return;
    }
    case PGP_S2KS_EXPERIMENTAL: {
        if ((s2k.gpg_ext_num != PGP_S2K_GPG_NO_SECRET) &&
            (s2k.gpg_ext_num != PGP_S2K_GPG_SMARTCARD)) {
            RNP_LOG("Unknown experimental s2k.");
            add(s2k.experimental.data(), s2k.experimental.size());
            return;
        }
        add("GNU", 3);
        add_byte(s2k.gpg_ext_num);
        if (s2k.gpg_ext_num == PGP_S2K_GPG_SMARTCARD) {
            static_assert(sizeof(s2k.gpg_serial) == 16, "invalid gpg serial length");
            size_t slen = s2k.gpg_serial_len > 16 ? 16 : s2k.gpg_serial_len;
            add_byte(s2k.gpg_serial_len);
            add(s2k.gpg_serial, slen);
        }
        return;
    }
    default:
        RNP_LOG("unknown s2k specifier");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}

rnp_result_t
pgp_packet_body_t::read(pgp_source_t &src) noexcept
{
    /* Make sure we have enough data for packet header */
    if (!src_peek_eq(&src, hdr_, 2)) {
        return RNP_ERROR_READ;
    }

    /* Read the packet header and length */
    size_t len = 0;
    if (!stream_pkt_hdr_len(&src, &len)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    if (!src_peek_eq(&src, hdr_, len)) {
        return RNP_ERROR_READ;
    }
    hdr_len_ = len;

    int ptag = get_packet_type(hdr_[0]);
    if ((ptag < 0) || ((tag_ != PGP_PKT_RESERVED) && (tag_ != ptag))) {
        RNP_LOG("tag mismatch: %d vs %d", (int) tag_, ptag);
        return RNP_ERROR_BAD_FORMAT;
    }
    tag_ = (pgp_pkt_type_t) ptag;

    if (!stream_read_pkt_len(&src, &len)) {
        return RNP_ERROR_READ;
    }

    /* early exit for the empty packet */
    if (!len) {
        return RNP_SUCCESS;
    }

    if (len > PGP_MAX_PKT_SIZE) {
        RNP_LOG("too large packet");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* Read the packet contents */
    try {
        data_.resize(len);
    } catch (const std::exception &e) {
        RNP_LOG("malloc of %d bytes failed, %s", (int) len, e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    size_t read = 0;
    if (!src_read(&src, data_.data(), len, &read) || (read != len)) {
        RNP_LOG("read %d instead of %d", (int) read, (int) len);
        return RNP_ERROR_READ;
    }
    pos_ = 0;
    return RNP_SUCCESS;
}

void
pgp_packet_body_t::write(pgp_dest_t &dst, bool hdr) noexcept
{
    if (hdr) {
        uint8_t hdr[6] = {
          (uint8_t)(tag_ | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT), 0, 0, 0, 0, 0};
        size_t hlen = 1 + write_packet_len(&hdr[1], data_.size());
        dst_write(&dst, hdr, hlen);
    }
    dst_write(&dst, data_.data(), data_.size());
}

void
pgp_packet_body_t::mark_secure(bool secure) noexcept
{
    secure_ = secure;
}

void
pgp_sk_sesskey_t::write(pgp_dest_t &dst) const
{
    pgp_packet_body_t pktbody(PGP_PKT_SK_SESSION_KEY);
    /* version and algorithm fields */
    pktbody.add_byte(version);
    pktbody.add_byte(alg);
    if (version == PGP_SKSK_V5) {
        pktbody.add_byte(aalg);
    }
    /* S2K specifier */
    pktbody.add_byte(s2k.specifier);
    pktbody.add_byte(s2k.hash_alg);

    switch (s2k.specifier) {
    case PGP_S2KS_SIMPLE:
        break;
    case PGP_S2KS_SALTED:
        pktbody.add(s2k.salt, sizeof(s2k.salt));
        break;
    case PGP_S2KS_ITERATED_AND_SALTED:
        pktbody.add(s2k.salt, sizeof(s2k.salt));
        pktbody.add_byte(s2k.iterations);
        break;
    default:
        RNP_LOG("Unexpected s2k specifier: %d", (int) s2k.specifier);
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    /* v5 : iv */
    if (version == PGP_SKSK_V5) {
        pktbody.add(iv, ivlen);
    }
    /* encrypted key and auth tag for v5 */
    if (enckeylen) {
        pktbody.add(enckey, enckeylen);
    }
    /* write packet */
    pktbody.write(dst);
}

rnp_result_t
pgp_sk_sesskey_t::parse(pgp_source_t &src)
{
    pgp_packet_body_t pkt(PGP_PKT_SK_SESSION_KEY);
    rnp_result_t      res = pkt.read(src);
    if (res) {
        return res;
    }

    /* version */
    uint8_t bt;
    if (!pkt.get(bt) || ((bt != PGP_SKSK_V4) && (bt != PGP_SKSK_V5))) {
        RNP_LOG("wrong packet version");
        return RNP_ERROR_BAD_FORMAT;
    }
    version = bt;
    /* symmetric algorithm */
    if (!pkt.get(bt)) {
        RNP_LOG("failed to get symm alg");
        return RNP_ERROR_BAD_FORMAT;
    }
    alg = (pgp_symm_alg_t) bt;

    if (version == PGP_SKSK_V5) {
        /* aead algorithm */
        if (!pkt.get(bt)) {
            RNP_LOG("failed to get aead alg");
            return RNP_ERROR_BAD_FORMAT;
        }
        aalg = (pgp_aead_alg_t) bt;
        if ((aalg != PGP_AEAD_EAX) && (aalg != PGP_AEAD_OCB)) {
            RNP_LOG("unsupported AEAD algorithm : %d", (int) aalg);
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }

    /* s2k */
    if (!pkt.get(s2k)) {
        RNP_LOG("failed to parse s2k");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* v4 key */
    if (version == PGP_SKSK_V4) {
        /* encrypted session key if present */
        size_t keylen = pkt.left();
        if (keylen) {
            if (keylen > PGP_MAX_KEY_SIZE + 1) {
                RNP_LOG("too long esk");
                return RNP_ERROR_BAD_FORMAT;
            }
            if (!pkt.get(enckey, keylen)) {
                RNP_LOG("failed to get key");
                return RNP_ERROR_BAD_FORMAT;
            }
        }
        enckeylen = keylen;
        return RNP_SUCCESS;
    }

    /* v5: iv + esk + tag. For both EAX and OCB ivlen and taglen are 16 octets */
    size_t noncelen = pgp_cipher_aead_nonce_len(aalg);
    size_t taglen = pgp_cipher_aead_tag_len(aalg);
    size_t keylen = 0;

    if (pkt.left() > noncelen + taglen + PGP_MAX_KEY_SIZE) {
        RNP_LOG("too long esk");
        return RNP_ERROR_BAD_FORMAT;
    }
    if (pkt.left() < noncelen + taglen + 8) {
        RNP_LOG("too short esk");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* iv */
    if (!pkt.get(iv, noncelen)) {
        RNP_LOG("failed to get iv");
        return RNP_ERROR_BAD_FORMAT;
    }
    ivlen = noncelen;

    /* key */
    keylen = pkt.left();
    if (!pkt.get(enckey, keylen)) {
        RNP_LOG("failed to get key");
        return RNP_ERROR_BAD_FORMAT;
    }
    enckeylen = keylen;
    return RNP_SUCCESS;
}
