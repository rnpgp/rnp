/*
 * Copyright (c) 2018, [Ribose Inc](https://www.ribose.com).
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
#include "stream-def.h"
#include "stream-dump.h"
#include "stream-armor.h"
#include "stream-packet.h"
#include "stream-parse.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "defs.h"
#include "types.h"
#include "symmetric.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "list.h"
#include "packet-parse.h"
#include "utils.h"

typedef struct pgp_dest_indent_param_t {
    int         level;
    bool        lstart;
    pgp_dest_t *writedst;
} pgp_dest_indent_param_t;

static rnp_result_t
indent_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    pgp_dest_indent_param_t *param = dst->param;
    const char *             line = buf;
    char                     indent[4] = {' ', ' ', ' ', ' '};

    if (!len) {
        return RNP_SUCCESS;
    }

    do {
        if (param->lstart) {
            for (int i = 0; i < param->level; i++) {
                dst_write(param->writedst, indent, sizeof(indent));
            }
            param->lstart = false;
        }

        for (size_t i = 0; i < len; i++) {
            if ((line[i] == '\n') || (i == len - 1)) {
                dst_write(param->writedst, line, i + 1);
                param->lstart = line[i] == '\n';
                line += i + 1;
                len -= i + 1;
                break;
            }
        }
    } while (len > 0);

    return RNP_SUCCESS;
}

static void
indent_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_indent_param_t *param = dst->param;
    if (!param) {
        return;
    }

    free(param);
}

static rnp_result_t
init_indent_dest(pgp_dest_t *dst, pgp_dest_t *origdst)
{
    pgp_dest_indent_param_t *param;

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    dst->write = indent_dst_write;
    dst->close = indent_dst_close;
    dst->finish = NULL;
    dst->no_cache = true;
    param = dst->param;
    param->writedst = origdst;
    param->lstart = true;

    return RNP_SUCCESS;
}

static void
indent_dest_increase(pgp_dest_t *dst)
{
    pgp_dest_indent_param_t *param = dst->param;
    param->level++;
}

static void
indent_dest_decrease(pgp_dest_t *dst)
{
    pgp_dest_indent_param_t *param = dst->param;
    if (param->level > 0) {
        param->level--;
    }
}

static void
indent_dest_set(pgp_dest_t *dst, int level)
{
    pgp_dest_indent_param_t *param = dst->param;
    param->level = level;
}

static size_t
vsnprinthex(char *str, size_t slen, uint8_t *buf, size_t buflen)
{
    static const char *hexes = "0123456789abcdef";
    size_t             idx = 0;

    for (size_t i = 0; (i < buflen) && (i < (slen - 1) / 2); i++) {
        str[idx++] = hexes[buf[i] >> 4];
        str[idx++] = hexes[buf[i] & 0xf];
    }
    str[idx] = '\0';
    return buflen * 2;
}

static rnp_result_t stream_dump_packets_raw(pgp_source_t *src, pgp_dest_t *dst);

static rnp_result_t
stream_dump_signature(pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_signature_t sig;
    rnp_result_t    ret;
    char            msg[128];

    if ((ret = stream_parse_signature(src, &sig))) {
        return ret;
    }

    dst_printf(dst, "Signature packet\n");
    indent_dest_increase(dst);

    dst_printf(dst, "version: %d\n", (int) sig.version);
    dst_printf(dst, "type: %d\n", (int) sig.type);
    if (sig.version < PGP_V4) {
        dst_printf(dst, "creation time: %d\n", (int) sig.creation_time);
        vsnprinthex(msg, sizeof(msg), sig.signer, sizeof(sig.signer));
        dst_printf(dst, "signing key id: 0x%s\n", msg);
    }
    dst_printf(dst, "public key algorithm: %d\n", (int) sig.palg);
    dst_printf(dst, "hash algorithm: %d\n", (int) sig.halg);
    vsnprinthex(msg, sizeof(msg), sig.lbits, sizeof(sig.lbits));
    dst_printf(dst, "lbits: 0x%s\n", msg);

    free_signature(&sig);
    indent_dest_decrease(dst);
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_key(pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_key_pkt_t key;
    rnp_result_t  ret;
    const char *  ktype;

    if ((ret = stream_parse_key(src, &key))) {
        return ret;
    }

    switch (key.tag) {
    case PGP_PTAG_CT_SECRET_KEY:
        ktype = "Secret key";
        break;
    case PGP_PTAG_CT_PUBLIC_KEY:
        ktype = "Public key";
        break;
    case PGP_PTAG_CT_SECRET_SUBKEY:
        ktype = "Secret subkey";
        break;
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        ktype = "Public subkey";
        break;
    default:
        ktype = "Unknown key";
    }

    dst_printf(dst, "%s packet\n", ktype);
    indent_dest_increase(dst);

    dst_printf(dst, "version: %d\n", (int) key.version);
    dst_printf(dst, "creation time: %d\n", (int) key.creation_time);
    if (key.version < PGP_V4) {
        dst_printf(dst, "v3 validity days: %d\n", (int) key.v3_days);
    }
    dst_printf(dst, "public key algorithm: %d\n", (int) key.alg);

    free_key_pkt(&key);
    indent_dest_decrease(dst);
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_userid(pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_userid_pkt_t uid;
    rnp_result_t     ret;
    const char *     utype;

    if ((ret = stream_parse_userid(src, &uid))) {
        return ret;
    }

    switch (uid.tag) {
    case PGP_PTAG_CT_USER_ID:
        utype = "UserID";
        break;
    case PGP_PTAG_CT_USER_ATTR:
        utype = "UserAttr";
        break;
    default:
        utype = "Unknown user id";
    }

    dst_printf(dst, "%s packet\n", utype);
    indent_dest_increase(dst);

    switch (uid.tag) {
    case PGP_PTAG_CT_USER_ID:
        dst_printf(dst, "id: ");
        dst_write(dst, uid.uid, uid.uid_len);
        dst_printf(dst, "\n");
        break;
    case PGP_PTAG_CT_USER_ATTR:
        dst_printf(dst, "id: (%d bytes of data)\n", (int) uid.uid_len);
        break;
    default:;
    }

    free_userid_pkt(&uid);
    indent_dest_decrease(dst);
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_pk_session_key(pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_pk_sesskey_pkt_t pkey;
    rnp_result_t         ret;
    char                 msg[128];

    if ((ret = stream_parse_pk_sesskey(src, &pkey))) {
        return ret;
    }

    dst_printf(dst, "Public-key encrypted session key packet\n");
    indent_dest_increase(dst);

    dst_printf(dst, "version: %d\n", (int) pkey.version);
    vsnprinthex(msg, sizeof(msg), pkey.key_id, sizeof(pkey.key_id));
    dst_printf(dst, "key id: 0x%s\n", msg);
    dst_printf(dst, "public key algorithm: %d\n", (int) pkey.alg);

    indent_dest_decrease(dst);
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_sk_session_key(pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_sk_sesskey_t skey;
    rnp_result_t     ret;
    char             msg[128];

    if ((ret = stream_parse_sk_sesskey(src, &skey))) {
        return ret;
    }

    dst_printf(dst, "Symmetric-key encrypted session key packet\n");
    indent_dest_increase(dst);

    dst_printf(dst, "version: %d\n", (int) skey.version);
    dst_printf(dst, "symmetric algorithm: %d\n", (int) skey.alg);
    if (skey.version == PGP_SKSK_V5) {
        dst_printf(dst, "aead algorithm: %d\n", (int) skey.aalg);
    }
    dst_printf(dst, "s2k specifier: %d\n", (int) skey.s2k.specifier);
    dst_printf(dst, "s2k hash algorithm: %d\n", (int) skey.s2k.hash_alg);
    if ((skey.s2k.specifier == PGP_S2KS_SALTED) ||
        (skey.s2k.specifier == PGP_S2KS_ITERATED_AND_SALTED)) {
        vsnprinthex(msg, sizeof(msg), skey.s2k.salt, PGP_SALT_SIZE);
        dst_printf(dst, "s2k salt: %s\n", msg);
    }
    if (skey.s2k.specifier == PGP_S2KS_ITERATED_AND_SALTED) {
        dst_printf(dst, "s2k iterations: %d\n", (int) skey.s2k.iterations);
    }
    if (skey.version == PGP_SKSK_V5) {
        vsnprinthex(msg, sizeof(msg), skey.iv, skey.ivlen);
        dst_printf(dst, "aead iv: %s (%d bytes)\n", msg, (int) skey.ivlen);
    }
    vsnprinthex(msg, sizeof(msg), skey.enckey, skey.enckeylen);
    dst_printf(dst, "encrypted key: %s (%d bytes)\n", msg, (int) skey.enckeylen);

    indent_dest_decrease(dst);

    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_encrypted(pgp_source_t *src, pgp_dest_t *dst)
{
    dst_printf(dst, "Encrypted data packet\n\n");
    return stream_skip_packet(src);
}

static rnp_result_t
stream_dump_one_pass(pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_one_pass_sig_t onepass;
    rnp_result_t       ret;
    char               msg[128];

    if ((ret = stream_parse_one_pass(src, &onepass))) {
        return ret;
    }

    dst_printf(dst, "One-pass signature packet\n");
    indent_dest_increase(dst);

    dst_printf(dst, "version: %d\n", (int) onepass.version);
    dst_printf(dst, "hash algorithm: %d\n", (int) onepass.halg);
    dst_printf(dst, "public key algorithm: %d\n", (int) onepass.palg);
    vsnprinthex(msg, sizeof(msg), onepass.keyid, sizeof(onepass.keyid));
    dst_printf(dst, "signing key id: 0x%s\n", msg);
    dst_printf(dst, "nested: %d\n", (int) onepass.nested);

    indent_dest_decrease(dst);
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_compressed(pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_source_t zsrc = {0};
    uint8_t      zalg;
    rnp_result_t ret;

    if ((ret = init_compressed_src(&zsrc, src))) {
        return ret;
    }

    dst_printf(dst, "Compressed data packet\n");
    indent_dest_increase(dst);

    get_compressed_src_alg(&zsrc, &zalg);
    dst_printf(dst, "compression algorithm: %d\nDecompressed contents:\n", (int) zalg);
    ret = stream_dump_packets_raw(&zsrc, dst);

    src_close(&zsrc);
    indent_dest_decrease(dst);
    return ret;
}

static rnp_result_t
stream_dump_literal(pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_source_t      lsrc = {0};
    pgp_literal_hdr_t lhdr = {0};
    rnp_result_t      ret;
    uint8_t           readbuf[16384];

    if ((ret = init_literal_src(&lsrc, src))) {
        return ret;
    }

    dst_printf(dst, "Literal data packet\n");
    indent_dest_increase(dst);

    get_literal_src_hdr(&lsrc, &lhdr);
    dst_printf(dst, "data format: '%c'\n", lhdr.format);
    dst_printf(dst, "filename: %s (len %d)\n", lhdr.fname, lhdr.fname_len);
    dst_printf(dst, "timestamp: %u\n", (unsigned) lhdr.timestamp);

    ret = RNP_SUCCESS;
    while (!src_eof(&lsrc)) {
        if (src_read(&lsrc, readbuf, sizeof(readbuf)) < 0) {
            ret = RNP_ERROR_READ;
            break;
        }
    }

    dst_printf(dst, "data bytes: %lu\n", (unsigned long) lsrc.readb);
    src_close(&lsrc);
    indent_dest_decrease(dst);

    return ret;
}

static rnp_result_t
stream_dump_packets_raw(pgp_source_t *src, pgp_dest_t *dst)
{
    char         msg[1024] = {0};
    char         smsg[128] = {0};
    uint8_t      hdr[PGP_MAX_HEADER_SIZE];
    ssize_t      hlen;
    int          tag;
    size_t       off;
    size_t       plen;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (src_eof(src)) {
        return RNP_SUCCESS;
    }

    while (!src_eof(src)) {
        hlen = stream_pkt_hdr_len(src);
        if (hlen < 0) {
            hlen = src_peek(src, hdr, 2);
            if (hlen < 2) {
                RNP_LOG("pkt header read failed");
                ret = RNP_ERROR_READ;
                goto finish;
            }
            RNP_LOG("bad packet header: 0x%x%x", hdr[0], hdr[1]);
            ret = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }

        if (src_peek(src, hdr, hlen) != hlen) {
            RNP_LOG("failed to read pkt header");
            ret = RNP_ERROR_READ;
            goto finish;
        }

        tag = get_packet_type(hdr[0]);
        off = src->readb;

        if (stream_partial_pkt_len(src)) {
            snprintf(msg, sizeof(msg), "partial len");
        } else if (stream_intedeterminate_pkt_len(src)) {
            snprintf(msg, sizeof(msg), "indeterminate len");
        } else {
            plen = get_pkt_len(hdr);
            snprintf(msg, sizeof(msg), "len %zu", plen);
        }
        vsnprinthex(smsg, sizeof(smsg), hdr, hlen);
        dst_printf(dst, ":off %zu: packet header 0x%s (tag %d, %s)\n", off, smsg, tag, msg);

        switch (tag) {
        case PGP_PTAG_CT_SIGNATURE:
            ret = stream_dump_signature(src, dst);
            break;
        case PGP_PTAG_CT_SECRET_KEY:
        case PGP_PTAG_CT_PUBLIC_KEY:
        case PGP_PTAG_CT_SECRET_SUBKEY:
        case PGP_PTAG_CT_PUBLIC_SUBKEY:
            ret = stream_dump_key(src, dst);
            break;
        case PGP_PTAG_CT_USER_ID:
        case PGP_PTAG_CT_USER_ATTR:
            ret = stream_dump_userid(src, dst);
            break;
        case PGP_PTAG_CT_PK_SESSION_KEY:
            ret = stream_dump_pk_session_key(src, dst);
            break;
        case PGP_PTAG_CT_SK_SESSION_KEY:
            ret = stream_dump_sk_session_key(src, dst);
            break;
        case PGP_PTAG_CT_SE_DATA:
        case PGP_PTAG_CT_SE_IP_DATA:
        case PGP_PTAG_CT_AEAD_ENCRYPTED:
            ret = stream_dump_encrypted(src, dst);
            break;
        case PGP_PTAG_CT_1_PASS_SIG:
            ret = stream_dump_one_pass(src, dst);
            break;
        case PGP_PTAG_CT_COMPRESSED:
            ret = stream_dump_compressed(src, dst);
            break;
        case PGP_PTAG_CT_LITDATA:
            ret = stream_dump_literal(src, dst);
            break;
        case PGP_PTAG_CT_MARKER:
        case PGP_PTAG_CT_TRUST:
        case PGP_PTAG_CT_MDC:
        default:
            dst_printf(dst, "Unknown pkt: %d\n\n", tag);
            ret = stream_skip_packet(src);
        }

        if (ret) {
            RNP_LOG("failed to process packet");
            goto finish;
        }
    }

    ret = RNP_SUCCESS;
finish:
    return ret;
}

rnp_result_t
stream_dump_packets(pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_source_t armorsrc = {0};
    pgp_dest_t   wrdst = {0};
    bool         armored = false;
    bool         indent = false;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    /* check whether source is armored */
    if (is_armored_source(src)) {
        if (is_cleartext_source(src)) {
            RNP_LOG("cleartext signed data is not supported yet");
            ret = RNP_ERROR_NOT_IMPLEMENTED;
            goto finish;
        }
        if ((ret = init_armored_src(&armorsrc, src))) {
            RNP_LOG("failed to parse armored data");
            goto finish;
        }
        armored = true;
        src = &armorsrc;
        dst_printf(dst, ":armored input\n");
    }

    if (src_eof(src)) {
        dst_printf(dst, ":empty input\n");
        ret = RNP_SUCCESS;
        goto finish;
    }

    if ((ret = init_indent_dest(&wrdst, dst))) {
        RNP_LOG("failed to init indent dest");
        goto finish;
    }
    indent = true;

    indent_dest_set(&wrdst, armored ? 1 : 0);

    ret = stream_dump_packets_raw(src, &wrdst);

finish:
    if (armored) {
        src_close(&armorsrc);
    }
    if (indent) {
        dst_close(&wrdst, false);
    }
    return ret;
}
