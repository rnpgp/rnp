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
#include "ctype.h"
#include "symmetric.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "list.h"
#include "packet-parse.h"
#include "crypto.h"
#include "crypto/s2k.h"
#include "utils.h"

static pgp_map_t sig_type_map[] = {
  {PGP_SIG_BINARY, "Signature of a binary document"},
  {PGP_SIG_TEXT, "Signature of a canonical text document"},
  {PGP_SIG_STANDALONE, "Standalone signature"},
  {PGP_CERT_GENERIC, "Generic certification of a User ID and Public Key packet"},
  {PGP_CERT_PERSONA, "Personal certification of a User ID and Public Key packet"},
  {PGP_CERT_CASUAL, "Casual certification of a User ID and Public Key packet"},
  {PGP_CERT_POSITIVE, "Positive certification of a User ID and Public Key packet"},
  {PGP_SIG_SUBKEY, "Subkey Binding Signature"},
  {PGP_SIG_PRIMARY, "Primary Key Binding Signature"},
  {PGP_SIG_DIRECT, "Signature directly on a key"},
  {PGP_SIG_REV_KEY, "Key revocation signature"},
  {PGP_SIG_REV_SUBKEY, "Subkey revocation signature"},
  {PGP_SIG_REV_CERT, "Certification revocation signature"},
  {PGP_SIG_TIMESTAMP, "Timestamp signature"},
  {PGP_SIG_3RD_PARTY, "Third-Party Confirmation signature"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

static pgp_map_t key_type_map[] = {
  {PGP_PTAG_CT_SECRET_KEY, "Secret key"},
  {PGP_PTAG_CT_PUBLIC_KEY, "Public key"},
  {PGP_PTAG_CT_SECRET_SUBKEY, "Secret subkey"},
  {PGP_PTAG_CT_PUBLIC_SUBKEY, "Public subkey"},
  {0x00, NULL},
};

static pgp_map_t pubkey_alg_map[] = {
  {PGP_PKA_RSA, "RSA"},
  {PGP_PKA_RSA_ENCRYPT_ONLY, "RSA (Encrypt-Only)"},
  {PGP_PKA_RSA_SIGN_ONLY, "RSA (Sign-Only)"},
  {PGP_PKA_ELGAMAL, "Elgamal (Encrypt-Only)"},
  {PGP_PKA_DSA, "DSA"},
  {PGP_PKA_ECDH, "ECDH"},
  {PGP_PKA_ECDSA, "ECDSA"},
  {PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN, "Elgamal"},
  {PGP_PKA_RESERVED_DH, "Reserved for DH (X9.42)"},
  {PGP_PKA_EDDSA, "EdDSA"},
  {PGP_PKA_SM2, "SM2"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

static pgp_map_t symm_alg_map[] = {
  {PGP_SA_PLAINTEXT, "Plaintext"},
  {PGP_SA_IDEA, "IDEA"},
  {PGP_SA_TRIPLEDES, "TripleDES"},
  {PGP_SA_CAST5, "CAST5"},
  {PGP_SA_BLOWFISH, "Blowfish"},
  {PGP_SA_AES_128, "AES-128"},
  {PGP_SA_AES_192, "AES-192"},
  {PGP_SA_AES_256, "AES-256"},
  {PGP_SA_TWOFISH, "Twofish"},
  {PGP_SA_CAMELLIA_128, "Camellia-128"},
  {PGP_SA_CAMELLIA_192, "Camellia-192"},
  {PGP_SA_CAMELLIA_256, "Camellia-256"},
  {PGP_SA_SM4, "SM4"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

static pgp_map_t compression_alg_map[] = {
  {PGP_C_NONE, "Uncompressed"},
  {PGP_C_ZIP, "ZIP"},
  {PGP_C_ZLIB, "ZLIB"},
  {PGP_C_BZIP2, "BZip2"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

static pgp_map_t aead_alg_map[] = {
  {PGP_AEAD_NONE, "None"},
  {PGP_AEAD_EAX, "EAX"},
  {PGP_AEAD_OCB, "OCB"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

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

static void
dst_print_mpi(pgp_dest_t *dst, const char *name, pgp_mpi_t *mpi, bool dumpbin)
{
    char hex[5000];
    if (!dumpbin) {
        dst_printf(dst, "%s: %d bits\n", name, (int) mpi_bits(mpi));
    } else {
        vsnprinthex(hex, sizeof(hex), mpi->mpi, mpi->len);
        dst_printf(dst, "%s: %d bits, %s\n", name, (int) mpi_bits(mpi), hex);
    }
}

static void
dst_print_palg(pgp_dest_t *dst, const char *name, pgp_pubkey_alg_t palg)
{
    const char *palg_name = pgp_str_from_map(palg, pubkey_alg_map);
    if (!name) {
        name = "public key algorithm";
    }

    dst_printf(dst, "%s: %d (%s)\n", name, (int) palg, palg_name);
}

static void
dst_print_halg(pgp_dest_t *dst, const char *name, pgp_hash_alg_t halg)
{
    const char *halg_name = pgp_show_hash_alg(halg);
    if (!name) {
        name = "hash algorithm";
    }

    dst_printf(dst, "%s: %d (%s)\n", name, (int) halg, halg_name);
}

static void
dst_print_salg(pgp_dest_t *dst, const char *name, pgp_symm_alg_t salg)
{
    const char *salg_name = pgp_str_from_map(salg, symm_alg_map);
    if (!name) {
        name = "symmetric algorithm";
    }

    dst_printf(dst, "%s: %d (%s)\n", name, (int) salg, salg_name);
}

static void
dst_print_s2k(pgp_dest_t *dst, pgp_s2k_t *s2k)
{
    char salt[32];
    dst_printf(dst, "s2k specifier: %d\n", (int) s2k->specifier);
    dst_print_halg(dst, "s2k hash algorithm", s2k->hash_alg);
    if ((s2k->specifier == PGP_S2KS_SALTED) ||
        (s2k->specifier == PGP_S2KS_ITERATED_AND_SALTED)) {
        vsnprinthex(salt, sizeof(salt), s2k->salt, PGP_SALT_SIZE);
        dst_printf(dst, "s2k salt: %s\n", salt);
    }
    if (s2k->specifier == PGP_S2KS_ITERATED_AND_SALTED) {
        int real_iter = pgp_s2k_decode_iterations(s2k->iterations);
        dst_printf(dst, "s2k iterations: %d (%d)\n", (int) s2k->iterations, real_iter);
    }
}

#define LINELEN 16

static void
dst_hexdump(pgp_dest_t *dst, const uint8_t *src, size_t length)
{
    size_t i;
    char   line[LINELEN + 1];

    for (i = 0; i < length; i++) {
        if (i % LINELEN == 0) {
            dst_printf(dst, "%.5" PRIsize "u | ", i);
        }
        dst_printf(dst, "%.02x ", (uint8_t) src[i]);
        line[i % LINELEN] = (isprint(src[i])) ? src[i] : '.';
        if (i % LINELEN == LINELEN - 1) {
            line[LINELEN] = 0x0;
            dst_printf(dst, " | %s\n", line);
        }
    }
    if (i % LINELEN != 0) {
        for (; i % LINELEN != 0; i++) {
            dst_printf(dst, "   ");
            line[i % LINELEN] = ' ';
        }
        line[LINELEN] = 0x0;
        dst_printf(dst, " | %s\n", line);
    }
}

static rnp_result_t stream_dump_packets_raw(rnp_dump_ctx_t *ctx,
                                            pgp_source_t *  src,
                                            pgp_dest_t *    dst);

static rnp_result_t
stream_dump_signature(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst)
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
    dst_printf(
      dst, "type: %d (%s)\n", (int) sig.type, pgp_str_from_map(sig.type, sig_type_map));
    if (sig.version < PGP_V4) {
        dst_printf(dst, "creation time: %d\n", (int) sig.creation_time);
        vsnprinthex(msg, sizeof(msg), sig.signer, sizeof(sig.signer));
        dst_printf(dst, "signing key id: 0x%s\n", msg);
    }
    dst_print_palg(dst, NULL, sig.palg);
    dst_printf(dst, "hash algorithm: %d (%s)\n", (int) sig.halg, pgp_show_hash_alg(sig.halg));
    vsnprinthex(msg, sizeof(msg), sig.lbits, sizeof(sig.lbits));
    dst_printf(dst, "lbits: 0x%s\n", msg);
    dst_printf(dst, "signature material:\n");
    indent_dest_increase(dst);

    switch (sig.palg) {
    case PGP_PKA_RSA:
        dst_print_mpi(dst, "rsa s", &sig.material.rsa.s, ctx->dump_mpi);
        break;
    case PGP_PKA_DSA:
        dst_print_mpi(dst, "dsa r", &sig.material.dsa.r, ctx->dump_mpi);
        dst_print_mpi(dst, "dsa s", &sig.material.dsa.s, ctx->dump_mpi);
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        dst_print_mpi(dst, "ecc r", &sig.material.ecc.r, ctx->dump_mpi);
        dst_print_mpi(dst, "ecc s", &sig.material.ecc.s, ctx->dump_mpi);
        break;
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        dst_print_mpi(dst, "eg r", &sig.material.eg.r, ctx->dump_mpi);
        dst_print_mpi(dst, "eg s", &sig.material.eg.s, ctx->dump_mpi);
        break;
    default:
        dst_printf(dst, "unknown algorithm\n");
    }
    indent_dest_decrease(dst);

    free_signature(&sig);
    indent_dest_decrease(dst);
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_key(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_key_pkt_t key;
    rnp_result_t  ret;
    char          msg[128];

    if ((ret = stream_parse_key(src, &key))) {
        return ret;
    }

    dst_printf(dst, "%s packet\n", pgp_str_from_map(key.tag, key_type_map));
    indent_dest_increase(dst);

    dst_printf(dst, "version: %d\n", (int) key.version);
    dst_printf(dst, "creation time: %d\n", (int) key.creation_time);
    if (key.version < PGP_V4) {
        dst_printf(dst, "v3 validity days: %d\n", (int) key.v3_days);
    }
    dst_print_palg(dst, NULL, key.alg);
    dst_printf(dst, "public key material:\n");
    indent_dest_increase(dst);

    switch (key.alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        dst_print_mpi(dst, "rsa n", &key.material.rsa.n, ctx->dump_mpi);
        dst_print_mpi(dst, "rsa e", &key.material.rsa.e, ctx->dump_mpi);
        break;
    case PGP_PKA_DSA:
        dst_print_mpi(dst, "dsa p", &key.material.dsa.p, ctx->dump_mpi);
        dst_print_mpi(dst, "dsa q", &key.material.dsa.q, ctx->dump_mpi);
        dst_print_mpi(dst, "dsa g", &key.material.dsa.g, ctx->dump_mpi);
        dst_print_mpi(dst, "dsa y", &key.material.dsa.y, ctx->dump_mpi);
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        dst_print_mpi(dst, "eg p", &key.material.eg.p, ctx->dump_mpi);
        dst_print_mpi(dst, "eg g", &key.material.eg.g, ctx->dump_mpi);
        dst_print_mpi(dst, "eg y", &key.material.eg.y, ctx->dump_mpi);
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2: {
        const ec_curve_desc_t *cdesc = get_curve_desc(key.material.ecc.curve);
        dst_print_mpi(dst, "ecc p", &key.material.ecc.p, ctx->dump_mpi);
        dst_printf(dst, "ecc curve: %s\n", cdesc ? cdesc->pgp_name : "unknown");
        break;
    }
    case PGP_PKA_ECDH: {
        const ec_curve_desc_t *cdesc = get_curve_desc(key.material.ecdh.curve);
        dst_print_mpi(dst, "ecdh p", &key.material.ecdh.p, ctx->dump_mpi);
        dst_printf(dst, "ecdh curve: %s\n", cdesc ? cdesc->pgp_name : "unknown");
        dst_print_halg(dst, "ecdh hash algorithm", key.material.ecdh.kdf_hash_alg);
        dst_printf(dst, "ecdh key wrap algorithm: %d\n", (int) key.material.ecdh.key_wrap_alg);
        break;
    }
    default:
        dst_printf(dst, "unknown public key algorithm\n");
    }
    indent_dest_decrease(dst);

    if (is_secret_key_pkt(key.tag)) {
        dst_printf(dst, "secret key material:\n");
        indent_dest_increase(dst);

        dst_printf(dst, "s2k usage: %d\n", (int) key.sec_protection.s2k.usage);
        if ((key.sec_protection.s2k.usage == PGP_S2KU_ENCRYPTED) ||
            (key.sec_protection.s2k.usage == PGP_S2KU_ENCRYPTED_AND_HASHED)) {
            dst_print_salg(dst, NULL, key.sec_protection.symm_alg);
            dst_print_s2k(dst, &key.sec_protection.s2k);
            size_t bl_size = pgp_block_size(key.sec_protection.symm_alg);
            if (bl_size) {
                vsnprinthex(msg, sizeof(msg), key.sec_protection.iv, bl_size);
                dst_printf(dst, "cipher iv: %s\n", msg);
            } else {
                dst_printf(dst, "cipher iv: unknown algorithm\n");
            }
            dst_printf(dst, "encrypted secret key data: %d bytes\n", (int) key.sec_len);
        }

        if (!key.sec_protection.s2k.usage) {
            dst_printf(dst, "cleartext secret key data: %d bytes\n", (int) key.sec_len);
        }
        indent_dest_decrease(dst);
    }

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
stream_dump_pk_session_key(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst)
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
    dst_print_palg(dst, NULL, pkey.alg);
    dst_printf(dst, "encrypted material:\n");
    indent_dest_increase(dst);

    switch (pkey.alg) {
    case PGP_PKA_RSA:
        dst_print_mpi(dst, "rsa m", &pkey.params.rsa.m, ctx->dump_mpi);
        break;
    case PGP_PKA_ELGAMAL:
        dst_print_mpi(dst, "eg g", &pkey.params.eg.g, ctx->dump_mpi);
        dst_print_mpi(dst, "eg m", &pkey.params.eg.m, ctx->dump_mpi);
        break;
    case PGP_PKA_SM2:
        dst_print_mpi(dst, "sm2 m", &pkey.params.sm2.m, ctx->dump_mpi);
        break;
    case PGP_PKA_ECDH:
        dst_print_mpi(dst, "ecdh p", &pkey.params.ecdh.p, ctx->dump_mpi);
        if (ctx->dump_mpi) {
            vsnprinthex(msg, sizeof(msg), pkey.params.ecdh.m, pkey.params.ecdh.mlen);
            dst_printf(dst, "ecdh m: %d bytes, %s\n", (int) pkey.params.ecdh.mlen, msg);
        } else {
            dst_printf(dst, "ecdh m: %d bytes\n", (int) pkey.params.ecdh.mlen);
        }
        break;
    default:
        dst_printf(dst, "unknown public key algorithm\n");
    }

    indent_dest_decrease(dst);
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
    dst_print_salg(dst, NULL, skey.alg);
    if (skey.version == PGP_SKSK_V5) {
        dst_printf(dst,
                   "aead algorithm: %d (%s)\n",
                   (int) skey.aalg,
                   pgp_str_from_map(skey.aalg, aead_alg_map));
    }
    dst_print_s2k(dst, &skey.s2k);
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
stream_dump_encrypted(pgp_source_t *src, pgp_dest_t *dst, int tag)
{
    switch (tag) {
    case PGP_PTAG_CT_SE_DATA:
        dst_printf(dst, "Symmetrically-encrypted data packet\n\n");
        break;
    case PGP_PTAG_CT_SE_IP_DATA:
        dst_printf(dst, "Symmetrically-encrypted integrity protected data packet\n\n");
        break;
    case PGP_PTAG_CT_AEAD_ENCRYPTED:
        dst_printf(dst, "AEAD-encrypted data packet\n\n");
        break;
    default:
        dst_printf(dst, "Unknown encrypted data packet\n\n");
        break;
    }

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
    dst_printf(dst,
               "signature type: %d (%s)\n",
               (int) onepass.type,
               pgp_str_from_map(onepass.type, sig_type_map));
    dst_print_halg(dst, NULL, onepass.halg);
    dst_print_palg(dst, NULL, onepass.palg);
    vsnprinthex(msg, sizeof(msg), onepass.keyid, sizeof(onepass.keyid));
    dst_printf(dst, "signing key id: 0x%s\n", msg);
    dst_printf(dst, "nested: %d\n", (int) onepass.nested);

    indent_dest_decrease(dst);
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_compressed(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst)
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
    dst_printf(dst,
               "compression algorithm: %d (%s)\nDecompressed contents:\n",
               (int) zalg,
               pgp_str_from_map(zalg, compression_alg_map));
    ret = stream_dump_packets_raw(ctx, &zsrc, dst);

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
stream_dump_packets_raw(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst)
{
    char         msg[1024 + PGP_MAX_HEADER_SIZE] = {0};
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

        plen = 0;
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

        if (ctx->dump_packets) {
            ssize_t rlen = plen + hlen;
            bool    part = false;

            if (!plen || (rlen > 1024 + hlen)) {
                rlen = 1024 + hlen;
                part = true;
            }

            dst_printf(dst, ":off %zu: packet contents ", off + hlen);
            rlen = src_peek(src, msg, rlen);
            if (rlen < 0) {
                dst_printf(dst, "- failed to read\n");
            } else {
                rlen -= hlen;
                if (part || ((size_t) rlen < plen)) {
                    dst_printf(dst, "(first %d bytes)\n", (int) rlen);
                } else {
                    dst_printf(dst, "(%d bytes)\n", (int) rlen);
                }
                dst_hexdump(dst, (uint8_t *) msg + hlen, rlen);
            }
            dst_printf(dst, "\n");
        }

        switch (tag) {
        case PGP_PTAG_CT_SIGNATURE:
            ret = stream_dump_signature(ctx, src, dst);
            break;
        case PGP_PTAG_CT_SECRET_KEY:
        case PGP_PTAG_CT_PUBLIC_KEY:
        case PGP_PTAG_CT_SECRET_SUBKEY:
        case PGP_PTAG_CT_PUBLIC_SUBKEY:
            ret = stream_dump_key(ctx, src, dst);
            break;
        case PGP_PTAG_CT_USER_ID:
        case PGP_PTAG_CT_USER_ATTR:
            ret = stream_dump_userid(src, dst);
            break;
        case PGP_PTAG_CT_PK_SESSION_KEY:
            ret = stream_dump_pk_session_key(ctx, src, dst);
            break;
        case PGP_PTAG_CT_SK_SESSION_KEY:
            ret = stream_dump_sk_session_key(src, dst);
            break;
        case PGP_PTAG_CT_SE_DATA:
        case PGP_PTAG_CT_SE_IP_DATA:
        case PGP_PTAG_CT_AEAD_ENCRYPTED:
            ret = stream_dump_encrypted(src, dst, tag);
            break;
        case PGP_PTAG_CT_1_PASS_SIG:
            ret = stream_dump_one_pass(src, dst);
            break;
        case PGP_PTAG_CT_COMPRESSED:
            ret = stream_dump_compressed(ctx, src, dst);
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
stream_dump_packets(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst)
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

    indent_dest_set(&wrdst, 0);

    ret = stream_dump_packets_raw(ctx, src, &wrdst);

finish:
    if (armored) {
        src_close(&armorsrc);
    }
    if (indent) {
        dst_close(&wrdst, false);
    }
    return ret;
}
