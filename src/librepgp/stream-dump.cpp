/*
 * Copyright (c) 2018-2020, [Ribose Inc](https://www.ribose.com).
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
#include "time-utils.h"
#include "stream-def.h"
#include "stream-dump.h"
#include "stream-armor.h"
#include "stream-packet.h"
#include "stream-parse.h"
#include "types.h"
#include "ctype.h"
#include "crypto/symmetric.h"
#include "crypto/s2k.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "crypto.h"
#include "json-utils.h"
#include <algorithm>

static const id_str_pair packet_tag_map[] = {
  {PGP_PKT_RESERVED, "Reserved"},
  {PGP_PKT_PK_SESSION_KEY, "Public-Key Encrypted Session Key"},
  {PGP_PKT_SIGNATURE, "Signature"},
  {PGP_PKT_SK_SESSION_KEY, "Symmetric-Key Encrypted Session Key"},
  {PGP_PKT_ONE_PASS_SIG, "One-Pass Signature"},
  {PGP_PKT_SECRET_KEY, "Secret Key"},
  {PGP_PKT_PUBLIC_KEY, "Public Key"},
  {PGP_PKT_SECRET_SUBKEY, "Secret Subkey"},
  {PGP_PKT_COMPRESSED, "Compressed Data"},
  {PGP_PKT_SE_DATA, "Symmetrically Encrypted Data"},
  {PGP_PKT_MARKER, "Marker"},
  {PGP_PKT_LITDATA, "Literal Data"},
  {PGP_PKT_TRUST, "Trust"},
  {PGP_PKT_USER_ID, "User ID"},
  {PGP_PKT_PUBLIC_SUBKEY, "Public Subkey"},
  {PGP_PKT_RESERVED2, "reserved2"},
  {PGP_PKT_RESERVED3, "reserved3"},
  {PGP_PKT_USER_ATTR, "User Attribute"},
  {PGP_PKT_SE_IP_DATA, "Symmetric Encrypted and Integrity Protected Data"},
  {PGP_PKT_MDC, "Modification Detection Code"},
  {PGP_PKT_AEAD_ENCRYPTED, "AEAD Encrypted Data Packet"},
  {0x00, NULL},
};

static const id_str_pair sig_type_map[] = {
  {PGP_SIG_BINARY, "Signature of a binary document"},
  {PGP_SIG_TEXT, "Signature of a canonical text document"},
  {PGP_SIG_STANDALONE, "Standalone signature"},
  {PGP_CERT_GENERIC, "Generic User ID certification"},
  {PGP_CERT_PERSONA, "Personal User ID certification"},
  {PGP_CERT_CASUAL, "Casual User ID certification"},
  {PGP_CERT_POSITIVE, "Positive User ID certification"},
  {PGP_SIG_SUBKEY, "Subkey Binding Signature"},
  {PGP_SIG_PRIMARY, "Primary Key Binding Signature"},
  {PGP_SIG_DIRECT, "Direct-key signature"},
  {PGP_SIG_REV_KEY, "Key revocation signature"},
  {PGP_SIG_REV_SUBKEY, "Subkey revocation signature"},
  {PGP_SIG_REV_CERT, "Certification revocation signature"},
  {PGP_SIG_TIMESTAMP, "Timestamp signature"},
  {PGP_SIG_3RD_PARTY, "Third-Party Confirmation signature"},
  {0x00, NULL},
};

static const id_str_pair sig_subpkt_type_map[] = {
  {PGP_SIG_SUBPKT_CREATION_TIME, "signature creation time"},
  {PGP_SIG_SUBPKT_EXPIRATION_TIME, "signature expiration time"},
  {PGP_SIG_SUBPKT_EXPORT_CERT, "exportable certification"},
  {PGP_SIG_SUBPKT_TRUST, "trust signature"},
  {PGP_SIG_SUBPKT_REGEXP, "regular expression"},
  {PGP_SIG_SUBPKT_REVOCABLE, "revocable"},
  {PGP_SIG_SUBPKT_KEY_EXPIRY, "key expiration time"},
  {PGP_SIG_SUBPKT_PREFERRED_SKA, "preferred symmetric algorithms"},
  {PGP_SIG_SUBPKT_REVOCATION_KEY, "revocation key"},
  {PGP_SIG_SUBPKT_ISSUER_KEY_ID, "issuer key ID"},
  {PGP_SIG_SUBPKT_NOTATION_DATA, "notation data"},
  {PGP_SIG_SUBPKT_PREFERRED_HASH, "preferred hash algorithms"},
  {PGP_SIG_SUBPKT_PREF_COMPRESS, "preferred compression algorithms"},
  {PGP_SIG_SUBPKT_KEYSERV_PREFS, "key server preferences"},
  {PGP_SIG_SUBPKT_PREF_KEYSERV, "preferred key server"},
  {PGP_SIG_SUBPKT_PRIMARY_USER_ID, "primary user ID"},
  {PGP_SIG_SUBPKT_POLICY_URI, "policy URI"},
  {PGP_SIG_SUBPKT_KEY_FLAGS, "key flags"},
  {PGP_SIG_SUBPKT_SIGNERS_USER_ID, "signer's user ID"},
  {PGP_SIG_SUBPKT_REVOCATION_REASON, "reason for revocation"},
  {PGP_SIG_SUBPKT_FEATURES, "features"},
  {PGP_SIG_SUBPKT_SIGNATURE_TARGET, "signature target"},
  {PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE, "embedded signature"},
  {PGP_SIG_SUBPKT_ISSUER_FPR, "issuer fingerprint"},
  {PGP_SIG_SUBPKT_PREFERRED_AEAD, "preferred AEAD algorithms"},
  {0x00, NULL},
};

static const id_str_pair key_type_map[] = {
  {PGP_PKT_SECRET_KEY, "Secret key"},
  {PGP_PKT_PUBLIC_KEY, "Public key"},
  {PGP_PKT_SECRET_SUBKEY, "Secret subkey"},
  {PGP_PKT_PUBLIC_SUBKEY, "Public subkey"},
  {0x00, NULL},
};

static const id_str_pair pubkey_alg_map[] = {
  {PGP_PKA_RSA, "RSA (Encrypt or Sign)"},
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
  {0x00, NULL},
};

static const id_str_pair symm_alg_map[] = {
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
  {0x00, NULL},
};

static const id_str_pair hash_alg_map[] = {
  {PGP_HASH_MD5, "MD5"},
  {PGP_HASH_SHA1, "SHA1"},
  {PGP_HASH_RIPEMD, "RIPEMD160"},
  {PGP_HASH_SHA256, "SHA256"},
  {PGP_HASH_SHA384, "SHA384"},
  {PGP_HASH_SHA512, "SHA512"},
  {PGP_HASH_SHA224, "SHA224"},
  {PGP_HASH_SM3, "SM3"},
  {PGP_HASH_SHA3_256, "SHA3-256"},
  {PGP_HASH_SHA3_512, "SHA3-512"},
  {0x00, NULL},
};

static const id_str_pair z_alg_map[] = {
  {PGP_C_NONE, "Uncompressed"},
  {PGP_C_ZIP, "ZIP"},
  {PGP_C_ZLIB, "ZLib"},
  {PGP_C_BZIP2, "BZip2"},
  {0x00, NULL},
};

static const id_str_pair aead_alg_map[] = {
  {PGP_AEAD_NONE, "None"},
  {PGP_AEAD_EAX, "EAX"},
  {PGP_AEAD_OCB, "OCB"},
  {0x00, NULL},
};

static const id_str_pair revoc_reason_map[] = {
  {PGP_REVOCATION_NO_REASON, "No reason"},
  {PGP_REVOCATION_SUPERSEDED, "Superseded"},
  {PGP_REVOCATION_COMPROMISED, "Compromised"},
  {PGP_REVOCATION_RETIRED, "Retired"},
  {PGP_REVOCATION_NO_LONGER_VALID, "No longer valid"},
  {0x00, NULL},
};

typedef struct pgp_dest_indent_param_t {
    int         level;
    bool        lstart;
    pgp_dest_t *writedst;
} pgp_dest_indent_param_t;

static rnp_result_t
indent_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    pgp_dest_indent_param_t *param = (pgp_dest_indent_param_t *) dst->param;
    const char *             line = (const char *) buf;
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
    pgp_dest_indent_param_t *param = (pgp_dest_indent_param_t *) dst->param;
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
    param = (pgp_dest_indent_param_t *) dst->param;
    param->writedst = origdst;
    param->lstart = true;

    return RNP_SUCCESS;
}

static void
indent_dest_increase(pgp_dest_t *dst)
{
    pgp_dest_indent_param_t *param = (pgp_dest_indent_param_t *) dst->param;
    param->level++;
}

static void
indent_dest_decrease(pgp_dest_t *dst)
{
    pgp_dest_indent_param_t *param = (pgp_dest_indent_param_t *) dst->param;
    if (param->level > 0) {
        param->level--;
    }
}

static void
indent_dest_set(pgp_dest_t *dst, int level)
{
    pgp_dest_indent_param_t *param = (pgp_dest_indent_param_t *) dst->param;
    param->level = level;
}

static size_t
vsnprinthex(char *str, size_t slen, const uint8_t *buf, size_t buflen)
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
    const char *palg_name = id_str_pair::lookup(pubkey_alg_map, palg, "Unknown");
    if (!name) {
        name = "public key algorithm";
    }

    dst_printf(dst, "%s: %d (%s)\n", name, (int) palg, palg_name);
}

static void
dst_print_halg(pgp_dest_t *dst, const char *name, pgp_hash_alg_t halg)
{
    const char *halg_name = id_str_pair::lookup(hash_alg_map, halg, "Unknown");
    if (!name) {
        name = "hash algorithm";
    }

    dst_printf(dst, "%s: %d (%s)\n", name, (int) halg, halg_name);
}

static void
dst_print_salg(pgp_dest_t *dst, const char *name, pgp_symm_alg_t salg)
{
    const char *salg_name = id_str_pair::lookup(symm_alg_map, salg, "Unknown");
    if (!name) {
        name = "symmetric algorithm";
    }

    dst_printf(dst, "%s: %d (%s)\n", name, (int) salg, salg_name);
}

static void
dst_print_aalg(pgp_dest_t *dst, const char *name, pgp_aead_alg_t aalg)
{
    const char *aalg_name = id_str_pair::lookup(aead_alg_map, aalg, "Unknown");
    if (!name) {
        name = "aead algorithm";
    }

    dst_printf(dst, "%s: %d (%s)\n", name, (int) aalg, aalg_name);
}

static void
dst_print_zalg(pgp_dest_t *dst, const char *name, pgp_compression_type_t zalg)
{
    const char *zalg_name = id_str_pair::lookup(z_alg_map, zalg, "Unknown");
    if (!name) {
        name = "compression algorithm";
    }

    dst_printf(dst, "%s: %d (%s)\n", name, (int) zalg, zalg_name);
}

static void
dst_print_raw(pgp_dest_t *dst, const char *name, const void *data, size_t len)
{
    dst_printf(dst, "%s: ", name);
    dst_write(dst, data, len);
    dst_printf(dst, "\n");
}

static void
dst_print_algs(
  pgp_dest_t *dst, const char *name, uint8_t *algs, size_t algc, const id_str_pair map[])
{
    if (!name) {
        name = "algorithms";
    }

    dst_printf(dst, "%s: ", name);
    for (size_t i = 0; i < algc; i++) {
        dst_printf(
          dst, "%s%s", id_str_pair::lookup(map, algs[i], "Unknown"), i + 1 < algc ? ", " : "");
    }
    dst_printf(dst, " (");
    for (size_t i = 0; i < algc; i++) {
        dst_printf(dst, "%d%s", (int) algs[i], i + 1 < algc ? ", " : "");
    }
    dst_printf(dst, ")\n");
}

static void
dst_print_sig_type(pgp_dest_t *dst, const char *name, pgp_sig_type_t sigtype)
{
    const char *sig_name = id_str_pair::lookup(sig_type_map, sigtype, "Unknown");
    if (!name) {
        name = "signature type";
    }
    dst_printf(dst, "%s: %d (%s)\n", name, (int) sigtype, sig_name);
}

static void
dst_print_hex(pgp_dest_t *dst, const char *name, const uint8_t *data, size_t len, bool bytes)
{
    char hex[512];
    vsnprinthex(hex, sizeof(hex), data, len);
    if (bytes) {
        dst_printf(dst, "%s: 0x%s (%d bytes)\n", name, hex, (int) len);
    } else {
        dst_printf(dst, "%s: 0x%s\n", name, hex);
    }
}

static void
dst_print_keyid(pgp_dest_t *dst, const char *name, const pgp_key_id_t &keyid)
{
    if (!name) {
        name = "key id";
    }
    dst_print_hex(dst, name, keyid.data(), keyid.size(), false);
}

static void
dst_print_s2k(pgp_dest_t *dst, pgp_s2k_t *s2k)
{
    dst_printf(dst, "s2k specifier: %d\n", (int) s2k->specifier);
    if ((s2k->specifier == PGP_S2KS_EXPERIMENTAL) && s2k->gpg_ext_num) {
        dst_printf(dst, "GPG extension num: %d\n", (int) s2k->gpg_ext_num);
        if (s2k->gpg_ext_num == PGP_S2K_GPG_SMARTCARD) {
            static_assert(sizeof(s2k->gpg_serial) == 16, "invalid s2k->gpg_serial size");
            size_t slen = s2k->gpg_serial_len > 16 ? 16 : s2k->gpg_serial_len;
            dst_print_hex(dst, "card serial number", s2k->gpg_serial, slen, true);
        }
        return;
    }
    if (s2k->specifier == PGP_S2KS_EXPERIMENTAL) {
        dst_print_hex(dst,
                      "Unknown experimental s2k",
                      s2k->experimental.data(),
                      s2k->experimental.size(),
                      true);
        return;
    }
    dst_print_halg(dst, "s2k hash algorithm", s2k->hash_alg);
    if ((s2k->specifier == PGP_S2KS_SALTED) ||
        (s2k->specifier == PGP_S2KS_ITERATED_AND_SALTED)) {
        dst_print_hex(dst, "s2k salt", s2k->salt, PGP_SALT_SIZE, false);
    }
    if (s2k->specifier == PGP_S2KS_ITERATED_AND_SALTED) {
        size_t real_iter = pgp_s2k_decode_iterations(s2k->iterations);
        dst_printf(dst, "s2k iterations: %zu (encoded as %u)\n", real_iter, s2k->iterations);
    }
}

static void
dst_print_time(pgp_dest_t *dst, const char *name, uint32_t time)
{
    if (!name) {
        name = "time";
    }
    auto str = rnp_ctime(time).substr(0, 24);
    dst_printf(dst,
               "%s: %zu (%s%s)\n",
               name,
               (size_t) time,
               rnp_y2k38_warning(time) ? ">=" : "",
               str.c_str());
}

static void
dst_print_expiration(pgp_dest_t *dst, const char *name, uint32_t seconds)
{
    if (!name) {
        name = "expiration";
    }
    if (seconds) {
        int days = seconds / (24 * 60 * 60);
        dst_printf(dst, "%s: %zu seconds (%d days)\n", name, (size_t) seconds, days);
    } else {
        dst_printf(dst, "%s: 0 (never)\n", name);
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
            dst_printf(dst, "%.5zu | ", i);
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
static void         stream_dump_signature_pkt(rnp_dump_ctx_t * ctx,
                                              pgp_signature_t *sig,
                                              pgp_dest_t *     dst);

static void
signature_dump_subpacket(rnp_dump_ctx_t *ctx, pgp_dest_t *dst, const pgp_sig_subpkt_t &subpkt)
{
    const char *sname = id_str_pair::lookup(sig_subpkt_type_map, subpkt.type, "Unknown");

    switch (subpkt.type) {
    case PGP_SIG_SUBPKT_CREATION_TIME:
        dst_print_time(dst, sname, subpkt.fields.create);
        break;
    case PGP_SIG_SUBPKT_EXPIRATION_TIME:
        dst_print_expiration(dst, sname, subpkt.fields.expiry);
        break;
    case PGP_SIG_SUBPKT_EXPORT_CERT:
        dst_printf(dst, "%s: %d\n", sname, (int) subpkt.fields.exportable);
        break;
    case PGP_SIG_SUBPKT_TRUST:
        dst_printf(dst,
                   "%s: amount %d, level %d\n",
                   sname,
                   (int) subpkt.fields.trust.amount,
                   (int) subpkt.fields.trust.level);
        break;
    case PGP_SIG_SUBPKT_REGEXP:
        dst_print_raw(dst, sname, subpkt.fields.regexp.str, subpkt.fields.regexp.len);
        break;
    case PGP_SIG_SUBPKT_REVOCABLE:
        dst_printf(dst, "%s: %d\n", sname, (int) subpkt.fields.revocable);
        break;
    case PGP_SIG_SUBPKT_KEY_EXPIRY:
        dst_print_expiration(dst, sname, subpkt.fields.expiry);
        break;
    case PGP_SIG_SUBPKT_PREFERRED_SKA:
        dst_print_algs(dst,
                       "preferred symmetric algorithms",
                       subpkt.fields.preferred.arr,
                       subpkt.fields.preferred.len,
                       symm_alg_map);
        break;
    case PGP_SIG_SUBPKT_REVOCATION_KEY:
        dst_printf(dst, "%s\n", sname);
        dst_printf(dst, "class: %d\n", (int) subpkt.fields.revocation_key.klass);
        dst_print_palg(dst, NULL, subpkt.fields.revocation_key.pkalg);
        dst_print_hex(
          dst, "fingerprint", subpkt.fields.revocation_key.fp, PGP_FINGERPRINT_SIZE, true);
        break;
    case PGP_SIG_SUBPKT_ISSUER_KEY_ID:
        dst_print_hex(dst, sname, subpkt.fields.issuer, PGP_KEY_ID_SIZE, false);
        break;
    case PGP_SIG_SUBPKT_NOTATION_DATA: {
        std::string          name(subpkt.fields.notation.name,
                         subpkt.fields.notation.name + subpkt.fields.notation.nlen);
        std::vector<uint8_t> value(subpkt.fields.notation.value,
                                   subpkt.fields.notation.value + subpkt.fields.notation.vlen);
        if (subpkt.fields.notation.human) {
            dst_printf(dst, "%s: %s = ", sname, name.c_str());
            dst_printf(dst, "%.*s\n", (int) value.size(), (char *) value.data());
        } else {
            char hex[64];
            vsnprinthex(hex, sizeof(hex), value.data(), value.size());
            dst_printf(dst, "%s: %s = ", sname, name.c_str());
            dst_printf(dst, "0x%s (%zu bytes)\n", hex, value.size());
        }
        break;
    }
    case PGP_SIG_SUBPKT_PREFERRED_HASH:
        dst_print_algs(dst,
                       "preferred hash algorithms",
                       subpkt.fields.preferred.arr,
                       subpkt.fields.preferred.len,
                       hash_alg_map);
        break;
    case PGP_SIG_SUBPKT_PREF_COMPRESS:
        dst_print_algs(dst,
                       "preferred compression algorithms",
                       subpkt.fields.preferred.arr,
                       subpkt.fields.preferred.len,
                       z_alg_map);
        break;
    case PGP_SIG_SUBPKT_KEYSERV_PREFS:
        dst_printf(dst, "%s\n", sname);
        dst_printf(dst, "no-modify: %d\n", (int) subpkt.fields.ks_prefs.no_modify);
        break;
    case PGP_SIG_SUBPKT_PREF_KEYSERV:
        dst_print_raw(
          dst, sname, subpkt.fields.preferred_ks.uri, subpkt.fields.preferred_ks.len);
        break;
    case PGP_SIG_SUBPKT_PRIMARY_USER_ID:
        dst_printf(dst, "%s: %d\n", sname, (int) subpkt.fields.primary_uid);
        break;
    case PGP_SIG_SUBPKT_POLICY_URI:
        dst_print_raw(dst, sname, subpkt.fields.policy.uri, subpkt.fields.policy.len);
        break;
    case PGP_SIG_SUBPKT_KEY_FLAGS: {
        uint8_t flg = subpkt.fields.key_flags;
        dst_printf(dst, "%s: 0x%02x ( ", sname, flg);
        dst_printf(dst, "%s", flg ? "" : "none");
        dst_printf(dst, "%s", flg & PGP_KF_CERTIFY ? "certify " : "");
        dst_printf(dst, "%s", flg & PGP_KF_SIGN ? "sign " : "");
        dst_printf(dst, "%s", flg & PGP_KF_ENCRYPT_COMMS ? "encrypt_comm " : "");
        dst_printf(dst, "%s", flg & PGP_KF_ENCRYPT_STORAGE ? "encrypt_storage " : "");
        dst_printf(dst, "%s", flg & PGP_KF_SPLIT ? "split " : "");
        dst_printf(dst, "%s", flg & PGP_KF_AUTH ? "auth " : "");
        dst_printf(dst, "%s", flg & PGP_KF_SHARED ? "shared " : "");
        dst_printf(dst, ")\n");
        break;
    }
    case PGP_SIG_SUBPKT_SIGNERS_USER_ID:
        dst_print_raw(dst, sname, subpkt.fields.signer.uid, subpkt.fields.signer.len);
        break;
    case PGP_SIG_SUBPKT_REVOCATION_REASON: {
        int         code = subpkt.fields.revocation_reason.code;
        const char *reason = id_str_pair::lookup(revoc_reason_map, code, "Unknown");
        dst_printf(dst, "%s: %d (%s)\n", sname, code, reason);
        dst_print_raw(dst,
                      "message",
                      subpkt.fields.revocation_reason.str,
                      subpkt.fields.revocation_reason.len);
        break;
    }
    case PGP_SIG_SUBPKT_FEATURES:
        dst_printf(dst, "%s: 0x%02x ( ", sname, subpkt.data[0]);
        dst_printf(dst, "%s", subpkt.fields.features & PGP_KEY_FEATURE_MDC ? "mdc " : "");
        dst_printf(dst, "%s", subpkt.fields.features & PGP_KEY_FEATURE_AEAD ? "aead " : "");
        dst_printf(dst, "%s", subpkt.fields.features & PGP_KEY_FEATURE_V5 ? "v5 keys " : "");
        dst_printf(dst, ")\n");
        break;
    case PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE:
        dst_printf(dst, "%s:\n", sname);
        stream_dump_signature_pkt(ctx, subpkt.fields.sig, dst);
        break;
    case PGP_SIG_SUBPKT_ISSUER_FPR:
        dst_print_hex(
          dst, sname, subpkt.fields.issuer_fp.fp, subpkt.fields.issuer_fp.len, true);
        break;
    case PGP_SIG_SUBPKT_PREFERRED_AEAD:
        dst_print_algs(dst,
                       "preferred aead algorithms",
                       subpkt.fields.preferred.arr,
                       subpkt.fields.preferred.len,
                       aead_alg_map);
        break;
    default:
        if (!ctx->dump_packets) {
            indent_dest_increase(dst);
            dst_hexdump(dst, subpkt.data, subpkt.len);
            indent_dest_decrease(dst);
        }
    }
}

static void
signature_dump_subpackets(rnp_dump_ctx_t * ctx,
                          pgp_dest_t *     dst,
                          pgp_signature_t *sig,
                          bool             hashed)
{
    bool empty = true;

    for (auto &subpkt : sig->subpkts) {
        if (subpkt.hashed != hashed) {
            continue;
        }
        empty = false;
        dst_printf(dst, ":type %d, len %d", (int) subpkt.type, (int) subpkt.len);
        dst_printf(dst, "%s\n", subpkt.critical ? ", critical" : "");
        if (ctx->dump_packets) {
            dst_printf(dst, ":subpacket contents:\n");
            indent_dest_increase(dst);
            dst_hexdump(dst, subpkt.data, subpkt.len);
            indent_dest_decrease(dst);
        }
        signature_dump_subpacket(ctx, dst, subpkt);
    }

    if (empty) {
        dst_printf(dst, "none\n");
    }
}

static void
stream_dump_signature_pkt(rnp_dump_ctx_t *ctx, pgp_signature_t *sig, pgp_dest_t *dst)
{
    indent_dest_increase(dst);

    dst_printf(dst, "version: %d\n", (int) sig->version);
    dst_print_sig_type(dst, "type", sig->type());
    if (sig->version < PGP_V4) {
        dst_print_time(dst, "creation time", sig->creation_time);
        dst_print_keyid(dst, "signing key id", sig->signer);
    }
    dst_print_palg(dst, NULL, sig->palg);
    dst_print_halg(dst, NULL, sig->halg);

    if (sig->version >= PGP_V4) {
        dst_printf(dst, "hashed subpackets:\n");
        indent_dest_increase(dst);
        signature_dump_subpackets(ctx, dst, sig, true);
        indent_dest_decrease(dst);

        dst_printf(dst, "unhashed subpackets:\n");
        indent_dest_increase(dst);
        signature_dump_subpackets(ctx, dst, sig, false);
        indent_dest_decrease(dst);
    }

    dst_print_hex(dst, "lbits", sig->lbits, sizeof(sig->lbits), false);
    dst_printf(dst, "signature material:\n");
    indent_dest_increase(dst);

    pgp_signature_material_t material = {};
    try {
        sig->parse_material(material);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return;
    }
    switch (sig->palg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        dst_print_mpi(dst, "rsa s", &material.rsa.s, ctx->dump_mpi);
        break;
    case PGP_PKA_DSA:
        dst_print_mpi(dst, "dsa r", &material.dsa.r, ctx->dump_mpi);
        dst_print_mpi(dst, "dsa s", &material.dsa.s, ctx->dump_mpi);
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        dst_print_mpi(dst, "ecc r", &material.ecc.r, ctx->dump_mpi);
        dst_print_mpi(dst, "ecc s", &material.ecc.s, ctx->dump_mpi);
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        dst_print_mpi(dst, "eg r", &material.eg.r, ctx->dump_mpi);
        dst_print_mpi(dst, "eg s", &material.eg.s, ctx->dump_mpi);
        break;
    default:
        dst_printf(dst, "unknown algorithm\n");
    }
    indent_dest_decrease(dst);
    indent_dest_decrease(dst);
}

static rnp_result_t
stream_dump_signature(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_signature_t sig;
    rnp_result_t    ret;

    dst_printf(dst, "Signature packet\n");
    try {
        ret = sig.parse(*src);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        indent_dest_increase(dst);
        dst_printf(dst, "failed to parse\n");
        indent_dest_decrease(dst);
        return ret;
    }
    stream_dump_signature_pkt(ctx, &sig, dst);
    return ret;
}

static rnp_result_t
stream_dump_key(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_key_pkt_t     key;
    rnp_result_t      ret;
    pgp_fingerprint_t keyfp = {};

    try {
        ret = key.parse(*src);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        return ret;
    }

    dst_printf(dst, "%s packet\n", id_str_pair::lookup(key_type_map, key.tag, "Unknown"));
    indent_dest_increase(dst);

    dst_printf(dst, "version: %d\n", (int) key.version);
    dst_print_time(dst, "creation time", key.creation_time);
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
        const ec_curve_desc_t *cdesc = get_curve_desc(key.material.ec.curve);
        dst_print_mpi(dst, "ecc p", &key.material.ec.p, ctx->dump_mpi);
        dst_printf(dst, "ecc curve: %s\n", cdesc ? cdesc->pgp_name : "unknown");
        break;
    }
    case PGP_PKA_ECDH: {
        const ec_curve_desc_t *cdesc = get_curve_desc(key.material.ec.curve);
        dst_print_mpi(dst, "ecdh p", &key.material.ec.p, ctx->dump_mpi);
        dst_printf(dst, "ecdh curve: %s\n", cdesc ? cdesc->pgp_name : "unknown");
        dst_print_halg(dst, "ecdh hash algorithm", key.material.ec.kdf_hash_alg);
        dst_printf(dst, "ecdh key wrap algorithm: %d\n", (int) key.material.ec.key_wrap_alg);
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
            if (key.sec_protection.s2k.specifier != PGP_S2KS_EXPERIMENTAL) {
                size_t bl_size = pgp_block_size(key.sec_protection.symm_alg);
                if (bl_size) {
                    dst_print_hex(dst, "cipher iv", key.sec_protection.iv, bl_size, true);
                } else {
                    dst_printf(dst, "cipher iv: unknown algorithm\n");
                }
            }
            dst_printf(dst, "encrypted secret key data: %d bytes\n", (int) key.sec_len);
        }

        if (!key.sec_protection.s2k.usage) {
            dst_printf(dst, "cleartext secret key data: %d bytes\n", (int) key.sec_len);
        }
        indent_dest_decrease(dst);
    }

    pgp_key_id_t keyid = {};
    if (!pgp_keyid(keyid, key)) {
        dst_print_hex(dst, "keyid", keyid.data(), keyid.size(), false);
    } else {
        dst_printf(dst, "keyid: failed to calculate");
    }

    if ((key.version > PGP_V3) && (ctx->dump_grips)) {
        if (!pgp_fingerprint(keyfp, key)) {
            dst_print_hex(dst, "fingerprint", keyfp.fingerprint, keyfp.length, false);
        } else {
            dst_printf(dst, "fingerprint: failed to calculate");
        }
    }

    if (ctx->dump_grips) {
        pgp_key_grip_t grip;
        if (rnp_key_store_get_key_grip(&key.material, grip)) {
            dst_print_hex(dst, "grip", grip.data(), grip.size(), false);
        } else {
            dst_printf(dst, "grip: failed to calculate");
        }
    }

    indent_dest_decrease(dst);
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_userid(pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_userid_pkt_t uid;
    rnp_result_t     ret;
    const char *     utype;

    try {
        ret = uid.parse(*src);
    } catch (const std::exception &e) {
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        return ret;
    }

    switch (uid.tag) {
    case PGP_PKT_USER_ID:
        utype = "UserID";
        break;
    case PGP_PKT_USER_ATTR:
        utype = "UserAttr";
        break;
    default:
        utype = "Unknown user id";
    }

    dst_printf(dst, "%s packet\n", utype);
    indent_dest_increase(dst);

    switch (uid.tag) {
    case PGP_PKT_USER_ID:
        dst_printf(dst, "id: ");
        dst_write(dst, uid.uid, uid.uid_len);
        dst_printf(dst, "\n");
        break;
    case PGP_PKT_USER_ATTR:
        dst_printf(dst, "id: (%d bytes of data)\n", (int) uid.uid_len);
        break;
    default:;
    }

    indent_dest_decrease(dst);
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_pk_session_key(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_pk_sesskey_t         pkey;
    pgp_encrypted_material_t material;
    rnp_result_t             ret;

    try {
        ret = pkey.parse(*src);
        if (!pkey.parse_material(material)) {
            ret = RNP_ERROR_BAD_FORMAT;
        }
    } catch (const std::exception &e) {
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        return ret;
    }

    dst_printf(dst, "Public-key encrypted session key packet\n");
    indent_dest_increase(dst);

    dst_printf(dst, "version: %d\n", (int) pkey.version);
    dst_print_keyid(dst, NULL, pkey.key_id);
    dst_print_palg(dst, NULL, pkey.alg);
    dst_printf(dst, "encrypted material:\n");
    indent_dest_increase(dst);

    switch (pkey.alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        dst_print_mpi(dst, "rsa m", &material.rsa.m, ctx->dump_mpi);
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        dst_print_mpi(dst, "eg g", &material.eg.g, ctx->dump_mpi);
        dst_print_mpi(dst, "eg m", &material.eg.m, ctx->dump_mpi);
        break;
    case PGP_PKA_SM2:
        dst_print_mpi(dst, "sm2 m", &material.sm2.m, ctx->dump_mpi);
        break;
    case PGP_PKA_ECDH:
        dst_print_mpi(dst, "ecdh p", &material.ecdh.p, ctx->dump_mpi);
        if (ctx->dump_mpi) {
            dst_print_hex(dst, "ecdh m", material.ecdh.m, material.ecdh.mlen, true);
        } else {
            dst_printf(dst, "ecdh m: %d bytes\n", (int) material.ecdh.mlen);
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

    try {
        ret = skey.parse(*src);
    } catch (const std::exception &e) {
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        return ret;
    }

    dst_printf(dst, "Symmetric-key encrypted session key packet\n");
    indent_dest_increase(dst);
    dst_printf(dst, "version: %d\n", (int) skey.version);
    dst_print_salg(dst, NULL, skey.alg);
    if (skey.version == PGP_SKSK_V5) {
        dst_print_aalg(dst, NULL, skey.aalg);
    }
    dst_print_s2k(dst, &skey.s2k);
    if (skey.version == PGP_SKSK_V5) {
        dst_print_hex(dst, "aead iv", skey.iv, skey.ivlen, true);
    }
    dst_print_hex(dst, "encrypted key", skey.enckey, skey.enckeylen, true);
    indent_dest_decrease(dst);

    return RNP_SUCCESS;
}

static bool
stream_dump_get_aead_hdr(pgp_source_t *src, pgp_aead_hdr_t *hdr)
{
    pgp_dest_t encdst = {};
    uint8_t    encpkt[64] = {};

    if (init_mem_dest(&encdst, &encpkt, sizeof(encpkt))) {
        return false;
    }
    mem_dest_discard_overflow(&encdst, true);

    if (stream_read_packet(src, &encdst)) {
        dst_close(&encdst, false);
        return false;
    }
    size_t len = std::min(encdst.writeb, sizeof(encpkt));
    dst_close(&encdst, false);

    pgp_source_t memsrc = {};
    if (init_mem_src(&memsrc, encpkt, len, false)) {
        return false;
    }
    bool res = get_aead_src_hdr(&memsrc, hdr);
    src_close(&memsrc);
    return res;
}

static rnp_result_t
stream_dump_aead_encrypted(pgp_source_t *src, pgp_dest_t *dst)
{
    dst_printf(dst, "AEAD-encrypted data packet\n");

    pgp_aead_hdr_t aead = {};
    if (!stream_dump_get_aead_hdr(src, &aead)) {
        dst_printf(dst, "ERROR: failed to read AEAD header\n");
        return RNP_ERROR_READ;
    }

    indent_dest_increase(dst);

    dst_printf(dst, "version: %d\n", (int) aead.version);
    dst_print_salg(dst, NULL, aead.ealg);
    dst_print_aalg(dst, NULL, aead.aalg);
    dst_printf(dst, "chunk size: %d\n", (int) aead.csize);
    dst_print_hex(dst, "initialization vector", aead.iv, aead.ivlen, true);

    indent_dest_decrease(dst);
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_encrypted(pgp_source_t *src, pgp_dest_t *dst, int tag)
{
    switch (tag) {
    case PGP_PKT_SE_DATA:
        dst_printf(dst, "Symmetrically-encrypted data packet\n\n");
        break;
    case PGP_PKT_SE_IP_DATA:
        dst_printf(dst, "Symmetrically-encrypted integrity protected data packet\n\n");
        break;
    case PGP_PKT_AEAD_ENCRYPTED:
        return stream_dump_aead_encrypted(src, dst);
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

    try {
        ret = onepass.parse(*src);
    } catch (const std::exception &e) {
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        return ret;
    }

    dst_printf(dst, "One-pass signature packet\n");
    indent_dest_increase(dst);

    dst_printf(dst, "version: %d\n", (int) onepass.version);
    dst_print_sig_type(dst, NULL, onepass.type);
    dst_print_halg(dst, NULL, onepass.halg);
    dst_print_palg(dst, NULL, onepass.palg);
    dst_print_keyid(dst, "signing key id", onepass.keyid);
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
    dst_print_zalg(dst, NULL, (pgp_compression_type_t) zalg);
    dst_printf(dst, "Decompressed contents:\n");
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
    dst_printf(dst, "filename: %s (len %d)\n", lhdr.fname, (int) lhdr.fname_len);
    dst_print_time(dst, "timestamp", lhdr.timestamp);

    ret = RNP_SUCCESS;
    while (!src_eof(&lsrc)) {
        size_t read = 0;
        if (!src_read(&lsrc, readbuf, sizeof(readbuf), &read)) {
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
stream_dump_marker(pgp_source_t &src, pgp_dest_t &dst)
{
    dst_printf(&dst, "Marker packet\n");
    indent_dest_increase(&dst);
    rnp_result_t ret = stream_parse_marker(src);
    dst_printf(&dst, "contents: %s\n", ret ? "invalid" : PGP_MARKER_CONTENTS);
    indent_dest_decrease(&dst);
    return ret;
}

static rnp_result_t
stream_dump_packets_raw(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst)
{
    char         msg[1024 + PGP_MAX_HEADER_SIZE] = {0};
    char         smsg[128] = {0};
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (src_eof(src)) {
        return RNP_SUCCESS;
    }

    /* do not allow endless recursion */
    if (++ctx->layers > MAXIMUM_NESTING_LEVEL) {
        RNP_LOG("Too many OpenPGP nested layers during the dump.");
        dst_printf(dst, ":too many OpenPGP packet layers, stopping.\n");
        ret = RNP_SUCCESS;
        goto finish;
    }

    while (!src_eof(src)) {
        pgp_packet_hdr_t hdr = {};
        size_t           off = src->readb;
        rnp_result_t     hdrret = stream_peek_packet_hdr(src, &hdr);
        if (hdrret) {
            ret = hdrret;
            goto finish;
        }

        if (hdr.partial) {
            snprintf(msg, sizeof(msg), "partial len");
        } else if (hdr.indeterminate) {
            snprintf(msg, sizeof(msg), "indeterminate len");
        } else {
            snprintf(msg, sizeof(msg), "len %zu", hdr.pkt_len);
        }
        vsnprinthex(smsg, sizeof(smsg), hdr.hdr, hdr.hdr_len);
        dst_printf(
          dst, ":off %zu: packet header 0x%s (tag %d, %s)\n", off, smsg, hdr.tag, msg);

        if (ctx->dump_packets) {
            size_t rlen = hdr.pkt_len + hdr.hdr_len;
            bool   part = false;

            if (!hdr.pkt_len || (rlen > 1024 + hdr.hdr_len)) {
                rlen = 1024 + hdr.hdr_len;
                part = true;
            }

            dst_printf(dst, ":off %zu: packet contents ", off + hdr.hdr_len);
            if (!src_peek(src, msg, rlen, &rlen)) {
                dst_printf(dst, "- failed to read\n");
            } else {
                rlen -= hdr.hdr_len;
                if (part || (rlen < hdr.pkt_len)) {
                    dst_printf(dst, "(first %d bytes)\n", (int) rlen);
                } else {
                    dst_printf(dst, "(%d bytes)\n", (int) rlen);
                }
                indent_dest_increase(dst);
                dst_hexdump(dst, (uint8_t *) msg + hdr.hdr_len, rlen);
                indent_dest_decrease(dst);
            }
            dst_printf(dst, "\n");
        }

        switch (hdr.tag) {
        case PGP_PKT_SIGNATURE:
            ret = stream_dump_signature(ctx, src, dst);
            break;
        case PGP_PKT_SECRET_KEY:
        case PGP_PKT_PUBLIC_KEY:
        case PGP_PKT_SECRET_SUBKEY:
        case PGP_PKT_PUBLIC_SUBKEY:
            ret = stream_dump_key(ctx, src, dst);
            break;
        case PGP_PKT_USER_ID:
        case PGP_PKT_USER_ATTR:
            ret = stream_dump_userid(src, dst);
            break;
        case PGP_PKT_PK_SESSION_KEY:
            ret = stream_dump_pk_session_key(ctx, src, dst);
            break;
        case PGP_PKT_SK_SESSION_KEY:
            ret = stream_dump_sk_session_key(src, dst);
            break;
        case PGP_PKT_SE_DATA:
        case PGP_PKT_SE_IP_DATA:
        case PGP_PKT_AEAD_ENCRYPTED:
            ctx->stream_pkts++;
            ret = stream_dump_encrypted(src, dst, hdr.tag);
            break;
        case PGP_PKT_ONE_PASS_SIG:
            ret = stream_dump_one_pass(src, dst);
            break;
        case PGP_PKT_COMPRESSED:
            ctx->stream_pkts++;
            ret = stream_dump_compressed(ctx, src, dst);
            break;
        case PGP_PKT_LITDATA:
            ctx->stream_pkts++;
            ret = stream_dump_literal(src, dst);
            break;
        case PGP_PKT_MARKER:
            ret = stream_dump_marker(*src, *dst);
            break;
        case PGP_PKT_TRUST:
        case PGP_PKT_MDC:
            dst_printf(dst, "Skipping unhandled pkt: %d\n\n", (int) hdr.tag);
            ret = stream_skip_packet(src);
            break;
        default:
            dst_printf(dst, "Skipping Unknown pkt: %d\n\n", (int) hdr.tag);
            ret = stream_skip_packet(src);
            if (ret) {
                goto finish;
            }
        }

        if (ret) {
            RNP_LOG("failed to process packet");
            if (++ctx->failures > MAXIMUM_ERROR_PKTS) {
                RNP_LOG("too many packet dump errors.");
                goto finish;
            }
        }

        if (ctx->stream_pkts > MAXIMUM_STREAM_PKTS) {
            RNP_LOG("Too many OpenPGP stream packets during the dump.");
            dst_printf(dst, ":too many OpenPGP stream packets, stopping.\n");
            ret = RNP_SUCCESS;
            goto finish;
        }
    }

    ret = RNP_SUCCESS;
finish:
    return ret;
}

static bool
stream_skip_cleartext(pgp_source_t *src)
{
    char   buf[4096];
    size_t read = 0;
    size_t siglen = strlen(ST_SIG_BEGIN);
    char * hdrpos;

    while (!src_eof(src)) {
        if (!src_peek(src, buf, sizeof(buf) - 1, &read) || (read <= siglen)) {
            return false;
        }
        buf[read] = '\0';

        if ((hdrpos = strstr(buf, ST_SIG_BEGIN))) {
            /* +1 here is to skip \n on the beginning of ST_SIG_BEGIN */
            src_skip(src, hdrpos - buf + 1);
            return true;
        }
        src_skip(src, read - siglen + 1);
    }
    return false;
}

rnp_result_t
stream_dump_packets(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst)
{
    pgp_source_t armorsrc = {0};
    pgp_dest_t   wrdst = {0};
    bool         armored = false;
    bool         indent = false;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    ctx->layers = 0;
    ctx->stream_pkts = 0;
    ctx->failures = 0;
    /* check whether source is cleartext - then skip till the signature */
    if (is_cleartext_source(src)) {
        dst_printf(dst, ":cleartext signed data\n");
        if (!stream_skip_cleartext(src)) {
            RNP_LOG("malformed cleartext signed data");
            ret = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
    }
    /* check whether source is armored */
    if (is_armored_source(src)) {
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

static bool
obj_add_intstr_json(json_object *obj, const char *name, int val, const id_str_pair map[])
{
    if (!obj_add_field_json(obj, name, json_object_new_int(val))) {
        return false;
    }
    if (!map) {
        return true;
    }
    char        namestr[64] = {0};
    const char *str = id_str_pair::lookup(map, val, "Unknown");
    snprintf(namestr, sizeof(namestr), "%s.str", name);
    return obj_add_field_json(obj, namestr, json_object_new_string(str));
}

static bool
obj_add_mpi_json(json_object *obj, const char *name, const pgp_mpi_t *mpi, bool contents)
{
    char strname[64] = {0};
    snprintf(strname, sizeof(strname), "%s.bits", name);
    if (!obj_add_field_json(obj, strname, json_object_new_int(mpi_bits(mpi)))) {
        return false;
    }
    if (!contents) {
        return true;
    }
    snprintf(strname, sizeof(strname), "%s.raw", name);
    return obj_add_hex_json(obj, strname, mpi->mpi, mpi->len);
}

static bool
subpacket_obj_add_algs(
  json_object *obj, const char *name, uint8_t *algs, size_t len, const id_str_pair map[])
{
    json_object *jso_algs = json_object_new_array();
    if (!jso_algs || !obj_add_field_json(obj, name, jso_algs)) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if (!array_add_element_json(jso_algs, json_object_new_int(algs[i]))) {
            return false;
        }
    }
    if (!map) {
        return true;
    }

    char strname[64] = {0};
    snprintf(strname, sizeof(strname), "%s.str", name);

    jso_algs = json_object_new_array();
    if (!jso_algs || !obj_add_field_json(obj, strname, jso_algs)) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if (!array_add_element_json(
              jso_algs,
              json_object_new_string(id_str_pair::lookup(map, algs[i], "Unknown")))) {
            return false;
        }
    }
    return true;
}

static bool
obj_add_s2k_json(json_object *obj, pgp_s2k_t *s2k)
{
    json_object *s2k_obj = json_object_new_object();
    if (!obj_add_field_json(obj, "s2k", s2k_obj)) {
        return false;
    }
    if (!obj_add_field_json(s2k_obj, "specifier", json_object_new_int(s2k->specifier))) {
        return false;
    }
    if ((s2k->specifier == PGP_S2KS_EXPERIMENTAL) && s2k->gpg_ext_num) {
        if (!obj_add_field_json(
              s2k_obj, "gpg extension", json_object_new_int(s2k->gpg_ext_num))) {
            return false;
        }
        if (s2k->gpg_ext_num == PGP_S2K_GPG_SMARTCARD) {
            size_t slen = s2k->gpg_serial_len > 16 ? 16 : s2k->gpg_serial_len;
            if (!obj_add_hex_json(s2k_obj, "card serial number", s2k->gpg_serial, slen)) {
                return false;
            }
        }
    }
    if (s2k->specifier == PGP_S2KS_EXPERIMENTAL) {
        return obj_add_hex_json(
          s2k_obj, "unknown experimental", s2k->experimental.data(), s2k->experimental.size());
    }
    if (!obj_add_intstr_json(s2k_obj, "hash algorithm", s2k->hash_alg, hash_alg_map)) {
        return false;
    }
    if (((s2k->specifier == PGP_S2KS_SALTED) ||
         (s2k->specifier == PGP_S2KS_ITERATED_AND_SALTED)) &&
        !obj_add_hex_json(s2k_obj, "salt", s2k->salt, PGP_SALT_SIZE)) {
        return false;
    }
    if (s2k->specifier == PGP_S2KS_ITERATED_AND_SALTED) {
        size_t real_iter = pgp_s2k_decode_iterations(s2k->iterations);
        if (!obj_add_field_json(s2k_obj, "iterations", json_object_new_int(real_iter))) {
            return false;
        }
    }
    return true;
}

static rnp_result_t stream_dump_signature_pkt_json(rnp_dump_ctx_t *       ctx,
                                                   const pgp_signature_t *sig,
                                                   json_object *          pkt);

static bool
signature_dump_subpacket_json(rnp_dump_ctx_t *        ctx,
                              const pgp_sig_subpkt_t &subpkt,
                              json_object *           obj)
{
    switch (subpkt.type) {
    case PGP_SIG_SUBPKT_CREATION_TIME:
        return obj_add_field_json(
          obj, "creation time", json_object_new_int64(subpkt.fields.create));
    case PGP_SIG_SUBPKT_EXPIRATION_TIME:
        return obj_add_field_json(
          obj, "expiration time", json_object_new_int64(subpkt.fields.expiry));
    case PGP_SIG_SUBPKT_EXPORT_CERT:
        return obj_add_field_json(
          obj, "exportable", json_object_new_boolean(subpkt.fields.exportable));
    case PGP_SIG_SUBPKT_TRUST:
        return obj_add_field_json(
                 obj, "amount", json_object_new_int(subpkt.fields.trust.amount)) &&
               obj_add_field_json(
                 obj, "level", json_object_new_int(subpkt.fields.trust.level));
    case PGP_SIG_SUBPKT_REGEXP:
        return obj_add_field_json(
          obj,
          "regexp",
          json_object_new_string_len(subpkt.fields.regexp.str, subpkt.fields.regexp.len));
    case PGP_SIG_SUBPKT_REVOCABLE:
        return obj_add_field_json(
          obj, "revocable", json_object_new_boolean(subpkt.fields.revocable));
    case PGP_SIG_SUBPKT_KEY_EXPIRY:
        return obj_add_field_json(
          obj, "key expiration", json_object_new_int64(subpkt.fields.expiry));
    case PGP_SIG_SUBPKT_PREFERRED_SKA:
        return subpacket_obj_add_algs(obj,
                                      "algorithms",
                                      subpkt.fields.preferred.arr,
                                      subpkt.fields.preferred.len,
                                      symm_alg_map);
    case PGP_SIG_SUBPKT_PREFERRED_HASH:
        return subpacket_obj_add_algs(obj,
                                      "algorithms",
                                      subpkt.fields.preferred.arr,
                                      subpkt.fields.preferred.len,
                                      hash_alg_map);
    case PGP_SIG_SUBPKT_PREF_COMPRESS:
        return subpacket_obj_add_algs(obj,
                                      "algorithms",
                                      subpkt.fields.preferred.arr,
                                      subpkt.fields.preferred.len,
                                      z_alg_map);
    case PGP_SIG_SUBPKT_PREFERRED_AEAD:
        return subpacket_obj_add_algs(obj,
                                      "algorithms",
                                      subpkt.fields.preferred.arr,
                                      subpkt.fields.preferred.len,
                                      aead_alg_map);
    case PGP_SIG_SUBPKT_REVOCATION_KEY:
        return obj_add_field_json(
                 obj, "class", json_object_new_int(subpkt.fields.revocation_key.klass)) &&
               obj_add_field_json(
                 obj, "algorithm", json_object_new_int(subpkt.fields.revocation_key.pkalg)) &&
               obj_add_hex_json(
                 obj, "fingerprint", subpkt.fields.revocation_key.fp, PGP_FINGERPRINT_SIZE);
    case PGP_SIG_SUBPKT_ISSUER_KEY_ID:
        return obj_add_hex_json(obj, "issuer keyid", subpkt.fields.issuer, PGP_KEY_ID_SIZE);
    case PGP_SIG_SUBPKT_KEYSERV_PREFS:
        return obj_add_field_json(
          obj, "no-modify", json_object_new_boolean(subpkt.fields.ks_prefs.no_modify));
    case PGP_SIG_SUBPKT_PREF_KEYSERV:
        return obj_add_field_json(obj,
                                  "uri",
                                  json_object_new_string_len(subpkt.fields.preferred_ks.uri,
                                                             subpkt.fields.preferred_ks.len));
    case PGP_SIG_SUBPKT_PRIMARY_USER_ID:
        return obj_add_field_json(
          obj, "primary", json_object_new_boolean(subpkt.fields.primary_uid));
    case PGP_SIG_SUBPKT_POLICY_URI:
        return obj_add_field_json(
          obj,
          "uri",
          json_object_new_string_len(subpkt.fields.policy.uri, subpkt.fields.policy.len));
    case PGP_SIG_SUBPKT_KEY_FLAGS: {
        uint8_t flg = subpkt.fields.key_flags;
        if (!obj_add_field_json(obj, "flags", json_object_new_int(flg))) {
            return false;
        }
        json_object *jso_flg = json_object_new_array();
        if (!jso_flg || !obj_add_field_json(obj, "flags.str", jso_flg)) {
            return false;
        }
        if ((flg & PGP_KF_CERTIFY) &&
            !array_add_element_json(jso_flg, json_object_new_string("certify"))) {
            return false;
        }
        if ((flg & PGP_KF_SIGN) &&
            !array_add_element_json(jso_flg, json_object_new_string("sign"))) {
            return false;
        }
        if ((flg & PGP_KF_ENCRYPT_COMMS) &&
            !array_add_element_json(jso_flg, json_object_new_string("encrypt_comm"))) {
            return false;
        }
        if ((flg & PGP_KF_ENCRYPT_STORAGE) &&
            !array_add_element_json(jso_flg, json_object_new_string("encrypt_storage"))) {
            return false;
        }
        if ((flg & PGP_KF_SPLIT) &&
            !array_add_element_json(jso_flg, json_object_new_string("split"))) {
            return false;
        }
        if ((flg & PGP_KF_AUTH) &&
            !array_add_element_json(jso_flg, json_object_new_string("auth"))) {
            return false;
        }
        if ((flg & PGP_KF_SHARED) &&
            !array_add_element_json(jso_flg, json_object_new_string("shared"))) {
            return false;
        }
        return true;
    }
    case PGP_SIG_SUBPKT_SIGNERS_USER_ID:
        return obj_add_field_json(
          obj,
          "uid",
          json_object_new_string_len(subpkt.fields.signer.uid, subpkt.fields.signer.len));
    case PGP_SIG_SUBPKT_REVOCATION_REASON: {
        if (!obj_add_intstr_json(
              obj, "code", subpkt.fields.revocation_reason.code, revoc_reason_map)) {
            return false;
        }
        return obj_add_field_json(
          obj,
          "message",
          json_object_new_string_len(subpkt.fields.revocation_reason.str,
                                     subpkt.fields.revocation_reason.len));
    }
    case PGP_SIG_SUBPKT_FEATURES:
        return obj_add_field_json(
                 obj,
                 "mdc",
                 json_object_new_boolean(subpkt.fields.features & PGP_KEY_FEATURE_MDC)) &&
               obj_add_field_json(
                 obj,
                 "aead",
                 json_object_new_boolean(subpkt.fields.features & PGP_KEY_FEATURE_AEAD)) &&
               obj_add_field_json(
                 obj,
                 "v5 keys",
                 json_object_new_boolean(subpkt.fields.features & PGP_KEY_FEATURE_V5));
    case PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE: {
        json_object *sig = json_object_new_object();
        if (!sig || !obj_add_field_json(obj, "signature", sig)) {
            return false;
        }
        return !stream_dump_signature_pkt_json(ctx, subpkt.fields.sig, sig);
    }
    case PGP_SIG_SUBPKT_ISSUER_FPR:
        return obj_add_hex_json(
          obj, "fingerprint", subpkt.fields.issuer_fp.fp, subpkt.fields.issuer_fp.len);
    case PGP_SIG_SUBPKT_NOTATION_DATA: {
        bool human = subpkt.fields.notation.human;
        if (!json_add(obj, "human", human) || !json_add(obj,
                                                        "name",
                                                        (char *) subpkt.fields.notation.name,
                                                        subpkt.fields.notation.nlen)) {
            return false;
        }
        if (human) {
            return json_add(obj,
                            "value",
                            (char *) subpkt.fields.notation.value,
                            subpkt.fields.notation.vlen);
        }
        return obj_add_hex_json(
          obj, "value", subpkt.fields.notation.value, subpkt.fields.notation.vlen);
    }
    default:
        if (!ctx->dump_packets) {
            return obj_add_hex_json(obj, "raw", subpkt.data, subpkt.len);
        }
        return true;
    }
    return true;
}

static json_object *
signature_dump_subpackets_json(rnp_dump_ctx_t *ctx, const pgp_signature_t *sig)
{
    json_object *res = json_object_new_array();

    for (auto &subpkt : sig->subpkts) {
        json_object *jso_subpkt = json_object_new_object();
        if (json_object_array_add(res, jso_subpkt)) {
            json_object_put(jso_subpkt);
            goto error;
        }

        if (!obj_add_intstr_json(jso_subpkt, "type", subpkt.type, sig_subpkt_type_map)) {
            goto error;
        }
        if (!obj_add_field_json(jso_subpkt, "length", json_object_new_int(subpkt.len))) {
            goto error;
        }
        if (!obj_add_field_json(
              jso_subpkt, "hashed", json_object_new_boolean(subpkt.hashed))) {
            goto error;
        }
        if (!obj_add_field_json(
              jso_subpkt, "critical", json_object_new_boolean(subpkt.critical))) {
            goto error;
        }

        if (ctx->dump_packets &&
            !obj_add_hex_json(jso_subpkt, "raw", subpkt.data, subpkt.len)) {
            goto error;
        }

        if (!signature_dump_subpacket_json(ctx, subpkt, jso_subpkt)) {
            goto error;
        }
    }

    return res;
error:
    json_object_put(res);
    return NULL;
}

static rnp_result_t
stream_dump_signature_pkt_json(rnp_dump_ctx_t *       ctx,
                               const pgp_signature_t *sig,
                               json_object *          pkt)
{
    json_object *            material = NULL;
    pgp_signature_material_t sigmaterial = {};
    rnp_result_t             ret = RNP_ERROR_OUT_OF_MEMORY;

    if (!obj_add_field_json(pkt, "version", json_object_new_int(sig->version))) {
        goto done;
    }
    if (!obj_add_intstr_json(pkt, "type", sig->type(), sig_type_map)) {
        goto done;
    }

    if (sig->version < PGP_V4) {
        if (!obj_add_field_json(
              pkt, "creation time", json_object_new_int(sig->creation_time))) {
            goto done;
        }
        if (!obj_add_hex_json(pkt, "signer", sig->signer.data(), sig->signer.size())) {
            goto done;
        }
    }
    if (!obj_add_intstr_json(pkt, "algorithm", sig->palg, pubkey_alg_map)) {
        goto done;
    }
    if (!obj_add_intstr_json(pkt, "hash algorithm", sig->halg, hash_alg_map)) {
        goto done;
    }

    if (sig->version >= PGP_V4) {
        json_object *subpkts = signature_dump_subpackets_json(ctx, sig);
        if (!subpkts) {
            goto done;
        }
        if (!obj_add_field_json(pkt, "subpackets", subpkts)) {
            goto done;
        }
    }

    if (!obj_add_hex_json(pkt, "lbits", sig->lbits, sizeof(sig->lbits))) {
        goto done;
    }

    material = json_object_new_object();
    if (!material || !obj_add_field_json(pkt, "material", material)) {
        goto done;
    }

    try {
        sig->parse_material(sigmaterial);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    switch (sig->palg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!obj_add_mpi_json(material, "s", &sigmaterial.rsa.s, ctx->dump_mpi)) {
            goto done;
        }
        break;
    case PGP_PKA_DSA:
        if (!obj_add_mpi_json(material, "r", &sigmaterial.dsa.r, ctx->dump_mpi) ||
            !obj_add_mpi_json(material, "s", &sigmaterial.dsa.s, ctx->dump_mpi)) {
            goto done;
        }
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        if (!obj_add_mpi_json(material, "r", &sigmaterial.ecc.r, ctx->dump_mpi) ||
            !obj_add_mpi_json(material, "s", &sigmaterial.ecc.s, ctx->dump_mpi)) {
            goto done;
        }
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (!obj_add_mpi_json(material, "r", &sigmaterial.eg.r, ctx->dump_mpi) ||
            !obj_add_mpi_json(material, "s", &sigmaterial.eg.s, ctx->dump_mpi)) {
            goto done;
        }
        break;
    default:
        break;
    }
    ret = RNP_SUCCESS;
done:
    return ret;
}

static rnp_result_t
stream_dump_signature_json(rnp_dump_ctx_t *ctx, pgp_source_t *src, json_object *pkt)
{
    pgp_signature_t sig;
    rnp_result_t    ret;
    try {
        ret = sig.parse(*src);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        return ret;
    }
    return stream_dump_signature_pkt_json(ctx, &sig, pkt);
}

static rnp_result_t
stream_dump_key_json(rnp_dump_ctx_t *ctx, pgp_source_t *src, json_object *pkt)
{
    pgp_key_pkt_t     key;
    rnp_result_t      ret;
    pgp_key_id_t      keyid = {};
    pgp_fingerprint_t keyfp = {};
    json_object *     material = NULL;

    try {
        ret = key.parse(*src);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        return ret;
    }

    ret = RNP_ERROR_OUT_OF_MEMORY;

    if (!obj_add_field_json(pkt, "version", json_object_new_int(key.version))) {
        goto done;
    }
    if (!obj_add_field_json(pkt, "creation time", json_object_new_int64(key.creation_time))) {
        goto done;
    }
    if ((key.version < PGP_V4) &&
        !obj_add_field_json(pkt, "v3 days", json_object_new_int(key.v3_days))) {
        goto done;
    }
    if (!obj_add_intstr_json(pkt, "algorithm", key.alg, pubkey_alg_map)) {
        goto done;
    }

    material = json_object_new_object();
    if (!material || !obj_add_field_json(pkt, "material", material)) {
        goto done;
    }

    switch (key.alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!obj_add_mpi_json(material, "n", &key.material.rsa.n, ctx->dump_mpi) ||
            !obj_add_mpi_json(material, "e", &key.material.rsa.e, ctx->dump_mpi)) {
            goto done;
        }
        break;
    case PGP_PKA_DSA:
        if (!obj_add_mpi_json(material, "p", &key.material.dsa.p, ctx->dump_mpi) ||
            !obj_add_mpi_json(material, "q", &key.material.dsa.q, ctx->dump_mpi) ||
            !obj_add_mpi_json(material, "g", &key.material.dsa.g, ctx->dump_mpi) ||
            !obj_add_mpi_json(material, "y", &key.material.dsa.y, ctx->dump_mpi)) {
            goto done;
        }
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (!obj_add_mpi_json(material, "p", &key.material.eg.p, ctx->dump_mpi) ||
            !obj_add_mpi_json(material, "g", &key.material.eg.g, ctx->dump_mpi) ||
            !obj_add_mpi_json(material, "y", &key.material.eg.y, ctx->dump_mpi)) {
            goto done;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2: {
        const ec_curve_desc_t *cdesc = get_curve_desc(key.material.ec.curve);
        if (!obj_add_mpi_json(material, "p", &key.material.ec.p, ctx->dump_mpi)) {
            goto done;
        }
        if (!obj_add_field_json(material,
                                "curve",
                                json_object_new_string(cdesc ? cdesc->pgp_name : "unknown"))) {
            goto done;
        }
        break;
    }
    case PGP_PKA_ECDH: {
        const ec_curve_desc_t *cdesc = get_curve_desc(key.material.ec.curve);
        if (!obj_add_mpi_json(material, "p", &key.material.ec.p, ctx->dump_mpi)) {
            goto done;
        }
        if (!obj_add_field_json(material,
                                "curve",
                                json_object_new_string(cdesc ? cdesc->pgp_name : "unknown"))) {
            goto done;
        }
        if (!obj_add_intstr_json(
              material, "hash algorithm", key.material.ec.kdf_hash_alg, hash_alg_map)) {
            goto done;
        }
        if (!obj_add_intstr_json(
              material, "key wrap algorithm", key.material.ec.key_wrap_alg, symm_alg_map)) {
            goto done;
        }
        break;
    }
    default:
        break;
    }

    if (is_secret_key_pkt(key.tag)) {
        if (!obj_add_field_json(
              material, "s2k usage", json_object_new_int(key.sec_protection.s2k.usage))) {
            goto done;
        }
        if (!obj_add_s2k_json(material, &key.sec_protection.s2k)) {
            goto done;
        }
        if (key.sec_protection.s2k.usage &&
            !obj_add_intstr_json(
              material, "symmetric algorithm", key.sec_protection.symm_alg, symm_alg_map)) {
            goto done;
        }
    }

    if (pgp_keyid(keyid, key) || !obj_add_hex_json(pkt, "keyid", keyid.data(), keyid.size())) {
        goto done;
    }

    if (ctx->dump_grips) {
        if (pgp_fingerprint(keyfp, key) ||
            !obj_add_hex_json(pkt, "fingerprint", keyfp.fingerprint, keyfp.length)) {
            goto done;
        }

        pgp_key_grip_t grip;
        if (!rnp_key_store_get_key_grip(&key.material, grip) ||
            !obj_add_hex_json(pkt, "grip", grip.data(), grip.size())) {
            goto done;
        }
    }
    ret = RNP_SUCCESS;
done:
    return ret;
}

static rnp_result_t
stream_dump_userid_json(pgp_source_t *src, json_object *pkt)
{
    pgp_userid_pkt_t uid;
    rnp_result_t     ret;

    try {
        ret = uid.parse(*src);
    } catch (const std::exception &e) {
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        return ret;
    }

    switch (uid.tag) {
    case PGP_PKT_USER_ID:
        if (!obj_add_field_json(
              pkt, "userid", json_object_new_string_len((char *) uid.uid, uid.uid_len))) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        break;
    case PGP_PKT_USER_ATTR:
        if (!obj_add_hex_json(pkt, "userattr", uid.uid, uid.uid_len)) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        break;
    default:;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_pk_session_key_json(rnp_dump_ctx_t *ctx, pgp_source_t *src, json_object *pkt)
{
    pgp_pk_sesskey_t         pkey;
    pgp_encrypted_material_t pkmaterial;
    rnp_result_t             ret;

    try {
        ret = pkey.parse(*src);
        if (!pkey.parse_material(pkmaterial)) {
            ret = RNP_ERROR_BAD_FORMAT;
        }
    } catch (const std::exception &e) {
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        return ret;
    }

    if (!obj_add_field_json(pkt, "version", json_object_new_int(pkey.version)) ||
        !obj_add_hex_json(pkt, "keyid", pkey.key_id.data(), pkey.key_id.size()) ||
        !obj_add_intstr_json(pkt, "algorithm", pkey.alg, pubkey_alg_map)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    json_object *material = json_object_new_object();
    if (!obj_add_field_json(pkt, "material", material)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    switch (pkey.alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!obj_add_mpi_json(material, "m", &pkmaterial.rsa.m, ctx->dump_mpi)) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (!obj_add_mpi_json(material, "g", &pkmaterial.eg.g, ctx->dump_mpi) ||
            !obj_add_mpi_json(material, "m", &pkmaterial.eg.m, ctx->dump_mpi)) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        break;
    case PGP_PKA_SM2:
        if (!obj_add_mpi_json(material, "m", &pkmaterial.sm2.m, ctx->dump_mpi)) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        break;
    case PGP_PKA_ECDH:
        if (!obj_add_mpi_json(material, "p", &pkmaterial.ecdh.p, ctx->dump_mpi) ||
            !obj_add_field_json(
              material, "m.bytes", json_object_new_int(pkmaterial.ecdh.mlen))) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        if (ctx->dump_mpi &&
            !obj_add_hex_json(material, "m", pkmaterial.ecdh.m, pkmaterial.ecdh.mlen)) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        break;
    default:;
    }

    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_sk_session_key_json(pgp_source_t *src, json_object *pkt)
{
    pgp_sk_sesskey_t skey;
    rnp_result_t     ret;

    try {
        ret = skey.parse(*src);
    } catch (const std::exception &e) {
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        return ret;
    }

    if (!obj_add_field_json(pkt, "version", json_object_new_int(skey.version)) ||
        !obj_add_intstr_json(pkt, "algorithm", skey.alg, symm_alg_map)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if ((skey.version == PGP_SKSK_V5) &&
        !obj_add_intstr_json(pkt, "aead algorithm", skey.aalg, aead_alg_map)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!obj_add_s2k_json(pkt, &skey.s2k)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if ((skey.version == PGP_SKSK_V5) &&
        !obj_add_hex_json(pkt, "aead iv", skey.iv, skey.ivlen)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!obj_add_hex_json(pkt, "encrypted key", skey.enckey, skey.enckeylen)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_encrypted_json(pgp_source_t *src, json_object *pkt, pgp_pkt_type_t tag)
{
    if (tag != PGP_PKT_AEAD_ENCRYPTED) {
        /* packet header with tag is already in pkt */
        return stream_skip_packet(src);
    }

    /* dumping AEAD data */
    pgp_aead_hdr_t aead = {};
    if (!stream_dump_get_aead_hdr(src, &aead)) {
        return RNP_ERROR_READ;
    }

    if (!obj_add_field_json(pkt, "version", json_object_new_int(aead.version)) ||
        !obj_add_intstr_json(pkt, "algorithm", aead.ealg, symm_alg_map) ||
        !obj_add_intstr_json(pkt, "aead algorithm", aead.aalg, aead_alg_map) ||
        !obj_add_field_json(pkt, "chunk size", json_object_new_int(aead.csize)) ||
        !obj_add_hex_json(pkt, "aead iv", aead.iv, aead.ivlen)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_one_pass_json(pgp_source_t *src, json_object *pkt)
{
    pgp_one_pass_sig_t onepass;
    rnp_result_t       ret;

    try {
        ret = onepass.parse(*src);
    } catch (const std::exception &e) {
        ret = RNP_ERROR_GENERIC;
    }
    if (ret) {
        return ret;
    }

    if (!obj_add_field_json(pkt, "version", json_object_new_int(onepass.version))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!obj_add_intstr_json(pkt, "type", onepass.type, sig_type_map)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!obj_add_intstr_json(pkt, "hash algorithm", onepass.halg, hash_alg_map)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!obj_add_intstr_json(pkt, "public key algorithm", onepass.palg, pubkey_alg_map)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!obj_add_hex_json(pkt, "signer", onepass.keyid.data(), onepass.keyid.size())) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!obj_add_field_json(pkt, "nested", json_object_new_boolean(onepass.nested))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
stream_dump_marker_json(pgp_source_t &src, json_object *pkt)
{
    rnp_result_t ret = stream_parse_marker(src);

    if (!obj_add_field_json(
          pkt, "contents", json_object_new_string(ret ? "invalid" : PGP_MARKER_CONTENTS))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return ret;
}

static rnp_result_t stream_dump_raw_packets_json(rnp_dump_ctx_t *ctx,
                                                 pgp_source_t *  src,
                                                 json_object **  jso);

static rnp_result_t
stream_dump_compressed_json(rnp_dump_ctx_t *ctx, pgp_source_t *src, json_object *pkt)
{
    pgp_source_t zsrc = {0};
    uint8_t      zalg;
    rnp_result_t ret;
    json_object *contents = NULL;

    if ((ret = init_compressed_src(&zsrc, src))) {
        return ret;
    }

    get_compressed_src_alg(&zsrc, &zalg);
    if (!obj_add_intstr_json(pkt, "algorithm", zalg, z_alg_map)) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    ret = stream_dump_raw_packets_json(ctx, &zsrc, &contents);
    if (!ret && !obj_add_field_json(pkt, "contents", contents)) {
        json_object_put(contents);
        ret = RNP_ERROR_OUT_OF_MEMORY;
    }
done:
    src_close(&zsrc);
    return ret;
}

static rnp_result_t
stream_dump_literal_json(pgp_source_t *src, json_object *pkt)
{
    pgp_source_t      lsrc = {0};
    pgp_literal_hdr_t lhdr = {0};
    rnp_result_t      ret;
    uint8_t           readbuf[16384];

    if ((ret = init_literal_src(&lsrc, src))) {
        return ret;
    }
    ret = RNP_ERROR_OUT_OF_MEMORY;
    get_literal_src_hdr(&lsrc, &lhdr);
    if (!obj_add_field_json(
          pkt, "format", json_object_new_string_len((char *) &lhdr.format, 1))) {
        goto done;
    }
    if (!obj_add_field_json(
          pkt, "filename", json_object_new_string_len(lhdr.fname, lhdr.fname_len))) {
        goto done;
    }
    if (!obj_add_field_json(pkt, "timestamp", json_object_new_int64(lhdr.timestamp))) {
        goto done;
    }

    while (!src_eof(&lsrc)) {
        size_t read = 0;
        if (!src_read(&lsrc, readbuf, sizeof(readbuf), &read)) {
            ret = RNP_ERROR_READ;
            goto done;
        }
    }

    if (!obj_add_field_json(pkt, "datalen", json_object_new_int64(lsrc.readb))) {
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    src_close(&lsrc);
    return ret;
}

static bool
stream_dump_hdr_json(pgp_source_t *src, pgp_packet_hdr_t *hdr, json_object *pkt)
{
    rnp_result_t hdrret = stream_peek_packet_hdr(src, hdr);
    if (hdrret) {
        return false;
    }

    json_object *jso_hdr = json_object_new_object();
    if (!jso_hdr) {
        return false;
    }

    if (!obj_add_field_json(jso_hdr, "offset", json_object_new_int64(src->readb))) {
        goto error;
    }
    if (!obj_add_intstr_json(jso_hdr, "tag", hdr->tag, packet_tag_map)) {
        goto error;
    }
    if (!obj_add_hex_json(jso_hdr, "raw", hdr->hdr, hdr->hdr_len)) {
        goto error;
    }
    if (!hdr->partial && !hdr->indeterminate &&
        !obj_add_field_json(jso_hdr, "length", json_object_new_int64(hdr->pkt_len))) {
        goto error;
    }
    if (!obj_add_field_json(jso_hdr, "partial", json_object_new_boolean(hdr->partial))) {
        goto error;
    }
    if (!obj_add_field_json(
          jso_hdr, "indeterminate", json_object_new_boolean(hdr->indeterminate))) {
        goto error;
    }
    return obj_add_field_json(pkt, "header", jso_hdr);
error:
    json_object_put(jso_hdr);
    return false;
}

static rnp_result_t
stream_dump_raw_packets_json(rnp_dump_ctx_t *ctx, pgp_source_t *src, json_object **jso)
{
    json_object *pkts = NULL;
    json_object *pkt = NULL;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    pkts = json_object_new_array();
    if (!pkts) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (src_eof(src)) {
        ret = RNP_SUCCESS;
        goto done;
    }

    /* do not allow endless recursion */
    if (++ctx->layers > MAXIMUM_NESTING_LEVEL) {
        RNP_LOG("Too many OpenPGP nested layers during the dump.");
        ret = RNP_SUCCESS;
        goto done;
    }

    while (!src_eof(src)) {
        pgp_packet_hdr_t hdr = {};

        pkt = json_object_new_object();
        if (!pkt) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }

        if (!stream_dump_hdr_json(src, &hdr, pkt)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }

        if (ctx->dump_packets) {
            size_t  rlen = hdr.pkt_len + hdr.hdr_len;
            uint8_t buf[2048 + sizeof(hdr.hdr)] = {0};

            if (!hdr.pkt_len || (rlen > 2048 + hdr.hdr_len)) {
                rlen = 2048 + hdr.hdr_len;
            }
            if (!src_peek(src, buf, rlen, &rlen) || (rlen < hdr.hdr_len)) {
                ret = RNP_ERROR_READ;
                goto done;
            }
            if (!obj_add_hex_json(pkt, "raw", buf + hdr.hdr_len, rlen - hdr.hdr_len)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
        }

        switch (hdr.tag) {
        case PGP_PKT_SIGNATURE:
            ret = stream_dump_signature_json(ctx, src, pkt);
            break;
        case PGP_PKT_SECRET_KEY:
        case PGP_PKT_PUBLIC_KEY:
        case PGP_PKT_SECRET_SUBKEY:
        case PGP_PKT_PUBLIC_SUBKEY:
            ret = stream_dump_key_json(ctx, src, pkt);
            break;
        case PGP_PKT_USER_ID:
        case PGP_PKT_USER_ATTR:
            ret = stream_dump_userid_json(src, pkt);
            break;
        case PGP_PKT_PK_SESSION_KEY:
            ret = stream_dump_pk_session_key_json(ctx, src, pkt);
            break;
        case PGP_PKT_SK_SESSION_KEY:
            ret = stream_dump_sk_session_key_json(src, pkt);
            break;
        case PGP_PKT_SE_DATA:
        case PGP_PKT_SE_IP_DATA:
        case PGP_PKT_AEAD_ENCRYPTED:
            ctx->stream_pkts++;
            ret = stream_dump_encrypted_json(src, pkt, hdr.tag);
            break;
        case PGP_PKT_ONE_PASS_SIG:
            ret = stream_dump_one_pass_json(src, pkt);
            break;
        case PGP_PKT_COMPRESSED:
            ctx->stream_pkts++;
            ret = stream_dump_compressed_json(ctx, src, pkt);
            break;
        case PGP_PKT_LITDATA:
            ctx->stream_pkts++;
            ret = stream_dump_literal_json(src, pkt);
            break;
        case PGP_PKT_MARKER:
            ret = stream_dump_marker_json(*src, pkt);
            break;
        case PGP_PKT_TRUST:
        case PGP_PKT_MDC:
            ret = stream_skip_packet(src);
            break;
        default:
            ret = stream_skip_packet(src);
        }

        if (ret) {
            RNP_LOG("failed to process packet");
            if (++ctx->failures > MAXIMUM_ERROR_PKTS) {
                RNP_LOG("too many packet dump errors.");
                goto done;
            }
            ret = RNP_SUCCESS;
        }

        if (json_object_array_add(pkts, pkt)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (ctx->stream_pkts > MAXIMUM_STREAM_PKTS) {
            RNP_LOG("Too many OpenPGP stream packets during the dump.");
            ret = RNP_SUCCESS;
            goto done;
        }

        pkt = NULL;
    }
done:
    if (ret) {
        json_object_put(pkts);
        json_object_put(pkt);
        pkts = NULL;
    }
    *jso = pkts;
    return ret;
}

rnp_result_t
stream_dump_packets_json(rnp_dump_ctx_t *ctx, pgp_source_t *src, json_object **jso)
{
    pgp_source_t armorsrc = {0};
    bool         armored = false;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    ctx->layers = 0;
    ctx->stream_pkts = 0;
    ctx->failures = 0;
    /* check whether source is cleartext - then skip till the signature */
    if (is_cleartext_source(src)) {
        if (!stream_skip_cleartext(src)) {
            RNP_LOG("malformed cleartext signed data");
            ret = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }
    }
    /* check whether source is armored */
    if (is_armored_source(src)) {
        if ((ret = init_armored_src(&armorsrc, src))) {
            RNP_LOG("failed to parse armored data");
            goto finish;
        }
        armored = true;
        src = &armorsrc;
    }

    if (src_eof(src)) {
        ret = RNP_ERROR_NOT_ENOUGH_DATA;
        goto finish;
    }

    ret = stream_dump_raw_packets_json(ctx, src, jso);
finish:
    if (armored) {
        src_close(&armorsrc);
    }
    return ret;
}
