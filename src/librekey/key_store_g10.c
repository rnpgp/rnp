/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
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

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <packet.h>

#include <rnp/rnp_sdk.h>

#include "key_store_pgp.h"
#include "key_store_g10.h"

#include "crypto/bn.h"
#include "crypto/s2k.h"
#include "symmetric.h"
#include "readerwriter.h"

#define G10_CBC_IV_SIZE 16

#define G10_OCB_NONCE_SIZE 12

#define G10_SHA1_HASH_SIZE 20

typedef struct {
    size_t   len;
    uint8_t *bytes;
} s_exp_block_t;

typedef struct sub_element_t sub_element_t;

typedef struct {
    DYNARRAY(sub_element_t, sub_element);
} s_exp_t;

struct sub_element_t {
    bool is_block;
    union {
        s_exp_t       s_exp;
        s_exp_block_t block;
    };
};

typedef struct format_info {
    pgp_symm_alg_t    cipher;
    pgp_cipher_mode_t cipher_mode;
    pgp_hash_alg_t    hash_alg;
    const char *      botan_cipher_name;
    size_t            chiper_block_size;
    const char *      g10_type;
    size_t            iv_size;
} format_info;

static bool g10_calculated_hash(pgp_seckey_t *key, uint8_t *checksum);

static const format_info formats[] = {{PGP_SA_AES_128,
                                       PGP_CIPHER_MODE_CBC,
                                       PGP_HASH_SHA1,
                                       "AES-128/CBC/NoPadding",
                                       16,
                                       "openpgp-s2k3-sha1-aes-cbc",
                                       G10_CBC_IV_SIZE},
                                      {PGP_SA_AES_256,
                                       PGP_CIPHER_MODE_CBC,
                                       PGP_HASH_SHA1,
                                       "AES-256/CBC/NoPadding",
                                       16,
                                       "openpgp-s2k3-sha1-aes256-cbc",
                                       G10_CBC_IV_SIZE},
                                      {PGP_SA_AES_128,
                                       PGP_CIPHER_MODE_OCB,
                                       PGP_HASH_SHA1,
                                       "AES-128/OCB/NoPadding",
                                       16,
                                       "openpgp-s2k3-ocb-aes",
                                       G10_OCB_NONCE_SIZE}};

static const format_info *
find_format(pgp_symm_alg_t cipher, pgp_cipher_mode_t mode, pgp_hash_alg_t hash_alg)
{
    for (size_t i = 0; i < ARRAY_SIZE(formats); i++) {
        if (formats[i].cipher == cipher && formats[i].cipher_mode == mode &&
            formats[i].hash_alg == hash_alg) {
            return &formats[i];
        }
    }
    return NULL;
}

static const format_info *
parse_format(const char *format, size_t format_len)
{
    for (size_t i = 0; i < ARRAY_SIZE(formats); i++) {
        if (strlen(formats[i].g10_type) == format_len &&
            !strncmp(formats[i].g10_type, format, format_len)) {
            return &formats[i];
        }
    }
    return NULL;
}

static void
destroy_s_exp(s_exp_t *s_exp)
{
    int i;

    if (s_exp == NULL) {
        return;
    }

    if (s_exp->sub_elements != NULL) {
        for (i = 0; i < s_exp->sub_elementc; i++) {
            if (s_exp->sub_elements[i].is_block) {
                if (s_exp->sub_elements[i].block.len > 0 &&
                    s_exp->sub_elements[i].block.bytes != NULL) {
                    free(s_exp->sub_elements[i].block.bytes);
                    s_exp->sub_elements[i].block.bytes = NULL;
                    s_exp->sub_elements[i].block.len = 0;
                }
            } else {
                destroy_s_exp(&s_exp->sub_elements[i].s_exp);
            }
        }
        FREE_ARRAY(s_exp, sub_element);
    }
}

static bool
add_block_to_sexp(s_exp_t *s_exp, uint8_t *bytes, size_t len)
{
    sub_element_t *sub_element;

    for (int i = 0; i < s_exp->sub_elementc; i++) {
        if (!s_exp->sub_elements[i].is_block) {
            continue;
        }
        if (len == s_exp->sub_elements[i].block.len &&
            !memcmp(s_exp->sub_elements[i].block.bytes, bytes, len)) {
            // do not duplicate blocks
            return true;
        }
    }

    EXPAND_ARRAY(s_exp, sub_element);
    if (s_exp->sub_elements == NULL) {
        return false;
    }

    sub_element = &s_exp->sub_elements[s_exp->sub_elementc++];

    sub_element->is_block = true;
    sub_element->block.len = (size_t) len;
    sub_element->block.bytes = malloc(sub_element->block.len);
    if (sub_element->block.bytes == NULL) {
        fprintf(stderr, "can't allocate memory\n");
        return false;
    }

    memcpy(sub_element->block.bytes, bytes, sub_element->block.len);
    return true;
}

static bool
add_string_block_to_sexp(s_exp_t *s_exp, const char *s)
{
    return add_block_to_sexp(s_exp, (uint8_t *) s, strlen(s));
}

static bool
add_sub_sexp_to_sexp(s_exp_t *s_exp, s_exp_t **sub_s_exp)
{
    sub_element_t *sub_element;

    EXPAND_ARRAY(s_exp, sub_element);
    if (s_exp->sub_elements == NULL) {
        return false;
    }

    sub_element = &s_exp->sub_elements[s_exp->sub_elementc++];
    sub_element->is_block = false;
    *sub_s_exp = &sub_element->s_exp;

    return true;
}

/*
 * Parse G10 S-exp.
 *
 * Supported format: (1:a2:ab(3:asd1:a))
 * It should be parsed to:
 *   - a
 *   - ab
 *   + - asd
 *     - a
 *
 */
static bool
parse_sexp(s_exp_t *s_exp, const char **r_bytes, size_t *r_length)
{
    size_t      length = *r_length;
    const char *bytes = *r_bytes;

    s_exp_t new_s_exp = {0};

    if (bytes == NULL || length == 0) {
        fprintf(stderr, "empty s-exp\n");
        return true;
    }

    if (*bytes != '(') { // doesn't start from (
        fprintf(stderr, "s-exp doesn't start from '('\n");
        return false;
    }

    bytes++;
    length--;

    do {
        if (length <= 0) { // unexpected end
            fprintf(stderr, "s-exp finished before ')'\n");
            destroy_s_exp(&new_s_exp);
            return false;
        }

        if (*bytes == '(') {
            s_exp_t *new_sub_s_exp;

            if (!add_sub_sexp_to_sexp(&new_s_exp, &new_sub_s_exp)) {
                return false;
            }

            if (!parse_sexp(new_sub_s_exp, &bytes, &length)) {
                destroy_s_exp(&new_s_exp);
                return false;
            }

            continue;
        }

        char *next;
        long  len = strtol(bytes, &next, 10);

        if (*next != ':') { // doesn't contain :
            fprintf(stderr, "s-exp doesn't contain ':'\n");
            destroy_s_exp(&new_s_exp);
            return false;
        }

        next++;

        length -= (next - bytes);
        bytes = next;

        if (len == LONG_MIN || len == LONG_MAX || len <= 0 || len >= length) {
            fprintf(
              stderr,
              "len over/under flow or bigger than remaining bytes, len: %ld, length: %zu\n",
              len,
              length);
            destroy_s_exp(&new_s_exp);
            return false;
        }

        if (!add_block_to_sexp(&new_s_exp, (uint8_t *) bytes, (size_t) len)) {
            destroy_s_exp(&new_s_exp);
            return false;
        }

        bytes += len;
        length -= len;

    } while (*bytes != ')');

    bytes++;
    length--;

    *s_exp = new_s_exp;
    *r_bytes = bytes;
    *r_length = length;

    return true;
}

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

static unsigned
block_to_unsigned(s_exp_block_t *block)
{
    char s[sizeof(STR(UINT_MAX)) + 1];
    if (block->len >= sizeof(s)) {
        return UINT_MAX;
    }

    memcpy(s, block->bytes, block->len);
    return (unsigned int) atoi(s);
}

static bool
add_unsigned_block_to_sexp(s_exp_t *s_exp, unsigned u)
{
    char s[sizeof(STR(UINT_MAX)) + 1];
    snprintf(s, sizeof(s), "%u", u);
    return add_block_to_sexp(s_exp, (uint8_t *) s, strlen(s));
}

static s_exp_t *
lookup_variable(s_exp_t *s_exp, const char *name)
{
    size_t name_len = strlen(name);
    for (int i = 0; i < s_exp->sub_elementc; i++) {
        if (s_exp->sub_elements[i].is_block) {
            continue;
        }
        if (s_exp->sub_elements[i].s_exp.sub_elementc < 2 ||
            !s_exp->sub_elements[i].s_exp.sub_elements[0].is_block) {
            fprintf(stderr, "Expected sub-s-exp with 2 first blocks\n");
            return NULL;
        }
        if (name_len == s_exp->sub_elements[i].s_exp.sub_elements[0].block.len &&
            !strncmp(name,
                     (const char *) s_exp->sub_elements[i].s_exp.sub_elements[0].block.bytes,
                     s_exp->sub_elements[i].s_exp.sub_elements[0].block.len)) {
            return &s_exp->sub_elements[i].s_exp;
        }
    }
    fprintf(stderr, "Haven't got variable '%s'\n", name);
    return NULL;
}

static BIGNUM *
read_bignum(s_exp_t *s_exp, const char *name)
{
    s_exp_t *var = lookup_variable(s_exp, name);
    if (var == NULL) {
        return NULL;
    }

    if (!var->sub_elements[1].is_block) {
        fprintf(stderr, "Expected block value\n");
        return NULL;
    }

    BIGNUM *res = PGPV_BN_bin2bn(
      var->sub_elements[1].block.bytes, (int) var->sub_elements[1].block.len, NULL);
    if (res == NULL) {
        char *buf = malloc((var->sub_elements[1].block.len * 3) + 1);
        if (buf == NULL) {
            fprintf(stderr, "Can't allocate memory\n");
            return NULL;
        }
        fprintf(stderr,
                "Can't convert variable '%s' to bignum. The value is: '%s'\n",
                name,
                rnp_strhexdump_upper(
                  buf, var->sub_elements[1].block.bytes, var->sub_elements[1].block.len, ""));
    }
    return res;
}

static bool
write_bignum(s_exp_t *s_exp, const char *name, BIGNUM *bn)
{
    uint8_t bnbuf[RNP_BUFSIZ];

    s_exp_t *sub_s_exp;

    bnbuf[0] = 0;

    if (PGPV_BN_bn2bin(bn, bnbuf + 1) < 0) {
        return false;
    }

    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, name)) {
        return false;
    }

    if (bnbuf[1] & 0x80) {
        if (!add_block_to_sexp(sub_s_exp, bnbuf, (size_t) BN_num_bytes(bn) + 1)) {
            return false;
        }
    } else {
        if (!add_block_to_sexp(sub_s_exp, bnbuf + 1, (size_t) BN_num_bytes(bn))) {
            return false;
        }
    }

    return true;
}

static bool
parse_pubkey(pgp_pubkey_t *pubkey, s_exp_t *s_exp, pgp_pubkey_alg_t alg)
{
    pubkey->version = PGP_V4;
    pubkey->birthtime = time(NULL);
    pubkey->duration = 0;
    pubkey->alg = alg;

    switch (alg) {
    case PGP_PKA_DSA:
        pubkey->key.dsa.p = read_bignum(s_exp, "p");
        if (pubkey->key.dsa.p == NULL) {
            return false;
        }

        pubkey->key.dsa.q = read_bignum(s_exp, "q");
        if (pubkey->key.dsa.q == NULL) {
            PGPV_BN_free(pubkey->key.dsa.p);
            return false;
        }

        pubkey->key.dsa.g = read_bignum(s_exp, "g");
        if (pubkey->key.dsa.g == NULL) {
            PGPV_BN_free(pubkey->key.dsa.p);
            PGPV_BN_free(pubkey->key.dsa.q);
            return false;
        }

        pubkey->key.dsa.y = read_bignum(s_exp, "y");
        if (pubkey->key.dsa.y == NULL) {
            PGPV_BN_free(pubkey->key.dsa.p);
            PGPV_BN_free(pubkey->key.dsa.q);
            PGPV_BN_free(pubkey->key.dsa.g);
            return false;
        }

        break;

    case PGP_PKA_RSA:
        pubkey->key.rsa.n = read_bignum(s_exp, "n");
        if (pubkey->key.rsa.n == NULL) {
            return false;
        }

        pubkey->key.rsa.e = read_bignum(s_exp, "e");
        if (pubkey->key.rsa.e == NULL) {
            PGPV_BN_free(pubkey->key.rsa.n);
            return false;
        }

        break;

    case PGP_PKA_ELGAMAL:
        pubkey->key.elgamal.p = read_bignum(s_exp, "p");
        if (pubkey->key.elgamal.p == NULL) {
            return false;
        }

        pubkey->key.elgamal.g = read_bignum(s_exp, "g");
        if (pubkey->key.elgamal.g == NULL) {
            PGPV_BN_free(pubkey->key.elgamal.p);
            return false;
        }

        pubkey->key.elgamal.y = read_bignum(s_exp, "y");
        if (pubkey->key.elgamal.y == NULL) {
            PGPV_BN_free(pubkey->key.elgamal.p);
            PGPV_BN_free(pubkey->key.elgamal.g);
            return false;
        }

        break;

    default:
        fprintf(stderr, "Unsupported public key algorithm: %d\n", alg);
        return false;
    }

    return true;
}

static bool
parse_seckey(pgp_seckey_t *seckey, s_exp_t *s_exp, pgp_pubkey_alg_t alg, bool has_header)
{
    if (seckey->pubkey.version != PGP_V2 && seckey->pubkey.version != PGP_V3 &&
        seckey->pubkey.version != PGP_V4) {
        fprintf(stderr, "You should run parse_seckey only after parse_pubkey\n");
        return false;
    }

    if (!has_header) {
        seckey->s2k_usage = PGP_S2KU_NONE;
        seckey->alg = PGP_SA_PLAINTEXT;
        seckey->hash_alg = PGP_HASH_UNKNOWN;
    }

    switch (alg) {
    case PGP_PKA_DSA:
        seckey->key.dsa.x = read_bignum(s_exp, "x");
        if (seckey->key.dsa.x == NULL) {
            return false;
        }

        break;

    case PGP_PKA_RSA:
        seckey->key.rsa.d = read_bignum(s_exp, "d");
        if (seckey->key.rsa.d == NULL) {
            return false;
        }

        seckey->key.rsa.p = read_bignum(s_exp, "p");
        if (seckey->key.rsa.p == NULL) {
            PGPV_BN_free(seckey->key.rsa.d);
            return false;
        }

        seckey->key.rsa.q = read_bignum(s_exp, "q");
        if (seckey->key.rsa.q == NULL) {
            PGPV_BN_free(seckey->key.rsa.d);
            PGPV_BN_free(seckey->key.rsa.p);
            return false;
        }

        seckey->key.rsa.u = read_bignum(s_exp, "u");
        if (seckey->key.rsa.u == NULL) {
            PGPV_BN_free(seckey->key.rsa.d);
            PGPV_BN_free(seckey->key.rsa.p);
            PGPV_BN_free(seckey->key.rsa.q);
            return false;
        }

        break;

    case PGP_PKA_ELGAMAL:
        seckey->key.elgamal.x = read_bignum(s_exp, "x");
        if (seckey->key.elgamal.x == NULL) {
            return false;
        }

        break;

    default:
        fprintf(stderr, "Unsupported public key algorithm: %d\n", alg);
        return false;
    }

    return true;
}

static pgp_seckey_t *
g10_decrypt_seckey(const pgp_key_t *key, FILE *passfp)
{
    uint8_t            derived_key[PGP_MAX_KEY_SIZE];
    char *             passphrase;
    char               pass[MAX_PASSPHRASE_LENGTH];
    unsigned           keysize;
    uint8_t *          decrypted;
    pgp_seckey_t *     seckey;
    s_exp_t            s_exp = {0};
    size_t             output_written = 0;
    size_t             input_consumed = 0;
    botan_cipher_t     decrypt;
    uint8_t            checksum[G10_SHA1_HASH_SIZE];
    const format_info *info;

    if (key->key.seckey.encrypted_len == 0) {
        fprintf(stderr, "Hasn't got encrypted data!\n");
        return NULL;
    }

    if (pgp_getpassphrase(passfp, pass, sizeof(pass)) == 0) {
        pass[0] = '\0';
    }

    passphrase = rnp_strdup(pass);
    pgp_forget(pass, sizeof(pass));
    if (passphrase == NULL) {
        (void) fprintf(stderr, "bad allocation\n");
        return false;
    }

    keysize = pgp_key_size(key->key.seckey.alg);
    if (keysize == 0) {
        (void) fprintf(stderr, "parse_seckey: unknown symmetric algo\n");
        pgp_forget(passphrase, strlen(passphrase));
        free(passphrase);
        return false;
    }

    if (pgp_s2k_iterated(key->key.seckey.hash_alg,
                         derived_key,
                         keysize,
                         passphrase,
                         key->key.seckey.salt,
                         key->key.seckey.s2k_iterations)) {
        (void) fprintf(stderr, "pgp_s2k_iterated failed\n");
        pgp_forget(passphrase, strlen(passphrase));
        free(passphrase);
        return false;
    }

    pgp_forget(passphrase, strlen(passphrase));
    free(passphrase);

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "input iv", key->key.seckey.iv, G10_CBC_IV_SIZE);
        hexdump(stderr, "key", derived_key, keysize);
        hexdump(stderr, "encrypted", key->key.seckey.encrypted, key->key.seckey.encrypted_len);
    }

    decrypted = malloc(key->key.seckey.encrypted_len);
    if (decrypted == NULL) {
        (void) fprintf(stderr, "can't allocate memory\n");
        return false;
    }

    info =
      find_format(key->key.seckey.alg, key->key.seckey.cipher_mode, key->key.seckey.hash_alg);
    if (info == NULL) {
        fprintf(stderr,
                "Unsupported format, alg: %d, chiper_mode: %d, hash: %d\n",
                key->key.seckey.alg,
                key->key.seckey.cipher_mode,
                key->key.seckey.hash_alg);
        return false;
    }

    if (botan_cipher_init(&decrypt, info->botan_cipher_name, BOTAN_CIPHER_INIT_FLAG_DECRYPT)) {
        (void) fprintf(stderr, "botan_cipher_init failed\n");
        return false;
    }

    if (botan_cipher_set_key(decrypt, derived_key, keysize)) {
        botan_cipher_destroy(decrypt);
        return false;
    }

    if (botan_cipher_start(decrypt, key->key.seckey.iv, info->iv_size)) {
        botan_cipher_destroy(decrypt);
        return false;
    }

    if (botan_cipher_update(decrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            decrypted,
                            key->key.seckey.encrypted_len,
                            &output_written,
                            key->key.seckey.encrypted,
                            key->key.seckey.encrypted_len,
                            &input_consumed)) {
        (void) fprintf(stderr, "botan_cipher_update failed\n");
        botan_cipher_destroy(decrypt);
        return false;
    }

    botan_cipher_destroy(decrypt);

    size_t      length = output_written;
    const char *bytes = (const char *) decrypted;

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "decrypted data", decrypted, length);
    }

    if (!parse_sexp(&s_exp, &bytes, &length)) {
        pgp_forget(decrypted, key->key.seckey.encrypted_len);
        free(decrypted);
        return false;
    }

    // ignore padding data

    pgp_forget(decrypted, key->key.seckey.encrypted_len);
    free(decrypted);

    if (s_exp.sub_elementc == 0 || s_exp.sub_elements[0].is_block) {
        destroy_s_exp(&s_exp);
        (void) fprintf(stderr, "Hasn't got sub s-exp with key data.\n");
        return false;
    }

    seckey = calloc(1, sizeof(*seckey));
    if (seckey == NULL) {
        destroy_s_exp(&s_exp);
        (void) fprintf(stderr, "can't allocate memory\n");
        return false;
    }

    seckey->pubkey = key->key.seckey.pubkey;

    if (!parse_seckey(seckey, &s_exp.sub_elements[0].s_exp, seckey->pubkey.alg, true)) {
        destroy_s_exp(&s_exp);
        return false;
    }

    memcpy(seckey->protected_at, key->key.seckey.protected_at, PGP_PROTECTED_AT_SIZE);

    if (!g10_calculated_hash(seckey, checksum)) {
        destroy_s_exp(&s_exp);
        return false;
    }

    // hash is optional
    if (s_exp.sub_elementc > 1) {
        if (s_exp.sub_elements[1].is_block || s_exp.sub_elements[1].s_exp.sub_elementc < 3 ||
            !s_exp.sub_elements[1].s_exp.sub_elements[0].is_block ||
            !s_exp.sub_elements[1].s_exp.sub_elements[1].is_block ||
            !s_exp.sub_elements[1].s_exp.sub_elements[2].is_block ||
            strncmp("hash",
                    (const char *) s_exp.sub_elements[1].s_exp.sub_elements[0].block.bytes,
                    s_exp.sub_elements[1].s_exp.sub_elements[0].block.len) != 0) {
            destroy_s_exp(&s_exp);
            (void) fprintf(stderr, "Has got wrong hash block at encrypted key data.\n");
            return false;
        }

        if (strncmp("sha1",
                    (const char *) s_exp.sub_elements[1].s_exp.sub_elements[1].block.bytes,
                    s_exp.sub_elements[1].s_exp.sub_elements[1].block.len) != 0) {
            destroy_s_exp(&s_exp);
            (void) fprintf(stderr, "Supported only sha1 hash at encrypted private key.\n");
            return false;
        }

        if (s_exp.sub_elements[1].s_exp.sub_elements[2].block.len != G10_SHA1_HASH_SIZE ||
            memcmp(checksum,
                   s_exp.sub_elements[1].s_exp.sub_elements[2].block.bytes,
                   G10_SHA1_HASH_SIZE) != 0) {
            if (rnp_get_debug(__FILE__)) {
                hexdump(stderr, "Expected hash", checksum, G10_SHA1_HASH_SIZE);
                hexdump(stderr,
                        "Has hash",
                        s_exp.sub_elements[1].s_exp.sub_elements[2].block.bytes,
                        s_exp.sub_elements[1].s_exp.sub_elements[2].block.len);
            }
            destroy_s_exp(&s_exp);
            (void) fprintf(stderr, "Incorrect hash at encrypted private key.\n");
            return false;
        }
    }

    destroy_s_exp(&s_exp);

    return seckey;
}

static bool
parse_protected_seckey(pgp_seckey_t *seckey, s_exp_t *s_exp)
{
    const format_info *format;

    s_exp_t *protected = lookup_variable(s_exp, "protected");
    if (protected == NULL) {
        return NULL;
    }

    if (protected->sub_elementc != 4 || !protected->sub_elements[1].is_block ||
        protected->sub_elements[2].is_block || !protected->sub_elements[3].is_block) {
        fprintf(stderr,
                "Wrong protected format, expected: (protected mode (parms) "
                "encrypted_octet_string)\n");
        return false;
    }

    format = parse_format((const char *) protected->sub_elements[1].block.bytes,
                          protected->sub_elements[1].block.len);
    if (format == NULL) {
        fprintf(stderr,
                "Unsupported protected mode: '%.*s'\n",
                (int) protected->sub_elements[1].block.len,
                protected->sub_elements[1].block.bytes);
        return false;
    }

    seckey->alg = format->cipher;
    seckey->cipher_mode = format->cipher_mode;
    seckey->hash_alg = format->hash_alg;

    s_exp_t *params = &protected->sub_elements[2].s_exp;

    if (params->sub_elementc != 2 || params->sub_elements[0].is_block ||
        !params->sub_elements[1].is_block) {
        fprintf(stderr, "Wrong params format, expected: ((hash salt no_of_iterations) iv)\n");
        return false;
    }

    s_exp_t *alg = &params->sub_elements[0].s_exp;

    if (alg->sub_elementc != 3 || !alg->sub_elements[0].is_block ||
        !alg->sub_elements[1].is_block || !alg->sub_elements[2].is_block) {
        fprintf(stderr,
                "Wrong params sub-level format, expected: (hash salt no_of_iterations)\n");
        return false;
    }

    if (strncmp("sha1",
                (const char *) alg->sub_elements[0].block.bytes,
                alg->sub_elements[0].block.len) != 0) {
        fprintf(stderr,
                "Wrong hashing algorithm, should be sha1 but %.*s\n",
                (int) alg->sub_elements[0].block.len,
                alg->sub_elements[0].block.bytes);
        return false;
    }

    seckey->hash_alg = PGP_HASH_SHA1;
    seckey->s2k_usage = PGP_S2KU_ENCRYPTED;
    seckey->s2k_specifier = PGP_S2KS_ITERATED_AND_SALTED;

    if (alg->sub_elements[1].block.len != PGP_SALT_SIZE) {
        fprintf(stderr,
                "Wrong salt size, should be %d but %d\n",
                PGP_SALT_SIZE,
                (int) alg->sub_elements[1].block.len);
        return false;
    }

    memcpy(seckey->salt, alg->sub_elements[1].block.bytes, alg->sub_elements[1].block.len);
    seckey->s2k_iterations = block_to_unsigned(&alg->sub_elements[2].block);
    if (seckey->s2k_iterations == UINT_MAX) {
        fprintf(stderr,
                "Wrong numbers of iteration, %.*s\n",
                (int) alg->sub_elements[2].block.len,
                alg->sub_elements[2].block.bytes);
        return false;
    }

    if (params->sub_elements[1].block.len != format->iv_size) {
        fprintf(stderr,
                "Wrong nonce size, should be %zu but %d\n",
                format->iv_size,
                (int) params->sub_elements[1].block.len);
        return false;
    }

    memcpy(seckey->iv, params->sub_elements[1].block.bytes, params->sub_elements[1].block.len);

    seckey->encrypted_len = protected->sub_elements[3].block.len;

    seckey->encrypted = malloc(seckey->encrypted_len);
    if (seckey->encrypted == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return false;
    }

    memcpy(seckey->encrypted,
           protected->sub_elements[3].block.bytes,
           protected->sub_elements[3].block.len);
    seckey->decrypt_cb = g10_decrypt_seckey;

    s_exp_t *protected_at = lookup_variable(s_exp, "protected-at");
    if (protected_at != NULL && protected_at->sub_elements[1].is_block) {
        if (protected_at->sub_elements[1].block.len != PGP_PROTECTED_AT_SIZE) {
            fprintf(stderr,
                    "protected-at has wrong length: %zu, expected, %d\n",
                    protected_at->sub_elements[1].block.len,
                    PGP_PROTECTED_AT_SIZE);
            return false;
        }
        memcpy(seckey->protected_at,
               protected_at->sub_elements[1].block.bytes,
               protected_at->sub_elements[1].block.len);
    }

    return true;
}

bool
rnp_key_store_g10_from_mem(pgp_io_t *       io,
                           rnp_key_store_t *pubring,
                           rnp_key_store_t *key_store,
                           pgp_memory_t *   memory)
{
    s_exp_t     s_exp = {0};
    size_t      length = memory->length;
    const char *bytes = (const char *) memory->buf;

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "S-exp", (const uint8_t *) bytes, length);
    }

    if (!parse_sexp(&s_exp, &bytes, &length)) {
        return false;
    }

    /* expected format:
     *  (<type>
     *    (<algo>
     *	   (x <mpi>)
     *	   (y <mpi>)
     *    )
     *  )
     */

    if (s_exp.sub_elementc != 2 || !s_exp.sub_elements[0].is_block ||
        s_exp.sub_elements[1].is_block) {
        fprintf(stderr, "Wrong format, expected: (<type> (...))\n");
        destroy_s_exp(&s_exp);
        return false;
    }

    bool private_key;
    bool protected;
    if (!strncmp("private-key",
                 (const char *) s_exp.sub_elements[0].block.bytes,
                 s_exp.sub_elements[0].block.len)) {
        private_key = true;
      protected
        = false;
    } else if (!strncmp("public-key",
                        (const char *) s_exp.sub_elements[0].block.bytes,
                        s_exp.sub_elements[0].block.len)) {
        private_key = false;
      protected
        = false;
    } else if (!strncmp("protected-private-key",
                        (const char *) s_exp.sub_elements[0].block.bytes,
                        s_exp.sub_elements[0].block.len)) {
        private_key = true;
      protected
        = true;
    } else {
        fprintf(stderr,
                "Unsupported top-level block: '%.*s'\n",
                (int) s_exp.sub_elements[0].block.len,
                s_exp.sub_elements[0].block.bytes);
        destroy_s_exp(&s_exp);
        return false;
    }

    s_exp_t *algorithm_s_exp = &s_exp.sub_elements[1].s_exp;

    if (algorithm_s_exp->sub_elementc < 2) {
        fprintf(stderr,
                "Wrong count of algorithm-level elements: %d, should great than 1\n",
                algorithm_s_exp->sub_elementc);
        destroy_s_exp(&s_exp);
        return false;
    }

    if (!algorithm_s_exp->sub_elements[0].is_block) {
        fprintf(stderr, "Expected block with algorithm name, but has s-exp\n");
        destroy_s_exp(&s_exp);
        return false;
    }

    pgp_pubkey_alg_t alg = PGP_PKA_NOTHING;

    if (!strncmp("rsa",
                 (const char *) algorithm_s_exp->sub_elements[0].block.bytes,
                 algorithm_s_exp->sub_elements[0].block.len)) {
        alg = PGP_PKA_RSA;
    } else if (!strncmp("openpgp-rsa",
                        (const char *) algorithm_s_exp->sub_elements[0].block.bytes,
                        algorithm_s_exp->sub_elements[0].block.len)) {
        alg = PGP_PKA_RSA;
    } else if (!strncmp("oid.1.2.840.113549.1.1.1",
                        (const char *) algorithm_s_exp->sub_elements[0].block.bytes,
                        algorithm_s_exp->sub_elements[0].block.len)) {
        alg = PGP_PKA_RSA;

    } else if (!strncmp("elg",
                        (const char *) algorithm_s_exp->sub_elements[0].block.bytes,
                        algorithm_s_exp->sub_elements[0].block.len)) {
        alg = PGP_PKA_ELGAMAL;
    } else if (!strncmp("elgamal",
                        (const char *) algorithm_s_exp->sub_elements[0].block.bytes,
                        algorithm_s_exp->sub_elements[0].block.len)) {
        alg = PGP_PKA_ELGAMAL;
    } else if (!strncmp("openpgp-elg",
                        (const char *) algorithm_s_exp->sub_elements[0].block.bytes,
                        algorithm_s_exp->sub_elements[0].block.len)) {
        alg = PGP_PKA_ELGAMAL;
    } else if (!strncmp("openpgp-elg-sig",
                        (const char *) algorithm_s_exp->sub_elements[0].block.bytes,
                        algorithm_s_exp->sub_elements[0].block.len)) {
        alg = PGP_PKA_ELGAMAL;

    } else if (!strncmp("dsa",
                        (const char *) algorithm_s_exp->sub_elements[0].block.bytes,
                        algorithm_s_exp->sub_elements[0].block.len)) {
        alg = PGP_PKA_DSA;
    } else if (!strncmp("openpgp-dsa",
                        (const char *) algorithm_s_exp->sub_elements[0].block.bytes,
                        algorithm_s_exp->sub_elements[0].block.len)) {
        alg = PGP_PKA_DSA;

    } else {
        fprintf(stderr,
                "Unsupported algorithm: '%.*s'\n",
                (int) s_exp.sub_elements[0].block.len,
                s_exp.sub_elements[0].block.bytes);
        destroy_s_exp(&s_exp);
        return false;
    }

    pgp_keydata_key_t keydata = {};

    if (!parse_pubkey(&keydata.pubkey, algorithm_s_exp, alg)) {
        destroy_s_exp(&s_exp);
        return false;
    }

    if (private_key) {
        // lookup for exsited key from KBX storage for example to update metadata
        if (pubring != NULL) {
            uint8_t       grip[PGP_FINGERPRINT_SIZE];
            pgp_pubkey_t *pubkey = NULL;
            if (!rnp_key_store_get_key_grip(&keydata.pubkey, grip)) {
                return false;
            }
            if (rnp_key_store_get_key_by_grip(io, pubring, grip, &pubkey)) {
                keydata.pubkey.birthtime = pubkey->birthtime;
                keydata.pubkey.duration = pubkey->duration;
            }
        }
        if (protected) {
            if (!parse_protected_seckey(&keydata.seckey, algorithm_s_exp)) {
                destroy_s_exp(&s_exp);
                return false;
            }
        } else {
            if (!parse_seckey(&keydata.seckey, algorithm_s_exp, alg, false)) {
                destroy_s_exp(&s_exp);
                return false;
            }
        }
    }

    destroy_s_exp(&s_exp);

    if (rnp_get_debug(__FILE__)) {
        uint8_t grip[PGP_FINGERPRINT_SIZE];
        char    grips[PGP_FINGERPRINT_HEX_SIZE];
        if (!rnp_key_store_get_key_grip(&keydata.pubkey, grip)) {
            return false;
        }
        fprintf(io->errs,
                "loaded G10 key with GRIP: %s\n",
                rnp_strhexdump_upper(grips, grip, PGP_FINGERPRINT_SIZE, ""));
    }

    return rnp_key_store_add_keydata(io,
                                     key_store,
                                     &keydata,
                                     NULL,
                                     private_key ? PGP_PTAG_CT_SECRET_KEY :
                                                   PGP_PTAG_CT_PUBLIC_KEY);
}

#define MAX_SIZE_T_LEN ((3 * sizeof(size_t) * CHAR_BIT / 8) + 2)

static bool
write_block(s_exp_block_t *block, pgp_memory_t *mem)
{
    if (!pgp_memory_pad(mem, MAX_SIZE_T_LEN)) {
        return false;
    }
    mem->length +=
      snprintf((char *) (mem->buf + mem->length), MAX_SIZE_T_LEN, "%zu", block->len);

    if (!pgp_memory_add(mem, (const uint8_t *) ":", 1)) {
        return false;
    }

    return pgp_memory_add(mem, block->bytes, block->len);
}

/*
 * Write G10 S-exp to buffer
 *
 * Supported format: (1:a2:ab(3:asd1:a))
 */
static bool
write_sexp(s_exp_t *s_exp, pgp_memory_t *mem)
{
    int i;

    if (!pgp_memory_add(mem, (const uint8_t *) "(", 1)) {
        return false;
    }

    for (i = 0; i < s_exp->sub_elementc; i++) {
        if (s_exp->sub_elements[i].is_block) {
            if (!write_block(&s_exp->sub_elements[i].block, mem)) {
                return false;
            }
        } else {
            if (!write_sexp(&s_exp->sub_elements[i].s_exp, mem)) {
                return false;
            }
        }
    }

    return pgp_memory_add(mem, (const uint8_t *) ")", 1);
}

static bool
write_pubkey(s_exp_t *s_exp, pgp_pubkey_t *key)
{
    switch (key->alg) {
    case PGP_PKA_DSA:
        if (!add_string_block_to_sexp(s_exp, "dsa")) {
            return false;
        }

        if (!write_bignum(s_exp, "p", key->key.dsa.p)) {
            return false;
        }

        if (!write_bignum(s_exp, "q", key->key.dsa.q)) {
            return false;
        }

        if (!write_bignum(s_exp, "g", key->key.dsa.g)) {
            return false;
        }

        if (!write_bignum(s_exp, "y", key->key.dsa.y)) {
            return false;
        }

        break;

    case PGP_PKA_RSA_SIGN_ONLY:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA:
        if (!add_string_block_to_sexp(s_exp, "rsa")) {
            return false;
        }

        if (!write_bignum(s_exp, "n", key->key.rsa.n)) {
            return false;
        }

        if (!write_bignum(s_exp, "e", key->key.rsa.e)) {
            return false;
        }

        break;

    case PGP_PKA_ELGAMAL:
        if (!add_string_block_to_sexp(s_exp, "elg")) {
            return false;
        }

        if (!write_bignum(s_exp, "p", key->key.elgamal.p)) {
            return false;
        }

        if (!write_bignum(s_exp, "g", key->key.elgamal.g)) {
            return false;
        }

        if (!write_bignum(s_exp, "y", key->key.elgamal.y)) {
            return false;
        }

    default:
        fprintf(stderr, "Unsupported public key algorithm: %d\n", key->alg);
        return NULL;
    }

    return true;
}

static bool
write_seckey(s_exp_t *s_exp, pgp_seckey_t *key)
{
    switch (key->pubkey.alg) {
    case PGP_PKA_DSA:
        if (!write_bignum(s_exp, "x", key->key.dsa.x)) {
            return false;
        }

        break;

    case PGP_PKA_RSA_SIGN_ONLY:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA:
        if (!write_bignum(s_exp, "d", key->key.rsa.d)) {
            return false;
        }

        if (!write_bignum(s_exp, "p", key->key.rsa.p)) {
            return false;
        }

        if (!write_bignum(s_exp, "q", key->key.rsa.q)) {
            return false;
        }

        if (!write_bignum(s_exp, "u", key->key.rsa.u)) {
            return false;
        }

        break;

    case PGP_PKA_ELGAMAL:
        if (!write_bignum(s_exp, "x", key->key.elgamal.x)) {
            return false;
        }

    default:
        fprintf(stderr, "Unsupported public key algorithm: %d\n", key->pubkey.alg);
        return NULL;
    }

    return true;
}

static bool
g10_calculated_hash(pgp_seckey_t *key, uint8_t *checksum)
{
    s_exp_t      s_exp = {0};
    s_exp_t *    sub_s_exp;
    pgp_memory_t mem = {0};
    pgp_hash_t   hash = {0};

    if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
        goto error;
    }

    if (hash._output_len != G10_SHA1_HASH_SIZE) {
        fprintf(stderr,
                "wrong hash size %zu, should be %d bytes\n",
                hash._output_len,
                G10_SHA1_HASH_SIZE);
        goto error;
    }

    if (!write_pubkey(&s_exp, &key->pubkey)) {
        goto error;
    }

    if (!write_seckey(&s_exp, key)) {
        goto error;
    }

    if (!add_sub_sexp_to_sexp(&s_exp, &sub_s_exp)) {
        goto error;
    }

    if (!add_string_block_to_sexp(sub_s_exp, "protected-at")) {
        goto error;
    }

    if (!add_block_to_sexp(sub_s_exp, (uint8_t *) key->protected_at, PGP_PROTECTED_AT_SIZE)) {
        goto error;
    }

    if (!write_sexp(&s_exp, &mem)) {
        goto error;
    }

    destroy_s_exp(&s_exp);

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "data for hashing", mem.buf, mem.length);
    }

    pgp_hash_add(&hash, mem.buf, mem.length);

    pgp_memory_release(&mem);

    if (!pgp_hash_finish(&hash, checksum)) {
        goto error;
    }

    return true;

error:
    destroy_s_exp(&s_exp);
    return false;
}

static bool
write_protected_seckey(s_exp_t *s_exp, pgp_seckey_t *key, const uint8_t *passphrase)
{
    const format_info *format;
    s_exp_t            raw_s_exp = {0};
    s_exp_t *          sub_s_exp, *sub_sub_s_exp, *sub_sub_sub_s_exp;
    botan_cipher_t     encrypt = NULL;
    uint8_t            derived_key[PGP_MAX_KEY_SIZE];
    unsigned           keysize;
    pgp_memory_t       raw = {0};
    uint8_t            checksum[G10_SHA1_HASH_SIZE];
    time_t             now;
    size_t             output_written = 0;
    size_t             input_consumed = 0;

    if (key->s2k_specifier != PGP_S2KS_ITERATED_AND_SALTED) {
        fprintf(stderr, "s2k should be iterated and salted\n");
        return false;
    }

    format = find_format(key->alg, key->cipher_mode, key->hash_alg);
    if (format == NULL) {
        fprintf(stderr,
                "Unsupported format, alg: %d, chiper_mode: %d, hash: %d\n",
                key->alg,
                key->cipher_mode,
                key->hash_alg);
        return false;
    }

    // if we had encrypted block, don't renecrypt
    if (key->encrypted_len > 0 && key->encrypted != NULL) {
        goto write;
    }

    // randomize IV and salt
    if (pgp_random(&key->iv[0], sizeof(key->iv))) {
        RNP_LOG("pgp_random failed");
        return false;
    }

    if (pgp_random(&key->salt[0], sizeof(key->salt))) {
        RNP_LOG("pgp_random failed");
        return false;
    }

    if (!add_sub_sexp_to_sexp(&raw_s_exp, &sub_s_exp)) {
        destroy_s_exp(&raw_s_exp);
        return false;
    }

    if (!write_seckey(sub_s_exp, key)) {
        destroy_s_exp(&raw_s_exp);
        return false;
    }

    // calculated hash
    time(&now);
    strftime(
      (char *) key->protected_at, sizeof(key->protected_at), "%Y%m%dT%H%M%S", gmtime(&now));

    if (!g10_calculated_hash(key, checksum)) {
        destroy_s_exp(&raw_s_exp);
        return false;
    }

    if (!add_sub_sexp_to_sexp(&raw_s_exp, &sub_s_exp)) {
        destroy_s_exp(&raw_s_exp);
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, "hash")) {
        destroy_s_exp(&raw_s_exp);
        pgp_memory_release(&raw);
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, "sha1")) {
        destroy_s_exp(&raw_s_exp);
        pgp_memory_release(&raw);
        return false;
    }

    if (!add_block_to_sexp(sub_s_exp, checksum, sizeof(checksum))) {
        destroy_s_exp(&raw_s_exp);
        pgp_memory_release(&raw);
        return false;
    }

    if (!write_sexp(&raw_s_exp, &raw)) {
        destroy_s_exp(&raw_s_exp);
        pgp_memory_release(&raw);
        return false;
    }

    keysize = pgp_key_size(key->alg);
    if (keysize == 0) {
        (void) fprintf(stderr, "parse_seckey: unknown symmetric algo");
        destroy_s_exp(&raw_s_exp);
        pgp_memory_release(&raw);
        return false;
    }

    if (pgp_s2k_iterated(format->hash_alg,
                         derived_key,
                         keysize,
                         (const char *) passphrase,
                         key->salt,
                         key->s2k_iterations)) {
        (void) fprintf(stderr, "pgp_s2k_iterated failed\n");
        destroy_s_exp(&raw_s_exp);
        pgp_memory_release(&raw);
        return false;
    }

    // add padding!
    for (int i = (int) (format->chiper_block_size - raw.length % format->chiper_block_size);
         i > 0;
         i--) {
        if (!pgp_memory_add(&raw, (const uint8_t *) "X", 1)) {
            return false;
        }
    }

    key->encrypted_len = raw.length;

    key->encrypted = malloc(key->encrypted_len);
    if (key->encrypted == NULL) {
        (void) fprintf(stderr, "can't allocate memory\n");
        destroy_s_exp(&raw_s_exp);
        pgp_memory_release(&raw);
        return false;
    }

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "input iv", key->iv, G10_CBC_IV_SIZE);
        hexdump(stderr, "key", derived_key, keysize);
        hexdump(stderr, "raw data", raw.buf, raw.length);
    }

    if (botan_cipher_init(
          &encrypt, format->botan_cipher_name, BOTAN_CIPHER_INIT_FLAG_ENCRYPT)) {
        (void) fprintf(stderr, "botan_cipher_init failed\n");
        goto error;
    }

    if (botan_cipher_set_key(encrypt, derived_key, keysize)) {
        goto error;
    }

    if (botan_cipher_start(encrypt, key->iv, format->iv_size)) {
        goto error;
    }

    if (botan_cipher_update(encrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            key->encrypted,
                            key->encrypted_len,
                            &output_written,
                            raw.buf,
                            raw.length,
                            &input_consumed)) {
        (void) fprintf(stderr, "botan_cipher_update failed\n");
        goto error;
    }

    destroy_s_exp(&raw_s_exp);
    pgp_memory_release(&raw);
    botan_cipher_destroy(encrypt);

    key->encrypted_len = output_written;

write:
    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, "protected")) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, format->g10_type)) {
        return false;
    }

    if (!add_sub_sexp_to_sexp(sub_s_exp, &sub_sub_s_exp)) {
        return false;
    }

    if (!add_sub_sexp_to_sexp(sub_sub_s_exp, &sub_sub_sub_s_exp)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_sub_sub_s_exp, "sha1")) {
        return false;
    }

    if (!add_block_to_sexp(sub_sub_sub_s_exp, key->salt, PGP_SALT_SIZE)) {
        return false;
    }

    if (!add_unsigned_block_to_sexp(sub_sub_sub_s_exp, key->s2k_iterations)) {
        return false;
    }

    if (!add_block_to_sexp(sub_sub_s_exp, key->iv, format->iv_size)) {
        return false;
    }

    if (!add_block_to_sexp(sub_s_exp, key->encrypted, key->encrypted_len)) {
        return false;
    }

    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, "protected-at")) {
        return false;
    }

    if (!add_block_to_sexp(sub_s_exp, (uint8_t *) key->protected_at, PGP_PROTECTED_AT_SIZE)) {
        return false;
    }

    return true;

error:
    free(key->encrypted);
    key->encrypted = NULL;
    key->encrypted_len = 0;
    destroy_s_exp(&raw_s_exp);
    pgp_memory_release(&raw);
    botan_cipher_destroy(encrypt);
    return false;
}

bool
rnp_key_store_g10_key_to_mem(pgp_io_t *     io,
                             pgp_key_t *    key,
                             const uint8_t *passphrase,
                             pgp_memory_t * memory)
{
    bool     rc;
    s_exp_t  s_exp = {0};
    s_exp_t *sub_s_exp;

    switch (key->type) {
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        if (!add_string_block_to_sexp(&s_exp, "public-key")) {
            return false;
        }

        if (!add_sub_sexp_to_sexp(&s_exp, &sub_s_exp)) {
            return false;
        }

        if (!write_pubkey(sub_s_exp, &key->key.pubkey)) {
            return false;
        }

        break;

    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        if (key->key.seckey.alg == PGP_SA_PLAINTEXT) {
            if (!add_string_block_to_sexp(&s_exp, "private-key")) {
                return false;
            }
        } else {
            if (!add_string_block_to_sexp(&s_exp, "protected-private-key")) {
                return false;
            }

            // force switch to AES with CBC and SHA-1
            if (key->key.seckey.alg != PGP_SA_AES_128) {
                key->key.seckey.alg = PGP_SA_AES_128;
            }

            if (key->key.seckey.cipher_mode != PGP_CIPHER_MODE_CBC) {
                key->key.seckey.cipher_mode = PGP_CIPHER_MODE_CBC;
            }

            if (key->key.seckey.hash_alg != PGP_HASH_SHA1) {
                key->key.seckey.hash_alg = PGP_HASH_SHA1;
            }
        }

        if (!add_sub_sexp_to_sexp(&s_exp, &sub_s_exp)) {
            return false;
        }

        if (!write_pubkey(sub_s_exp, &key->key.pubkey)) {
            return false;
        }

        if (passphrase == NULL || *passphrase == '\0') {
            if (!write_seckey(sub_s_exp, &key->key.seckey)) {
                return false;
            }
        } else {
            switch (key->key.seckey.alg) {
            case PGP_SA_PLAINTEXT:
                if (!write_seckey(sub_s_exp, &key->key.seckey)) {
                    return false;
                }
                break;

            case PGP_SA_AES_128:
            case PGP_SA_AES_256:
                if (!write_protected_seckey(sub_s_exp, &key->key.seckey, passphrase)) {
                    return false;
                }
                break;

            default:
                fprintf(stderr,
                        "Unsupported private key symetric algorithm: %d\n",
                        key->key.seckey.alg);
                return false;
            }
        }

        break;

    default:
        fprintf(stderr, "Can't write key type: %d\n", key->type);
        return false;
    }

    rc = write_sexp(&s_exp, memory);
    destroy_s_exp(&s_exp);
    return rc;
}