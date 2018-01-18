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
#include <time.h>

#include <rnp/rnp_sdk.h>

#include "key_store_pgp.h"
#include "key_store_g10.h"

#include "crypto/bn.h"
#include "crypto/s2k.h"
#include "symmetric.h"
#include "writer.h"
#include "pgp-key.h"
#include <botan/ffi.h>

#define G10_CBC_IV_SIZE 16

#define G10_OCB_NONCE_SIZE 12

#define G10_SHA1_HASH_SIZE 20

#define G10_PROTECTED_AT_SIZE 15

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

static bool g10_calculated_hash(const pgp_seckey_t *key,
                                const char *        protected_at,
                                uint8_t *           checksum);
pgp_seckey_t *g10_decrypt_seckey(const uint8_t *     data,
                                 size_t              data_len,
                                 const pgp_pubkey_t *pubkey,
                                 const char *        password);

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
    unsigned i;

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

    for (unsigned i = 0; i < s_exp->sub_elementc; i++) {
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

        if (len == LONG_MIN || len == LONG_MAX || len <= 0 || (size_t) len >= length) {
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
    for (unsigned i = 0; i < s_exp->sub_elementc; i++) {
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

static bignum_t *
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

    bignum_t *res =
      bn_bin2bn(var->sub_elements[1].block.bytes, (int) var->sub_elements[1].block.len, NULL);
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
write_bignum(s_exp_t *s_exp, const char *name, bignum_t *bn)
{
    uint8_t bnbuf[RNP_BUFSIZ];

    s_exp_t *sub_s_exp;

    bnbuf[0] = 0;

    if (bn_bn2bin(bn, bnbuf + 1) < 0) {
        return false;
    }

    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, name)) {
        return false;
    }

    size_t sz;
    if (bnbuf[1] & 0x80) {
        if (!bn_num_bytes(bn, &sz) || !add_block_to_sexp(sub_s_exp, bnbuf, sz + 1)) {
            return false;
        }
    } else {
        if (!bn_num_bytes(bn, &sz) || !add_block_to_sexp(sub_s_exp, bnbuf + 1, sz)) {
            return false;
        }
    }

    return true;
}

static bool
parse_pubkey(pgp_pubkey_t *pubkey, s_exp_t *s_exp, pgp_pubkey_alg_t alg)
{
    pubkey->version = PGP_V4;
    pubkey->alg = alg;
    switch (alg) {
    case PGP_PKA_DSA:
        pubkey->key.dsa.p = read_bignum(s_exp, "p");
        if (pubkey->key.dsa.p == NULL) {
            return false;
        }

        pubkey->key.dsa.q = read_bignum(s_exp, "q");
        if (pubkey->key.dsa.q == NULL) {
            bn_free(pubkey->key.dsa.p);
            return false;
        }

        pubkey->key.dsa.g = read_bignum(s_exp, "g");
        if (pubkey->key.dsa.g == NULL) {
            bn_free(pubkey->key.dsa.p);
            bn_free(pubkey->key.dsa.q);
            return false;
        }

        pubkey->key.dsa.y = read_bignum(s_exp, "y");
        if (pubkey->key.dsa.y == NULL) {
            bn_free(pubkey->key.dsa.p);
            bn_free(pubkey->key.dsa.q);
            bn_free(pubkey->key.dsa.g);
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
            bn_free(pubkey->key.rsa.n);
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
            bn_free(pubkey->key.elgamal.p);
            return false;
        }

        pubkey->key.elgamal.y = read_bignum(s_exp, "y");
        if (pubkey->key.elgamal.y == NULL) {
            bn_free(pubkey->key.elgamal.p);
            bn_free(pubkey->key.elgamal.g);
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
parse_seckey(pgp_seckey_t *seckey, s_exp_t *s_exp, pgp_pubkey_alg_t alg)
{
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
            bn_free(seckey->key.rsa.d);
            return false;
        }

        seckey->key.rsa.q = read_bignum(s_exp, "q");
        if (seckey->key.rsa.q == NULL) {
            bn_free(seckey->key.rsa.d);
            bn_free(seckey->key.rsa.p);
            return false;
        }

        seckey->key.rsa.u = read_bignum(s_exp, "u");
        if (seckey->key.rsa.u == NULL) {
            bn_free(seckey->key.rsa.d);
            bn_free(seckey->key.rsa.p);
            bn_free(seckey->key.rsa.q);
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

static bool
decrypt_protected_section(const uint8_t *     encrypted_data,
                          size_t              encrypted_data_len,
                          const pgp_seckey_t *seckey,
                          const char *        password,
                          s_exp_t *           r_s_exp)
{
    const format_info *info = NULL;
    unsigned           keysize = 0;
    uint8_t            derived_key[PGP_MAX_KEY_SIZE];
    uint8_t *          decrypted_data = NULL;
    size_t             decrypted_data_len = 0;
    size_t             output_written = 0;
    size_t             input_consumed = 0;
    botan_cipher_t     decrypt = NULL;
    bool               ret = false;

    // sanity checks
    keysize = pgp_key_size(seckey->protection.symm_alg);
    if (!keysize) {
        RNP_LOG("parse_seckey: unknown symmetric algo");
        goto done;
    }
    // find the protection format in our table
    info = find_format(seckey->protection.symm_alg,
                       seckey->protection.cipher_mode,
                       seckey->protection.s2k.hash_alg);
    if (!info) {
        RNP_LOG("Unsupported format, alg: %d, chiper_mode: %d, hash: %d",
                seckey->protection.symm_alg,
                seckey->protection.cipher_mode,
                seckey->protection.s2k.hash_alg);
        goto done;
    }

    // derive the key
    if (pgp_s2k_iterated(seckey->protection.s2k.hash_alg,
                         derived_key,
                         keysize,
                         password,
                         seckey->protection.s2k.salt,
                         seckey->protection.s2k.iterations)) {
        RNP_LOG("pgp_s2k_iterated failed");
        goto done;
    }
    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "input iv", seckey->protection.iv, G10_CBC_IV_SIZE);
        hexdump(stderr, "key", derived_key, keysize);
        hexdump(stderr, "encrypted", encrypted_data, encrypted_data_len);
    }

    // decrypt
    decrypted_data = malloc(encrypted_data_len);
    if (decrypted_data == NULL) {
        RNP_LOG("can't allocate memory");
        goto done;
    }
    if (botan_cipher_init(&decrypt, info->botan_cipher_name, BOTAN_CIPHER_INIT_FLAG_DECRYPT)) {
        RNP_LOG("botan_cipher_init failed");
        goto done;
    }
    if (botan_cipher_set_key(decrypt, derived_key, keysize) ||
        botan_cipher_start(decrypt, seckey->protection.iv, info->iv_size)) {
        goto done;
    }
    if (botan_cipher_update(decrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            decrypted_data,
                            encrypted_data_len,
                            &output_written,
                            encrypted_data,
                            encrypted_data_len,
                            &input_consumed)) {
        RNP_LOG("botan_cipher_update failed");
        goto done;
    }
    decrypted_data_len = output_written;
    const char *decrypted_bytes = (const char *) decrypted_data;
    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "decrypted data", decrypted_data, decrypted_data_len);
    }

    // parse and validate the decrypted s-exp
    size_t s_exp_len = decrypted_data_len;
    if (!parse_sexp(r_s_exp, &decrypted_bytes, &s_exp_len)) {
        goto done;
    }
    if (r_s_exp->sub_elementc == 0 || r_s_exp->sub_elements[0].is_block) {
        RNP_LOG("Hasn't got sub s-exp with key data.");
        goto done;
    }

    ret = true;

done:
    if (!ret) {
        destroy_s_exp(r_s_exp);
    }
    pgp_forget(decrypted_data, decrypted_data_len);
    free(decrypted_data);
    botan_cipher_destroy(decrypt);
    return ret;
}

static bool
parse_protected_seckey(pgp_seckey_t *seckey, s_exp_t *s_exp, const char *password)
{
    const format_info *format;
    bool               ret = false;
    s_exp_t            decrypted_s_exp = {0};

    // find and validate the protected section
    s_exp_t *protected = lookup_variable(s_exp, "protected");
    if (!protected) {
        RNP_LOG("missing protected section");
        goto done;
    }
    if (protected->sub_elementc != 4 || !protected->sub_elements[1].is_block ||
        protected->sub_elements[2].is_block || !protected->sub_elements[3].is_block) {
        RNP_LOG("Wrong protected format, expected: (protected mode (parms) "
                "encrypted_octet_string)\n");
        goto done;
    }

    // lookup the protection format
    format = parse_format((const char *) protected->sub_elements[1].block.bytes,
                          protected->sub_elements[1].block.len);
    if (format == NULL) {
        RNP_LOG("Unsupported protected mode: '%.*s'\n",
                (int) protected->sub_elements[1].block.len,
                protected->sub_elements[1].block.bytes);
        goto done;
    }

    // fill in some fields based on the lookup above
    seckey->protection.symm_alg = format->cipher;
    seckey->protection.cipher_mode = format->cipher_mode;
    seckey->protection.s2k.hash_alg = format->hash_alg;

    // locate and validate the protection parameters
    s_exp_t *params = &protected->sub_elements[2].s_exp;
    if (params->sub_elementc != 2 || params->sub_elements[0].is_block ||
        !params->sub_elements[1].is_block) {
        RNP_LOG("Wrong params format, expected: ((hash salt no_of_iterations) iv)\n");
        goto done;
    }

    // locate and validate the (hash salt no_of_iterations) exp
    s_exp_t *alg = &params->sub_elements[0].s_exp;
    if (alg->sub_elementc != 3 || !alg->sub_elements[0].is_block ||
        !alg->sub_elements[1].is_block || !alg->sub_elements[2].is_block) {
        RNP_LOG("Wrong params sub-level format, expected: (hash salt no_of_iterations)\n");
        goto done;
    }
    if (strncmp("sha1",
                (const char *) alg->sub_elements[0].block.bytes,
                alg->sub_elements[0].block.len) != 0) {
        RNP_LOG("Wrong hashing algorithm, should be sha1 but %.*s\n",
                (int) alg->sub_elements[0].block.len,
                alg->sub_elements[0].block.bytes);
        goto done;
    }

    // fill in some constant values
    seckey->protection.s2k.hash_alg = PGP_HASH_SHA1;
    seckey->protection.s2k.usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
    seckey->protection.s2k.specifier = PGP_S2KS_ITERATED_AND_SALTED;

    // check salt size
    if (alg->sub_elements[1].block.len != PGP_SALT_SIZE) {
        RNP_LOG("Wrong salt size, should be %d but %d\n",
                PGP_SALT_SIZE,
                (int) alg->sub_elements[1].block.len);
        goto done;
    }

    // salt
    memcpy(seckey->protection.s2k.salt,
           alg->sub_elements[1].block.bytes,
           alg->sub_elements[1].block.len);
    seckey->protection.s2k.iterations = block_to_unsigned(&alg->sub_elements[2].block);
    if (seckey->protection.s2k.iterations == UINT_MAX) {
        RNP_LOG("Wrong numbers of iteration, %.*s\n",
                (int) alg->sub_elements[2].block.len,
                alg->sub_elements[2].block.bytes);
        goto done;
    }

    // iv
    if (params->sub_elements[1].block.len != format->iv_size) {
        RNP_LOG("Wrong nonce size, should be %zu but %d\n",
                format->iv_size,
                (int) params->sub_elements[1].block.len);
        goto done;
    }
    memcpy(seckey->protection.iv,
           params->sub_elements[1].block.bytes,
           params->sub_elements[1].block.len);

    // we're all done if no password was provided (decryption not requested)
    if (!password) {
        seckey->encrypted = true;
        ret = true;
        goto done;
    }

    // password was provided, so decrypt
    if (!decrypt_protected_section(protected->sub_elements[3].block.bytes,
                                   protected->sub_elements[3].block.len,
                                   seckey,
                                   password,
                                   &decrypted_s_exp)) {
        goto done;
    }
    // see if we have a protected-at section
    s_exp_t *protected_at_s_exp = lookup_variable(s_exp, "protected-at");
    char     protected_at[G10_PROTECTED_AT_SIZE];
    if (protected_at_s_exp != NULL && protected_at_s_exp->sub_elements[1].is_block) {
        if (protected_at_s_exp->sub_elements[1].block.len != G10_PROTECTED_AT_SIZE) {
            RNP_LOG("protected-at has wrong length: %zu, expected, %d\n",
                    protected_at_s_exp->sub_elements[1].block.len,
                    G10_PROTECTED_AT_SIZE);
            goto done;
        }
        memcpy(protected_at,
               protected_at_s_exp->sub_elements[1].block.bytes,
               protected_at_s_exp->sub_elements[1].block.len);
    }
    // parse MPIs
    if (!parse_seckey(seckey, &decrypted_s_exp.sub_elements[0].s_exp, seckey->pubkey.alg)) {
        RNP_LOG("failed to parse seckey");
        goto done;
    }
    // check hash, if present
    if (decrypted_s_exp.sub_elementc > 1) {
        if (decrypted_s_exp.sub_elements[1].is_block ||
            decrypted_s_exp.sub_elements[1].s_exp.sub_elementc < 3 ||
            !decrypted_s_exp.sub_elements[1].s_exp.sub_elements[0].is_block ||
            !decrypted_s_exp.sub_elements[1].s_exp.sub_elements[1].is_block ||
            !decrypted_s_exp.sub_elements[1].s_exp.sub_elements[2].is_block ||
            strncmp(
              "hash",
              (const char *) decrypted_s_exp.sub_elements[1].s_exp.sub_elements[0].block.bytes,
              decrypted_s_exp.sub_elements[1].s_exp.sub_elements[0].block.len) != 0) {
            RNP_LOG("Has got wrong hash block at encrypted key data.");
            goto done;
        }

        if (strncmp(
              "sha1",
              (const char *) decrypted_s_exp.sub_elements[1].s_exp.sub_elements[1].block.bytes,
              decrypted_s_exp.sub_elements[1].s_exp.sub_elements[1].block.len) != 0) {
            RNP_LOG("Supported only sha1 hash at encrypted private key.");
            goto done;
        }

        if (!g10_calculated_hash(seckey, protected_at, seckey->checkhash)) {
            RNP_LOG("failed to calculate hash");
            goto done;
        }

        if (decrypted_s_exp.sub_elements[1].s_exp.sub_elements[2].block.len !=
              G10_SHA1_HASH_SIZE ||
            memcmp(seckey->checkhash,
                   decrypted_s_exp.sub_elements[1].s_exp.sub_elements[2].block.bytes,
                   G10_SHA1_HASH_SIZE) != 0) {
            if (rnp_get_debug(__FILE__)) {
                hexdump(stderr, "Expected hash", seckey->checkhash, G10_SHA1_HASH_SIZE);
                hexdump(stderr,
                        "Has hash",
                        decrypted_s_exp.sub_elements[1].s_exp.sub_elements[2].block.bytes,
                        decrypted_s_exp.sub_elements[1].s_exp.sub_elements[2].block.len);
            }
            RNP_LOG("Incorrect hash at encrypted private key.");
            goto done;
        }
    }
    seckey->encrypted = false;
    ret = true;

done:
    destroy_s_exp(&decrypted_s_exp);
    return ret;
}

static bool
g10_parse_seckey(pgp_io_t *       io,
                 pgp_seckey_t *   seckey,
                 const uint8_t *  data,
                 size_t           data_len,
                 rnp_key_store_t *pubring,
                 const char *     password)
{
    s_exp_t s_exp = {0};
    bool    ret = false;
    // pgp_io_t    io = {.outs = stdout, .errs = stderr, .res = stdout};

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "S-exp", (const uint8_t *) data, data_len);
    }

    const char *bytes = (const char *) data;
    if (!parse_sexp(&s_exp, &bytes, &data_len)) {
        goto done;
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
        goto done;
    }

    bool protected;
    if (!strncmp("private-key",
                 (const char *) s_exp.sub_elements[0].block.bytes,
                 s_exp.sub_elements[0].block.len)) {
      protected
        = false;
    } else if (!strncmp("protected-private-key",
                        (const char *) s_exp.sub_elements[0].block.bytes,
                        s_exp.sub_elements[0].block.len)) {
      protected
        = true;
    } else {
        fprintf(stderr,
                "Unsupported top-level block: '%.*s'\n",
                (int) s_exp.sub_elements[0].block.len,
                s_exp.sub_elements[0].block.bytes);
        goto done;
    }

    s_exp_t *algorithm_s_exp = &s_exp.sub_elements[1].s_exp;

    if (algorithm_s_exp->sub_elementc < 2) {
        fprintf(stderr,
                "Wrong count of algorithm-level elements: %d, should great than 1\n",
                algorithm_s_exp->sub_elementc);
        goto done;
    }

    if (!algorithm_s_exp->sub_elements[0].is_block) {
        fprintf(stderr, "Expected block with algorithm name, but has s-exp\n");
        goto done;
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
        goto done;
    }

    if (!parse_pubkey(&seckey->pubkey, algorithm_s_exp, alg)) {
        RNP_LOG("failed to parse pubkey");
        goto done;
    }

    if (pubring) {
        uint8_t    grip[PGP_FINGERPRINT_SIZE];
        pgp_key_t *pubkey = NULL;
        if (!rnp_key_store_get_key_grip(&seckey->pubkey, grip)) {
            goto done;
        }
        if ((pubkey = rnp_key_store_get_key_by_grip(io, pubring, grip))) {
            pgp_pubkey_t tmp = seckey->pubkey;
            seckey->pubkey = *pgp_get_pubkey(pubkey);
            seckey->pubkey.key = tmp.key;
        }
    }

    if (protected) {
        if (!parse_protected_seckey(seckey, algorithm_s_exp, password)) {
            goto done;
        }
    } else {
        seckey->protection.s2k.usage = PGP_S2KU_NONE;
        seckey->protection.symm_alg = PGP_SA_PLAINTEXT;
        seckey->protection.s2k.hash_alg = PGP_HASH_UNKNOWN;
        if (!parse_seckey(seckey, algorithm_s_exp, alg)) {
            RNP_LOG("failed to parse seckey");
            goto done;
        }
    }

    if (rnp_get_debug(__FILE__)) {
        uint8_t grip[PGP_FINGERPRINT_SIZE];
        char    grips[PGP_FINGERPRINT_HEX_SIZE];
        if (rnp_key_store_get_key_grip(&seckey->pubkey, grip)) {
            RNP_LOG("loaded G10 key with GRIP: %s\n",
                    rnp_strhexdump_upper(grips, grip, PGP_FINGERPRINT_SIZE, ""));
        }
    }
    ret = true;

done:
    destroy_s_exp(&s_exp);
    if (!ret) {
        pgp_seckey_free(seckey);
    }
    return ret;
}

pgp_seckey_t *
g10_decrypt_seckey(const uint8_t *     data,
                   size_t              data_len,
                   const pgp_pubkey_t *pubkey,
                   const char *        password)
{
    pgp_seckey_t *seckey = NULL;
    pgp_io_t      io = {.errs = stderr, .res = stdout, .outs = stdout};
    bool          ok = false;

    if (!password) {
        return NULL;
    }

    seckey = calloc(1, sizeof(*seckey));
    if (!g10_parse_seckey(&io, seckey, data, data_len, NULL, password)) {
        goto done;
    }
    if (pubkey) {
        pgp_pubkey_t tmp = seckey->pubkey;
        seckey->pubkey = *pubkey;
        seckey->pubkey.key = tmp.key;
    }
    ok = true;

done:
    if (!ok) {
        free(seckey);
        seckey = NULL;
    }
    return seckey;
}

bool
rnp_key_store_g10_from_mem(pgp_io_t *       io,
                           rnp_key_store_t *pubring,
                           rnp_key_store_t *key_store,
                           pgp_memory_t *   memory)
{
    pgp_key_t *key = NULL;
    bool       ret = false;

    pgp_keydata_key_t keydata = {{0}};
    if (!g10_parse_seckey(io, &keydata.seckey, memory->buf, memory->length, pubring, NULL)) {
        goto done;
    }
    if (!rnp_key_store_add_keydata(io, key_store, &keydata, &key, PGP_PTAG_CT_SECRET_KEY)) {
        goto done;
    }
    if (key->packetc != 0) {
        // shouldn't ever happen, but just in case
        goto done;
    }
    EXPAND_ARRAY(key, packet);
    if (!key->packets) {
        goto done;
    }
    key->packets[0].raw = malloc(memory->length);
    key->packets[0].length = memory->length;
    memcpy(key->packets[0].raw, memory->buf, memory->length);
    key->packetc++;
    key->format = G10_KEY_STORE;
    key->is_protected = keydata.seckey.encrypted;
    ret = true;

done:
    if (!ret) {
        pgp_key_free_data(key);
        rnp_key_store_remove_key(io, key_store, key);
    }
    return ret;
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
    if (!pgp_memory_add(mem, (const uint8_t *) "(", 1)) {
        return false;
    }

    for (unsigned i = 0; i < s_exp->sub_elementc; i++) {
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
write_pubkey(s_exp_t *s_exp, const pgp_pubkey_t *key)
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
write_seckey(s_exp_t *s_exp, const pgp_seckey_t *key)
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
write_protected_seckey(s_exp_t *s_exp, pgp_seckey_t *seckey, const char *password)
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

    if (seckey->protection.s2k.specifier != PGP_S2KS_ITERATED_AND_SALTED) {
        fprintf(stderr, "s2k should be iterated and salted\n");
        return false;
    }

    format = find_format(seckey->protection.symm_alg,
                         seckey->protection.cipher_mode,
                         seckey->protection.s2k.hash_alg);
    if (format == NULL) {
        fprintf(stderr,
                "Unsupported format, alg: %d, chiper_mode: %d, hash: %d\n",
                seckey->protection.symm_alg,
                seckey->protection.cipher_mode,
                seckey->protection.s2k.hash_alg);
        return false;
    }

    // randomize IV and salt
    rng_t rng = {0};
    if (!rng_init(&rng, RNG_SYSTEM) ||
        !rng_get_data(&rng, &seckey->protection.iv[0], sizeof(seckey->protection.iv)) ||
        !rng_get_data(
          &rng, &seckey->protection.s2k.salt[0], sizeof(seckey->protection.s2k.salt))) {
        rng_destroy(&rng);
        RNP_LOG("rng_generate failed");
        return false;
    }
    rng_destroy(&rng);

    if (!add_sub_sexp_to_sexp(&raw_s_exp, &sub_s_exp)) {
        destroy_s_exp(&raw_s_exp);
        return false;
    }

    if (!write_seckey(sub_s_exp, seckey)) {
        destroy_s_exp(&raw_s_exp);
        return false;
    }

    // calculated hash
    time(&now);
    char protected_at[G10_PROTECTED_AT_SIZE + 1];
    strftime(protected_at, sizeof(protected_at), "%Y%m%dT%H%M%S", gmtime(&now));

    if (!g10_calculated_hash(seckey, protected_at, checksum)) {
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

    keysize = pgp_key_size(seckey->protection.symm_alg);
    if (keysize == 0) {
        (void) fprintf(stderr, "parse_seckey: unknown symmetric algo");
        destroy_s_exp(&raw_s_exp);
        pgp_memory_release(&raw);
        return false;
    }

    if (pgp_s2k_iterated(format->hash_alg,
                         derived_key,
                         keysize,
                         (const char *) password,
                         seckey->protection.s2k.salt,
                         seckey->protection.s2k.iterations)) {
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

    size_t   encrypted_data_len = raw.length;
    uint8_t *encrypted_data = malloc(encrypted_data_len);
    if (encrypted_data == NULL) {
        (void) fprintf(stderr, "can't allocate memory\n");
        destroy_s_exp(&raw_s_exp);
        pgp_memory_release(&raw);
        return false;
    }

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "input iv", seckey->protection.iv, G10_CBC_IV_SIZE);
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

    if (botan_cipher_start(encrypt, seckey->protection.iv, format->iv_size)) {
        goto error;
    }

    if (botan_cipher_update(encrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            encrypted_data,
                            encrypted_data_len,
                            &output_written,
                            raw.buf,
                            raw.length,
                            &input_consumed)) {
        (void) fprintf(stderr, "botan_cipher_update failed\n");
        goto error;
    }

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

    if (!add_block_to_sexp(sub_sub_sub_s_exp, seckey->protection.s2k.salt, PGP_SALT_SIZE)) {
        return false;
    }

    if (!add_unsigned_block_to_sexp(sub_sub_sub_s_exp, seckey->protection.s2k.iterations)) {
        return false;
    }

    if (!add_block_to_sexp(sub_sub_s_exp, seckey->protection.iv, format->iv_size)) {
        return false;
    }

    if (!add_block_to_sexp(sub_s_exp, encrypted_data, encrypted_data_len)) {
        return false;
    }

    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, "protected-at")) {
        return false;
    }

    if (!add_block_to_sexp(sub_s_exp, (uint8_t *) protected_at, G10_PROTECTED_AT_SIZE)) {
        return false;
    }

    return true;

error:
    free(encrypted_data);
    destroy_s_exp(&raw_s_exp);
    pgp_memory_release(&raw);
    botan_cipher_destroy(encrypt);
    return false;
}

bool
g10_write_seckey(pgp_output_t *output, pgp_seckey_t *seckey, const char *password)
{
    s_exp_t      s_exp = {0};
    s_exp_t *    sub_s_exp = NULL;
    pgp_memory_t mem = {0};
    bool protected = true;
    bool ret = false;

    switch (seckey->protection.s2k.usage) {
    case PGP_S2KU_NONE:
      protected
        = false;
        break;
    case PGP_S2KU_ENCRYPTED_AND_HASHED:
      protected
        = true;
        // TODO: these are forced for now, until openpgp-native is implemented
        seckey->protection.symm_alg = PGP_SA_AES_128;
        seckey->protection.cipher_mode = PGP_CIPHER_MODE_CBC;
        seckey->protection.s2k.hash_alg = PGP_HASH_SHA1;
        break;
    default:
        RNP_LOG("unsupported s2k usage");
        goto done;
    }
    if (!add_string_block_to_sexp(&s_exp,
                                  protected ? "protected-private-key" : "private-key") ||
        !add_sub_sexp_to_sexp(&s_exp, &sub_s_exp) ||
        !write_pubkey(sub_s_exp, &seckey->pubkey)) {
        goto done;
    }
    if (protected) {
        if (!write_protected_seckey(sub_s_exp, seckey, password)) {
            goto done;
        }
    } else {
        if (!write_seckey(sub_s_exp, seckey)) {
            goto done;
        }
    }
    if (!write_sexp(&s_exp, &mem) || !pgp_write(output, mem.buf, mem.length)) {
        goto done;
    }
    ret = true;

done:
    pgp_memory_release(&mem);
    destroy_s_exp(&s_exp);
    return ret;
}

static bool
g10_calculated_hash(const pgp_seckey_t *key, const char *protected_at, uint8_t *checksum)
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
        RNP_LOG("failed to write pubkey");
        goto error;
    }

    if (!write_seckey(&s_exp, key)) {
        RNP_LOG("failed to write seckey");
        goto error;
    }

    if (!add_sub_sexp_to_sexp(&s_exp, &sub_s_exp)) {
        goto error;
    }

    if (!add_string_block_to_sexp(sub_s_exp, "protected-at")) {
        goto error;
    }

    if (!add_block_to_sexp(sub_s_exp, (uint8_t *) protected_at, G10_PROTECTED_AT_SIZE)) {
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

bool
rnp_key_store_g10_key_to_mem(pgp_io_t *io, pgp_key_t *key, pgp_memory_t *memory)
{
    if (DYNARRAY_IS_EMPTY(key, packet)) {
        return false;
    }
    if (key->format != G10_KEY_STORE) {
        RNP_LOG("incorrect format: %d", key->format);
        return false;
    }
    return pgp_memory_add(memory, key->packets[0].raw, key->packets[0].length);
}
