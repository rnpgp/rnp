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

typedef struct {
    size_t   len;
    uint8_t *bytes;
} s_exp_block_t;

typedef struct s_exp s_exp_t;

struct s_exp {
    DYNARRAY(s_exp_block_t, block);

    DYNARRAY(s_exp_t, sub_s_exp);
};

static void
destroy_s_exp(s_exp_t *s_exp)
{
    int i;

    if (s_exp == NULL) {
        return;
    }

    if (s_exp->blocks != NULL) {
        for (i = 0; i < s_exp->blockc; i++) {
            if (s_exp->blocks[i].len > 0 && s_exp->blocks[i].bytes != NULL) {
                free(s_exp->blocks[i].bytes);
                s_exp->blocks[i].bytes = NULL;
                s_exp->blocks[i].len = 0;
            }
        }
        FREE_ARRAY(s_exp, block);
    }

    if (s_exp->sub_s_exps != NULL) {
        for (i = 0; i < s_exp->sub_s_expc; i++) {
            destroy_s_exp(&s_exp->sub_s_exps[i]);
        }
        FREE_ARRAY(s_exp, sub_s_exp);
    }
}

static bool
add_block_to_sexp(s_exp_t *s_exp, uint8_t *bytes, size_t len)
{
    s_exp_block_t *block;

    for (int i = 0; i < s_exp->blockc; i++) {
        if (len == s_exp->blocks[i].len && !memcmp(s_exp->blocks[i].bytes, bytes, len)) {
            // do not duplicate blocks
            return true;
        }
    }

    EXPAND_ARRAY(s_exp, block);
    if (s_exp->blocks == NULL) {
        return false;
    }

    block = &s_exp->blocks[s_exp->blockc++];

    block->len = (size_t) len;
    block->bytes = malloc(block->len);
    if (block->bytes == NULL) {
        fprintf(stderr, "can't allocate memory\n");
        return false;
    }

    memcpy(block->bytes, bytes, block->len);
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
    EXPAND_ARRAY(s_exp, sub_s_exp);
    if (s_exp->sub_s_exps == NULL) {
        return false;
    }

    *sub_s_exp = &s_exp->sub_s_exps[s_exp->sub_s_expc++];

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

    s_exp_t new_s_exp = {};

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

static s_exp_block_t *
lookup_variable(s_exp_t *s_exp, const char *name)
{
    for (int i = 0; i < s_exp->sub_s_expc; i++) {
        if (s_exp->sub_s_exps[i].blockc != 2) {
            fprintf(stderr,
                    "Expected 2 block (<name> <value>) but has: %d\n",
                    s_exp->sub_s_exps[i].blockc);
            return NULL;
        }
        if (!strncmp(name,
                     (const char *) s_exp->sub_s_exps[i].blocks[0].bytes,
                     s_exp->sub_s_exps[i].blocks[0].len)) {
            return &s_exp->sub_s_exps[i].blocks[1];
        }
    }
    fprintf(stderr, "Haven't got variable '%s'\n", name);
    return NULL;
}

static BIGNUM *
read_bignum(s_exp_t *s_exp, const char *name)
{
    s_exp_block_t *var = lookup_variable(s_exp, name);
    if (var == NULL) {
        return NULL;
    }

    BIGNUM *res = PGPV_BN_bin2bn(var->bytes, (int) var->len, NULL);
    if (res == NULL) {
        char *buf = malloc((var->len * 3) + 1);
        if (buf == NULL) {
            fprintf(stderr, "Can't allocate memory\n");
            return NULL;
        }
        fprintf(stderr,
                "Can't convert variable '%s' to bignum. The value is: '%s'\n",
                name,
                rnp_strhexdump(buf, var->bytes, var->len, ""));
    }
    return res;
}

static bool
write_bignum(s_exp_t *s_exp, const char *name, BIGNUM *bn)
{
    uint8_t bnbuf[RNP_BUFSIZ];

    s_exp_t *sub_s_exp;

    if (PGPV_BN_bn2bin(bn, bnbuf) < 0) {
        return false;
    }

    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, name)) {
        return false;
    }

    if (!add_block_to_sexp(sub_s_exp, bnbuf, (size_t) BN_num_bytes(bn))) {
        return false;
    }

    return true;
}

static bool
parse_pubkey(pgp_keydata_key_t *keydata, s_exp_t *s_exp, pgp_pubkey_alg_t alg)
{
    keydata->pubkey.version = PGP_V4;
    keydata->pubkey.birthtime = time(NULL);
    keydata->pubkey.duration = 0;
    keydata->pubkey.alg = alg;

    switch (alg) {
    case PGP_PKA_DSA:
        keydata->pubkey.key.dsa.p = read_bignum(s_exp, "p");
        if (keydata->pubkey.key.dsa.p == NULL) {
            return false;
        }

        keydata->pubkey.key.dsa.q = read_bignum(s_exp, "q");
        if (keydata->pubkey.key.dsa.q == NULL) {
            PGPV_BN_free(keydata->pubkey.key.dsa.p);
            return false;
        }

        keydata->pubkey.key.dsa.g = read_bignum(s_exp, "g");
        if (keydata->pubkey.key.dsa.g == NULL) {
            PGPV_BN_free(keydata->pubkey.key.dsa.p);
            PGPV_BN_free(keydata->pubkey.key.dsa.q);
            return false;
        }

        keydata->pubkey.key.dsa.y = read_bignum(s_exp, "y");
        if (keydata->pubkey.key.dsa.y == NULL) {
            PGPV_BN_free(keydata->pubkey.key.dsa.p);
            PGPV_BN_free(keydata->pubkey.key.dsa.q);
            PGPV_BN_free(keydata->pubkey.key.dsa.g);
            return false;
        }

        break;

    case PGP_PKA_RSA:
        keydata->pubkey.key.rsa.n = read_bignum(s_exp, "n");
        if (keydata->pubkey.key.rsa.n == NULL) {
            return false;
        }

        keydata->pubkey.key.rsa.e = read_bignum(s_exp, "e");
        if (keydata->pubkey.key.rsa.e == NULL) {
            PGPV_BN_free(keydata->pubkey.key.rsa.n);
            return false;
        }

        break;

    case PGP_PKA_ELGAMAL:
        keydata->pubkey.key.elgamal.p = read_bignum(s_exp, "p");
        if (keydata->pubkey.key.elgamal.p == NULL) {
            return false;
        }

        keydata->pubkey.key.elgamal.g = read_bignum(s_exp, "g");
        if (keydata->pubkey.key.elgamal.g == NULL) {
            PGPV_BN_free(keydata->pubkey.key.elgamal.p);
            return false;
        }

        keydata->pubkey.key.elgamal.y = read_bignum(s_exp, "y");
        if (keydata->pubkey.key.elgamal.y == NULL) {
            PGPV_BN_free(keydata->pubkey.key.elgamal.p);
            PGPV_BN_free(keydata->pubkey.key.elgamal.g);
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
parse_seckey(pgp_keydata_key_t *keydata, s_exp_t *s_exp, pgp_pubkey_alg_t alg)
{
    if (keydata->seckey.pubkey.version != PGP_V2 && keydata->seckey.pubkey.version != PGP_V3 &&
        keydata->seckey.pubkey.version != PGP_V4) {
        fprintf(stderr, "You should run parse_seckey only after parse_pubkey\n");
        return false;
    }

    keydata->seckey.s2k_usage = PGP_S2KU_NONE;
    keydata->seckey.alg = PGP_SA_DEFAULT_CIPHER;
    keydata->seckey.hash_alg = PGP_HASH_UNKNOWN;

    switch (alg) {
    case PGP_PKA_DSA:
        keydata->seckey.key.dsa.x = read_bignum(s_exp, "x");
        if (keydata->seckey.key.dsa.x == NULL) {
            return false;
        }

        break;

    case PGP_PKA_RSA:
        keydata->seckey.key.rsa.d = read_bignum(s_exp, "d");
        if (keydata->seckey.key.rsa.d == NULL) {
            return false;
        }

        keydata->seckey.key.rsa.p = read_bignum(s_exp, "p");
        if (keydata->seckey.key.rsa.p == NULL) {
            PGPV_BN_free(keydata->seckey.key.rsa.d);
            return false;
        }

        keydata->seckey.key.rsa.q = read_bignum(s_exp, "q");
        if (keydata->seckey.key.rsa.q == NULL) {
            PGPV_BN_free(keydata->seckey.key.rsa.d);
            PGPV_BN_free(keydata->seckey.key.rsa.p);
            return false;
        }

        keydata->seckey.key.rsa.u = read_bignum(s_exp, "u");
        if (keydata->seckey.key.rsa.u == NULL) {
            PGPV_BN_free(keydata->seckey.key.rsa.d);
            PGPV_BN_free(keydata->seckey.key.rsa.p);
            PGPV_BN_free(keydata->seckey.key.rsa.q);
            return false;
        }

        break;

    case PGP_PKA_ELGAMAL:
        keydata->seckey.key.elgamal.x = read_bignum(s_exp, "x");
        if (keydata->seckey.key.elgamal.x == NULL) {
            return false;
        }

        break;

    default:
        fprintf(stderr, "Unsupported public key algorithm: %d\n", alg);
        return false;
    }

    return true;
}

bool
rnp_key_store_g10_from_mem(pgp_io_t *       io,
                           rnp_key_store_t *pubring,
                           rnp_key_store_t *key_store,
                           pgp_memory_t *   memory)
{
    s_exp_t     s_exp = {};
    size_t      length = memory->length;
    const char *bytes = (const char *) memory->buf;

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

    if (s_exp.blockc != 1) {
        fprintf(stderr, "Wrong count of top-level block: %d, should be 1\n", s_exp.blockc);
        destroy_s_exp(&s_exp);
        return false;
    }

    if (s_exp.sub_s_expc != 1) {
        fprintf(
          stderr, "Wrong count of top-level sub-s-exp: %d, should be 1\n", s_exp.sub_s_expc);
        destroy_s_exp(&s_exp);
        return false;
    }

    bool private_key;
    if (!strncmp("private-key", (const char *) s_exp.blocks[0].bytes, s_exp.blocks[0].len)) {
        private_key = true;
    } else if (!strncmp(
                 "public-key", (const char *) s_exp.blocks[0].bytes, s_exp.blocks[0].len)) {
        private_key = false;
    } else {
        fprintf(stderr,
                "Unsupported top-level block: '%.*s'\n",
                (int) s_exp.blocks[0].len,
                s_exp.blocks[0].bytes);
        destroy_s_exp(&s_exp);
        return false;
    }

    s_exp_t *algorithm_s_exp = &s_exp.sub_s_exps[0];

    if (algorithm_s_exp->blockc != 1) {
        fprintf(stderr,
                "Wrong count of algorithm-level block: %d, should be 1\n",
                algorithm_s_exp->blockc);
        destroy_s_exp(&s_exp);
        return false;
    }

    if (algorithm_s_exp->sub_s_expc == 0) {
        fprintf(stderr,
                "Wrong count of algorithm-level sub-s-exp: %d, should be bigger than 0\n",
                algorithm_s_exp->sub_s_expc);
        destroy_s_exp(&s_exp);
        return false;
    }

    pgp_pubkey_alg_t alg = PGP_PKA_NOTHING;

    if (!strncmp("rsa",
                 (const char *) algorithm_s_exp->blocks[0].bytes,
                 algorithm_s_exp->blocks[0].len)) {
        alg = PGP_PKA_RSA;
    } else if (!strncmp("openpgp-rsa",
                        (const char *) algorithm_s_exp->blocks[0].bytes,
                        algorithm_s_exp->blocks[0].len)) {
        alg = PGP_PKA_RSA;
    } else if (!strncmp("oid.1.2.840.113549.1.1.1",
                        (const char *) algorithm_s_exp->blocks[0].bytes,
                        algorithm_s_exp->blocks[0].len)) {
        alg = PGP_PKA_RSA;

    } else if (!strncmp("elg",
                        (const char *) algorithm_s_exp->blocks[0].bytes,
                        algorithm_s_exp->blocks[0].len)) {
        alg = PGP_PKA_ELGAMAL;
    } else if (!strncmp("elgamal",
                        (const char *) algorithm_s_exp->blocks[0].bytes,
                        algorithm_s_exp->blocks[0].len)) {
        alg = PGP_PKA_ELGAMAL;
    } else if (!strncmp("openpgp-elg",
                        (const char *) algorithm_s_exp->blocks[0].bytes,
                        algorithm_s_exp->blocks[0].len)) {
        alg = PGP_PKA_ELGAMAL;
    } else if (!strncmp("openpgp-elg-sig",
                        (const char *) algorithm_s_exp->blocks[0].bytes,
                        algorithm_s_exp->blocks[0].len)) {
        alg = PGP_PKA_ELGAMAL;

    } else if (!strncmp("dsa",
                        (const char *) algorithm_s_exp->blocks[0].bytes,
                        algorithm_s_exp->blocks[0].len)) {
        alg = PGP_PKA_DSA;
    } else if (!strncmp("openpgp-dsa",
                        (const char *) algorithm_s_exp->blocks[0].bytes,
                        algorithm_s_exp->blocks[0].len)) {
        alg = PGP_PKA_DSA;

    } else {
        fprintf(stderr,
                "Unsupported algorithm: '%.*s'\n",
                (int) s_exp.blocks[0].len,
                s_exp.blocks[0].bytes);
        destroy_s_exp(&s_exp);
        return false;
    }

    pgp_keydata_key_t keydata = {};

    if (!parse_pubkey(&keydata, algorithm_s_exp, alg)) {
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
        if (!parse_seckey(&keydata, algorithm_s_exp, alg)) {
            destroy_s_exp(&s_exp);
            return false;
        }
    }

    destroy_s_exp(&s_exp);

    if (rnp_get_debug(__FILE__)) {
        uint8_t grip[PGP_FINGERPRINT_SIZE];
        char    grips[PGP_FINGERPRINT_HEX_SIZE];
        if (!rnp_key_store_get_key_grip(&keydata.pubkey, grip)) {
            return false;
        }
        fprintf(
          io->errs, "loaded G10 key with GRIP: %s\n", rnp_strhexdump(grips, grip, 20, ""));
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

    for (i = 0; i < s_exp->blockc; i++) {
        if (!write_block(&s_exp->blocks[i], mem)) {
            return false;
        }
    }

    for (i = 0; i < s_exp->sub_s_expc; i++) {
        if (!write_sexp(&s_exp->sub_s_exps[i], mem)) {
            return false;
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
        if (!add_string_block_to_sexp(s_exp, "dsa")) {
            return false;
        }

        if (!write_bignum(s_exp, "x", key->key.dsa.x)) {
            return false;
        }

        break;

    case PGP_PKA_RSA_SIGN_ONLY:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA:
        if (!add_string_block_to_sexp(s_exp, "rsa")) {
            return false;
        }

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
        if (!add_string_block_to_sexp(s_exp, "elg")) {
            return false;
        }

        if (!write_bignum(s_exp, "x", key->key.elgamal.x)) {
            return false;
        }

    default:
        fprintf(stderr, "Unsupported public key algorithm: %d\n", key->pubkey.alg);
        return NULL;
    }

    return true;
}

bool
rnp_key_store_g10_key_to_mem(pgp_io_t *     io,
                             pgp_key_t *    key,
                             const uint8_t *passphrase,
                             pgp_memory_t * memory)
{
    bool     rc;
    s_exp_t  s_exp = {};
    s_exp_t *sub_s_exp;

    if (!add_sub_sexp_to_sexp(&s_exp, &sub_s_exp)) {
        return false;
    }

    switch (key->type) {
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        if (!add_block_to_sexp(&s_exp, (uint8_t *) "public-key", sizeof("public-key") - 1)) {
            return false;
        }

        if (!write_pubkey(sub_s_exp, &key->key.pubkey)) {
            return false;
        }

        break;

    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        if (!add_block_to_sexp(&s_exp, (uint8_t *) "private-key", sizeof("private-key") - 1)) {
            return false;
        }

        if (!write_pubkey(sub_s_exp, &key->key.pubkey)) {
            return false;
        }

        if (!write_seckey(sub_s_exp, &key->key.seckey)) {
            return false;
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