/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: symmetric.c,v 1.18 2010/11/07 08:39:59 agc Exp $");
#endif

#include <string.h>
#include <stdlib.h>

#include <botan/ffi.h>

#include "crypto.h"
#include "packet-show.h"
#include "utils.h"
#include "rnpsdk.h"

int
pgp_cipher_set_iv(pgp_crypt_t *cipher, const uint8_t *iv)
{
    (void) memcpy(cipher->iv, iv, cipher->blocksize);
    cipher->num = 0;
    return 0;
}

int
pgp_cipher_set_key(pgp_crypt_t *cipher, const uint8_t *key)
{
    (void) memcpy(cipher->key, key, cipher->keysize);
    return 0;
}

int
pgp_cipher_cfb_resync(pgp_crypt_t *decrypt)
{
    if ((size_t) decrypt->num == decrypt->blocksize) {
        return 0;
    }

    memmove(
      decrypt->civ + decrypt->blocksize - decrypt->num, decrypt->civ, (unsigned) decrypt->num);
    (void) memcpy(
      decrypt->civ, decrypt->siv + decrypt->num, decrypt->blocksize - decrypt->num);
    decrypt->num = 0;
    return 0;
}

int
pgp_cipher_finish(pgp_crypt_t *crypt)
{
    if (crypt->block_cipher_obj) {
        botan_block_cipher_destroy(crypt->block_cipher_obj);
        crypt->block_cipher_obj = NULL;
    }
    return 0;
}

int
pgp_cipher_block_encrypt(const pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in)
{
    if (botan_block_cipher_encrypt_blocks(crypt->block_cipher_obj, in, out, 1) == 0)
        return 0;
    return -1;
}

int
pgp_cipher_block_decrypt(const pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in)
{
    if (botan_block_cipher_decrypt_blocks(crypt->block_cipher_obj, in, out, 1) == 0)
        return 0;
    return -1;
}

int
pgp_cipher_cfb_encrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t bytes)
{
    for (size_t i = 0; i < bytes; ++i) {
        if (crypt->num == 0) {
            botan_block_cipher_encrypt_blocks(
              crypt->block_cipher_obj, crypt->iv, crypt->iv, 1);
        }
        out[i] = in[i] ^ crypt->iv[crypt->num];
        crypt->iv[crypt->num] = out[i];

        crypt->num = (crypt->num + 1) % crypt->blocksize;
    }
    return 0;
}

int
pgp_cipher_cfb_decrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t bytes)
{
    for (size_t i = 0; i < bytes; ++i) {
        uint8_t ciphertext = in[i];

        if (crypt->num == 0) {
            botan_block_cipher_encrypt_blocks(
              crypt->block_cipher_obj, crypt->iv, crypt->iv, 1);
        }

        out[i] = in[i] ^ crypt->iv[crypt->num];
        crypt->iv[crypt->num] = ciphertext;

        crypt->num = (crypt->num + 1) % crypt->blocksize;
    }
    return 0;
}

/* structure to map string to cipher def */
typedef struct str2cipher_t {
    const char *   s; /* cipher name */
    pgp_symm_alg_t i; /* cipher def */
} str2cipher_t;

static str2cipher_t str2cipher[] = {{"cast5", PGP_SA_CAST5},
                                    {"idea", PGP_SA_IDEA},
                                    {"blowfish", PGP_SA_BLOWFISH},
                                    {"twofish", PGP_SA_TWOFISH},
                                    {"sm4", PGP_SA_SM4},
                                    {"aes128", PGP_SA_AES_128},
                                    {"aes192", PGP_SA_AES_192},
                                    {"aes256", PGP_SA_AES_256},
                                    {"camellia128", PGP_SA_CAMELLIA_128},
                                    {"camellia192", PGP_SA_CAMELLIA_192},
                                    {"camellia256", PGP_SA_CAMELLIA_256},
                                    {"tripledes", PGP_SA_TRIPLEDES},
                                    {NULL, 0}};

/* convert from a string to a cipher definition */
pgp_symm_alg_t
pgp_str_to_cipher(const char *cipher)
{
    str2cipher_t *sp;

    for (sp = str2cipher; cipher && sp->s; sp++) {
        if (rnp_strcasecmp(cipher, sp->s) == 0) {
            return sp->i;
        }
    }
    return PGP_SA_DEFAULT_CIPHER;
}

static const char *
pgp_sa_to_botan_string(pgp_symm_alg_t alg)
{
    switch (alg) {
#if defined(BOTAN_HAS_IDEA)
    case PGP_SA_IDEA:
        return "IDEA";
#endif

#if defined(BOTAN_HAS_DES)
    case PGP_SA_TRIPLEDES:
        return "TripleDES";
#endif

#if defined(BOTAN_HAS_CAST)
    case PGP_SA_CAST5:
        return "CAST-128";
#endif

#if defined(BOTAN_HAS_BLOWFISH)
    case PGP_SA_BLOWFISH:
        return "Blowfish";
#endif

#if defined(BOTAN_HAS_AES)
    case PGP_SA_AES_128:
        return "AES-128";
    case PGP_SA_AES_192:
        return "AES-192";
    case PGP_SA_AES_256:
        return "AES-256";
#endif

#if defined(BOTAN_HAS_SM4)
    case PGP_SA_SM4:
        return "SM4";
#endif

#if defined(BOTAN_HAS_TWOFISH)
    case PGP_SA_TWOFISH:
        return "Twofish";
#endif

#if defined(BOTAN_HAS_CAMELLIA)
    case PGP_SA_CAMELLIA_128:
        return "Camellia-128";
    case PGP_SA_CAMELLIA_192:
        return "Camellia-192";
    case PGP_SA_CAMELLIA_256:
        return "Camellia-256";
#endif

    case PGP_SA_PLAINTEXT:
        return NULL; // ???
    default:
        fprintf(stderr, "Unsupported PGP symmetric alg %d", (int) alg);
        return NULL;
    }
}

bool
pgp_crypt_any(pgp_crypt_t *crypt, pgp_symm_alg_t alg)
{
    const char *cipher_name = pgp_sa_to_botan_string(alg);
    if (cipher_name == NULL)
        return false;

    memset(crypt, 0x0, sizeof(*crypt));

    crypt->alg = alg;
    crypt->blocksize = pgp_block_size(alg);
    crypt->keysize = pgp_key_size(alg);

    if (botan_block_cipher_init(&(crypt->block_cipher_obj), cipher_name) != 0) {
        (void) fprintf(stderr, "Block cipher '%s' not available\n", cipher_name);
        return false;
    }

    return true;
}

unsigned
pgp_block_size(pgp_symm_alg_t alg)
{
    switch (alg) {
    case PGP_SA_IDEA:
    case PGP_SA_TRIPLEDES:
    case PGP_SA_CAST5:
    case PGP_SA_BLOWFISH:
        return 8;

    case PGP_SA_AES_128:
    case PGP_SA_AES_192:
    case PGP_SA_AES_256:
    case PGP_SA_TWOFISH:
    case PGP_SA_CAMELLIA_128:
    case PGP_SA_CAMELLIA_192:
    case PGP_SA_CAMELLIA_256:
    case PGP_SA_SM4:
        return 16;

    default:
        fprintf(stderr, "Unknown PGP symmetric alg %d", (int) alg);
        return 0;
    }
}

unsigned
pgp_key_size(pgp_symm_alg_t alg)
{
    switch (alg) {
    case PGP_SA_IDEA:
    case PGP_SA_CAST5:
    case PGP_SA_BLOWFISH:
    case PGP_SA_AES_128:
    case PGP_SA_CAMELLIA_128:
    case PGP_SA_SM4:
        return 16;

    case PGP_SA_TRIPLEDES:
    case PGP_SA_AES_192:
    case PGP_SA_CAMELLIA_192:
        return 24;

    case PGP_SA_TWOFISH:
    case PGP_SA_AES_256:
    case PGP_SA_CAMELLIA_256:
        return 32;

    default:
        return 0;
    }
}

bool
pgp_encrypt_init(pgp_crypt_t *encrypt)
{
    /* \todo should there be a separate pgp_encrypt_init? */
    return pgp_decrypt_init(encrypt);
}

bool
pgp_decrypt_init(pgp_crypt_t *crypt)
{
    if (botan_block_cipher_set_key(crypt->block_cipher_obj, crypt->key, crypt->keysize) != 0) {
        (void) fprintf(stderr, "Failure setting key on block cipher object\n");
        return false;
    }

    pgp_cipher_block_encrypt(crypt, crypt->siv, crypt->iv);
    (void) memcpy(crypt->civ, crypt->siv, crypt->blocksize);
    crypt->num = 0;
    return true;
}

size_t
pgp_decrypt_se(pgp_crypt_t *decrypt, void *outvoid, const void *invoid, size_t count)
{
    const uint8_t *in = invoid;
    uint8_t *      out = outvoid;
    int            saved = (int) count;

    /*
     * in order to support v3's weird resyncing we have to implement CFB
     * mode ourselves
     */
    while (count-- > 0) {
        uint8_t t;

        if ((size_t) decrypt->num == decrypt->blocksize) {
            (void) memcpy(decrypt->siv, decrypt->civ, decrypt->blocksize);
            pgp_cipher_block_decrypt(decrypt, decrypt->civ, decrypt->civ);
            decrypt->num = 0;
        }
        t = decrypt->civ[decrypt->num];
        *out++ = t ^ (decrypt->civ[decrypt->num++] = *in++);
    }

    return (size_t) saved;
}

size_t
pgp_encrypt_se(pgp_crypt_t *encrypt, void *outvoid, const void *invoid, size_t count)
{
    const uint8_t *in = invoid;
    uint8_t *      out = outvoid;
    int            saved = (int) count;

    /*
     * in order to support v3's weird resyncing we have to implement CFB
     * mode ourselves
     */
    while (count-- > 0) {
        if ((size_t) encrypt->num == encrypt->blocksize) {
            (void) memcpy(encrypt->siv, encrypt->civ, encrypt->blocksize);
            pgp_cipher_block_encrypt(encrypt, encrypt->civ, encrypt->civ);
            encrypt->num = 0;
        }
        encrypt->civ[encrypt->num] = *out++ = encrypt->civ[encrypt->num] ^ *in++;
        ++encrypt->num;
    }

    return (size_t) saved;
}

/**
\ingroup HighLevel_Supported
\brief Is this Symmetric Algorithm supported?
\param alg Symmetric Algorithm to check
\return 1 if supported; else 0
*/
bool
pgp_is_sa_supported(pgp_symm_alg_t alg)
{
    const char *cipher_name = pgp_sa_to_botan_string(alg);
    if (cipher_name != NULL)
        return true;

    fprintf(stderr, "\nWarning: %s not supported\n", pgp_show_symm_alg(alg));
    return false;
}

size_t
pgp_encrypt_se_ip(pgp_crypt_t *crypt, void *out, const void *in, size_t count)
{
    if (!pgp_is_sa_supported(crypt->alg)) {
        return 0;
    }

    pgp_cipher_cfb_encrypt(crypt, out, in, count);

    /* \todo test this number was encrypted */
    return count;
}

size_t
pgp_decrypt_se_ip(pgp_crypt_t *crypt, void *out, const void *in, size_t count)
{
    if (!pgp_is_sa_supported(crypt->alg)) {
        return 0;
    }

    pgp_cipher_cfb_decrypt(crypt, out, in, count);

    /* \todo check this number was in fact decrypted */
    return count;
}
