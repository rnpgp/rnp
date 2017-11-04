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

#include "crypto.h"
#include "config.h"
#include <rnp/rnp_sdk.h>

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <botan/ffi.h>

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
pgp_cipher_start(pgp_crypt_t *crypt, pgp_symm_alg_t alg, const uint8_t *key, const uint8_t *iv)
{
    memset(crypt, 0x0, sizeof(*crypt));

    const char *cipher_name = pgp_sa_to_botan_string(alg);
    if (cipher_name == NULL) {
        fprintf(stderr, "Unsupported algorithm: %d\n", alg);
        return false;
    }

    crypt->alg = alg;
    crypt->blocksize = pgp_block_size(alg);

    // This shouldn't happen if pgp_sa_to_botan_string returned a ptr
    if (botan_block_cipher_init(&(crypt->obj), cipher_name) != 0) {
        (void) fprintf(stderr, "Block cipher '%s' not available\n", cipher_name);
        return false;
    }

    const size_t keysize = pgp_key_size(alg);

    if (botan_block_cipher_set_key(crypt->obj, key, keysize) != 0) {
        (void) fprintf(stderr, "Failure setting key on block cipher object\n");
        return false;
    }

    if (iv != NULL) {
        // Otherwise left as all zeros via memset at start of function
        memcpy(crypt->iv, iv, crypt->blocksize);
    }

    crypt->remaining = 0;

    return true;
}

void
pgp_cipher_cfb_resync(pgp_crypt_t *crypt, uint8_t *buf)
{
    /* iv will be encrypted in the upcoming call to encrypt/decrypt */
    memcpy(crypt->iv, buf, crypt->blocksize);
    crypt->remaining = 0;
}

int
pgp_cipher_finish(pgp_crypt_t *crypt)
{
    if (!crypt) {
        return 0;
    }
    if (crypt->obj) {
        botan_block_cipher_destroy(crypt->obj);
        crypt->obj = NULL;
    }
    botan_scrub_mem((uint8_t *) crypt, sizeof(crypt));
    return 0;
}

/* we rely on fact that in and out could be the same */
int
pgp_cipher_cfb_encrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t bytes)
{
    uint64_t *in64;
    uint64_t  buf64[512]; // 4KB - page size
    uint64_t  iv64[2];
    size_t    blocks, blockb;
    unsigned  blsize = crypt->blocksize;

    /* encrypting till the block boundary */
    while (bytes && crypt->remaining) {
        *out = *in++ ^ crypt->iv[blsize - crypt->remaining];
        crypt->iv[blsize - crypt->remaining] = *out++;
        crypt->remaining--;
        bytes--;
    }

    if (!bytes) {
        return 0;
    }

    /* encrypting full blocks */
    if (bytes > blsize) {
        memcpy(iv64, crypt->iv, blsize);
        while ((blocks = bytes & ~(blsize - 1)) > 0) {
            if (blocks > sizeof(buf64)) {
                blocks = sizeof(buf64);
            }
            bytes -= blocks;
            blockb = blocks;
            memcpy(buf64, in, blockb);
            in64 = buf64;

            if (blsize == 16) {
                blocks >>= 4;
                while (blocks--) {
                    botan_block_cipher_encrypt_blocks(
                      crypt->obj, (uint8_t *) iv64, (uint8_t *) iv64, 1);
                    *in64 ^= iv64[0];
                    iv64[0] = *in64++;
                    *in64 ^= iv64[1];
                    iv64[1] = *in64++;
                }
            } else {
                blocks >>= 3;
                while (blocks--) {
                    botan_block_cipher_encrypt_blocks(
                      crypt->obj, (uint8_t *) iv64, (uint8_t *) iv64, 1);
                    *in64 ^= iv64[0];
                    iv64[0] = *in64++;
                }
            }

            memcpy(out, buf64, blockb);
            out += blockb;
            in += blockb;
        }

        memcpy(crypt->iv, iv64, blsize);
    }

    if (!bytes) {
        return 0;
    }

    botan_block_cipher_encrypt_blocks(crypt->obj, crypt->iv, crypt->iv, 1);
    crypt->remaining = blsize;

    /* encrypting tail */
    while (bytes) {
        *out = *in++ ^ crypt->iv[blsize - crypt->remaining];
        crypt->iv[blsize - crypt->remaining] = *out++;
        crypt->remaining--;
        bytes--;
    }

    return 0;
}

/* we rely on fact that in and out could be the same */
int
pgp_cipher_cfb_decrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t bytes)
{
    /* for better code readability */
    uint64_t *out64, *in64;
    uint64_t  inbuf64[512]; // 4KB - page size
    uint64_t  outbuf64[512];
    uint64_t  iv64[2];
    size_t    blocks, blockb;
    unsigned  blsize = crypt->blocksize;

    /* decrypting till the block boundary */
    while (bytes && crypt->remaining) {
        uint8_t c = *in++;
        *out++ = c ^ crypt->iv[blsize - crypt->remaining];
        crypt->iv[blsize - crypt->remaining] = c;
        crypt->remaining--;
        bytes--;
    }

    if (!bytes) {
        return 0;
    }

    /* decrypting full blocks */
    if (bytes > blsize) {
        memcpy(iv64, crypt->iv, blsize);

        while ((blocks = bytes & ~(blsize - 1)) > 0) {
            if (blocks > sizeof(inbuf64)) {
                blocks = sizeof(inbuf64);
            }
            bytes -= blocks;
            blockb = blocks;
            memcpy(inbuf64, in, blockb);
            out64 = outbuf64;
            in64 = inbuf64;

            if (blsize == 16) {
                blocks >>= 4;
                while (blocks--) {
                    botan_block_cipher_encrypt_blocks(
                      crypt->obj, (uint8_t *) iv64, (uint8_t *) iv64, 1);
                    *out64++ = *in64 ^ iv64[0];
                    iv64[0] = *in64++;
                    *out64++ = *in64 ^ iv64[1];
                    iv64[1] = *in64++;
                }
            } else {
                blocks >>= 3;
                while (blocks--) {
                    botan_block_cipher_encrypt_blocks(
                      crypt->obj, (uint8_t *) iv64, (uint8_t *) iv64, 1);
                    *out64++ = *in64 ^ iv64[0];
                    iv64[0] = *in64++;
                }
            }

            memcpy(out, outbuf64, blockb);
            out += blockb;
            in += blockb;
        }

        memcpy(crypt->iv, iv64, blsize);
    }

    if (!bytes) {
        return 0;
    }

    botan_block_cipher_encrypt_blocks(crypt->obj, crypt->iv, crypt->iv, 1);
    crypt->remaining = blsize;

    /* decrypting tail */
    while (bytes) {
        uint8_t c = *in++;
        *out++ = c ^ crypt->iv[blsize - crypt->remaining];
        crypt->iv[blsize - crypt->remaining] = c;
        crypt->remaining--;
        bytes--;
    }

    return 0;
}

pgp_symm_alg_t
pgp_cipher_alg_id(pgp_crypt_t *cipher)
{
    return cipher->alg;
}

size_t
pgp_cipher_block_size(pgp_crypt_t *cipher)
{
    return cipher->blocksize;
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
        if (rnp_get_debug(__FILE__)) {
            RNP_LOG("Unknown PGP symmetric alg %d", (int) alg);
        }
        return 0;
    }
}

unsigned
pgp_key_size(pgp_symm_alg_t alg)
{
    /* Update MAX_SYMM_KEY_SIZE after adding algorithm
     * with bigger key size.
     */
    static_assert(32 == MAX_SYMM_KEY_SIZE, "MAX_SYMM_KEY_SIZE must be updated");

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

    fprintf(stderr, "\nWarning: cipher %d not supported", (int) alg);
    return false;
}
