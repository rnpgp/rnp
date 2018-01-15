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

#ifndef SYMMETRIC_CRYPTO_H_
#define SYMMETRIC_CRYPTO_H_

#include "crypto/rng.h"

/** pgp_crypt_t */
typedef struct pgp_crypt_t {
    pgp_symm_alg_t alg;
    size_t         blocksize;

    union {
        struct pgp_crypt_cfb_param_t {
            size_t                            remaining;
            struct botan_block_cipher_struct *obj;
            uint8_t                           iv[PGP_MAX_BLOCK_SIZE];
        } cfb;
        struct pgp_crypt_aead_param_t {
            pgp_aead_alg_t              alg;
            bool                        decrypt;
            size_t                      granularity;
            struct botan_cipher_struct *obj;
        } aead;
    };

    rng_t *rng;
} pgp_crypt_t;

typedef struct pgp_aead_params_t {
    pgp_symm_alg_t ealg;                       /* underlying symmetric algorithm */
    pgp_aead_alg_t aalg;                       /* AEAD algorithm, i.e. EAX, OCB, etc */
    uint8_t        iv[PGP_AEAD_MAX_NONCE_LEN]; /* initial vector for the message */
    uint8_t        ad[PGP_AEAD_MAX_AD_LEN];    /* additional data */
    size_t         adlen;                      /* length of the additional data */
} pgp_aead_params_t;

pgp_symm_alg_t pgp_str_to_cipher(const char *name);
unsigned       pgp_block_size(pgp_symm_alg_t);
unsigned       pgp_key_size(pgp_symm_alg_t);
bool           pgp_is_sa_supported(pgp_symm_alg_t);
size_t         pgp_cipher_block_size(pgp_crypt_t *crypt);
pgp_symm_alg_t pgp_cipher_alg_id(pgp_crypt_t *crypt);

/**
 * Initialize a cipher object.
 * @param iv if null an all-zero IV is assumed
 */
bool pgp_cipher_cfb_start(pgp_crypt_t *  crypt,
                          pgp_symm_alg_t alg,
                          const uint8_t *key,
                          const uint8_t *iv);

// Deallocate all storage
int pgp_cipher_cfb_finish(pgp_crypt_t *crypt);
// CFB encryption/decryption
int pgp_cipher_cfb_encrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t len);
int pgp_cipher_cfb_decrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t len);

void pgp_cipher_cfb_resync(pgp_crypt_t *crypt, uint8_t *buf);

/** @brief Initialize AEAD cipher instance
 *  @param crypt pgp crypto object
 *  @param ealg symmetric encryption algorithm to use together with AEAD cipher mode
 *  @param aalg AEAD cipher mode. Only EAX is supported now
 *  @param key key buffer. Number of key bytes is determined by ealg.
 *  @param decrypt true for decryption, or false for encryption
 *  @return true on success or false otherwise.
 */
bool pgp_cipher_aead_init(pgp_crypt_t *  crypt,
                          pgp_symm_alg_t ealg,
                          pgp_aead_alg_t aalg,
                          const uint8_t *key,
                          bool           decrypt);

/** @brief Return the AEAD cipher update granularity. Botan FFI will consume chunks which are
 *         multiple of this value. See the description of pgp_cipher_aead_update()
 *  @param crypt initialized AEAD crypto
 *  @return Update granularity value in bytes
 */
size_t pgp_cipher_aead_granularity(pgp_crypt_t *crypt);

/** @brief Set associated data
 *  @param crypt initialized AEAD crypto
 *  @param ad buffer with data. Cannot be NULL.
 *  @param len number of bytes in ad
 *  @return true on success or false otherwise.
 */
bool pgp_cipher_aead_set_ad(pgp_crypt_t *crypt, const uint8_t *ad, size_t len);

/** @brief Start the cipher operation, using the given nonce
 *  @param crypt initialized AEAD crypto
 *  @param nonce buffer with nonce, cannot be NULL.
 *  @param len number of bytes in nonce. Must conform to the cipher properties.
 *  @return true on success or false otherwise.
 */
bool pgp_cipher_aead_start(pgp_crypt_t *crypt, const uint8_t *nonce, size_t len);

/** @brief Update the cipher. This should be called for non-final data, respecting the
 *         update granularity of underlying botan cipher. Now it is 256 bytes.
 *  @param crypt initialized AEAD crypto
 *  @param out buffer to put processed data. Cannot be NULL, and should be large enough to put
 *             len bytes
 *  @param in buffer with input, cannot be NULL
 *  @param len number of bytes to process. Should be multiple of update granularity.
 *  @return true on success or false otherwise. On success exactly len processed bytes will be
 *          stored in out buffer
 */
bool pgp_cipher_aead_update(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t len);

/** @brief Do final update on the cipher. For decryption final chunk should contain at least
 *         authentication tag, for encryption input could be zero-size.
 *  @param crypt initialized AEAD crypto
 *  @param out buffer to put processed data. For decryption it should be large enough to put
 *             len bytes minus authentication tag, for encryption it should be large enough to
 *             put len byts plus a tag.
 *  @param in buffer with input, if any. May be NULL for encryption, then len should be zero.
 *            For decryption it should contain at least authentication tag.
 *  @param len number of input bytes bytes
 *  @return true on success or false otherwise. On success for decryption len minus tag size
 *               bytes will be stored in out, for encryption out will contain len bytes plus
 *               tag size.
 */
bool pgp_cipher_aead_finish(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t len);

/** @brief Destroy the cipher object, deallocating all the memory.
 *  @param crypt initialized AEAD crypto
 */
void pgp_cipher_aead_destroy(pgp_crypt_t *crypt);

/** @brief Helper function to set AEAD-EAX nonce for the chunk by it's index
 *  @param iv Initial vector for the message, must have 16 bytes of data
 *  @param nonce Nonce to fill up, should have space for 16 bytes of data
 *  @param index Chunk's index
 */
void pgp_cipher_aead_eax_nonce(const uint8_t *iv, uint8_t *nonce, size_t index);

#endif
