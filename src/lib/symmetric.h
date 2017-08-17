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

/** pgp_crypt_t */
struct pgp_crypt_t {
    pgp_symm_alg_t alg;
    size_t         blocksize;
    size_t         num; // offset for CFB

    uint8_t iv[PGP_MAX_BLOCK_SIZE];
    uint8_t civ[PGP_MAX_BLOCK_SIZE];
    uint8_t siv[PGP_MAX_BLOCK_SIZE];
    /* siv is needed for weird v3 resync */

    struct botan_block_cipher_struct *block_cipher_obj;
};

pgp_symm_alg_t pgp_str_to_cipher(const char *name);
unsigned pgp_block_size(pgp_symm_alg_t);
unsigned pgp_key_size(pgp_symm_alg_t);
bool     pgp_is_sa_supported(pgp_symm_alg_t);

/**
* Initialize a cipher object.
* @param iv if null an all-zero IV is assumed
*/
bool pgp_cipher_start(pgp_crypt_t *  cipher,
                      pgp_symm_alg_t alg,
                      const uint8_t *key,
                      const uint8_t *iv);

// Deallocate all storage
int pgp_cipher_finish(pgp_crypt_t *cipher);

int pgp_cipher_block_size(pgp_crypt_t *cipher);
int pgp_cipher_key_size(pgp_crypt_t *cipher);
pgp_symm_alg_t pgp_cipher_alg_id(pgp_crypt_t *cipher);

// Encrypt a single block
int pgp_cipher_block_encrypt(const pgp_crypt_t *cipher, uint8_t *out, const uint8_t *in);

// CFB encryption/decryption
int pgp_cipher_cfb_encrypt(pgp_crypt_t *cipher, uint8_t *out, const uint8_t *in, size_t len);
int pgp_cipher_cfb_decrypt(pgp_crypt_t *cipher, uint8_t *out, const uint8_t *in, size_t len);

int pgp_cipher_cfb_resync(pgp_crypt_t *cipher);

// Higher level operations
size_t pgp_encrypt_se(pgp_crypt_t *, void *, const void *, size_t);
size_t pgp_decrypt_se_ip(pgp_crypt_t *, void *, const void *, size_t);

#endif
