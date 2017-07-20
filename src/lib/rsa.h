/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#ifndef RNP_RSA_H_
#define RNP_RSA_H_

#include <stdint.h>
#include "packet.h"

/*
 * RSA encrypt/decrypt
 */

int pgp_genkey_rsa(pgp_seckey_t *seckey, size_t numbits);

int pgp_rsa_encrypt_pkcs1(uint8_t *               out,
                          size_t                  out_len,
                          const uint8_t *         key,
                          size_t                  key_len,
                          const pgp_rsa_pubkey_t *pubkey);

int pgp_rsa_decrypt_pkcs1(uint8_t *               out,
                          size_t                  out_len,
                          const uint8_t *         key,
                          size_t                  key_len,
                          const pgp_rsa_seckey_t *privkey,
                          const pgp_rsa_pubkey_t *pubkey);

/*
 * RSA signature generation and verification
 */

/*
 * Returns 1 for valid 0 for invalid/error
 */
bool pgp_rsa_pkcs1_verify_hash(const uint8_t *         sig_buf,
                               size_t                  sig_buf_size,
                               pgp_hash_alg_t          hash_alg,
                               const uint8_t *         hash,
                               size_t                  hash_len,
                               const pgp_rsa_pubkey_t *pubkey);

/*
 * Returns # bytes written to sig_buf on success, 0 on error
 */
int pgp_rsa_pkcs1_sign_hash(uint8_t *      sig_buf,
                            size_t         sig_buf_size,
                            pgp_hash_alg_t hash_alg,
                            const uint8_t *hash,
                            size_t         hash_len,
                            const pgp_rsa_seckey_t *,
                            const pgp_rsa_pubkey_t *);

#endif
