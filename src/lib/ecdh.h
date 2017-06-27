/*-
 * Copyright (c) 2017 Ribose Inc.
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

#ifndef ECDH_H_
#define ECDH_H_

#include <stdint.h>
#include <stdbool.h>
#include "errors.h"
#include "rnp.h"
#include "packet.h"

/* Size of wrapped and obfuscated key size
 *
 * RNP pads a key with PKCS-5 always to 40 bytes,
 * then 8 bytes is added by 3394.
 */
#define ECDH_WRAPPED_KEY_SIZE 48

/*
 * Performs ECDH encryption
 *
 * @param in plaintext to be encrypted
 * @param length length of an input
 * @param pubkey public key to be used for encryption
 * @param ephemeral_key [out]
 * @param wrapped_key [out]
 *
 * @return PGP_E_OK on success, otherwise error code
 */
rnp_result pgp_ecdh_encrypt_pkcs5(const uint8_t *const     session_key,
                                  size_t                   session_key_len,
                                  uint8_t *                wrapped_key,
                                  size_t *                 wrapped_key_len,
                                  botan_mp_t               ephemeral_key,
                                  const pgp_ecdh_pubkey_t *pubkey,
                                  const pgp_fingerprint_t *fingerprint);

rnp_result pgp_ecdh_decrypt_pkcs5(uint8_t *                session_key,
                                  size_t *                 session_key_len,
                                  uint8_t *                wrapped_key,
                                  size_t                   wrapped_key_len,
                                  const botan_mp_t         ephemeral_key,
                                  const pgp_ecc_seckey_t * seckey,
                                  const pgp_ecdh_pubkey_t *pubkey,
                                  const pgp_fingerprint_t *fingerprint);
#endif // ECDH_H_