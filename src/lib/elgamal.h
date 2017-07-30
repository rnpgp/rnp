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

#ifndef RNP_ELG_H_
#define RNP_ELG_H_

#include <stdint.h>
#include "packet.h"

/*
 * Performs ElGamal encryption
 * Result of an encryption is composed of two parts - g2k and encm
 *
 * @param g2k [out] buffer stores first part of encryption (g^k % p)
 * @param encm [out] buffer stores second part of encryption (y^k * in % p)
 * @param in plaintext to be encrypted
 * @param length length of an input
 * @param pubkey public key to be used for encryption
 *
 * @pre g2k size must be at least equal to byte size of prime `p'
 * @pre encm size must be at least equal to byte size of prime `p'
 *
 * @return     on success - number of bytes written to g2k and encm
 *            on failure -1
 */
int pgp_elgamal_public_encrypt_pkcs1(uint8_t *                   g2k,
                                     uint8_t *                   encm,
                                     const uint8_t *             in,
                                     size_t                      length,
                                     const pgp_elgamal_pubkey_t *pubkey);

/*
 * Performs ElGamal decryption
 *
 * @param out [out] decrypted plaintext
 * @param g2k buffer stores first part of encryption (g^k % p)
 * @param encm buffer stores second part of encryption (y^k * in % p)
 * @param length length of g2k or in (must be equal to byte size of prime `p')
 * @param seckey private part of a key used for decryption
 * @param pubkey public domain parameters (p,g) used for decryption
 *
 * @pre g2k size must be at least equal to byte size of prime `p'
 * @pre encm size must be at least equal to byte size of prime `p'
 * @pre byte-size of `g2k' must be equal to `encm'
 *
 * @return     on success - number of bytes written to g2k and encm
 *            on failure -1
 */
int pgp_elgamal_private_decrypt_pkcs1(uint8_t *                   out,
                                      const uint8_t *             g2k,
                                      const uint8_t *             in,
                                      size_t                      length,
                                      const pgp_elgamal_seckey_t *seckey,
                                      const pgp_elgamal_pubkey_t *pubkey);

#endif
