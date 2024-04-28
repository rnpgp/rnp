/*-
 * Copyright (c) 2021-2023 Ribose Inc.
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

#include "crypto.h"
#include "config.h"
#include "defaults.h"

void
pgp_cipher_cfb_resync(pgp_crypt_t *crypt, const uint8_t *buf)
{
    /* iv will be encrypted in the upcoming call to encrypt/decrypt */
    memcpy(crypt->cfb.iv, buf, crypt->blocksize);
    crypt->cfb.remaining = 0;
}

size_t
pgp_cipher_block_size(pgp_crypt_t *crypt)
{
    return crypt->blocksize;
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

#if defined(ENABLE_AEAD)
size_t
pgp_cipher_aead_granularity(pgp_crypt_t *crypt)
{
    return crypt->aead.granularity;
}

size_t
pgp_cipher_aead_nonce(pgp_aead_alg_t aalg, const uint8_t *iv, uint8_t *nonce, size_t index)
{
    switch (aalg) {
    case PGP_AEAD_EAX:
        /* The nonce for EAX mode is computed by treating the starting
        initialization vector as a 16-octet, big-endian value and
        exclusive-oring the low eight octets of it with the chunk index.
        */
        memcpy(nonce, iv, PGP_AEAD_EAX_NONCE_LEN);
        for (int i = 15; (i > 7) && index; i--) {
            nonce[i] ^= index & 0xff;
            index = index >> 8;
        }
        return PGP_AEAD_EAX_NONCE_LEN;
    case PGP_AEAD_OCB:
        /* The nonce for a chunk of chunk index "i" in OCB processing is defined as:
           OCB-Nonce_{i} = IV[1..120] xor i
        */
        memcpy(nonce, iv, PGP_AEAD_OCB_NONCE_LEN);
        for (int i = 14; (i >= 0) && index; i--) {
            nonce[i] ^= index & 0xff;
            index = index >> 8;
        }
        return PGP_AEAD_OCB_NONCE_LEN;
    default:
        return 0;
    }
}

#endif

size_t
pgp_cipher_aead_nonce_len(pgp_aead_alg_t aalg)
{
    switch (aalg) {
    case PGP_AEAD_EAX:
        return PGP_AEAD_EAX_NONCE_LEN;
    case PGP_AEAD_OCB:
        return PGP_AEAD_OCB_NONCE_LEN;
    default:
        return 0;
    }
}

size_t
pgp_cipher_aead_tag_len(pgp_aead_alg_t aalg)
{
    switch (aalg) {
    case PGP_AEAD_EAX:
    case PGP_AEAD_OCB:
        return PGP_AEAD_EAX_OCB_TAG_LEN;
    default:
        return 0;
    }
}
