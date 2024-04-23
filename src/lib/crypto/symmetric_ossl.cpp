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

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "mem.h"
#include "utils.h"

static const char *
pgp_sa_to_openssl_string(int alg, bool silent = false)
{
    switch (alg) {
#if defined(ENABLE_IDEA)
    case PGP_SA_IDEA:
        return "idea-ecb";
#endif
    case PGP_SA_TRIPLEDES:
        return "des-ede3";
#if defined(ENABLE_CAST5)
    case PGP_SA_CAST5:
        return "cast5-ecb";
#endif
#if defined(ENABLE_BLOWFISH)
    case PGP_SA_BLOWFISH:
        return "bf-ecb";
#endif
    case PGP_SA_AES_128:
        return "aes-128-ecb";
    case PGP_SA_AES_192:
        return "aes-192-ecb";
    case PGP_SA_AES_256:
        return "aes-256-ecb";
#if defined(ENABLE_SM2)
    case PGP_SA_SM4:
        return "sm4-ecb";
#endif
    case PGP_SA_CAMELLIA_128:
        return "camellia-128-ecb";
    case PGP_SA_CAMELLIA_192:
        return "camellia-192-ecb";
    case PGP_SA_CAMELLIA_256:
        return "camellia-256-ecb";
    default:
        if (!silent) {
            RNP_LOG("Unsupported symmetric algorithm %d", alg);
        }
        return NULL;
    }
}

bool
pgp_cipher_cfb_start(pgp_crypt_t *  crypt,
                     pgp_symm_alg_t alg,
                     const uint8_t *key,
                     const uint8_t *iv)
{
    memset(crypt, 0x0, sizeof(*crypt));

    const char *cipher_name = pgp_sa_to_openssl_string(alg);
    if (!cipher_name) {
        RNP_LOG("Unsupported algorithm: %d", alg);
        return false;
    }

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        /* LCOV_EXCL_START */
        RNP_LOG("Cipher %s is not supported by OpenSSL.", cipher_name);
        return false;
        /* LCOV_EXCL_END */
    }

    crypt->alg = alg;
    crypt->blocksize = pgp_block_size(alg);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int             res = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    if (res != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to initialize cipher.");
        EVP_CIPHER_CTX_free(ctx);
        return false;
        /* LCOV_EXCL_END */
    }
    crypt->cfb.obj = ctx;

    if (iv) {
        // Otherwise left as all zeros via memset at start of function
        memcpy(crypt->cfb.iv, iv, crypt->blocksize);
    }

    crypt->cfb.remaining = 0;
    return true;
}

void
pgp_cipher_cfb_resync(pgp_crypt_t *crypt, const uint8_t *buf)
{
    /* iv will be encrypted in the upcoming call to encrypt/decrypt */
    memcpy(crypt->cfb.iv, buf, crypt->blocksize);
    crypt->cfb.remaining = 0;
}

int
pgp_cipher_cfb_finish(pgp_crypt_t *crypt)
{
    if (!crypt) {
        return 0; // LCOV_EXCL_LINE
    }
    if (crypt->cfb.obj) {
        EVP_CIPHER_CTX_free(crypt->cfb.obj);
        crypt->cfb.obj = NULL;
    }
    OPENSSL_cleanse((uint8_t *) crypt, sizeof(*crypt));
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
    size_t    blsize = crypt->blocksize;

    /* encrypting till the block boundary */
    while (bytes && crypt->cfb.remaining) {
        *out = *in++ ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = *out++;
        crypt->cfb.remaining--;
        bytes--;
    }

    if (!bytes) {
        return 0;
    }

    /* encrypting full blocks */
    if (bytes > blsize) {
        memcpy(iv64, crypt->cfb.iv, blsize);
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
                    int outlen = 16;
                    EVP_EncryptUpdate(
                      crypt->cfb.obj, (uint8_t *) iv64, &outlen, (uint8_t *) iv64, 16);
                    if (outlen != 16) {
                        RNP_LOG("Bad outlen: must be 16"); // LCOV_EXCL_LINE
                    }
                    *in64 ^= iv64[0];
                    iv64[0] = *in64++;
                    *in64 ^= iv64[1];
                    iv64[1] = *in64++;
                }
            } else {
                blocks >>= 3;
                while (blocks--) {
                    int outlen = 8;
                    EVP_EncryptUpdate(
                      crypt->cfb.obj, (uint8_t *) iv64, &outlen, (uint8_t *) iv64, 8);
                    if (outlen != 8) {
                        RNP_LOG("Bad outlen: must be 8"); // LCOV_EXCL_LINE
                    }
                    *in64 ^= iv64[0];
                    iv64[0] = *in64++;
                }
            }

            memcpy(out, buf64, blockb);
            out += blockb;
            in += blockb;
        }

        memcpy(crypt->cfb.iv, iv64, blsize);
    }

    if (!bytes) {
        return 0;
    }

    int outlen = blsize;
    EVP_EncryptUpdate(crypt->cfb.obj, crypt->cfb.iv, &outlen, crypt->cfb.iv, (int) blsize);
    if (outlen != (int) blsize) {
        RNP_LOG("Bad outlen: must be %zu", blsize); // LCOV_EXCL_LINE
    }
    crypt->cfb.remaining = blsize;

    /* encrypting tail */
    while (bytes) {
        *out = *in++ ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = *out++;
        crypt->cfb.remaining--;
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
    size_t    blsize = crypt->blocksize;

    /* decrypting till the block boundary */
    while (bytes && crypt->cfb.remaining) {
        uint8_t c = *in++;
        *out++ = c ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = c;
        crypt->cfb.remaining--;
        bytes--;
    }

    if (!bytes) {
        return 0;
    }

    /* decrypting full blocks */
    if (bytes > blsize) {
        memcpy(iv64, crypt->cfb.iv, blsize);

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
                    int outlen = 16;
                    EVP_EncryptUpdate(
                      crypt->cfb.obj, (uint8_t *) iv64, &outlen, (uint8_t *) iv64, 16);
                    if (outlen != 16) {
                        RNP_LOG("Bad outlen: must be 16"); // LCOV_EXCL_LINE
                    }
                    *out64++ = *in64 ^ iv64[0];
                    iv64[0] = *in64++;
                    *out64++ = *in64 ^ iv64[1];
                    iv64[1] = *in64++;
                }
            } else {
                blocks >>= 3;
                while (blocks--) {
                    int outlen = 8;
                    EVP_EncryptUpdate(
                      crypt->cfb.obj, (uint8_t *) iv64, &outlen, (uint8_t *) iv64, 8);
                    if (outlen != 8) {
                        RNP_LOG("Bad outlen: must be 8"); // LCOV_EXCL_LINE
                    }
                    *out64++ = *in64 ^ iv64[0];
                    iv64[0] = *in64++;
                }
            }

            memcpy(out, outbuf64, blockb);
            out += blockb;
            in += blockb;
        }

        memcpy(crypt->cfb.iv, iv64, blsize);
    }

    if (!bytes) {
        return 0;
    }

    int outlen = blsize;
    EVP_EncryptUpdate(crypt->cfb.obj, crypt->cfb.iv, &outlen, crypt->cfb.iv, (int) blsize);
    if (outlen != (int) blsize) {
        RNP_LOG("Bad outlen: must be %zu", blsize); // LCOV_EXCL_LINE
    }
    crypt->cfb.remaining = blsize;

    /* decrypting tail */
    while (bytes) {
        uint8_t c = *in++;
        *out++ = c ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = c;
        crypt->cfb.remaining--;
        bytes--;
    }

    return 0;
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

bool
pgp_is_sa_supported(int alg, bool silent)
{
    return pgp_sa_to_openssl_string(alg, silent);
}

#if defined(ENABLE_AEAD)

static const char *
openssl_aead_name(pgp_symm_alg_t ealg, pgp_aead_alg_t aalg)
{
    switch (aalg) {
    case PGP_AEAD_OCB:
        break;
    default:
        RNP_LOG("Only OCB mode is supported by the OpenSSL backend.");
        return NULL;
    }
    switch (ealg) {
    case PGP_SA_AES_128:
        return "AES-128-OCB";
    case PGP_SA_AES_192:
        return "AES-192-OCB";
    case PGP_SA_AES_256:
        return "AES-256-OCB";
    default:
        RNP_LOG("Only AES-OCB is supported by the OpenSSL backend.");
        return NULL;
    }
}

bool
pgp_cipher_aead_init(pgp_crypt_t *  crypt,
                     pgp_symm_alg_t ealg,
                     pgp_aead_alg_t aalg,
                     const uint8_t *key,
                     bool           decrypt)
{
    memset(crypt, 0x0, sizeof(*crypt));
    /* OpenSSL backend currently supports only AES-OCB */
    const char *algname = openssl_aead_name(ealg, aalg);
    if (!algname) {
        return false;
    }
    auto cipher = EVP_get_cipherbyname(algname);
    if (!cipher) {
        /* LCOV_EXCL_START */
        RNP_LOG("Cipher %s is not supported.", algname);
        return false;
        /* LCOV_EXCL_END */
    }
    /* Create and setup context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to create cipher context: %lu", ERR_peek_last_error());
        return false;
        /* LCOV_EXCL_END */
    }

    crypt->aead.key = new rnp::secure_vector<uint8_t>(key, key + pgp_key_size(ealg));
    crypt->alg = ealg;
    crypt->blocksize = pgp_block_size(ealg);
    crypt->aead.cipher = cipher;
    crypt->aead.obj = ctx;
    crypt->aead.alg = aalg;
    crypt->aead.decrypt = decrypt;
    crypt->aead.granularity = crypt->blocksize;
    crypt->aead.taglen = PGP_AEAD_EAX_OCB_TAG_LEN;
    crypt->aead.ad_len = 0;
    crypt->aead.n_len = pgp_cipher_aead_nonce_len(aalg);
    return true;
}

size_t
pgp_cipher_aead_granularity(pgp_crypt_t *crypt)
{
    return crypt->aead.granularity;
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

#if defined(ENABLE_AEAD)
bool
pgp_cipher_aead_set_ad(pgp_crypt_t *crypt, const uint8_t *ad, size_t len)
{
    assert(len <= sizeof(crypt->aead.ad));
    memcpy(crypt->aead.ad, ad, len);
    crypt->aead.ad_len = len;
    return true;
}

bool
pgp_cipher_aead_start(pgp_crypt_t *crypt, const uint8_t *nonce, size_t len)
{
    auto &aead = crypt->aead;
    auto  ctx = aead.obj;
    int   enc = aead.decrypt ? 0 : 1;
    assert(len == aead.n_len);
    EVP_CIPHER_CTX_reset(ctx);
    if (EVP_CipherInit_ex(ctx, aead.cipher, NULL, NULL, NULL, enc) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to initialize cipher: %lu", ERR_peek_last_error());
        return false;
        /* LCOV_EXCL_END */
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, aead.n_len, NULL) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set nonce length: %lu", ERR_peek_last_error());
        return false;
        /* LCOV_EXCL_END */
    }
    if (EVP_CipherInit_ex(ctx, NULL, NULL, aead.key->data(), nonce, enc) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to start cipher: %lu", ERR_peek_last_error());
        return false;
        /* LCOV_EXCL_END */
    }
    int adlen = 0;
    if (EVP_CipherUpdate(ctx, NULL, &adlen, aead.ad, aead.ad_len) != 1) {
        /* LCOV_EXCL_START */
        RNP_LOG("Failed to set AD: %lu", ERR_peek_last_error());
        return false;
        /* LCOV_EXCL_END */
    }
    return true;
}

bool
pgp_cipher_aead_update(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t len)
{
    if (!len) {
        return true;
    }
    int  out_len = 0;
    bool res = EVP_CipherUpdate(crypt->aead.obj, out, &out_len, in, len) == 1;
    if (!res) {
        RNP_LOG("Failed to update cipher: %lu", ERR_peek_last_error()); // LCOV_EXCL_LINE
    }
    assert(out_len == (int) len);
    return res;
}

void
pgp_cipher_aead_reset(pgp_crypt_t *crypt)
{
    /* Do nothing as subsequent pgp_cipher_aead_start() call will reset context */
}

bool
pgp_cipher_aead_finish(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t len)
{
    auto &aead = crypt->aead;
    auto  ctx = aead.obj;
    if (aead.decrypt) {
        assert(len >= aead.taglen);
        if (len < aead.taglen) {
            /* LCOV_EXCL_START */
            RNP_LOG("Invalid state: too few input bytes.");
            return false;
            /* LCOV_EXCL_END */
        }
        size_t data_len = len - aead.taglen;
        int    out_len = 0;
        if (EVP_CipherUpdate(ctx, out, &out_len, in, data_len) != 1) {
            /* LCOV_EXCL_START */
            RNP_LOG("Failed to update cipher: %lu", ERR_peek_last_error());
            return false;
            /* LCOV_EXCL_END */
        }
        uint8_t tag[PGP_AEAD_MAX_TAG_LEN] = {0};
        memcpy(tag, in + data_len, aead.taglen);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, aead.taglen, tag) != 1) {
            /* LCOV_EXCL_START */
            RNP_LOG("Failed to set tag: %lu", ERR_peek_last_error());
            return false;
            /* LCOV_EXCL_END */
        }
        int out_len2 = 0;
        if (EVP_CipherFinal_ex(ctx, out + out_len, &out_len2) != 1) {
            /* Zero value if auth tag is incorrect */
            if (ERR_peek_last_error()) {
                /* LCOV_EXCL_START */
                RNP_LOG("Failed to finish AEAD decryption: %lu", ERR_peek_last_error());
                /* LCOV_EXCL_END */
            }
            return false;
        }
        assert(out_len + out_len2 == (int) (len - aead.taglen));
    } else {
        int out_len = 0;
        if (EVP_CipherUpdate(ctx, out, &out_len, in, len) != 1) {
            /* LCOV_EXCL_START */
            RNP_LOG("Failed to update cipher: %lu", ERR_peek_last_error());
            return false;
            /* LCOV_EXCL_END */
        }
        int out_len2 = 0;
        if (EVP_CipherFinal_ex(ctx, out + out_len, &out_len2) != 1) {
            /* LCOV_EXCL_START */
            RNP_LOG("Failed to finish AEAD encryption: %lu", ERR_peek_last_error());
            return false;
            /* LCOV_EXCL_END */
        }
        assert(out_len + out_len2 == (int) len);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, aead.taglen, out + len) != 1) {
            /* LCOV_EXCL_START */
            RNP_LOG("Failed to get tag: %lu", ERR_peek_last_error());
            return false;
            /* LCOV_EXCL_END */
        }
    }
    return true;
}

void
pgp_cipher_aead_destroy(pgp_crypt_t *crypt)
{
    if (crypt->aead.obj) {
        EVP_CIPHER_CTX_free(crypt->aead.obj);
    }
    delete crypt->aead.key;
    memset(crypt, 0x0, sizeof(*crypt));
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
