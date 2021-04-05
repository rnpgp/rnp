/*
 * Copyright (c) 2021, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include "eddsa.h"
#include "utils.h"
#include "bn.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/ec.h>

rnp_result_t
eddsa_validate_key(rng_t *rng, const pgp_ec_key_t *key, bool secret)
{
    EVP_PKEY *evpkey =
      secret ?
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, key->x.mpi, key->x.len) :
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, &key->p.mpi[1], key->p.len - 1);
    if (!evpkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_result_t  ret = RNP_ERROR_GENERIC;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (!ctx) {
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_check(ctx) > 0) {
        ret = RNP_SUCCESS;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpkey);
    return ret;
}

rnp_result_t
eddsa_generate(rng_t *rng, pgp_ec_key_t *key, size_t numbits)
{
    if (numbits != 255) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) {
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        return RNP_ERROR_GENERIC;
    }
    rnp_result_t ret = RNP_ERROR_GENERIC;
    EVP_PKEY *   pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        RNP_LOG("EC keygen failed: %lu", ERR_peek_last_error());
        goto done;
    }
    static_assert(sizeof(key->x.mpi) > 32, "mpi is too small.");
    key->x.len = sizeof(key->x.mpi);
    if (EVP_PKEY_get_raw_private_key(pkey, key->x.mpi, &key->x.len) <= 0) {
        RNP_LOG("Failed get raw private key: %lu", ERR_peek_last_error());
        goto done;
    }
    assert(key->x.len == 32);
    key->p.len = sizeof(key->p.mpi) - 1;
    if (EVP_PKEY_get_raw_public_key(pkey, &key->p.mpi[1], &key->p.len) <= 0) {
        RNP_LOG("Failed get raw private key: %lu", ERR_peek_last_error());
        goto done;
    }
    assert(key->p.len == 32);
    key->p.mpi[0] = 0x40;
    key->p.len++;
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

rnp_result_t
eddsa_verify(const pgp_ec_signature_t *sig,
             const uint8_t *           hash,
             size_t                    hash_len,
             const pgp_ec_key_t *      key)
{
    if ((mpi_bytes(&sig->r) > 32) || (mpi_bytes(&sig->s) > 32)) {
        RNP_LOG("Invalid EdDSA signature.");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (mpi_bytes(&key->p) != 33) {
        RNP_LOG("Invalid EdDSA public key.");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    EVP_PKEY *evpkey = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, NULL, &key->p.mpi[1], mpi_bytes(&key->p) - 1);
    if (!evpkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t ret = RNP_ERROR_SIGNATURE_INVALID;
    uint8_t      sigbuf[64] = {0};
    /* init context and sign */
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX *  md = EVP_MD_CTX_new();
    if (!md) {
        RNP_LOG("Failed to allocate MD ctx: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_DigestVerifyInit(md, &ctx, NULL, NULL, evpkey) <= 0) {
        RNP_LOG("Failed to initialize signing: %lu", ERR_peek_last_error());
        goto done;
    }
    mpi2mem(&sig->r, &sigbuf[32 - mpi_bytes(&sig->r)]);
    mpi2mem(&sig->s, &sigbuf[64 - mpi_bytes(&sig->s)]);

    if (EVP_DigestVerify(md, sigbuf, 64, hash, hash_len) > 0) {
        ret = RNP_SUCCESS;
    }
done:
    /* line below will also free ctx */
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(evpkey);
    return ret;
}

rnp_result_t
eddsa_sign(rng_t *             rng,
           pgp_ec_signature_t *sig,
           const uint8_t *     hash,
           size_t              hash_len,
           const pgp_ec_key_t *key)
{
    if (mpi_bytes(&key->x) == 0) {
        RNP_LOG("private key not set");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    EVP_PKEY *evpkey =
      EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, key->x.mpi, key->x.len);
    if (!evpkey) {
        RNP_LOG("Failed to load private key: %lu", ERR_peek_last_error());
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t ret = RNP_ERROR_GENERIC;
    /* init context and sign */
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX *  md = EVP_MD_CTX_new();
    if (!md) {
        RNP_LOG("Failed to allocate MD ctx: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_DigestSignInit(md, &ctx, NULL, NULL, evpkey) <= 0) {
        RNP_LOG("Failed to initialize signing: %lu", ERR_peek_last_error());
        goto done;
    }
    static_assert((sizeof(sig->r.mpi) == PGP_MPINT_SIZE) && (PGP_MPINT_SIZE >= 64),
                  "invalid mpi type/size");
    sig->r.len = PGP_MPINT_SIZE;
    if (EVP_DigestSign(md, sig->r.mpi, &sig->r.len, hash, hash_len) <= 0) {
        RNP_LOG("Signing failed: %lu", ERR_peek_last_error());
        sig->r.len = 0;
        goto done;
    }
    assert(sig->r.len == 64);
    sig->r.len = 32;
    sig->s.len = 32;
    memcpy(sig->s.mpi, &sig->r.mpi[32], 32);
    ret = RNP_SUCCESS;
done:
    /* line below will also free ctx */
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(evpkey);
    return ret;
}
