/*-
 * Copyright (c) 2017-2022 Ribose Inc.
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

#include <stdlib.h>
#include <string.h>
#include <botan/ffi.h>
#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <rnp/rnp_def.h>
#include "elgamal.h"
#include "utils.h"
#include "bn.h"

// Max supported key byte size
#define ELGAMAL_MAX_P_BYTELEN BITS_TO_BYTES(PGP_MPINT_BITS)

static bool
elgamal_load_public_key(botan_pubkey_t *pubkey, const pgp_eg_key_t *keydata)
{
    bignum_t *p = NULL;
    bignum_t *g = NULL;
    bignum_t *y = NULL;
    bool      res = false;

    // Check if provided public key byte size is not greater than ELGAMAL_MAX_P_BYTELEN.
    if (mpi_bytes(&keydata->p) > ELGAMAL_MAX_P_BYTELEN) {
        goto done;
    }

    if (!(p = mpi2bn(&keydata->p)) || !(g = mpi2bn(&keydata->g)) ||
        !(y = mpi2bn(&keydata->y))) {
        goto done;
    }

    res =
      !botan_pubkey_load_elgamal(pubkey, BN_HANDLE_PTR(p), BN_HANDLE_PTR(g), BN_HANDLE_PTR(y));
done:
    bn_free(p);
    bn_free(g);
    bn_free(y);
    return res;
}

static bool
elgamal_load_secret_key(botan_privkey_t *seckey, const pgp_eg_key_t *keydata)
{
    bignum_t *p = NULL;
    bignum_t *g = NULL;
    bignum_t *x = NULL;
    bool      res = false;

    // Check if provided secret key byte size is not greater than ELGAMAL_MAX_P_BYTELEN.
    if (mpi_bytes(&keydata->p) > ELGAMAL_MAX_P_BYTELEN) {
        goto done;
    }

    if (!(p = mpi2bn(&keydata->p)) || !(g = mpi2bn(&keydata->g)) ||
        !(x = mpi2bn(&keydata->x))) {
        goto done;
    }

    res = !botan_privkey_load_elgamal(
      seckey, BN_HANDLE_PTR(p), BN_HANDLE_PTR(g), BN_HANDLE_PTR(x));
done:
    bn_free(p);
    bn_free(g);
    bn_free(x);
    return res;
}

bool
elgamal_validate_key(const pgp_eg_key_t *key, bool secret)
{
    // Check if provided public key byte size is not greater than ELGAMAL_MAX_P_BYTELEN.
    if (mpi_bytes(&key->p) > ELGAMAL_MAX_P_BYTELEN) {
        return false;
    }

    /* Use custom validation since we added some custom validation, and Botan has slow test for
     * prime for p */
    try {
        Botan::BigInt p(key->p.mpi, key->p.len);
        Botan::BigInt g(key->g.mpi, key->g.len);

        /* 1 < g < p */
        if ((g.cmp_word(1) != 1) || (g.cmp(p) != -1)) {
            return false;
        }
        /* g ^ (p - 1) = 1 mod p */
        if (Botan::power_mod(g, p - 1, p).cmp_word(1)) {
            return false;
        }
        /* check for small order subgroups */
        Botan::Modular_Reducer reducer(p);
        Botan::BigInt          v = g;
        for (size_t i = 2; i < (1 << 17); i++) {
            v = reducer.multiply(v, g);
            if (!v.cmp_word(1)) {
                RNP_LOG("Small subgroup detected. Order %zu", i);
                return false;
            }
        }
        if (!secret) {
            return true;
        }
        /* check that g ^ x = y (mod p) */
        Botan::BigInt y(key->y.mpi, key->y.len);
        Botan::BigInt x(key->x.mpi, key->x.len);
        return Botan::power_mod(g, x, p) == y;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

rnp_result_t
elgamal_encrypt_pkcs1(rnp::RNG *          rng,
                      pgp_eg_encrypted_t *out,
                      const uint8_t *     in,
                      size_t              in_len,
                      const pgp_eg_key_t *key)
{
    botan_pubkey_t        b_key = NULL;
    botan_pk_op_encrypt_t op_ctx = NULL;
    rnp_result_t          ret = RNP_ERROR_BAD_PARAMETERS;
    /* Max size of an output len is twice an order of underlying group (p length) */
    uint8_t enc_buf[ELGAMAL_MAX_P_BYTELEN * 2] = {0};
    size_t  p_len;

    if (!elgamal_load_public_key(&b_key, key)) {
        RNP_LOG("Failed to load public key");
        goto end;
    }

    /* Size of output buffer must be equal to twice the size of key byte len.
     * as ElGamal encryption outputs concatenation of two components, both
     * of size equal to size of public key byte len.
     * Successful call to botan's ElGamal encryption will return output that's
     * always 2*pubkey size.
     */
    p_len = mpi_bytes(&key->p) * 2;

    if (botan_pk_op_encrypt_create(&op_ctx, b_key, "PKCS1v15", 0) ||
        botan_pk_op_encrypt(op_ctx, rng->handle(), enc_buf, &p_len, in, in_len)) {
        RNP_LOG("Failed to create operation context");
        goto end;
    }

    /*
     * Botan's ElGamal formats the g^k and msg*(y^k) together into a single byte string.
     * We have to parse out the two values after encryption, as rnp stores those values
     * separatelly.
     *
     * We don't trim zeros from octet string as it is done before final marshalling
     * (add_packet_body_mpi)
     *
     * We must assume that botan copies even number of bytes to output buffer (to avoid
     * memory corruption)
     */
    p_len /= 2;
    if (mem2mpi(&out->g, enc_buf, p_len) && mem2mpi(&out->m, enc_buf + p_len, p_len)) {
        ret = RNP_SUCCESS;
    }
end:
    botan_pk_op_encrypt_destroy(op_ctx);
    botan_pubkey_destroy(b_key);
    return ret;
}

rnp_result_t
elgamal_decrypt_pkcs1(rnp::RNG *                rng,
                      uint8_t *                 out,
                      size_t *                  out_len,
                      const pgp_eg_encrypted_t *in,
                      const pgp_eg_key_t *      key)
{
    botan_privkey_t       b_key = NULL;
    botan_pk_op_decrypt_t op_ctx = NULL;
    rnp_result_t          ret = RNP_ERROR_BAD_PARAMETERS;
    uint8_t               enc_buf[ELGAMAL_MAX_P_BYTELEN * 2] = {0};
    size_t                p_len;
    size_t                g_len;
    size_t                m_len;

    if (!mpi_bytes(&key->x)) {
        RNP_LOG("empty secret key");
        goto end;
    }

    // Check if provided public key byte size is not greater than ELGAMAL_MAX_P_BYTELEN.
    p_len = mpi_bytes(&key->p);
    g_len = mpi_bytes(&in->g);
    m_len = mpi_bytes(&in->m);

    if ((2 * p_len > sizeof(enc_buf)) || (g_len > p_len) || (m_len > p_len)) {
        RNP_LOG("Unsupported/wrong public key or encrypted data");
        goto end;
    }

    if (!elgamal_load_secret_key(&b_key, key)) {
        RNP_LOG("Failed to load private key");
        goto end;
    }

    /* Botan expects ciphertext to be concatenated (g^k | encrypted m). Size must
     * be equal to twice the byte size of public key, potentially prepended with zeros.
     */
    memcpy(&enc_buf[p_len - g_len], in->g.mpi, g_len);
    memcpy(&enc_buf[2 * p_len - m_len], in->m.mpi, m_len);

    *out_len = p_len;
    if (botan_pk_op_decrypt_create(&op_ctx, b_key, "PKCS1v15", 0) ||
        botan_pk_op_decrypt(op_ctx, out, out_len, enc_buf, 2 * p_len)) {
        RNP_LOG("Decryption failed");
        goto end;
    }
    ret = RNP_SUCCESS;
end:
    botan_pk_op_decrypt_destroy(op_ctx);
    botan_privkey_destroy(b_key);
    return ret;
}

rnp_result_t
elgamal_generate(rnp::RNG *rng, pgp_eg_key_t *key, size_t keybits)
{
    if ((keybits < 1024) || (keybits > PGP_MPINT_BITS)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    botan_privkey_t key_priv = NULL;
    rnp_result_t    ret = RNP_ERROR_GENERIC;
    bignum_t *      p = bn_new();
    bignum_t *      g = bn_new();
    bignum_t *      y = bn_new();
    bignum_t *      x = bn_new();

    if (!p || !g || !y || !x) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto end;
    }

start:
    if (botan_privkey_create_elgamal(&key_priv, rng->handle(), keybits, keybits - 1)) {
        RNP_LOG("Wrong parameters");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto end;
    }

    if (botan_privkey_get_field(BN_HANDLE_PTR(y), key_priv, "y")) {
        RNP_LOG("Failed to obtain public key");
        goto end;
    }
    if (bn_num_bytes(*y) < BITS_TO_BYTES(keybits)) {
        botan_privkey_destroy(key_priv);
        goto start;
    }

    if (botan_privkey_get_field(BN_HANDLE_PTR(p), key_priv, "p") ||
        botan_privkey_get_field(BN_HANDLE_PTR(g), key_priv, "g") ||
        botan_privkey_get_field(BN_HANDLE_PTR(y), key_priv, "y") ||
        botan_privkey_get_field(BN_HANDLE_PTR(x), key_priv, "x")) {
        RNP_LOG("Botan FFI call failed");
        ret = RNP_ERROR_GENERIC;
        goto end;
    }

    if (bn2mpi(p, &key->p) && bn2mpi(g, &key->g) && bn2mpi(y, &key->y) && bn2mpi(x, &key->x)) {
        ret = RNP_SUCCESS;
    }
end:
    bn_free(p);
    bn_free(g);
    bn_free(y);
    bn_free(x);
    botan_privkey_destroy(key_priv);
    return ret;
}
