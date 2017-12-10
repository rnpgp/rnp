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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <botan/ffi.h>

#include <librepgp/packet-parse.h>

#include "crypto/sm2.h"
#include "ec.h"
#include "crypto.h"
#include "utils.h"

rnp_result_t
pgp_sm2_sign_hash(rng_t *                 rng,
                  pgp_ecc_sig_t *         sign,
                  const uint8_t *         hashbuf,
                  size_t                  hash_len,
                  const pgp_ecc_seckey_t *seckey,
                  const pgp_ecc_pubkey_t *pubkey)
{
    const ec_curve_desc_t *curve = get_curve_desc(pubkey->curve);
    botan_pk_op_sign_t     signer = NULL;
    botan_privkey_t        key = NULL;
    rnp_result_t           ret = RNP_ERROR_GENERIC;
    uint8_t                out_buf[2 * MAX_CURVE_BYTELEN] = {0};

    if (curve == NULL) {
        return RNP_ERROR_GENERIC;
    }
    const size_t sign_half_len = BITS_TO_BYTES(curve->bitlen);

    if (sign->r || sign->s) {
        // Caller must not allocate r and s
        return RNP_ERROR_GENERIC;
    }

    if (botan_privkey_load_sm2(&key, seckey->x->mp, curve->botan_name)) {
        RNP_LOG("Can't load private key");
        return RNP_ERROR_BAD_FORMAT;
    }

    if (botan_pk_op_sign_create(&signer, key, "", 0)) {
        goto end;
    }

    if (botan_pk_op_sign_update(signer, hashbuf, hash_len)) {
        goto end;
    }

    size_t sig_len = 2 * sign_half_len;
    if (botan_pk_op_sign_finish(signer, rng_handle(rng), out_buf, &sig_len)) {
        RNP_LOG("Signing failed");
        goto end;
    }

    // Allocate memory and copy results
    sign->r = BN_bin2bn(out_buf, sign_half_len, sign->r);
    sign->s = BN_bin2bn(out_buf + sign_half_len, sign_half_len, sign->s);
    if (!sign->r || !sign->s) {
        goto end;
    }

    // All good now
    ret = RNP_SUCCESS;

end:
    if (ret != RNP_SUCCESS) {
        BN_clear_free(sign->r);
        BN_clear_free(sign->s);
    }
    botan_privkey_destroy(key);
    botan_pk_op_sign_destroy(signer);

    return ret;
}

rnp_result_t
pgp_sm2_verify_hash(const pgp_ecc_sig_t *   sign,
                    const uint8_t *         hash,
                    size_t                  hash_len,
                    const pgp_ecc_pubkey_t *pubkey)
{
    const ec_curve_desc_t *curve = get_curve_desc(pubkey->curve);

    botan_mp_t           public_x = NULL;
    botan_mp_t           public_y = NULL;
    botan_pubkey_t       pub = NULL;
    botan_pk_op_verify_t verifier = NULL;
    rnp_result_t         ret = RNP_ERROR_SIGNATURE_INVALID;
    uint8_t              sign_buf[2 * MAX_CURVE_BYTELEN] = {0};
    uint8_t              point_bytes[BITS_TO_BYTES(521) * 2 + 1] = {0};
    size_t               r_blen, s_blen;

    if (curve == NULL) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const size_t sign_half_len = BITS_TO_BYTES(curve->bitlen);

    if (!BN_num_bytes(pubkey->point, &r_blen) || (r_blen > sizeof(point_bytes)) ||
        BN_bn2bin(pubkey->point, point_bytes) || (point_bytes[0] != 0x04)) {
        RNP_LOG("Failed to load public key");
        goto end;
    }

    if (botan_mp_init(&public_x) || botan_mp_init(&public_y) ||
        botan_mp_from_bin(public_x, &point_bytes[1], sign_half_len) ||
        botan_mp_from_bin(public_y, &point_bytes[1 + sign_half_len], sign_half_len)) {
        goto end;
    }

    if (botan_pubkey_load_sm2(&pub, public_x, public_y, curve->botan_name)) {
        RNP_LOG("Failed to load public key");
        goto end;
    }

    if (botan_pk_op_verify_create(&verifier, pub, "", 0)) {
        goto end;
    }

    if (botan_pk_op_verify_update(verifier, hash, hash_len)) {
        goto end;
    }

    if (!BN_num_bytes(sign->r, &r_blen) || (r_blen > sign_half_len) ||
        !BN_num_bytes(sign->s, &s_blen) || (s_blen > sign_half_len) ||
        (sign_half_len > MAX_CURVE_BYTELEN)) {
        goto end;
    }

    BN_bn2bin(sign->r, &sign_buf[sign_half_len - r_blen]);
    BN_bn2bin(sign->s, &sign_buf[sign_half_len + sign_half_len - s_blen]);

    ret = botan_pk_op_verify_finish(verifier, sign_buf, sign_half_len * 2) ?
            RNP_ERROR_SIGNATURE_INVALID :
            RNP_SUCCESS;

end:
    botan_mp_destroy(public_x);
    botan_mp_destroy(public_y);
    botan_pubkey_destroy(pub);
    botan_pk_op_verify_destroy(verifier);
    return ret;
}

rnp_result_t
pgp_sm2_encrypt(rng_t *                 rng,
                uint8_t *               out,
                size_t *                out_len,
                const uint8_t *         key,
                size_t                  key_len,
                pgp_hash_alg_t          hash_algo,
                const pgp_ecc_pubkey_t *pubkey)
{
    rnp_result_t retval = RNP_ERROR_GENERIC;

    const ec_curve_desc_t *curve = get_curve_desc(pubkey->curve);
    botan_mp_t             public_x = NULL;
    botan_mp_t             public_y = NULL;
    botan_pubkey_t         sm2_key = NULL;
    botan_pk_op_encrypt_t  enc_op = NULL;
    size_t                 sz;

    const size_t point_len = BITS_TO_BYTES(curve->bitlen);
    uint8_t      point_bytes[BITS_TO_BYTES(521) * 2 + 1] = {0};
    size_t       hash_alg_len;

    if (curve == NULL) {
        return RNP_ERROR_GENERIC;
    }

    if (!pgp_digest_length(hash_algo, &hash_alg_len)) {
        RNP_LOG("Unknown hash algorithm for SM2 encryption");
        goto done;
    }

    /*
    * Format of SM2 ciphertext is a point (2*point_len+1) plus
    * the masked ciphertext (out_len) plus a hash.
    */
    const size_t ctext_len = (2 * point_len + 1) + key_len + hash_alg_len;

    if (*out_len < ctext_len) {
        RNP_LOG("output buffer for SM2 encryption too short");
        goto done;
    }

    if (!BN_num_bytes(pubkey->point, &sz) || (sz > sizeof(point_bytes)) ||
        BN_bn2bin(pubkey->point, point_bytes) || (point_bytes[0] != 0x04)) {
        RNP_LOG("Failed to load public key");
        goto done;
    }

    if (botan_mp_init(&public_x) || botan_mp_init(&public_y) ||
        botan_mp_from_bin(public_x, &point_bytes[1], point_len) ||
        botan_mp_from_bin(public_y, &point_bytes[1 + point_len], point_len)) {
        goto done;
    }

    const char *curve_name = curve->botan_name;
    if (botan_pubkey_load_sm2_enc(&sm2_key, public_x, public_y, curve_name)) {
        RNP_LOG("Failed to load public key");
        goto done;
    }

    if (botan_pubkey_check_key(sm2_key, rng_handle(rng), 1) != 0) {
        goto done;
    }

    /*
    SM2 encryption doesn't have any kind of format specifier because
    it's an all in one scheme, only the hash (used for the integrity
    check) is specified.
    */
    if (botan_pk_op_encrypt_create(&enc_op, sm2_key, pgp_hash_name_botan(hash_algo), 0) != 0) {
        goto done;
    }

    if (botan_pk_op_encrypt(enc_op, rng_handle(rng), out, out_len, key, key_len) == 0) {
        out[*out_len] = hash_algo;
        *out_len += 1;
        retval = RNP_SUCCESS;
    }

done:
    botan_pk_op_encrypt_destroy(enc_op);
    botan_pubkey_destroy(sm2_key);

    return retval;
}

rnp_result_t
pgp_sm2_decrypt(uint8_t *               out,
                size_t *                out_len,
                const uint8_t *         ctext,
                size_t                  ctext_len,
                const pgp_ecc_seckey_t *privkey,
                const pgp_ecc_pubkey_t *pubkey)
{
    const ec_curve_desc_t *curve = get_curve_desc(pubkey->curve);
    botan_pk_op_decrypt_t  decrypt_op = NULL;
    botan_privkey_t        key = NULL;
    rnp_result_t           retval = RNP_ERROR_GENERIC;

    if (curve == NULL || ctext_len < 64) {
        goto done;
    }

    if (botan_privkey_load_sm2_enc(&key, privkey->x->mp, curve->botan_name)) {
        RNP_LOG("Can't load private key");
        goto done;
    }

    const uint8_t hash_id = ctext[ctext_len - 1];

    const char *hash_name = pgp_hash_name_botan(hash_id);
    if (!hash_name) {
        RNP_LOG("Unknown hash used in SM2 ciphertext");
        goto done;
    }

    if (botan_pk_op_decrypt_create(&decrypt_op, key, hash_name, 0) != 0) {
        goto done;
    }

    if (botan_pk_op_decrypt(decrypt_op, out, out_len, ctext, ctext_len - 1) == 0) {
        retval = RNP_SUCCESS;
    }

done:
    botan_privkey_destroy(key);
    botan_pk_op_decrypt_destroy(decrypt_op);
    return retval;
}
