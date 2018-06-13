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

#include <string.h>
#include <botan/ffi.h>
#include "sm2.h"
#include "hash.h"
#include "utils.h"

rnp_result_t
sm2_sign(rng_t *             rng,
         pgp_ec_signature_t *sig,
         const uint8_t *     hash,
         size_t              hash_len,
         const pgp_ec_key_t *key)
{
    const ec_curve_desc_t *curve = get_curve_desc(key->curve);
    botan_pk_op_sign_t     signer = NULL;
    botan_privkey_t        b_key = NULL;
    rnp_result_t           ret = RNP_ERROR_GENERIC;
    uint8_t                out_buf[2 * MAX_CURVE_BYTELEN] = {0};
    bignum_t *             x = NULL;

    if (curve == NULL) {
        return RNP_ERROR_GENERIC;
    }
    const size_t sign_half_len = BITS_TO_BYTES(curve->bitlen);
    size_t       sig_len = 2 * sign_half_len;

    x = mpi2bn(&key->x);
    if (botan_privkey_load_sm2(&b_key, BN_HANDLE_PTR(x), curve->botan_name)) {
        RNP_LOG("Can't load private key");
        goto end;
    }

    if (botan_pk_op_sign_create(&signer, b_key, "", 0)) {
        goto end;
    }

    if (botan_pk_op_sign_update(signer, hash, hash_len)) {
        goto end;
    }

    if (botan_pk_op_sign_finish(signer, rng_handle(rng), out_buf, &sig_len)) {
        RNP_LOG("Signing failed");
        goto end;
    }

    // Allocate memory and copy results
    if (mem2mpi(&sig->r, out_buf, sign_half_len) &&
        mem2mpi(&sig->s, out_buf + sign_half_len, sign_half_len)) {
        // All good now
        ret = RNP_SUCCESS;
    }
end:
    bn_free(x);
    botan_privkey_destroy(b_key);
    botan_pk_op_sign_destroy(signer);
    return ret;
}

rnp_result_t
sm2_verify(const pgp_ec_signature_t *sig,
           const uint8_t *           hash,
           size_t                    hash_len,
           const pgp_ec_key_t *      key)
{
    const ec_curve_desc_t *curve = get_curve_desc(key->curve);

    botan_mp_t           public_x = NULL;
    botan_mp_t           public_y = NULL;
    botan_pubkey_t       pub = NULL;
    botan_pk_op_verify_t verifier = NULL;
    rnp_result_t         ret = RNP_ERROR_SIGNATURE_INVALID;
    uint8_t              sign_buf[2 * MAX_CURVE_BYTELEN] = {0};
    size_t               r_blen, s_blen;

    if (curve == NULL) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const size_t sign_half_len = BITS_TO_BYTES(curve->bitlen);

    r_blen = mpi_bytes(&key->p);
    if (!r_blen || (r_blen != (2 * sign_half_len + 1)) || (key->p.mpi[0] != 0x04)) {
        RNP_LOG("Failed to load public key");
        goto end;
    }

    if (botan_mp_init(&public_x) || botan_mp_init(&public_y) ||
        botan_mp_from_bin(public_x, &key->p.mpi[1], sign_half_len) ||
        botan_mp_from_bin(public_y, &key->p.mpi[1 + sign_half_len], sign_half_len)) {
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

    r_blen = sig->r.len;
    s_blen = sig->s.len;
    if (!r_blen || (r_blen > sign_half_len) || !s_blen || (s_blen > sign_half_len) ||
        (sign_half_len > MAX_CURVE_BYTELEN)) {
        goto end;
    }

    mpi2mem(&sig->r, sign_buf + sign_half_len - r_blen);
    mpi2mem(&sig->s, sign_buf + 2 * sign_half_len - s_blen);

    if (!botan_pk_op_verify_finish(verifier, sign_buf, sign_half_len * 2)) {
        ret = RNP_SUCCESS;
    }
end:
    botan_mp_destroy(public_x);
    botan_mp_destroy(public_y);
    botan_pubkey_destroy(pub);
    botan_pk_op_verify_destroy(verifier);
    return ret;
}

rnp_result_t
sm2_encrypt(rng_t *              rng,
            pgp_sm2_encrypted_t *out,
            const uint8_t *      in,
            size_t               in_len,
            pgp_hash_alg_t       hash_algo,
            const pgp_ec_key_t * key)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    const ec_curve_desc_t *curve = get_curve_desc(key->curve);
    botan_mp_t             public_x = NULL;
    botan_mp_t             public_y = NULL;
    botan_pubkey_t         sm2_key = NULL;
    botan_pk_op_encrypt_t  enc_op = NULL;
    size_t                 sz;

    const size_t point_len = BITS_TO_BYTES(curve->bitlen);
    uint8_t      point_bytes[BITS_TO_BYTES(521) * 2 + 1] = {0};
    size_t       hash_alg_len;
    size_t       ctext_len;
    const char * curve_name = NULL;

    if (curve == NULL) {
        return RNP_ERROR_GENERIC;
    }

    hash_alg_len = pgp_digest_length(hash_algo);
    if (!hash_alg_len) {
        RNP_LOG("Unknown hash algorithm for SM2 encryption");
        goto done;
    }

    /*
     * Format of SM2 ciphertext is a point (2*point_len+1) plus
     * the masked ciphertext (out_len) plus a hash.
     */
    ctext_len = (2 * point_len + 1) + in_len + hash_alg_len;
    curve_name = curve->botan_name;

    if (ctext_len > PGP_MPINT_SIZE) {
        RNP_LOG("too large output for SM2 encryption");
        goto done;
    }

    sz = mpi_bytes(&key->p);
    if (!sz || (sz > sizeof(point_bytes)) || (key->p.mpi[0] != 0x04)) {
        RNP_LOG("Failed to load public key");
        goto done;
    }

    if (botan_mp_init(&public_x) || botan_mp_init(&public_y) ||
        botan_mp_from_bin(public_x, &key->p.mpi[1], point_len) ||
        botan_mp_from_bin(public_y, &key->p.mpi[1 + point_len], point_len)) {
        goto done;
    }

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

    out->m.len = sizeof(out->m.mpi);
    if (botan_pk_op_encrypt(enc_op, rng_handle(rng), out->m.mpi, &out->m.len, in, in_len) ==
        0) {
        out->m.mpi[out->m.len++] = hash_algo;
        ret = RNP_SUCCESS;
    }
done:
    botan_mp_destroy(public_x);
    botan_mp_destroy(public_y);
    botan_pk_op_encrypt_destroy(enc_op);
    botan_pubkey_destroy(sm2_key);
    return ret;
}

rnp_result_t
sm2_decrypt(uint8_t *                  out,
            size_t *                   out_len,
            const pgp_sm2_encrypted_t *in,
            const pgp_ec_key_t *       key)
{
    const ec_curve_desc_t *curve = get_curve_desc(key->curve);
    botan_pk_op_decrypt_t  decrypt_op = NULL;
    botan_privkey_t        b_key = NULL;
    botan_mp_t             x = NULL;
    size_t                 in_len;
    rnp_result_t           ret = RNP_ERROR_GENERIC;
    uint8_t                hash_id;
    const char *           hash_name = NULL;

    in_len = mpi_bytes(&in->m);
    if (curve == NULL || in_len < 64) {
        goto done;
    }

    if (botan_mp_init(&x) || botan_mp_from_bin(x, key->x.mpi, mpi_bytes(&key->x))) {
        goto done;
    }

    if (botan_privkey_load_sm2_enc(&b_key, x, curve->botan_name)) {
        RNP_LOG("Can't load private key");
        goto done;
    }

    hash_id = in->m.mpi[in_len - 1];
    hash_name = pgp_hash_name_botan((pgp_hash_alg_t) hash_id);
    if (!hash_name) {
        RNP_LOG("Unknown hash used in SM2 ciphertext");
        goto done;
    }

    if (botan_pk_op_decrypt_create(&decrypt_op, b_key, hash_name, 0) != 0) {
        goto done;
    }

    if (botan_pk_op_decrypt(decrypt_op, out, out_len, in->m.mpi, in_len - 1) == 0) {
        ret = RNP_SUCCESS;
    }
done:
    botan_mp_destroy(x);
    botan_privkey_destroy(b_key);
    botan_pk_op_decrypt_destroy(decrypt_op);
    return ret;
}
