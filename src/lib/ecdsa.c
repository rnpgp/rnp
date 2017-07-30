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

#include "ecdsa.h"
#include "crypto.h"
#include "packet.h"
#include "readerwriter.h"
#include "utils.h"
#include "utils.h"

extern ec_curve_desc_t ec_curves[PGP_CURVE_MAX];

pgp_curve_t
find_curve_by_OID(const uint8_t *oid, size_t oid_len)
{
    for (size_t i = 0; i < ARRAY_SIZE(ec_curves); i++) {
        if ((oid_len == ec_curves[i].OIDhex_len) &&
            (!memcmp(oid, ec_curves[i].OIDhex, oid_len))) {
            return i;
        }
    }

    return PGP_CURVE_MAX;
}

pgp_errcode_t
pgp_ecdsa_genkeypair(pgp_seckey_t *seckey, pgp_curve_t curve)
{
    /**
     * Keeps "0x04 || x || y"
     * \see 13.2.  ECDSA and ECDH Conversion Primitives
     *
     * P-521 is biggest supported curve for ECDSA
     */
    uint8_t         point_bytes[BITS_TO_BYTES(521) * 2 + 1] = {0};
    const size_t    filed_byte_size = BITS_TO_BYTES(ec_curves[curve].bitlen);
    botan_privkey_t pr_key = NULL;
    botan_pubkey_t  pu_key = NULL;
    botan_rng_t     rng = NULL;
    BIGNUM *        public_x = NULL;
    BIGNUM *        public_y = NULL;
    pgp_errcode_t   ret = PGP_E_C_KEY_GENERATION_FAILED;

    if (botan_rng_init(&rng, NULL)) {
        goto end;
    }

    if (botan_privkey_create_ecdsa(&pr_key, rng, ec_curves[curve].botan_name)) {
        goto end;
    }

    if (botan_privkey_export_pubkey(&pu_key, pr_key)) {
        goto end;
    }

    // Crash if seckey is null. It's clean and easy to debug design
    public_x = BN_new();
    public_y = BN_new();
    seckey->key.ecc.x = BN_new();

    if (!public_x || !public_y || !seckey->key.ecc.x) {
        RNP_LOG("Allocation failed");
        goto end;
    }

    if (botan_pubkey_get_field(public_x->mp, pu_key, "public_x")) {
        goto end;
    }

    if (botan_pubkey_get_field(public_y->mp, pu_key, "public_y")) {
        goto end;
    }

    if (botan_privkey_get_field(seckey->key.ecc.x->mp, pr_key, "x")) {
        goto end;
    }

    const size_t x_bytes = BN_num_bytes(public_x);
    const size_t y_bytes = BN_num_bytes(public_y);

    // Safety check
    if ((x_bytes > filed_byte_size) || (y_bytes > filed_byte_size)) {
        RNP_LOG("Key generation failed");
        goto end;
    }

    /*
     * Convert coordinates to MPI stored as
     * "0x04 || x || y"
     *
     *  \see 13.2.  ECDSA and ECDH Conversion Primitives
     *
     * Note: Generated pk/sk may not always have exact number of bytes
     *       which is important when converting to octet-string
     */
    point_bytes[0] = 0x04;
    BN_bn2bin(public_x, &point_bytes[1 + filed_byte_size - x_bytes]);
    BN_bn2bin(public_y, &point_bytes[1 + filed_byte_size + (filed_byte_size - y_bytes)]);

    seckey->pubkey.key.ecc.point = BN_bin2bn(point_bytes, (2 * filed_byte_size) + 1, NULL);
    if (!seckey->pubkey.key.ecc.point) {
        goto end;
    }

    // All good now
    ret = PGP_E_OK;

end:
    if (rng != NULL) {
        botan_rng_destroy(rng);
    }
    if (pr_key != NULL) {
        botan_privkey_destroy(pr_key);
    }
    if (pu_key != NULL) {
        botan_pubkey_destroy(pu_key);
    }
    if (public_x != NULL) {
        BN_free(public_x);
    }
    if (public_y != NULL) {
        BN_free(public_y);
    }
    if (PGP_E_OK != ret) {
        RNP_LOG("ECDSA key generation failed");
        pgp_seckey_free(seckey);
    }

    return ret;
}

pgp_errcode_t
pgp_ecdsa_sign_hash(pgp_ecc_sig_t *         sign,
                    const uint8_t *         hashbuf,
                    size_t                  hash_len,
                    const pgp_ecc_seckey_t *seckey,
                    const pgp_ecc_pubkey_t *pubkey)
{
    botan_pk_op_sign_t signer = NULL;
    botan_privkey_t    key = NULL;
    botan_rng_t        rng = NULL;
    pgp_errcode_t      ret = PGP_E_FAIL;
    uint8_t            out_buf[2 * MAX_CURVE_BYTELEN] = {0};
    const size_t       sign_half_len = BITS_TO_BYTES(ec_curves[pubkey->curve].bitlen);

    if (sign->r || sign->s) {
        // Caller must not allocate r and s
        return PGP_E_FAIL;
    }

    if (botan_privkey_load_ecdsa(&key, seckey->x->mp, ec_curves[pubkey->curve].botan_name)) {
        RNP_LOG("Can't load private key");
        return PGP_E_FAIL;
    }

    if (botan_rng_init(&rng, NULL)) {
        goto end;
    }

    if (botan_pk_op_sign_create(&signer, key, "Raw", 0)) {
        goto end;
    }

    if (botan_pk_op_sign_update(signer, hashbuf, hash_len)) {
        goto end;
    }

    size_t sig_len = 2 * sign_half_len;
    if (botan_pk_op_sign_finish(signer, rng, out_buf, &sig_len)) {
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
    ret = PGP_E_OK;

end:
    if (ret != PGP_E_OK) {
        BN_clear_free(sign->r);
        BN_clear_free(sign->s);
    }
    botan_privkey_destroy(key);
    botan_rng_destroy(rng);
    botan_pk_op_sign_destroy(signer);

    return ret;
}

pgp_errcode_t
pgp_ecdsa_verify_hash(const pgp_ecc_sig_t *   sign,
                      const uint8_t *         hash,
                      size_t                  hash_len,
                      const pgp_ecc_pubkey_t *pubkey)
{
    botan_mp_t           public_x = NULL;
    botan_mp_t           public_y = NULL;
    botan_pubkey_t       pub = NULL;
    botan_pk_op_verify_t verifier = NULL;
    pgp_errcode_t        ret = PGP_E_V_BAD_SIGNATURE;
    uint8_t              sign_buf[2 * MAX_CURVE_BYTELEN] = {0};
    const size_t         sign_half_len = BITS_TO_BYTES(ec_curves[pubkey->curve].bitlen);
    uint8_t              point_bytes[BITS_TO_BYTES(521) * 2 + 1] = {0};

    if ((BN_num_bytes(pubkey->point) > sizeof(point_bytes)) ||
        BN_bn2bin(pubkey->point, point_bytes) || (point_bytes[0] != 0x04)) {
        RNP_LOG("Failed to load public key");
        goto end;
    }

    if (botan_mp_init(&public_x) || botan_mp_init(&public_y) ||
        botan_mp_from_bin(public_x, &point_bytes[1], sign_half_len) ||
        botan_mp_from_bin(public_y, &point_bytes[1 + sign_half_len], sign_half_len)) {
        goto end;
    }

    const char *curve_name = ec_curves[pubkey->curve].botan_name;
    if (botan_pubkey_load_ecdsa(&pub, public_x, public_y, curve_name)) {
        RNP_LOG("Failed to load public key");
        goto end;
    }

    if (botan_pk_op_verify_create(&verifier, pub, "Raw", 0)) {
        goto end;
    }

    if (botan_pk_op_verify_update(verifier, hash, hash_len)) {
        goto end;
    }

    if ((BN_num_bytes(sign->r) > sign_half_len) || (BN_num_bytes(sign->s) > sign_half_len) ||
        (sign_half_len > MAX_CURVE_BYTELEN)) {
        goto end;
    }

    BN_bn2bin(sign->r, &sign_buf[sign_half_len - BN_num_bytes(sign->r)]);
    BN_bn2bin(sign->s, &sign_buf[sign_half_len + sign_half_len - BN_num_bytes(sign->s)]);

    ret = botan_pk_op_verify_finish(verifier, sign_buf, sign_half_len * 2) ?
            PGP_E_V_BAD_SIGNATURE :
            PGP_E_OK;

end:
    botan_mp_destroy(public_x);
    botan_mp_destroy(public_y);
    botan_pubkey_destroy(pub);
    botan_pk_op_verify_destroy(verifier);
    return ret;
}

pgp_errcode_t
ec_serialize_pubkey(pgp_output_t *output, const pgp_ecc_pubkey_t *pubkey)
{
    const ec_curve_desc_t *curve = &ec_curves[pubkey->curve];

    if (pgp_write_scalar(output, curve->OIDhex_len, 1) &&
        pgp_write(output, curve->OIDhex, curve->OIDhex_len) &&
        pgp_write_mpi(output, pubkey->point)) {
        return PGP_E_OK;
    }

    return PGP_E_W_WRITE_FAILED;
}
