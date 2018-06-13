/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
#include "ecdsa.h"
#include "utils.h"

rnp_result_t
ecdsa_sign(rng_t *             rng,
           pgp_ec_signature_t *sig,
           const uint8_t *     hash,
           size_t              hash_len,
           const pgp_ec_key_t *key)
{
    botan_pk_op_sign_t     signer = NULL;
    botan_privkey_t        b_key = NULL;
    rnp_result_t           ret = RNP_ERROR_GENERIC;
    uint8_t                out_buf[2 * MAX_CURVE_BYTELEN] = {0};
    const ec_curve_desc_t *curve = get_curve_desc(key->curve);
    bignum_t *             x = NULL;

    if (!curve) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const size_t curve_order = BITS_TO_BYTES(curve->bitlen);
    const size_t leftmost_bytes = hash_len > curve_order ? curve_order : hash_len;
    size_t       sig_len = 2 * curve_order;

    if (!(x = mpi2bn(&key->x))) {
        goto end;
    }

    if (botan_privkey_load_ecdsa(&b_key, BN_HANDLE_PTR(x), curve->botan_name)) {
        RNP_LOG("Can't load private key");
        goto end;
    }

    if (botan_pk_op_sign_create(&signer, b_key, "Raw", 0)) {
        goto end;
    }

    if (botan_pk_op_sign_update(signer, hash, leftmost_bytes)) {
        goto end;
    }

    if (botan_pk_op_sign_finish(signer, rng_handle(rng), out_buf, &sig_len)) {
        RNP_LOG("Signing failed");
        goto end;
    }

    // Allocate memory and copy results
    if (mem2mpi(&sig->r, out_buf, curve_order) &&
        mem2mpi(&sig->s, out_buf + curve_order, curve_order)) {
        ret = RNP_SUCCESS;
    }
end:
    bn_free(x);
    botan_privkey_destroy(b_key);
    botan_pk_op_sign_destroy(signer);
    return ret;
}

rnp_result_t
ecdsa_verify(const pgp_ec_signature_t *sig,
             const uint8_t *           hash,
             size_t                    hash_len,
             const pgp_ec_key_t *      key)
{
    botan_mp_t           public_x = NULL;
    botan_mp_t           public_y = NULL;
    botan_pubkey_t       pub = NULL;
    botan_pk_op_verify_t verifier = NULL;
    rnp_result_t         ret = RNP_ERROR_SIGNATURE_INVALID;
    uint8_t              sign_buf[2 * MAX_CURVE_BYTELEN] = {0};
    uint8_t              point_bytes[BITS_TO_BYTES(521) * 2 + 1] = {0};
    size_t               r_blen, s_blen;

    const ec_curve_desc_t *curve = get_curve_desc(key->curve);
    if (!curve) {
        RNP_LOG("unknown curve");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const size_t curve_order = BITS_TO_BYTES(curve->bitlen);
    const size_t leftmost_bytes = hash_len > curve_order ? curve_order : hash_len;

    r_blen = mpi_bytes(&key->p);
    if (!r_blen || (r_blen > sizeof(point_bytes)) || (key->p.mpi[0] != 0x04)) {
        RNP_LOG("Failed to load public key");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto end;
    }
    mpi2mem(&key->p, point_bytes);

    if (botan_mp_init(&public_x) || botan_mp_init(&public_y) ||
        botan_mp_from_bin(public_x, &point_bytes[1], curve_order) ||
        botan_mp_from_bin(public_y, &point_bytes[1 + curve_order], curve_order)) {
        goto end;
    }

    if (botan_pubkey_load_ecdsa(&pub, public_x, public_y, curve->botan_name)) {
        RNP_LOG("Failed to load public key");
        goto end;
    }

    if (botan_pk_op_verify_create(&verifier, pub, "Raw", 0)) {
        goto end;
    }

    if (botan_pk_op_verify_update(verifier, hash, leftmost_bytes)) {
        goto end;
    }

    r_blen = mpi_bytes(&sig->r);
    s_blen = mpi_bytes(&sig->s);
    if ((r_blen > curve_order) || (s_blen > curve_order) ||
        (curve_order > MAX_CURVE_BYTELEN)) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto end;
    }

    // Both can't fail
    mpi2mem(&sig->r, &sign_buf[curve_order - r_blen]);
    mpi2mem(&sig->s, &sign_buf[curve_order + curve_order - s_blen]);

    if (!botan_pk_op_verify_finish(verifier, sign_buf, curve_order * 2)) {
        ret = RNP_SUCCESS;
    }
end:
    botan_mp_destroy(public_x);
    botan_mp_destroy(public_y);
    botan_pubkey_destroy(pub);
    botan_pk_op_verify_destroy(verifier);
    return ret;
}

pgp_hash_alg_t
ecdsa_get_min_hash(pgp_curve_t curve)
{
    return (curve == PGP_CURVE_NIST_P_256) ?
             PGP_HASH_SHA256 :
             (curve == PGP_CURVE_NIST_P_384) ?
             PGP_HASH_SHA384 :
             (curve == PGP_CURVE_NIST_P_521) ? PGP_HASH_SHA512 : PGP_HASH_UNKNOWN;
}
