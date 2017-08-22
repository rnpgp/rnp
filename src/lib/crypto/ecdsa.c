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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <botan/ffi.h>

#include <librepgp/packet-parse.h>

#include "ec.h"
#include "ecdsa.h"
#include "crypto.h"
#include "readerwriter.h"
#include "utils.h"

rnp_result
pgp_ecdsa_sign_hash(pgp_ecc_sig_t *         sign,
                    const uint8_t *         hashbuf,
                    size_t                  hash_len,
                    const pgp_ecc_seckey_t *seckey,
                    const pgp_ecc_pubkey_t *pubkey)
{
    botan_pk_op_sign_t     signer = NULL;
    botan_privkey_t        key = NULL;
    botan_rng_t            rng = NULL;
    rnp_result             ret = PGP_E_FAIL;
    uint8_t                out_buf[2 * MAX_CURVE_BYTELEN] = {0};
    const ec_curve_desc_t *curve = get_curve_desc(pubkey->curve);

    if (!curve) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (sign->r || sign->s) {
        // Caller must not allocate r and s
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (botan_privkey_load_ecdsa(&key, seckey->x->mp, curve->botan_name)) {
        RNP_LOG("Can't load private key");
        return RNP_ERROR_GENERIC;
    }

    if (botan_rng_init(&rng, NULL)) {
        goto end;
    }

    if (botan_pk_op_sign_create(&signer, key, "Raw", 0)) {
        goto end;
    }

    const size_t curve_order = BITS_TO_BYTES(curve->bitlen);
    const size_t leftmost_bytes = hash_len > curve_order ? curve_order : hash_len;
    if (botan_pk_op_sign_update(signer, &hashbuf[hash_len - leftmost_bytes], leftmost_bytes)) {
        goto end;
    }

    size_t sig_len = 2 * curve_order;
    if (botan_pk_op_sign_finish(signer, rng, out_buf, &sig_len)) {
        RNP_LOG("Signing failed");
        goto end;
    }

    // Allocate memory and copy results
    sign->r = BN_bin2bn(out_buf, curve_order, sign->r);
    sign->s = BN_bin2bn(out_buf + curve_order, curve_order, sign->s);
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
    botan_rng_destroy(rng);
    botan_pk_op_sign_destroy(signer);

    return ret;
}

rnp_result
pgp_ecdsa_verify_hash(const pgp_ecc_sig_t *   sign,
                      const uint8_t *         hash,
                      size_t                  hash_len,
                      const pgp_ecc_pubkey_t *pubkey)
{
    botan_mp_t           public_x = NULL;
    botan_mp_t           public_y = NULL;
    botan_pubkey_t       pub = NULL;
    botan_pk_op_verify_t verifier = NULL;
    rnp_result           ret = RNP_ERROR_SIGNATURE_INVALID;
    uint8_t              sign_buf[2 * MAX_CURVE_BYTELEN] = {0};
    uint8_t              point_bytes[BITS_TO_BYTES(521) * 2 + 1] = {0};

    const ec_curve_desc_t *curve = get_curve_desc(pubkey->curve);

    if (!curve) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if ((BN_num_bytes(pubkey->point) > sizeof(point_bytes)) ||
        BN_bn2bin(pubkey->point, point_bytes) || (point_bytes[0] != 0x04)) {
        RNP_LOG("Failed to load public key");
        goto end;
    }

    const size_t curve_order = BITS_TO_BYTES(curve->bitlen);
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

    const size_t leftmost_bytes = hash_len > curve_order ? curve_order : hash_len;
    if (botan_pk_op_verify_update(
          verifier, &hash[hash_len - leftmost_bytes], leftmost_bytes)) {
        goto end;
    }

    if ((BN_num_bytes(sign->r) > curve_order) || (BN_num_bytes(sign->s) > curve_order) ||
        (curve_order > MAX_CURVE_BYTELEN)) {
        goto end;
    }

    BN_bn2bin(sign->r, &sign_buf[curve_order - BN_num_bytes(sign->r)]);
    BN_bn2bin(sign->s, &sign_buf[curve_order + curve_order - BN_num_bytes(sign->s)]);

    ret = botan_pk_op_verify_finish(verifier, sign_buf, curve_order * 2) ?
            RNP_ERROR_SIGNATURE_INVALID :
            RNP_SUCCESS;

end:
    botan_mp_destroy(public_x);
    botan_mp_destroy(public_y);
    botan_pubkey_destroy(pub);
    botan_pk_op_verify_destroy(verifier);
    return ret;
}
