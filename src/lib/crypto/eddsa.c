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

#include "eddsa.h"
#include "crypto/bn.h"
#include <string.h>
#include <botan/ffi.h>
#include "utils.h"
#include <rnp/rnp_def.h>

bool
pgp_genkey_eddsa(pgp_seckey_t *seckey, size_t curve_len)
{
    if (curve_len != 255)
        return false;

    botan_privkey_t eddsa = NULL;
    botan_rng_t     rng = NULL;
    bool            retval = false;
    uint8_t         key_bits[64];

    if (botan_rng_init(&rng, NULL) != 0)
        goto end;

    if (botan_privkey_create(&eddsa, "Ed25519", NULL, rng) != 0)
        goto end;

    if (botan_privkey_ed25519_get_privkey(eddsa, key_bits) != 0)
        goto end;

    // First 32 bytesof key_bits are the EdDSA seed (private key)
    // Second 32 bytes are the EdDSA public key

    seckey->key.ecc.x = BN_bin2bn(key_bits, 32, NULL);
    seckey->pubkey.key.ecc.curve = PGP_CURVE_ED25519;

    // Hack to insert the required 0x40 prefix on the public key
    key_bits[31] = 0x40;
    seckey->pubkey.key.ecc.point = BN_bin2bn(key_bits + 31, 33, NULL);

    retval = true;

end:
    botan_rng_destroy(rng);
    botan_privkey_destroy(eddsa);
    return retval;
}

int
pgp_eddsa_verify_hash(const BIGNUM *          r,
                      const BIGNUM *          s,
                      const uint8_t *         hash,
                      size_t                  hash_len,
                      const pgp_ecc_pubkey_t *pubkey)
{
    botan_pubkey_t       eddsa = NULL;
    botan_pk_op_verify_t verify_op = NULL;
    int                  result = 0;
    uint8_t              bn_buf[64];

    // Check curve OID matches 25519
    if (pubkey->curve != PGP_CURVE_ED25519)
        goto done;

    // Unexpected size for Ed25519 key
    if (BN_num_bytes(pubkey->point) != 33)
        goto done;

    BN_bn2bin(pubkey->point, bn_buf);

    /*
    * See draft-ietf-openpgp-rfc4880bis-01 section 13.3
    */
    if (bn_buf[0] != 0x40)
        goto done;

    if (botan_pubkey_load_ed25519(&eddsa, bn_buf + 1))
        goto done;

    if (botan_pk_op_verify_create(&verify_op, eddsa, "Pure", 0) != 0)
        goto done;

    if (botan_pk_op_verify_update(verify_op, hash, hash_len) != 0)
        goto done;

    // Unexpected size for Ed25519 signature
    if (BN_num_bytes(r) > 32 || BN_num_bytes(s) > 32)
        goto done;

    memset(bn_buf, 0, sizeof(bn_buf));
    BN_bn2bin(r, &bn_buf[32 - BN_num_bytes(r)]);
    BN_bn2bin(s, &bn_buf[32 + 32 - BN_num_bytes(s)]);

    result = (botan_pk_op_verify_finish(verify_op, bn_buf, 64) == 0);

done:
    botan_pk_op_verify_destroy(verify_op);
    botan_pubkey_destroy(eddsa);
    return result;
}

int
pgp_eddsa_sign_hash(BIGNUM *                r,
                    BIGNUM *                s,
                    const uint8_t *         hash,
                    size_t                  hash_len,
                    const pgp_ecc_seckey_t *seckey,
                    const pgp_ecc_pubkey_t *pubkey)
{
    botan_privkey_t    eddsa = NULL;
    botan_pk_op_sign_t sign_op = NULL;
    botan_rng_t        rng = NULL;
    int                result = -1;
    uint8_t            bn_buf[64] = {0};

    // Check curve OID matches 25519
    if (pubkey->curve != PGP_CURVE_ED25519) {
        goto done;
    }

    // Unexpected size for Ed25519 key
    if (BN_num_bytes(seckey->x) > 32)
        goto done;

    if (botan_rng_init(&rng, NULL) != 0)
        goto done;

    BN_bn2bin(seckey->x, bn_buf + (32 - BN_num_bytes(seckey->x)));

    if (botan_privkey_load_ed25519(&eddsa, bn_buf) != 0)
        goto done;

    if (botan_pk_op_sign_create(&sign_op, eddsa, "Pure", 0) != 0)
        goto done;

    if (botan_pk_op_sign_update(sign_op, hash, hash_len) != 0)
        goto done;

    size_t sig_size = sizeof(bn_buf);
    if (botan_pk_op_sign_finish(sign_op, rng, bn_buf, &sig_size) != 0)
        goto done;

    // Unexpected size...
    if (sig_size != 64)
        goto done;

    BN_bin2bn(bn_buf, 32, r);
    BN_bin2bn(bn_buf + 32, 32, s);
    result = 0;

done:
    botan_rng_destroy(rng);
    botan_pk_op_sign_destroy(sign_op);
    botan_privkey_destroy(eddsa);
    return result;
}
