/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
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

#include "ec.h"
#include "packet.h"
#include "writer.h"

/**
 * EC Curves definition used by implementation
 *
 * \see RFC4880 bis01 - 9.2. ECC Curve OID
 *
 * Order of the elements in this array corresponds to
 * values in pgp_curve_t enum.
 */
// TODO: Check size of this array against PGP_CURVE_MAX with static assert
const ec_curve_desc_t ec_curves[] = {
  {PGP_CURVE_UNKNOWN, 0, {0}, 0, NULL, NULL},

  {PGP_CURVE_NIST_P_256,
   256,
   {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
   8,
   "secp256r1",
   "NIST P-256"},
  {PGP_CURVE_NIST_P_384, 384, {0x2B, 0x81, 0x04, 0x00, 0x22}, 5, "secp384r1", "NIST P-384"},
  {PGP_CURVE_NIST_P_521, 521, {0x2B, 0x81, 0x04, 0x00, 0x23}, 5, "secp521r1", "NIST P-521"},
  {PGP_CURVE_ED25519,
   255,
   {0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01},
   9,
   "Ed25519",
   "Ed25519"},
  {PGP_CURVE_SM2_P_256,
   256,
   {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D},
   8,
   "sm2p256v1",
   "SM2 P-256"},
};

pgp_curve_t
find_curve_by_OID(const uint8_t *oid, size_t oid_len)
{
    for (size_t i = 0; i < PGP_CURVE_MAX; i++) {
        if ((oid_len == ec_curves[i].OIDhex_len) &&
            (!memcmp(oid, ec_curves[i].OIDhex, oid_len))) {
            return i;
        }
    }

    return PGP_CURVE_MAX;
}

const ec_curve_desc_t *
get_curve_desc(const pgp_curve_t curve_id)
{
    return (curve_id < PGP_CURVE_MAX && curve_id > 0) ? &ec_curves[curve_id] : NULL;
}

bool
ec_serialize_pubkey(pgp_output_t *output, const pgp_ecc_pubkey_t *pubkey)
{
    const ec_curve_desc_t *curve = get_curve_desc(pubkey->curve);
    if (!curve) {
        return false;
    }

    return pgp_write_scalar(output, curve->OIDhex_len, 1) &&
           pgp_write(output, curve->OIDhex, curve->OIDhex_len) &&
           pgp_write_mpi(output, pubkey->point);
}
