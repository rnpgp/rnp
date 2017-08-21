/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
#ifndef _EC_H_
#define _EC_H_

#include <rnp/rnp_types.h>
#include "packet.h"

/**
 * Maximal length of the OID in hex representation.
 *
 * \see RFC4880 bis01 - 9.2 ECC Curve OID
 */
#define MAX_CURVE_OID_HEX_LEN 9U

/**
 * Structure holds description of elliptic curve
 */
typedef struct ec_curve_desc_t {
    const pgp_curve_t rnp_curve_id;
    const size_t      bitlen;
    const uint8_t     OIDhex[MAX_CURVE_OID_HEX_LEN];
    const size_t      OIDhex_len;
    const char *      botan_name;
    const char *      pgp_name;
} ec_curve_desc_t;

/*
 * @brief   Finds curve ID by hex representation of OID
 *
 * @param   oid       buffer with OID in hex
 * @param   oid_len   length of oid buffer
 *
 * @returns success curve ID
 *          failure PGP_CURVE_MAX is returned
 *
 * @remarks see RFC 4880 bis 01 - 9.2 ECC Curve OID
 */
pgp_curve_t find_curve_by_OID(const uint8_t *oid, size_t oid_len);

/*
 * @brief   Serialize EC public to octet string
 *
 * @param   output      generated output
 * @param   pubkey      initialized ECDSA public key
 *
 * @pre     output      must be not null
 * @pre     pubkey      must be not null
 *
 * @returns true on success
 *
 * @remarks see RFC 4880 bis 01 - 5.5.2 Public-Key Packet Formats
 */
bool ec_serialize_pubkey(pgp_output_t *output, const pgp_ecc_pubkey_t *pubkey);

/*
 * @brief   Returns pointer to the curve descriptor
 *
 * @param   Valid curve ID
 *
 * @returns NULL if wrong ID provided, otherwise descriptor
 *
 */
const ec_curve_desc_t *get_curve_desc(const pgp_curve_t curve_id);

/*
 * @brief   Generates EC key in uncompressed format
 *
 * @param   seckey[out] private part of the key
 * @param   alg_id ID of EC algorithm
 * @param   curve underlying ECC curve ID
 *
 * @pre     alg_id MUST be supported algorithm
 *
 * @returns RNP_ERROR_BAD_PARAMETERS unknown curve_id
 * @returns RNP_ERROR_OUT_OF_MEMORY memory allocation failed
 * @returns RNP_ERROR_KEY_GENERATION implementation error
 */
rnp_result pgp_genkey_ec_uncompressed(pgp_seckey_t *         seckey,
                                      const pgp_pubkey_alg_t alg_id,
                                      const pgp_curve_t      curve);

#endif
