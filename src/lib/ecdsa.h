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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef EC_H_
#define EC_H_

#include <stdint.h>
#include <stdbool.h>
#include "errors.h"
#include "rnp.h"
#include "packet.h"

/* -----------------------------------------------------------------------------
 * @brief   Finds curve ID by hex representation of OID
 *
 * @param   oid       buffer with OID in hex
 * @param   oid_len   length of oid buffer
 *
 * @returns success curve ID
 *          failure PGP_CURVE_MAX is returned
 *
 * @remarks see RFC 4880 bis 01 - 9.2 ECC Curve OID
-------------------------------------------------------------------------------- */
pgp_curve_t find_curve_by_OID(const uint8_t *oid, size_t oid_len);

/* -----------------------------------------------------------------------------
 * @brief   Serialize ECDSA public to octet string
 *
 * @param   output      generated output
 * @param   pubkey      initialized ECDSA public key
 *
 * @pre     output      must be not null
 * @pre     pubkey      must be not null
 *
 * @returns success PGP_E_OK, error code otherwise
 *
 * @remarks see RFC 4880 bis 01 - 5.5.2 Public-Key Packet Formats
-------------------------------------------------------------------------------- */
pgp_errcode_t ec_serialize_pubkey(pgp_output_t *output, const pgp_ecc_pubkey_t *pubkey);

/* -----------------------------------------------------------------------------
 * @brief   Generate ECDSA keypair
 *
 * @param   seckey[out] private part of the key
 * @param   curve       underlying ECC curve ID
 *
 * @returns success PGP_E_OK, error code otherwise
 *
-------------------------------------------------------------------------------- */
pgp_errcode_t pgp_ecdsa_genkeypair(pgp_seckey_t *seckey, pgp_curve_t curve);

pgp_errcode_t pgp_ecdsa_sign_hash(pgp_ecc_sig_t *         sign,
                                  const uint8_t *         hashbuf,
                                  size_t                  hash_len,
                                  const pgp_ecc_seckey_t *prvkey,
                                  const pgp_ecc_pubkey_t *pubkey);

pgp_errcode_t pgp_ecdsa_verify_hash(const pgp_ecc_sig_t *   sign,
                                    const uint8_t *         hash,
                                    size_t                  hash_len,
                                    const pgp_ecc_pubkey_t *pubkey);

#endif // EC_H_