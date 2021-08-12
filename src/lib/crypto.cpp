/*
 * Copyright (c) 2017-2020, [Ribose Inc](https://www.ribose.com).
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
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: crypto.c,v 1.36 2014/02/17 07:39:19 agc Exp $");
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>
#include <time.h>
#include <rnp/rnp_def.h>

#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>

#include "types.h"
#include "crypto/common.h"
#include "crypto.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "utils.h"

bool
pgp_generate_seckey(const rnp_keygen_crypto_params_t *crypto,
                    pgp_key_pkt_t *                   seckey,
                    bool                              primary)
{
    if (!crypto || !seckey) {
        RNP_LOG("NULL args");
        return false;
    }

    /* populate pgp key structure */
    *seckey = {};
    seckey->version = PGP_V4;
    seckey->creation_time = time(NULL);
    seckey->alg = crypto->key_alg;
    seckey->material.alg = crypto->key_alg;
    seckey->tag = primary ? PGP_PKT_SECRET_KEY : PGP_PKT_SECRET_SUBKEY;

    switch (seckey->alg) {
    case PGP_PKA_RSA:
        if (rsa_generate(crypto->rng, &seckey->material.rsa, crypto->rsa.modulus_bit_len)) {
            RNP_LOG("failed to generate RSA key");
            return false;
        }
        break;
    case PGP_PKA_DSA:
        if (dsa_generate(crypto->rng,
                         &seckey->material.dsa,
                         crypto->dsa.p_bitlen,
                         crypto->dsa.q_bitlen)) {
            RNP_LOG("failed to generate DSA key");
            return false;
        }
        break;
    case PGP_PKA_EDDSA:
        if (eddsa_generate(
              crypto->rng, &seckey->material.ec, get_curve_desc(PGP_CURVE_ED25519)->bitlen)) {
            RNP_LOG("failed to generate EDDSA key");
            return false;
        }
        break;
    case PGP_PKA_ECDH:
        if (!ecdh_set_params(&seckey->material.ec, crypto->ecc.curve)) {
            RNP_LOG("Unsupported curve [ID=%d]", crypto->ecc.curve);
            return false;
        }
        if (crypto->ecc.curve == PGP_CURVE_25519) {
            if (x25519_generate(crypto->rng, &seckey->material.ec)) {
                RNP_LOG("failed to generate x25519 key");
                return false;
            }
            seckey->material.ec.curve = crypto->ecc.curve;
            break;
        }
    /* FALLS THROUGH for non-x25519 curves */
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
        if (!curve_supported(crypto->ecc.curve)) {
            RNP_LOG("EC generate: curve %d is not supported.", (int) crypto->ecc.curve);
            return false;
        }
        if (ec_generate(crypto->rng, &seckey->material.ec, seckey->alg, crypto->ecc.curve)) {
            RNP_LOG("failed to generate EC key");
            return false;
        }
        seckey->material.ec.curve = crypto->ecc.curve;
        break;
    case PGP_PKA_ELGAMAL:
        if (elgamal_generate(crypto->rng, &seckey->material.eg, crypto->elgamal.key_bitlen)) {
            RNP_LOG("failed to generate ElGamal key");
            return false;
        }
        break;
    default:
        RNP_LOG("key generation not implemented for PK alg: %d", seckey->alg);
        return false;
    }
    seckey->sec_protection.s2k.usage = PGP_S2KU_NONE;
    seckey->material.secret = true;
    /* fill the sec_data/sec_len */
    if (encrypt_secret_key(seckey, NULL, NULL)) {
        RNP_LOG("failed to fill sec_data");
        return false;
    }
    return true;
}

bool
key_material_equal(const pgp_key_material_t *key1, const pgp_key_material_t *key2)
{
    if (key1->alg != key2->alg) {
        return false;
    }

    switch (key1->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return mpi_equal(&key1->rsa.n, &key2->rsa.n) && mpi_equal(&key1->rsa.e, &key2->rsa.e);
    case PGP_PKA_DSA:
        return mpi_equal(&key1->dsa.p, &key2->dsa.p) &&
               mpi_equal(&key1->dsa.q, &key2->dsa.q) &&
               mpi_equal(&key1->dsa.g, &key2->dsa.g) && mpi_equal(&key1->dsa.y, &key2->dsa.y);
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return mpi_equal(&key1->eg.p, &key2->eg.p) && mpi_equal(&key1->eg.g, &key2->eg.g) &&
               mpi_equal(&key1->eg.y, &key2->eg.y);
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
        return (key1->ec.curve == key2->ec.curve) && mpi_equal(&key1->ec.p, &key2->ec.p);
    default:
        RNP_LOG("unknown public key algorithm: %d", (int) key1->alg);
        return false;
    }
}

rnp_result_t
validate_pgp_key_material(const pgp_key_material_t *material, rng_t *rng)
{
#ifdef FUZZERS_ENABLED
    /* do not timeout on large keys during fuzzing */
    return RNP_SUCCESS;
#else
    switch (material->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return rsa_validate_key(rng, &material->rsa, material->secret);
    case PGP_PKA_DSA:
        return dsa_validate_key(rng, &material->dsa, material->secret);
    case PGP_PKA_EDDSA:
        return eddsa_validate_key(rng, &material->ec, material->secret);
    case PGP_PKA_ECDH:
        if (!curve_supported(material->ec.curve)) {
            /* allow to import key if curve is not supported */
            RNP_LOG("ECDH validate: curve %d is not supported.", (int) material->ec.curve);
            return RNP_SUCCESS;
        }
        return ecdh_validate_key(rng, &material->ec, material->secret);
    case PGP_PKA_ECDSA:
        if (!curve_supported(material->ec.curve)) {
            /* allow to import key if curve is not supported */
            RNP_LOG("ECDH validate: curve %d is not supported.", (int) material->ec.curve);
            return RNP_SUCCESS;
        }
        return ecdsa_validate_key(rng, &material->ec, material->secret);
    case PGP_PKA_SM2:
#if defined(ENABLE_SM2)
        return sm2_validate_key(rng, &material->ec, material->secret);
#else
        RNP_LOG("SM2 key validation is not available.");
        return RNP_ERROR_NOT_IMPLEMENTED;
#endif
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return elgamal_validate_key(rng, &material->eg, material->secret);
    default:
        RNP_LOG("unknown public key algorithm: %d", (int) material->alg);
    }

    return RNP_ERROR_BAD_PARAMETERS;
#endif
}
