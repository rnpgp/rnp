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
#include <rnp/rnp_sdk.h>
#include <rnp/rnp_def.h>

#include <librepgp/reader.h>

#include "types.h"
#include "crypto/common.h"
#include "crypto.h"
#include "memory.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "utils.h"

bool
pgp_generate_seckey(const rnp_keygen_crypto_params_t *crypto, pgp_seckey_t *seckey)
{
    bool ok = false;

    if (!crypto || !seckey) {
        RNP_LOG("NULL args");
        goto end;
    }
    /* populate pgp key structure */
    seckey->pubkey.version = PGP_V4;
    seckey->pubkey.creation = time(NULL);
    seckey->pubkey.alg = crypto->key_alg;
    rng_t *rng = crypto->rng;

    switch (seckey->pubkey.alg) {
    case PGP_PKA_RSA:
        if (rsa_generate(rng, &seckey->pubkey.key.rsa, crypto->rsa.modulus_bit_len)) {
            RNP_LOG("failed to generate RSA key");
            goto end;
        }
        break;
    case PGP_PKA_DSA:
        if (dsa_generate(
              rng, &seckey->pubkey.key.dsa, crypto->dsa.p_bitlen, crypto->dsa.q_bitlen)) {
            RNP_LOG("failed to generate DSA key");
            goto end;
        }
        break;
    case PGP_PKA_EDDSA:
        if (!pgp_genkey_eddsa(rng, seckey, get_curve_desc(PGP_CURVE_ED25519)->bitlen)) {
            RNP_LOG("failed to generate EDDSA key");
            goto end;
        }
        break;
    case PGP_PKA_ECDH:
        if (!set_ecdh_params(seckey, crypto->ecc.curve)) {
            RNP_LOG("Unsupported curve [ID=%d]", crypto->ecc.curve);
            goto end;
        }
    /* FALLTHROUGH */
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
        if (pgp_genkey_ec_uncompressed(rng, seckey, seckey->pubkey.alg, crypto->ecc.curve) !=
            RNP_SUCCESS) {
            RNP_LOG("failed to generate EC key");
            goto end;
        }
        seckey->pubkey.key.ecc.curve = crypto->ecc.curve;
        break;
    case PGP_PKA_ELGAMAL:
        if (elgamal_generate(rng, &seckey->pubkey.key.eg, crypto->elgamal.key_bitlen)) {
            RNP_LOG("failed to generate ElGamal key");
            goto end;
        }
        break;
    default:
        RNP_LOG("key generation not implemented for PK alg: %d", seckey->pubkey.alg);
        goto end;
        break;
    }
    seckey->protection.s2k.usage = PGP_S2KU_NONE;
    ok = true;

end:
    if (!ok && seckey) {
        RNP_LOG("failed, freeing internal seckey data");
        pgp_seckey_free(seckey);
    }
    return ok;
}
