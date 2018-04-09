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
#include "crypto/bn.h"
#include "crypto/ec.h"
#include "crypto/ecdh.h"
#include "crypto/ecdsa.h"
#include "crypto/eddsa.h"
#include "crypto/elgamal.h"
#include "crypto/rsa.h"
#include "crypto/rng.h"
#include "crypto/sm2.h"
#include "crypto.h"
#include "memory.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "utils.h"

/**
\ingroup Core_MPI
\brief Decrypt and unencode MPI
\param buf Buffer in which to write decrypted unencoded MPI
\param buflen Length of buffer
\param encmpi
\param seckey
\return length of MPI
\note only RSA at present
*/
int
pgp_decrypt_decode_mpi(rng_t *             rng,
                       uint8_t *           buf,
                       size_t              buflen,
                       const bignum_t *    g_to_k,
                       const bignum_t *    encmpi,
                       const pgp_seckey_t *seckey)
{
    uint8_t encmpibuf[RNP_BUFSIZ] = {0};
    uint8_t gkbuf[RNP_BUFSIZ] = {0};
    int     n;
    size_t  encmpi_byte_len;

    if (!bn_num_bytes(encmpi, &encmpi_byte_len)) {
        RNP_LOG("Bad param: encmpi");
        return -1;
    }

    /* MPI can't be more than 65,536 */
    if (encmpi_byte_len > sizeof(encmpibuf)) {
        RNP_LOG("encmpi_byte_len too big %zu", encmpi_byte_len);
        return -1;
    }
    switch (seckey->pubkey.alg) {
    case PGP_PKA_RSA:
        bn_bn2bin(encmpi, encmpibuf);
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "encrypted", encmpibuf, 16);
        }
        n = pgp_rsa_decrypt_pkcs1(rng,
                                  buf,
                                  buflen,
                                  encmpibuf,
                                  encmpi_byte_len,
                                  &seckey->key.rsa,
                                  &seckey->pubkey.key.rsa);
        if (n <= 0) {
            RNP_LOG("ops_rsa_private_decrypt failure");
            return -1;
        }
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "decoded m", buf, n);
        }
        return n;
    case PGP_PKA_SM2:
        bn_bn2bin(encmpi, encmpibuf);

        size_t       out_len = buflen;
        rnp_result_t err = pgp_sm2_decrypt(buf,
                                           &out_len,
                                           encmpibuf,
                                           encmpi_byte_len,
                                           &seckey->key.ecc,
                                           &seckey->pubkey.key.ecc);

        if (err != RNP_SUCCESS) {
            RNP_LOG("Error in SM2 decryption");
            return -1;
        }
        return out_len;

    case PGP_PKA_DSA:
    case PGP_PKA_ELGAMAL: {
        size_t gklen, mlen;

        if (!bn_num_bytes(g_to_k, &gklen) || !bn_num_bytes(encmpi, &mlen) ||
            (gklen > sizeof(gkbuf)) || (mlen > sizeof(encmpi)) || bn_bn2bin(g_to_k, gkbuf) ||
            bn_bn2bin(encmpi, encmpibuf)) {
            return -1;
        }

        buf_t       out = {.pbuf = buf, .len = buflen};
        const buf_t g2k = {.pbuf = gkbuf, .len = gklen};
        const buf_t m = {.pbuf = encmpibuf, .len = mlen};

        const rnp_result_t ret = elgamal_decrypt_pkcs1(
          rng, &out, &g2k, &m, &seckey->key.elgamal, &seckey->pubkey.key.elgamal);

        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "decoded m", out.pbuf, out.len);
        }

        if (ret) {
            RNP_LOG("ElGamal decryption failure [%X]", ret);
            return false;
        }
        return out.len;
    }
    case PGP_PKA_ECDH: {
        pgp_fingerprint_t fingerprint;
        size_t            out_len = buflen;
        if (bn_bn2bin(encmpi, encmpibuf)) {
            RNP_LOG("Can't find session key");
            return -1;
        }

        if (!pgp_fingerprint(&fingerprint, &seckey->pubkey)) {
            RNP_LOG("ECDH fingerprint calculation failed");
            return -1;
        }

        const rnp_result_t ret = pgp_ecdh_decrypt_pkcs5(buf,
                                                        &out_len,
                                                        encmpibuf,
                                                        encmpi_byte_len,
                                                        g_to_k,
                                                        &seckey->key.ecc,
                                                        &seckey->pubkey.key.ecdh,
                                                        &fingerprint);

        if (ret || (out_len > INT_MAX)) {
            RNP_LOG("ECDH decryption error [%u]", ret);
            return -1;
        }

        return (int) out_len;
    }

    default:
        RNP_LOG("Unsupported public key algorithm [%d]", seckey->pubkey.alg);
        return -1;
    }
}

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
        if (pgp_genkey_rsa(rng, seckey, crypto->rsa.modulus_bit_len) != 1) {
            RNP_LOG("failed to generate RSA key");
            goto end;
        }
        break;
    case PGP_PKA_DSA:
        if (dsa_keygen(rng,
                       &seckey->pubkey.key.dsa,
                       &seckey->key.dsa,
                       crypto->dsa.p_bitlen,
                       crypto->dsa.q_bitlen)) {
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
        if (elgamal_keygen(rng,
                           &seckey->pubkey.key.elgamal,
                           &seckey->key.elgamal,
                           crypto->elgamal.key_bitlen)) {
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

bool
to_buf(buf_t *b, const uint8_t *in, size_t len)
{
    if (b->len < len) {
        return false;
    }
    memcpy(b->pbuf, in, len);
    b->len = len;
    return true;
}

const buf_t
mpi2buf(pgp_mpi_t *val, bool uselen)
{
    return (buf_t){.pbuf = val->mpi, .len = uselen ? val->len : sizeof(val->mpi)};
}

bignum_t *
mpi2bn(const pgp_mpi_t *val)
{
    return bn_bin2bn(val->mpi, val->len, NULL);
}

bool
bn2mpi(bignum_t *bn, pgp_mpi_t *val)
{
    return bn_num_bytes(bn, &val->len) && (bn_bn2bin(bn, val->mpi) == 0);
}

void
mpi_forget(pgp_mpi_t *val)
{
    pgp_forget(val, sizeof(*val));
    val->len = 0;
}