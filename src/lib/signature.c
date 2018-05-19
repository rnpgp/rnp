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

/** \file
 */
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: signature.c,v 1.34 2012/03/05 02:20:18 christos Exp $");
#endif

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <rnp/rnp_sdk.h>
#include "crypto/common.h"
#include "packet-create.h"
#include "fingerprint.h"
#include "signature.h"
#include "pgp-key.h"
#include <librepgp/stream-sig.h>
#include "utils.h"

static bool
hash_add_key(pgp_hash_t *hash, const pgp_key_pkt_t *key)
{
    return signature_hash_key(key, hash);
}

static bool
init_key_sig(pgp_hash_t *hash, const pgp_sig_t *sig, const pgp_key_pkt_t *key)
{
    pgp_hash_create(hash, sig->info.hash_alg);
    return hash_add_key(hash, key);
}

static void
hash_add_trailer(pgp_hash_t *hash, const pgp_sig_t *sig, const uint8_t *raw_packet)
{
    if (sig->info.version == PGP_V4) {
        if (raw_packet) {
            pgp_hash_add(
              hash, raw_packet + sig->v4_hashstart, (unsigned) sig->info.v4_hashlen);
        }
        pgp_hash_add_int(hash, (unsigned) sig->info.version, 1);
        pgp_hash_add_int(hash, 0xff, 1);
        pgp_hash_add_int(hash, (unsigned) sig->info.v4_hashlen, 4);
    } else {
        pgp_hash_add_int(hash, (unsigned) sig->info.type, 1);
        pgp_hash_add_int(hash, (unsigned) sig->info.creation, 4);
    }
}

/**
   \ingroup Core_Signature
   \brief Checks a signature
   \param hash Signature Hash to be checked
   \param length Signature Length
   \param sig The Signature to be checked
   \param signer The signer's public key
   \return 1 if good; else 0
*/
bool
pgp_check_sig(rng_t *              rng,
              const uint8_t *      hash,
              unsigned             length,
              const pgp_sig_t *    sig,
              const pgp_key_pkt_t *signer)
{
    if (rnp_get_debug(__FILE__)) {
        hexdump(stdout, "hash", hash, length);
    }

    switch (sig->info.key_alg) {
    case PGP_PKA_DSA:
        return !dsa_verify(&sig->info.sig.dsa, hash, length, &signer->material.dsa);
    case PGP_PKA_EDDSA:
        return !eddsa_verify(&sig->info.sig.ec, hash, length, &signer->material.ec);
    case PGP_PKA_SM2:
        return !sm2_verify(&sig->info.sig.ec, hash, length, &signer->material.ec);
    case PGP_PKA_RSA:
        return !rsa_verify_pkcs1(
          rng, &sig->info.sig.rsa, sig->info.hash_alg, hash, length, &signer->material.rsa);
    case PGP_PKA_ECDSA:
        return !ecdsa_verify(&sig->info.sig.ec, hash, length, &signer->material.ec);
    default:
        RNP_LOG("Unknown algorithm");
        return false;
    }
}

static bool
finalise_sig(rng_t *              rng,
             pgp_hash_t *         hash,
             const pgp_sig_t *    sig,
             const pgp_key_pkt_t *signer,
             const uint8_t *      raw_packet)
{
    hash_add_trailer(hash, sig, raw_packet);

    uint8_t hashout[PGP_MAX_HASH_SIZE];
    size_t  hash_len = pgp_hash_finish(hash, hashout);
    return pgp_check_sig(rng, hashout, hash_len, sig, signer);
}

/**
 * \ingroup Core_Signature
 *
 * \brief Verify a certification signature.
 *
 * \param key The public key that was signed.
 * \param id The user ID that was signed
 * \param sig The signature.
 * \param signer The public key of the signer.
 * \param raw_packet The raw signature packet.
 * \return true if OK
 */
bool
pgp_check_useridcert_sig(rnp_ctx_t *          rnp_ctx,
                         const pgp_key_pkt_t *key,
                         const uint8_t *      id,
                         const pgp_sig_t *    sig,
                         const pgp_key_pkt_t *signer,
                         const uint8_t *      raw_packet)
{
    pgp_hash_t hash;
    size_t     userid_len;

    userid_len = strlen((const char *) id);
    if (!init_key_sig(&hash, sig, key)) {
        RNP_LOG("failed to start key sig");
        return false;
    }
    if (sig->info.version == PGP_V4) {
        pgp_hash_add_int(&hash, 0xb4, 1);
        pgp_hash_add_int(&hash, (unsigned) userid_len, 4);
    }
    pgp_hash_add(&hash, id, (unsigned) userid_len);
    return finalise_sig(rnp_ctx_rng_handle(rnp_ctx), &hash, sig, signer, raw_packet);
}

/**
 * \ingroup Core_Signature
 *
 * Verify a certification signature.
 *
 * \param key The public key that was signed.
 * \param attribute The user attribute that was signed
 * \param sig The signature.
 * \param signer The public key of the signer.
 * \param raw_packet The raw signature packet.
 * \return true if OK
 */
bool
pgp_check_userattrcert_sig(rnp_ctx_t *          rnp_ctx,
                           const pgp_key_pkt_t *key,
                           const pgp_data_t *   attribute,
                           const pgp_sig_t *    sig,
                           const pgp_key_pkt_t *signer,
                           const uint8_t *      raw_packet)
{
    pgp_hash_t hash;

    if (!init_key_sig(&hash, sig, key)) {
        RNP_LOG("failed to start key sig");
        return false;
    }
    if (sig->info.version == PGP_V4) {
        pgp_hash_add_int(&hash, 0xd1, 1);
        pgp_hash_add_int(&hash, (unsigned) attribute->len, 4);
    }
    pgp_hash_add(&hash, attribute->contents, (unsigned) attribute->len);
    return finalise_sig(rnp_ctx_rng_handle(rnp_ctx), &hash, sig, signer, raw_packet);
}

/**
 * \ingroup Core_Signature
 *
 * Verify a subkey signature.
 *
 * \param key The public key whose subkey was signed.
 * \param subkey The subkey of the public key that was signed.
 * \param sig The signature.
 * \param signer The public key of the signer.
 * \param raw_packet The raw signature packet.
 * \return true if OK
 */
bool
pgp_check_subkey_sig(rnp_ctx_t *          rnp_ctx,
                     const pgp_key_pkt_t *key,
                     const pgp_key_pkt_t *subkey,
                     const pgp_sig_t *    sig,
                     const pgp_key_pkt_t *signer,
                     const uint8_t *      raw_packet)
{
    pgp_hash_t hash;

    if (!init_key_sig(&hash, sig, key)) {
        RNP_LOG("failed to start key sig");
        return false;
    }
    if (!hash_add_key(&hash, subkey)) {
        RNP_LOG("failed to hash key");
        return false;
    }
    return finalise_sig(rnp_ctx_rng_handle(rnp_ctx), &hash, sig, signer, raw_packet);
}

/**
 * \ingroup Core_Signature
 *
 * Verify a direct signature.
 *
 * \param key The public key which was signed.
 * \param sig The signature.
 * \param signer The public key of the signer.
 * \param raw_packet The raw signature packet.
 * \return true if OK
 */
bool
pgp_check_direct_sig(rnp_ctx_t *          rnp_ctx,
                     const pgp_key_pkt_t *key,
                     const pgp_sig_t *    sig,
                     const pgp_key_pkt_t *signer,
                     const uint8_t *      raw_packet)
{
    pgp_hash_t hash;
    unsigned   ret;

    if (!init_key_sig(&hash, sig, key)) {
        RNP_LOG("failed to start key sig");
        return false;
    }
    ret = finalise_sig(rnp_ctx_rng_handle(rnp_ctx), &hash, sig, signer, raw_packet);
    return ret;
}
