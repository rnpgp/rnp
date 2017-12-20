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

#include "crypto/bn.h"
#include "crypto/ec.h"
#include "crypto/ecdsa.h"
#include "crypto/eddsa.h"
#include "crypto/dsa.h"
#include "crypto/sm2.h"
#include "crypto/rsa.h"
#include "crypto/rng.h"
#include "hash.h"
#include "packet-create.h"
#include "readerwriter.h"
#include "fingerprint.h"
#include "signature.h"
#include "utils.h"

/** \ingroup Core_Create
 * needed for signature creation
 */
struct pgp_create_sig_t {
    pgp_hash_t    hash;
    pgp_sig_t     sig;
    pgp_memory_t *mem;
    pgp_output_t *output;  /* how to do the writing */
    unsigned      hashoff; /* hashed count offset */
    unsigned      hashlen;
    unsigned      unhashoff;
};

/**
   \ingroup Core_Signature
   Creates new pgp_create_sig_t
   \return new pgp_create_sig_t
   \note It is the caller's responsibility to call pgp_create_sig_delete()
   \sa pgp_create_sig_delete()
*/
pgp_create_sig_t *
pgp_create_sig_new(void)
{
    return calloc(1, sizeof(pgp_create_sig_t));
}

/**
   \ingroup Core_Signature
   Free signature and memory associated with it
   \param sig struct to free
   \sa pgp_create_sig_new()
*/
void
pgp_create_sig_delete(pgp_create_sig_t *sig)
{
    if (!sig) {
        return;
    }
    pgp_memory_free(sig->mem);
    sig->mem = NULL;
    pgp_output_delete(sig->output);
    sig->output = NULL;
    free(sig);
}

#if 0
void
pgp_dump_sig(pgp_sig_t *sig)
{
}
#endif

/* XXX: both this and verify would be clearer if the signature were */
/* treated as an MPI. */
static bool
rsa_sign(rng_t *                 rng,
         pgp_hash_t *            hash,
         const pgp_rsa_pubkey_t *pubrsa,
         const pgp_rsa_seckey_t *secrsa,
         pgp_output_t *          out)
{
    unsigned  hash_size;
    int       sig_size = 0;
    uint8_t   hashbuf[128];
    uint8_t   sigbuf[RNP_BUFSIZ];
    bignum_t *bn;

    pgp_hash_alg_t hash_alg = pgp_hash_alg_type(hash);

    hash_size = pgp_hash_finish(hash, hashbuf);

    /**
     * The high 16 bits (first two octets) of the hash are included
     * in the Signature packet to provide a quick test to reject
     * some invalid signatures. - RFC 4880
     */
    pgp_write(out, &hashbuf[0], 2);

    sig_size = pgp_rsa_pkcs1_sign_hash(
      rng, sigbuf, sizeof(sigbuf), hash_alg, hashbuf, hash_size, secrsa, pubrsa);

    if (sig_size == 0) {
        RNP_LOG("Internal error");
        return false;
    }
    bn = bn_bin2bn(sigbuf, sig_size, NULL);
    pgp_write_mpi(out, bn);
    bn_free(bn);
    return true;
}

static bool
dsa_sign(rng_t *                 rng,
         pgp_hash_t *            hash,
         const pgp_dsa_pubkey_t *dsa,
         const pgp_dsa_seckey_t *sdsa,
         pgp_output_t *          output)
{
    unsigned hashsize;
    unsigned t;
    uint8_t  hashbuf[RNP_BUFSIZ];
    DSA_SIG *dsasig;

    /* hashsize must be "equal in size to the number of bits of q,  */
    /* the group generated by the DSA key's generator value */
    /* 160/8 = 20 */

    hashsize = 20;

    /* finalise hash */
    t = pgp_hash_finish(hash, &hashbuf[0]);
    if (t != 20) {
        RNP_LOG("hashfinish not 20");
        return false;
    }

    pgp_write(output, &hashbuf[0], 2);

    /* write signature to buf */
    dsasig = pgp_dsa_sign(rng, hashbuf, hashsize, sdsa, dsa);

    /* convert and write the sig out to memory */
    pgp_write_mpi(output, dsasig->r);
    pgp_write_mpi(output, dsasig->s);
    DSA_SIG_free(dsasig);
    return true;
}

static bool
ecdsa_sign(rng_t *                 rng,
           pgp_hash_t *            hash,
           const pgp_ecc_pubkey_t *pub_key,
           const pgp_ecc_seckey_t *prv_key,
           pgp_output_t *          output)
{
    uint8_t       hashbuf[PGP_MAX_HASH_SIZE];
    pgp_ecc_sig_t sig = {NULL, NULL};

    const ec_curve_desc_t *curve = get_curve_desc(pub_key->curve);
    if (!curve) {
        RNP_LOG("Unknown curve");
        return false;
    }

    // "-2" because ECDSA on P-521 must work with SHA-512 digest
    if (BITS_TO_BYTES(curve->bitlen) - 2 > pgp_hash_output_length(hash)) {
        RNP_LOG("Message hash to small");
        return false;
    }

    /* finalise hash */
    size_t hashsize = pgp_hash_finish(hash, hashbuf);
    if (!pgp_write(output, &hashbuf[0], 2))
        return false;

    /* write signature to buf */
    if (pgp_ecdsa_sign_hash(rng, &sig, hashbuf, hashsize, prv_key, pub_key) != RNP_SUCCESS) {
        return false;
    }

    /* convert and write the sig out to memory */
    bool ret = !!pgp_write_mpi(output, sig.r);
    ret &= !!pgp_write_mpi(output, sig.s);

    bn_free(sig.r);
    bn_free(sig.s);
    return ret;
}

static bool
sm2_sign(rng_t *                 rng,
         pgp_hash_t *            hash,
         const pgp_ecc_pubkey_t *pub_key,
         const pgp_ecc_seckey_t *prv_key,
         pgp_output_t *          output)
{
    uint8_t       hashbuf[PGP_MAX_HASH_SIZE];
    pgp_ecc_sig_t sig = {NULL, NULL};

    const ec_curve_desc_t *curve = get_curve_desc(pub_key->curve);
    if (!curve) {
        RNP_LOG("Unknown curve");
        return false;
    }

    // "-2" because SM2 on P-521 must work with SHA-512 digest
    if (BITS_TO_BYTES(curve->bitlen) - 2 > pgp_hash_output_length(hash)) {
        RNP_LOG("Message hash to small");
        return false;
    }

    /* finalise hash */
    size_t hashsize = pgp_hash_finish(hash, hashbuf);
    if (!pgp_write(output, &hashbuf[0], 2))
        return false;

    /* write signature to buf */
    if (pgp_sm2_sign_hash(rng, &sig, hashbuf, hashsize, prv_key, pub_key) != RNP_SUCCESS) {
        return false;
    }

    /* convert and write the sig out to memory */
    bool ret = !!pgp_write_mpi(output, sig.r);
    ret &= !!pgp_write_mpi(output, sig.s);

    bn_free(sig.r);
    bn_free(sig.s);
    return ret;
}

static bool
eddsa_sign(rng_t *                 rng,
           pgp_hash_t *            hash,
           const pgp_ecc_pubkey_t *pubkey,
           const pgp_ecc_seckey_t *seckey,
           pgp_output_t *          output)
{
    uint8_t hashbuf[RNP_BUFSIZ];
    bool    ret = false;

    /* finalise hash */
    unsigned hashsize = pgp_hash_finish(hash, &hashbuf[0]);

    pgp_write(output, &hashbuf[0], 2);

    /* write signature to buf */
    bignum_t *r = bn_new();
    bignum_t *s = bn_new();
    if (!r || !s) {
        goto end;
    }

    if (pgp_eddsa_sign_hash(rng, r, s, hashbuf, hashsize, seckey, pubkey) < 0)
        goto end;

    /* convert and write the sig out to memory */
    pgp_write_mpi(output, r);
    pgp_write_mpi(output, s);
    ret = true;

end:
    bn_free(r);
    bn_free(s);
    return ret;
}

static unsigned
eddsa_verify(const uint8_t *         hash,
             size_t                  hash_length,
             const pgp_ecc_sig_t *   sig,
             const pgp_ecc_pubkey_t *pubecc)
{
    return pgp_eddsa_verify_hash(sig->r, sig->s, hash, hash_length, pubecc);
}

static bool
rsa_verify(rng_t *                 rng,
           pgp_hash_alg_t          hash_alg,
           const uint8_t *         hash,
           size_t                  hash_length,
           const pgp_rsa_sig_t *   sig,
           const pgp_rsa_pubkey_t *pubrsa)
{
    size_t  sig_blen = 0;
    size_t  sz;
    uint8_t sigbuf[RNP_BUFSIZ];

    /* RSA key can't be bigger than 65535 bits, so... */
    if (!bn_num_bytes(pubrsa->n, &sz) || (sz > sizeof(sigbuf))) {
        RNP_LOG("keysize too big");
        return false;
    }

    if (!bn_num_bytes(sig->sig, &sig_blen) || (sig_blen > sizeof(sigbuf))) {
        RNP_LOG("Signature too big");
        return false;
    }
    bn_bn2bin(sig->sig, sigbuf);

    return pgp_rsa_pkcs1_verify_hash(
      rng, sigbuf, sig_blen, hash_alg, hash, hash_length, pubrsa);
}

static bool
hash_add_key(pgp_hash_t *hash, const pgp_pubkey_t *key)
{
    pgp_memory_t * mem = pgp_memory_new();
    const unsigned dontmakepacket = 0;
    size_t         len;

    if (mem == NULL) {
        (void) fprintf(stderr, "can't allocate mem\n");
        return false;
    }
    if (!pgp_build_pubkey(mem, key, dontmakepacket)) {
        return false;
    }
    len = pgp_mem_len(mem);
    pgp_hash_add_int(hash, 0x99, 1);
    pgp_hash_add_int(hash, (unsigned) len, 2);
    pgp_hash_add(hash, pgp_mem_data(mem), (unsigned) len);
    pgp_memory_free(mem);
    return true;
}

static bool
init_key_sig(pgp_hash_t *hash, const pgp_sig_t *sig, const pgp_pubkey_t *key)
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
        pgp_hash_add_int(hash, (unsigned) sig->info.birthtime, 4);
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
pgp_check_sig(rng_t *             rng,
              const uint8_t *     hash,
              unsigned            length,
              const pgp_sig_t *   sig,
              const pgp_pubkey_t *signer)
{
    unsigned ret = false;

    if (rnp_get_debug(__FILE__)) {
        hexdump(stdout, "hash", hash, length);
    }

    switch (sig->info.key_alg) {
    case PGP_PKA_DSA:
        ret = pgp_dsa_verify(hash, length, &sig->info.sig.dsa, &signer->key.dsa);
        break;

    case PGP_PKA_EDDSA:
        ret = eddsa_verify(hash, length, &sig->info.sig.ecc, &signer->key.ecc);
        break;

    case PGP_PKA_SM2:
        ret = pgp_sm2_verify_hash(&sig->info.sig.ecc, hash, length, &signer->key.ecc) ==
              RNP_SUCCESS;
        break;

    case PGP_PKA_RSA:
        ret = rsa_verify(
          rng, sig->info.hash_alg, hash, length, &sig->info.sig.rsa, &signer->key.rsa);
        break;

    case PGP_PKA_ECDSA:
        ret = (pgp_ecdsa_verify_hash(&sig->info.sig.ecc, hash, length, &signer->key.ecc) ==
               RNP_SUCCESS);
        break;

    default:
        RNP_LOG("Unknown algorithm");
        return false;
    }

    return ret;
}

static bool
finalise_sig(rng_t *             rng,
             pgp_hash_t *        hash,
             const pgp_sig_t *   sig,
             const pgp_pubkey_t *signer,
             const uint8_t *     raw_packet)
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
pgp_check_useridcert_sig(rnp_ctx_t *         rnp_ctx,
                         const pgp_pubkey_t *key,
                         const uint8_t *     id,
                         const pgp_sig_t *   sig,
                         const pgp_pubkey_t *signer,
                         const uint8_t *     raw_packet)
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
pgp_check_userattrcert_sig(rnp_ctx_t *         rnp_ctx,
                           const pgp_pubkey_t *key,
                           const pgp_data_t *  attribute,
                           const pgp_sig_t *   sig,
                           const pgp_pubkey_t *signer,
                           const uint8_t *     raw_packet)
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
pgp_check_subkey_sig(rnp_ctx_t *         rnp_ctx,
                     const pgp_pubkey_t *key,
                     const pgp_pubkey_t *subkey,
                     const pgp_sig_t *   sig,
                     const pgp_pubkey_t *signer,
                     const uint8_t *     raw_packet)
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
pgp_check_direct_sig(rnp_ctx_t *         rnp_ctx,
                     const pgp_pubkey_t *key,
                     const pgp_sig_t *   sig,
                     const pgp_pubkey_t *signer,
                     const uint8_t *     raw_packet)
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

static void
start_sig_in_mem(pgp_create_sig_t *sig)
{
    /* since this has subpackets and stuff, we have to buffer the whole */
    /* thing to get counts before writing. */
    sig->mem = pgp_memory_new();
    if (sig->mem == NULL) {
        (void) fprintf(stderr, "can't allocate mem\n");
        return;
    }
    pgp_memory_init(sig->mem, 100);
    pgp_writer_set_memory(sig->output, sig->mem);

    /* write nearly up to the first subpacket */
    pgp_write_scalar(sig->output, (unsigned) sig->sig.info.version, 1);
    pgp_write_scalar(sig->output, (unsigned) sig->sig.info.type, 1);
    pgp_write_scalar(sig->output, (unsigned) sig->sig.info.key_alg, 1);
    pgp_write_scalar(sig->output, (unsigned) sig->sig.info.hash_alg, 1);

    /* dummy hashed subpacket count */
    sig->hashoff = (unsigned) pgp_mem_len(sig->mem);
    pgp_write_scalar(sig->output, 0, 2);
}

/**
 * \ingroup Core_Signature
 *
 * pgp_sig_start() creates a V4 public key signature
 *
 * \param sig The signature structure to initialise
 * \param key The public key to be signed
 * \param id The user ID being bound to the key
 * \param type Signature type
 */
bool
pgp_sig_start_key_sig(pgp_create_sig_t *  sig,
                      const pgp_pubkey_t *key,
                      const uint8_t *     id,
                      pgp_sig_type_t      type,
                      pgp_hash_alg_t      hash_alg)
{
    sig->output = pgp_output_new();
    if (sig->output == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return false;
    }

    /* XXX:  refactor with check (in several ways - check should
     * probably use the buffered writer to construct packets
     * (done), and also should share code for hash calculation) */
    sig->sig.info.version = PGP_V4;
    sig->sig.info.hash_alg = hash_alg;
    sig->sig.info.key_alg = key->alg;
    sig->sig.info.type = type;
    sig->hashlen = (unsigned) -1;
    if (!init_key_sig(&sig->hash, &sig->sig, key)) {
        RNP_LOG("failed to start key sig");
        return false;
    }
    pgp_hash_add_int(&sig->hash, 0xb4, 1);
    pgp_hash_add_int(&sig->hash, (unsigned) strlen((const char *) id), 4);
    pgp_hash_add(&sig->hash, id, (unsigned) strlen((const char *) id));
    start_sig_in_mem(sig);
    return true;
}

bool
pgp_sig_start_subkey_sig(pgp_create_sig_t *  sig,
                         const pgp_pubkey_t *key,
                         const pgp_pubkey_t *subkey,
                         pgp_sig_type_t      type,
                         pgp_hash_alg_t      hash_alg)
{
    sig->output = pgp_output_new();
    if (sig->output == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return false;
    }

    sig->sig.info.version = PGP_V4;
    sig->sig.info.hash_alg = hash_alg;
    sig->sig.info.key_alg = key->alg;
    sig->sig.info.type = type;
    sig->hashlen = (unsigned) -1;
    if (!init_key_sig(&sig->hash, &sig->sig, key)) {
        RNP_LOG("failed to start key sig");
        return false;
    }
    if (!hash_add_key(&sig->hash, subkey)) {
        RNP_LOG("failed to hash key");
        return false;
    }
    start_sig_in_mem(sig);
    return true;
}

/**
 * \ingroup Core_Signature
 *
 * Create a V4 public key signature over some cleartext.
 *
 * \param sig The signature structure to initialise
 * \param id
 * \param type
 * \todo Expand description. Allow other hashes.
 */

void
pgp_sig_start(pgp_create_sig_t *   sig,
              const pgp_seckey_t * key,
              const pgp_hash_alg_t hash,
              const pgp_sig_type_t type)
{
    sig->output = pgp_output_new();
    if (sig->output == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return;
    }

    /* XXX:  refactor with check (in several ways - check should
     * probably use the buffered writer to construct packets
     * (done), and also should share code for hash calculation) */
    sig->sig.info.version = PGP_V4;
    sig->sig.info.key_alg = key->pubkey.alg;
    sig->sig.info.hash_alg = hash;
    sig->sig.info.type = type;

    sig->hashlen = (unsigned) -1;

    if (rnp_get_debug(__FILE__)) {
        fprintf(stderr, "initialising hash for sig in mem\n");
    }
    pgp_hash_create(&sig->hash, sig->sig.info.hash_alg);
    start_sig_in_mem(sig);
}

/**
 * \ingroup Core_Signature
 *
 * Mark the end of the hashed subpackets in the signature
 *
 * \param sig
 */

unsigned
pgp_sig_end_hashed_subpkts(pgp_create_sig_t *sig)
{
    sig->hashlen = (unsigned) (pgp_mem_len(sig->mem) - sig->hashoff - 2);
    pgp_memory_place_int(sig->mem, sig->hashoff, sig->hashlen, 2);
    /* dummy unhashed subpacket count */
    sig->unhashoff = (unsigned) pgp_mem_len(sig->mem);
    return pgp_write_scalar(sig->output, 0, 2);
}

/**
 * \ingroup Core_Signature
 *
 * Write out a signature
 *
 * \param sig
 * \param key
 * \param seckey
 * \param info
 *
 */

bool
pgp_sig_write(rng_t *             rng,
              pgp_output_t *      output,
              pgp_create_sig_t *  sig,
              const pgp_pubkey_t *key,
              const pgp_seckey_t *seckey)
{
    bool   ret = false;
    size_t len = pgp_mem_len(sig->mem);

    /* check key not decrypted */
    switch (seckey->pubkey.alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (seckey->key.rsa.d == NULL) {
            (void) fprintf(stderr, "pgp_sig_write: null rsa.d\n");
            return false;
        }
        break;

    case PGP_PKA_DSA:
        if (seckey->key.dsa.x == NULL) {
            (void) fprintf(stderr, "pgp_sig_write: null dsa.x\n");
            return false;
        }
        break;

    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        if (seckey->key.ecc.x == NULL) {
            RNP_LOG("null ecc.x");
            return false;
        }
        break;

    default:
        (void) fprintf(stderr, "Unsupported algorithm %d\n", seckey->pubkey.alg);
        return false;
    }

    // TODO: Is this correct at all?
    if (sig->hashlen == (unsigned) -1) {
        RNP_LOG("bad hashed data len");
        return false;
    }

    pgp_memory_place_int(sig->mem, sig->unhashoff, (unsigned) (len - sig->unhashoff - 2), 2);

    /* add the packet from version number to end of hashed subpackets */
    if (rnp_get_debug(__FILE__)) {
        (void) fprintf(stderr, "ops_write_sig: hashed packet info\n");
    }
    pgp_hash_add(&sig->hash, pgp_mem_data(sig->mem), sig->unhashoff);

    /* add final trailer */
    pgp_hash_add_int(&sig->hash, (unsigned) sig->sig.info.version, 1);
    pgp_hash_add_int(&sig->hash, 0xff, 1);
    /* +6 for version, type, pk alg, hash alg, hashed subpacket length */
    pgp_hash_add_int(&sig->hash, sig->hashlen + 6, 4);

    if (rnp_get_debug(__FILE__)) {
        (void) fprintf(stderr, "ops_write_sig: done writing hashed\n");
    }
    /* XXX: technically, we could figure out how big the signature is */
    /* and write it directly to the output instead of via memory. */

    switch (seckey->pubkey.alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!rsa_sign(rng, &sig->hash, &key->key.rsa, &seckey->key.rsa, sig->output)) {
            RNP_LOG("rsa_sign failure");
            return false;
        }
        break;

    case PGP_PKA_EDDSA:
        if (!eddsa_sign(rng, &sig->hash, &key->key.ecc, &seckey->key.ecc, sig->output)) {
            RNP_LOG("eddsa_sign failure");
            return false;
        }
        break;

    case PGP_PKA_SM2:
        if (!sm2_sign(rng, &sig->hash, &key->key.ecc, &seckey->key.ecc, sig->output)) {
            RNP_LOG("sm2_sign failure");
            return false;
        }
        break;

    case PGP_PKA_DSA:
        if (!dsa_sign(rng, &sig->hash, &key->key.dsa, &seckey->key.dsa, sig->output)) {
            RNP_LOG("dsa_sign failure");
            return false;
        }
        break;

    /*
     * ECDH is signed with ECDSA. This must be changed when ECDH will support
     * X25519, but I need to check how it should be done exactly.
     */
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
        if (!ecdsa_sign(rng, &sig->hash, &key->key.ecc, &seckey->key.ecc, sig->output)) {
            RNP_LOG("ecdsa sign failure");
            return false;
        }
        break;
    default:
        (void) fprintf(stderr, "Unsupported algorithm %d\n", seckey->pubkey.alg);
        return false;
    }

    ret = pgp_write_ptag(output, PGP_PTAG_CT_SIGNATURE);
    if (ret) {
        len = pgp_mem_len(sig->mem);
        ret = pgp_write_length(output, (unsigned) len) &&
              pgp_write(output, pgp_mem_data(sig->mem), (unsigned) len);
    }
    pgp_memory_free(sig->mem);
    sig->mem = NULL;

    if (ret == false) {
        PGP_ERROR_1(&output->errors, PGP_E_W, "%s", "Cannot write signature");
    }
    return ret;
}

/* add a time stamp to the output */
unsigned
pgp_sig_add_time(pgp_create_sig_t *sig, int64_t when, pgp_content_enum tag)
{
    switch (tag) {
    case PGP_PTAG_SS_CREATION_TIME:
    case PGP_PTAG_SS_EXPIRATION_TIME:
    case PGP_PTAG_SS_KEY_EXPIRY:
        break;
    default:
        (void) fprintf(stderr, "Wrong pgp signature time tag");
        return false;
    }
    /* just do 32-bit timestamps for just now - it's in the protocol */
    return pgp_write_ss_header(sig->output, 4, tag) &&
           pgp_write_scalar(sig->output, (uint32_t) when, (unsigned) sizeof(uint32_t));
}

/**
 * \ingroup Core_Signature
 *
 * Adds issuer's key ID to the signature
 *
 * \param sig
 * \param keyid
 */

unsigned
pgp_sig_add_issuer_keyid(pgp_create_sig_t *sig, const uint8_t keyid[PGP_KEY_ID_SIZE])
{
    return pgp_write_ss_header(sig->output, PGP_KEY_ID_SIZE, PGP_PTAG_SS_ISSUER_KEY_ID) &&
           pgp_write(sig->output, keyid, PGP_KEY_ID_SIZE);
}

/**
 * \ingroup Core_Signature
 *
 * Adds primary user ID to the signature
 *
 * \param sig
 * \param primary
 */
void
pgp_sig_add_primary_userid(pgp_create_sig_t *sig, unsigned primary)
{
    pgp_write_ss_header(sig->output, 1, PGP_PTAG_SS_PRIMARY_USER_ID);
    pgp_write_scalar(sig->output, primary, 1);
}

unsigned
pgp_sig_add_key_flags(pgp_create_sig_t *sig, const uint8_t *key_flags, size_t octet_count)
{
    return pgp_write_ss_header(sig->output, octet_count, PGP_PTAG_SS_KEY_FLAGS) &&
           pgp_write(sig->output, key_flags, octet_count);
}

unsigned
pgp_sig_add_pref_symm_algs(pgp_create_sig_t *sig, const uint8_t *algs, size_t octet_count)
{
    return pgp_write_ss_header(sig->output, octet_count, PGP_PTAG_SS_PREFERRED_SKA) &&
           pgp_write(sig->output, algs, octet_count);
}

unsigned
pgp_sig_add_pref_hash_algs(pgp_create_sig_t *sig, const uint8_t *algs, size_t octet_count)
{
    return pgp_write_ss_header(sig->output, octet_count, PGP_PTAG_SS_PREFERRED_HASH) &&
           pgp_write(sig->output, algs, octet_count);
}

unsigned
pgp_sig_add_pref_compress_algs(pgp_create_sig_t *sig, const uint8_t *algs, size_t octet_count)
{
    return pgp_write_ss_header(sig->output, octet_count, PGP_PTAG_SS_PREF_COMPRESS) &&
           pgp_write(sig->output, algs, octet_count);
}

unsigned
pgp_sig_add_key_server_prefs(pgp_create_sig_t *sig, const uint8_t *flags, size_t octet_count)
{
    return pgp_write_ss_header(sig->output, octet_count, PGP_PTAG_SS_KEYSERV_PREFS) &&
           pgp_write(sig->output, flags, octet_count);
}

unsigned
pgp_sig_add_preferred_key_server(pgp_create_sig_t *sig, const uint8_t *uri)
{
    size_t length = strlen((const char *) uri);
    return pgp_write_ss_header(sig->output, (unsigned) length, PGP_PTAG_SS_PREF_KEYSERV) &&
           pgp_write(sig->output, uri, length);
}

/**
 * \ingroup Core_Signature
 *
 * Get the hash structure in use for the signature.
 *
 * \param sig The signature structure.
 * \return The hash structure.
 */
pgp_hash_t *
pgp_sig_get_hash(pgp_create_sig_t *sig)
{
    return &sig->hash;
}

/**
    Pick up hash algorithm according to secret key and preferences set in the context
*/
pgp_hash_alg_t
pgp_pick_hash_alg(rnp_ctx_t *ctx, const pgp_seckey_t *seckey)
{
    if (seckey->pubkey.alg == PGP_PKA_DSA) {
        return PGP_HASH_SHA1;
    } else if (seckey->pubkey.alg == PGP_PKA_ECDSA) {
        size_t               dlen_key = 0, dlen_ctx = 0;
        const pgp_hash_alg_t h_key = ecdsa_get_min_hash(seckey->pubkey.key.ecc.curve);
        if (!pgp_digest_length(h_key, &dlen_key) || !pgp_digest_length(ctx->halg, &dlen_ctx)) {
            return PGP_HASH_UNKNOWN;
        }
        return (dlen_key > dlen_ctx) ? h_key : ctx->halg;
    } else {
        return ctx->halg;
    }
}
