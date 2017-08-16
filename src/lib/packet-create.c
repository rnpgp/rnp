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
__RCSID("$NetBSD: create.c,v 1.38 2010/11/15 08:03:39 agc Exp $");
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "crypto/bn.h"
#include "crypto/rsa.h"
#include "crypto/elgamal.h"
#include "packet-create.h"
#include "packet.h"
#include "signature.h"
#include "crypto/s2k.h"
#include "crypto/sm2.h"
#include "writer.h"
#include "readerwriter.h"
#include "memory.h"
#include "utils.h"

#include "pgp-key.h"
#include <rnp/rnp_sdk.h>
#include "crypto/ecdsa.h"
#include <rnp/rnp_def.h>
#include "crypto/ecdh.h"

extern ec_curve_desc_t ec_curves[PGP_CURVE_MAX];

/**
 * \ingroup Core_Create
 * \param length
 * \param type
 * \param output
 * \return 1 if OK, otherwise 0
 */

unsigned
pgp_write_ss_header(pgp_output_t *output, unsigned length, pgp_content_enum type)
{
    // add 1 here since length includes the 1-octet subpacket type
    return pgp_write_length(output, length + 1) &&
           pgp_write_scalar(
             output, (unsigned) (type - (unsigned) PGP_PTAG_SIG_SUBPKT_BASE), 1);
}

/**
 * \ingroup Core_WritePackets
 * \brief Writes a User Id packet
 * \param id
 * \param output
 * \return 1 if OK, otherwise 0
 */
unsigned
pgp_write_struct_userid(pgp_output_t *output, const uint8_t *id)
{
    return pgp_write_ptag(output, PGP_PTAG_CT_USER_ID) &&
           pgp_write_length(output, (unsigned) strlen((const char *) id)) &&
           pgp_write(output, id, (unsigned) strlen((const char *) id));
}

/**
 * \ingroup Core_WritePackets
 * \brief Write a User Id packet.
 * \param userid
 * \param output
 *
 * \return return value from pgp_write_struct_userid()
 */
unsigned
pgp_write_userid(const uint8_t *userid, pgp_output_t *output)
{
    return pgp_write_struct_userid(output, userid);
}

/**
\ingroup Core_MPI
*/
static unsigned
mpi_length(const BIGNUM *bn)
{
    return (unsigned) (2 + (BN_num_bits(bn) + 7) / 8);
}

static unsigned
pubkey_length(const pgp_pubkey_t *key)
{
    switch (key->alg) {
    case PGP_PKA_DSA:
        return mpi_length(key->key.dsa.p) + mpi_length(key->key.dsa.q) +
               mpi_length(key->key.dsa.g) + mpi_length(key->key.dsa.y);
    case PGP_PKA_ECDH:
        return 1 // length of curve OID
               + ec_curves[key->key.ecc.curve].OIDhex_len + mpi_length(key->key.ecc.point) +
               1    // Size of following fields
               + 1  // Value 1 reserved for future use
               + 1  // Hash function ID used with KDF
               + 1; // Symmetric algorithm used to wrap symmetric key
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_SM2_ENCRYPT:
        return 1 + // length of curve OID
               +ec_curves[key->key.ecc.curve].OIDhex_len + mpi_length(key->key.ecc.point);

    case PGP_PKA_RSA:
        return mpi_length(key->key.rsa.n) + mpi_length(key->key.rsa.e);

    default:
        RNP_LOG("unknown key algorithm");
    }
    return 0;
}

static unsigned
seckey_length(const pgp_seckey_t *key)
{
    int len;

    len = 0;
    switch (key->pubkey.alg) {
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_SM2_ENCRYPT:
        return mpi_length(key->key.ecc.x) + pubkey_length(&key->pubkey);
    case PGP_PKA_DSA:
        return (unsigned) (mpi_length(key->key.dsa.x) + pubkey_length(&key->pubkey));
    case PGP_PKA_RSA:
        len = mpi_length(key->key.rsa.d) + mpi_length(key->key.rsa.p) +
              mpi_length(key->key.rsa.q) + mpi_length(key->key.rsa.u);

        return (unsigned) (len + pubkey_length(&key->pubkey));
    default:
        RNP_LOG("unknown key algorithm");
    }
    return 0;
}

/*
 * Note that we support v3 keys here because they're needed for for
 * verification - the writer doesn't allow them, though
 */

static bool
write_pubkey_body(const pgp_pubkey_t *key, pgp_output_t *output)
{
    if (!(pgp_write_scalar(output, (unsigned) key->version, 1) &&
          pgp_write_scalar(output, (unsigned) key->birthtime, 4))) {
        return false;
    }

    if (key->version != 4 && !pgp_write_scalar(output, key->days_valid, 2)) {
        return false;
    }

    if (!pgp_write_scalar(output, (unsigned) key->alg, 1)) {
        return false;
    }

    switch (key->alg) {
    case PGP_PKA_DSA:
        return pgp_write_mpi(output, key->key.dsa.p) &&
               pgp_write_mpi(output, key->key.dsa.q) &&
               pgp_write_mpi(output, key->key.dsa.g) && pgp_write_mpi(output, key->key.dsa.y);
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_SM2_ENCRYPT:
        return ec_serialize_pubkey(output, &key->key.ecc);
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return pgp_write_mpi(output, key->key.rsa.n) && pgp_write_mpi(output, key->key.rsa.e);
    case PGP_PKA_ECDH:
        return ec_serialize_pubkey(output, &key->key.ecdh.ec) &&
               pgp_write_scalar(output, 3 /*size of following attributes*/, 1) &&
               pgp_write_scalar(output, 1 /*reserved*/, 1) &&
               pgp_write_scalar(output, (uint8_t) key->key.ecdh.kdf_hash_alg, 1) &&
               pgp_write_scalar(output, (uint8_t) key->key.ecdh.key_wrap_alg, 1);
    case PGP_PKA_ELGAMAL:
        return pgp_write_mpi(output, key->key.elgamal.p) &&
               pgp_write_mpi(output, key->key.elgamal.g) &&
               pgp_write_mpi(output, key->key.elgamal.y);

    default:
        RNP_LOG("bad algorithm");
        break;
    }
    return false;
}

static bool
hash_bn(pgp_hash_t *hash, BIGNUM *bignum)
{
    uint8_t *bn;
    size_t   bits;
    size_t   bytes;
    uint8_t  length[2];

    if (BN_is_zero(bignum)) {
        length[0] = length[1] = 0;
        pgp_hash_add(hash, length, 2);
        return true;
    }
    if ((bits = (size_t) BN_num_bits(bignum)) < 1) {
        RNP_LOG("bad size");
        return false;
    }
    if ((bytes = (size_t) BN_num_bytes(bignum)) < 1) {
        RNP_LOG("bad size");
        return false;
    }
    if ((bn = calloc(1, bytes)) == NULL) {
        RNP_LOG("bad bn alloc");
        return false;
    }
    BN_bn2bin(bignum, bn);
    length[0] = (uint8_t)((bits >> 8) & 0xff);
    length[1] = (uint8_t)(bits & 0xff);
    pgp_hash_add(hash, length, 2);
    pgp_hash_add(hash, bn, bytes);
    free(bn);
    return true;
}

static bool
hash_key_material(const pgp_seckey_t *key, uint8_t *result)
{
    pgp_hash_t hash = {0};
    pgp_hash_create(&hash, PGP_HASH_SHA1);

    switch (key->pubkey.alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        hash_bn(&hash, key->key.rsa.d);
        hash_bn(&hash, key->key.rsa.p);
        hash_bn(&hash, key->key.rsa.q);
        hash_bn(&hash, key->key.rsa.u);
        break;
    case PGP_PKA_DSA:
        hash_bn(&hash, key->key.dsa.x);
        break;
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_SM2_ENCRYPT:
        hash_bn(&hash, key->key.ecc.x);
        break;
    case PGP_PKA_ELGAMAL:
        hash_bn(&hash, key->key.elgamal.x);
        break;
    default:
        return false;
    }
    pgp_hash_finish(&hash, result);
    return true;
}

/*
 * Note that we support v3 keys here because they're needed for
 * verification.
 */
static bool
write_seckey_body(const pgp_seckey_t *key, const uint8_t *passphrase, pgp_output_t *output)
{
    /* RFC4880 Section 5.5.3 Secret-Key Packet Formats */

    uint8_t sesskey[PGP_MAX_KEY_SIZE];
    uint8_t checkhash[PGP_CHECKHASH_SIZE];
    size_t  sesskey_size;

    sesskey_size = pgp_key_size(key->alg);

    if (sesskey_size == 0) {
        RNP_LOG("unknown encryption algorithm");
        return false;
    }

    if (!write_pubkey_body(&key->pubkey, output)) {
        return false;
    }
    if (key->s2k_usage != PGP_S2KU_ENCRYPTED_AND_HASHED) {
        RNP_LOG("s2k usage");
        return false;
    }
    if (!pgp_write_scalar(output, (unsigned) key->s2k_usage, 1)) {
        return false;
    }
    if (!pgp_write_scalar(output, (unsigned) key->alg, 1)) {
        return false;
    }

    if (key->s2k_specifier != PGP_S2KS_SIMPLE && key->s2k_specifier != PGP_S2KS_SALTED &&
        key->s2k_specifier != PGP_S2KS_ITERATED_AND_SALTED) {
        RNP_LOG("invalid/unsupported s2k specifier %d", key->s2k_specifier);
        return false;
    }
    if (!pgp_write_scalar(output, (unsigned) key->s2k_specifier, 1)) {
        return false;
    }

    if (!pgp_write_scalar(output, (unsigned) key->hash_alg, 1)) {
        return false;
    }

    switch (key->s2k_specifier) {
    case PGP_S2KS_SIMPLE:
        /* no data to write */
        if (pgp_s2k_simple(key->hash_alg, sesskey, sesskey_size, (const char *) passphrase) <
            0) {
            RNP_LOG("pgp_s2k_simple failed");
            return false;
        }
        break;

    case PGP_S2KS_SALTED:
        /* 8-octet salt value */
        if (pgp_random(__UNCONST(&key->salt[0]), PGP_SALT_SIZE)) {
            RNP_LOG("pgp_random failed");
            return false;
        }
        if (!pgp_write(output, key->salt, PGP_SALT_SIZE)) {
            return false;
        }
        if (pgp_s2k_salted(
              key->hash_alg, sesskey, sesskey_size, (const char *) passphrase, key->salt)) {
            RNP_LOG("pgp_s2k_salted failed");
            return false;
        }
        break;

    case PGP_S2KS_ITERATED_AND_SALTED:
        /* 8-octet salt value */
        if (pgp_random(__UNCONST(&key->salt[0]), PGP_SALT_SIZE)) {
            RNP_LOG("pgp_random failed");
            return false;
        }
        if (pgp_s2k_iterated(key->hash_alg,
                             sesskey,
                             sesskey_size,
                             (const char *) passphrase,
                             key->salt,
                             key->s2k_iterations)) {
            RNP_LOG("pgp_s2k_iterated failed");
            return false;
        }
        uint8_t encoded_iterations = pgp_s2k_encode_iterations(key->s2k_iterations);

        if (!pgp_write(output, key->salt, PGP_SALT_SIZE)) {
            return false;
        }
        if (!pgp_write_scalar(output, encoded_iterations, 1)) {
            return false;
        }
        break;
    }

    if (!pgp_write(output, &key->iv[0], pgp_block_size(key->alg))) {
        return false;
    }

    /* use this session key to encrypt */

    pgp_crypt_t *crypted = malloc(sizeof(pgp_crypt_t));
    if (!crypted) {
        RNP_LOG("Memory allcoation failed");
        return false;
    }
    pgp_crypt_any(crypted, key->alg);
    pgp_cipher_set_iv(crypted, key->iv);
    pgp_cipher_set_key(crypted, sesskey);
    pgp_encrypt_init(crypted);

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "writing: iv=", key->iv, pgp_block_size(key->alg));
        hexdump(stderr, "key= ", sesskey, sesskey_size);
        (void) fprintf(stderr, "\nturning encryption on...\n");
    }
    pgp_push_enc_crypt(output, crypted);

    switch (key->pubkey.alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!pgp_write_mpi(output, key->key.rsa.d) || !pgp_write_mpi(output, key->key.rsa.p) ||
            !pgp_write_mpi(output, key->key.rsa.q) || !pgp_write_mpi(output, key->key.rsa.u)) {
            if (rnp_get_debug(__FILE__)) {
                RNP_LOG("4 x mpi not written - problem");
            }
            return false;
        }
        break;
    case PGP_PKA_DSA:
        if (!pgp_write_mpi(output, key->key.dsa.x))
            return false;
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_SM2_ENCRYPT:
    case PGP_PKA_ECDH:
        if (!pgp_write_mpi(output, key->key.ecc.x))
            return false;
        break;
    case PGP_PKA_ELGAMAL:
        if (!pgp_write_mpi(output, key->key.elgamal.x))
            return false;
        break;
    default:
        return false;
    }

    if (key->checkhash) {
        memcpy(checkhash, key->checkhash, PGP_CHECKHASH_SIZE);
    } else if (!hash_key_material(key, checkhash)) {
        return false;
    }
    if (!pgp_write(output, checkhash, PGP_CHECKHASH_SIZE)) {
        return false;
    }

    pgp_writer_pop(output);
    pgp_cipher_finish(crypted);
    free(crypted);
    return true;
}

/**
 * \ingroup Core_WritePackets
 * \brief Writes a Public Key packet
 * \param key
 * \param output
 * \return 1 if OK, otherwise 0
 */
bool
pgp_write_struct_pubkey(pgp_output_t *output, pgp_content_enum tag, const pgp_pubkey_t *key)
{
    return pgp_write_ptag(output, tag) &&
           pgp_write_length(output, 1 + 4 + 1 + pubkey_length(key)) &&
           write_pubkey_body(key, output);
}

static bool
packet_matches(const pgp_rawpacket_t *pkt, const pgp_content_enum tags[], size_t tag_count)
{
    for (size_t i = 0; i < tag_count; i++) {
        if (pkt->tag == tags[i]) {
            return true;
        }
    }
    return false;
}

static bool
write_matching_packets(pgp_output_t *         output,
                       const pgp_key_t *      key,
                       const pgp_content_enum tags[],
                       size_t                 tag_count)
{
    for (int i = 0; i < key->packetc; i++) {
        pgp_rawpacket_t *pkt = &key->packets[i];

        if (!packet_matches(pkt, tags, tag_count)) {
            RNP_LOG("skipping packet with tag: %d", pkt->tag);
            continue;
        }
        if (!pgp_write(output, pkt->raw, (unsigned) pkt->length)) {
            return false;
        }
    }
    return true;
}

/**
   \ingroup HighLevel_KeyWrite

   \brief Writes a transferable PGP public key to the given output stream.

   \param key Key to be written
   \param armoured Flag is set for armoured output
   \param output Output stream

*/

unsigned
pgp_write_xfer_pubkey(pgp_output_t *         output,
                      const pgp_key_t *      key,
                      const rnp_key_store_t *subkeys,
                      const unsigned         armoured)
{
    static const pgp_content_enum permitted_tags[] = {PGP_PTAG_CT_PUBLIC_KEY,
                                                      PGP_PTAG_CT_PUBLIC_SUBKEY,
                                                      PGP_PTAG_CT_USER_ID,
                                                      PGP_PTAG_CT_SIGNATURE};
    if (armoured) {
        pgp_writer_push_armoured(output, PGP_PGP_PUBLIC_KEY_BLOCK);
    }
    if (!write_matching_packets(output, key, permitted_tags, ARRAY_SIZE(permitted_tags))) {
        return false;
    }
    if (armoured) {
        pgp_writer_info_finalise(&output->errors, &output->writer);
        pgp_writer_pop(output);
    }
    return true;
}

/**
   \ingroup HighLevel_KeyWrite

   \brief Writes a transferable PGP secret key to the given output stream.

   \param key Key to be written
   \param passphrase
   \param pplen
   \param armoured Flag is set for armoured output
   \param output Output stream

*/

bool
pgp_write_xfer_seckey(pgp_output_t *         output,
                      const pgp_key_t *      key,
                      const uint8_t *        passphrase,
                      const rnp_key_store_t *subkeys,
                      unsigned               armoured)
{
    static const pgp_content_enum permitted_tags[] = {PGP_PTAG_CT_SECRET_KEY,
                                                      PGP_PTAG_CT_SECRET_SUBKEY,
                                                      PGP_PTAG_CT_USER_ID,
                                                      PGP_PTAG_CT_SIGNATURE};
    if (armoured) {
        pgp_writer_push_armoured(output, PGP_PGP_PRIVATE_KEY_BLOCK);
    }
    if (!write_matching_packets(output, key, permitted_tags, ARRAY_SIZE(permitted_tags))) {
        return false;
    }
    if (armoured) {
        pgp_writer_info_finalise(&output->errors, &output->writer);
        pgp_writer_pop(output);
    }
    return true;
}

bool
pgp_write_xfer_anykey(pgp_output_t *         output,
                      const pgp_key_t *      key,
                      const uint8_t *        passphrase,
                      const rnp_key_store_t *subkeys,
                      unsigned               armoured)
{
    int i;

    switch (key->type) {
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        if (!pgp_write_xfer_pubkey(output, key, NULL, armoured)) {
            fprintf(stderr, "Can't write public key\n");
            return false;
        }
        break;

    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        if (!pgp_write_xfer_seckey(output, key, passphrase, NULL, armoured)) {
            RNP_LOG("Can't write private key");
            return false;
        }
        break;

    case PGP_PTAG_CT_ENCRYPTED_SECRET_KEY:
    case PGP_PTAG_CT_ENCRYPTED_SECRET_SUBKEY:
        if (key->packetc == 0) {
            fprintf(stderr, "Can't write encrypted private key without RAW packed.\n");
            return false;
        }
        for (i = 0; i < key->packetc; i++) {
            if (!pgp_write(output, key->packets[i].raw, key->packets[i].length)) {
                fprintf(stderr, "Can't write part of encrypted private key\n");
                return false;
            }
        }
        break;

    default:
        fprintf(stderr, "Can't write key type: %d\n", key->type);
        return false;
    }

    return true;
}

/**
 * \ingroup Core_Create
 * \param out
 * \param key
 * \param make_packet
 */

void
pgp_build_pubkey(pgp_memory_t *out, const pgp_pubkey_t *key, unsigned make_packet)
{
    pgp_output_t *output;

    output = pgp_output_new();
    if (output == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return;
    }
    pgp_memory_init(out, 128);
    pgp_writer_set_memory(output, out);
    write_pubkey_body(key, output);
    if (make_packet) {
        pgp_memory_make_packet(out, PGP_PTAG_CT_PUBLIC_KEY);
    }
    pgp_output_delete(output);
}

/**
 * \ingroup Core_WritePackets
 * \brief Writes a Secret Key packet.
 * \param key The secret key
 * \param passphrase The passphrase
 * \param pplen Length of passphrase
 * \param output
 * \return 1 if OK; else 0
 */
unsigned
pgp_write_struct_seckey(pgp_content_enum    tag,
                        const pgp_seckey_t *key,
                        const uint8_t *     passphrase,
                        pgp_output_t *      output)
{
    int length = 0;

    if (key->pubkey.version != 4) {
        (void) fprintf(stderr, "pgp_write_struct_seckey: public key version\n");
        return false;
    }

    /* Ref: RFC4880 Section 5.5.3 */

    /* pubkey, excluding MPIs */
    length += 1 + 4 + 1 + 1;

    /* s2k usage */
    length += 1;

    switch (key->s2k_usage) {
    case PGP_S2KU_NONE:
        /* nothing to add */
        break;

    case PGP_S2KU_ENCRYPTED_AND_HASHED: /* 254 */
    case PGP_S2KU_ENCRYPTED:            /* 255 */

        /* Ref: RFC4880 Section 3.7 */
        length += 1; /* s2k_specifier */

        switch (key->s2k_specifier) {
        case PGP_S2KS_SIMPLE:
            length += 1; /* hash algorithm */
            break;

        case PGP_S2KS_SALTED:
            length += 1 + 8; /* hash algorithm + salt */
            break;

        case PGP_S2KS_ITERATED_AND_SALTED:
            length += 1 + 8 + 1; /* hash algorithm, salt +
                                  * count */
            break;

        default:
            (void) fprintf(stderr, "pgp_write_struct_seckey: s2k spec\n");
            return false;
        }
        break;

    default:
        (void) fprintf(stderr, "pgp_write_struct_seckey: s2k usage\n");
        return false;
    }

    /* IV */
    if (key->s2k_usage) {
        length += pgp_block_size(key->alg);
    }
    /* checksum or hash */
    switch (key->s2k_usage) {
    case PGP_S2KU_NONE:
    case PGP_S2KU_ENCRYPTED:
        length += 2;
        break;

    case PGP_S2KU_ENCRYPTED_AND_HASHED:
        length += PGP_CHECKHASH_SIZE;
        break;

    default:
        (void) fprintf(stderr, "pgp_write_struct_seckey: s2k cksum usage\n");
        return false;
    }

    /* secret key and public key MPIs */
    length += (unsigned) seckey_length(key);

    return pgp_write_ptag(output, tag) &&
           /* pgp_write_length(output,1+4+1+1+seckey_length(key)+2) && */
           pgp_write_length(output, (unsigned) length) &&
           write_seckey_body(key, passphrase, output);
}

/**
 * \ingroup Core_Create
 *
 * \brief Create a new pgp_output_t structure.
 *
 * \return the new structure.
 * \note It is the responsiblity of the caller to call pgp_output_delete().
 * \sa pgp_output_delete()
 */
pgp_output_t *
pgp_output_new(void)
{
    return calloc(1, sizeof(pgp_output_t));
}

/**
 * \ingroup Core_Create
 * \brief Delete an pgp_output_t strucut and associated resources.
 *
 * Delete an pgp_output_t structure. If a writer is active, then
 * that is also deleted.
 *
 * \param info the structure to be deleted.
 */
void
pgp_output_delete(pgp_output_t *output)
{
    if (!output) {
        return;
    }
    pgp_writer_info_delete(&output->writer);
    free(output);
}

/**
 \ingroup Core_Create
 \brief Calculate the checksum for a session key
 \param sesskey Session Key to use
 \param cs Checksum to be written
 \return 1 if OK; else 0
*/
unsigned
pgp_calc_sesskey_checksum(pgp_pk_sesskey_t *sesskey, uint8_t cs[2])
{
    uint32_t checksum = 0;
    unsigned i;

    if (!pgp_is_sa_supported(sesskey->symm_alg)) {
        return false;
    }

    for (i = 0; i < pgp_key_size(sesskey->symm_alg); i++) {
        checksum += sesskey->key[i];
    }
    checksum = checksum % 65536;

    cs[0] = (uint8_t)((checksum >> 8) & 0xff);
    cs[1] = (uint8_t)(checksum & 0xff);

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "nm buf checksum:", cs, 2);
    }
    return true;
}

static unsigned
create_unencoded_m_buf(pgp_pk_sesskey_t *sesskey, pgp_crypt_t *cipherinfo, uint8_t *m_buf)
{
    unsigned i;

    /* m_buf is the buffer which will be encoded in PKCS#1 block
     * encoding to form the "m" value used in the Public Key
     * Encrypted Session Key Packet as defined in RFC Section 5.1
     * "Public-Key Encrypted Session Key Packet". Notice that
     * in case of ECDH different than PKCS#1 encoding is used.
     *
     * Format:
     *   m = symm_alg_ID || session key || checksum
     */
    m_buf[0] = sesskey->symm_alg;
    for (i = 0; i < cipherinfo->keysize; i++) {
        /* XXX - Flexelint - Warning 679: Suspicious Truncation in arithmetic expression
         * combining with pointer */
        m_buf[1 + i] = sesskey->key[i];
    }

    return pgp_calc_sesskey_checksum(sesskey, m_buf + 1 + cipherinfo->keysize);
}

/**
 \ingroup Core_Create
\brief Creates an pgp_pk_sesskey_t struct from key
\param key Key to use
\param cipher Encryption algorithm used
\return pgp_pk_sesskey_t struct
\note It is the caller's responsiblity to free the returned pointer
*/
pgp_pk_sesskey_t *
pgp_create_pk_sesskey(const pgp_pubkey_t *pubkey, pgp_symm_alg_t cipher)
{
    /*
     * Creates a random session key and encrypts it for the given key
     *
     * Encryption used is PK
     * can be any, we're hardcoding RSA for now
     */

    pgp_crypt_t       cipherinfo;
    pgp_pk_sesskey_t *sesskey = NULL;
    uint8_t *         encoded_key = NULL;
    size_t            sz_encoded_key = 0;

    if (pubkey == NULL) {
        (void) fprintf(stderr, "pgp_create_pk_sesskey: bad pub key\n");
        return NULL;
    }

    switch (pubkey->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_DSA:
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ECDH:
    case PGP_PKA_SM2_ENCRYPT:
        break;
    default:
        RNP_LOG("Bad public key encryption algorithm");
        return NULL;
    }

    (void) memset(&cipherinfo, 0x0, sizeof(cipherinfo));

    if (pgp_crypt_any(&cipherinfo, cipher) == 0) {
        return NULL;
    }

    /* allocate encoded_key here */

    /* The buffer stores the key plus alg_id (1 byte) + checksum (2 bytes) */

    sz_encoded_key = cipherinfo.keysize + 1 + 2;
    encoded_key = calloc(1, sz_encoded_key);
    if (encoded_key == NULL) {
        (void) fprintf(stderr, "pgp_create_pk_sesskey: can't allocate\n");
        goto error;
    }

    if ((sesskey = calloc(1, sizeof(*sesskey))) == NULL) {
        (void) fprintf(stderr, "pgp_create_pk_sesskey: can't allocate\n");
        goto error;
    }

    sesskey->version = PGP_PKSK_V3;
    if (!pgp_keyid(sesskey->key_id, PGP_KEY_ID_SIZE, pubkey)) {
        goto error;
    }
    sesskey->alg = pubkey->alg;
    sesskey->symm_alg = cipher;
    if (pgp_random(sesskey->key, cipherinfo.keysize)) {
        (void) fprintf(stderr, "pgp_random failed\n");
        goto error;
    }

    if (create_unencoded_m_buf(sesskey, &cipherinfo, &encoded_key[0]) == 0) {
        free(sesskey);
        sesskey = NULL;
        goto done;
    }

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "Encrypting for keyid", sesskey->key_id, sizeof(sesskey->key_id));
        hexdump(stderr, "sesskey created", sesskey->key, cipherinfo.keysize);
        hexdump(stderr, "encoded key buf", encoded_key, cipherinfo.keysize + 1 + 2);
    }

    /* and encrypt it */
    switch (pubkey->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY: {
        uint8_t encmpibuf[RNP_BUFSIZ];
        int     n;

        n = pgp_rsa_encrypt_pkcs1(
          encmpibuf, sizeof(encmpibuf), encoded_key, sz_encoded_key, &pubkey->key.rsa);
        if (n <= 0) {
            (void) fprintf(stderr, "pgp_rsa_encrypt_pkcs1 failure\n");
            free(sesskey);
            sesskey = NULL;
            goto done;
        }

        sesskey->params.rsa.encrypted_m = BN_bin2bn(encmpibuf, n, NULL);

        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "encrypted mpi", encmpibuf, n);
        }
    } break;

    case PGP_PKA_SM2_ENCRYPT: {
       uint8_t encmpibuf[RNP_BUFSIZ];
       size_t out_len = sizeof(encmpibuf);
       pgp_errcode_t err = pgp_sm2_encrypt(encmpibuf,
                                           &out_len,
                                           encoded_key,
                                           sz_encoded_key,
                                           &pubkey->key.ecc);

       if (err != PGP_E_OK) {
          goto done;
       }

       sesskey->params.sm2.encrypted_m = BN_bin2bn(encmpibuf, out_len, NULL);

    } break;


    case PGP_PKA_ECDH: {
        uint8_t           encmpibuf[ECDH_WRAPPED_KEY_SIZE] = {0};
        size_t            out_len = sizeof(encmpibuf);
        pgp_fingerprint_t fingerprint;

        if (!pgp_fingerprint(&fingerprint, pubkey)) {
            RNP_LOG("ECDH fingerprint calculation failed");
            goto done;
        }

        sesskey->params.ecdh.ephemeral_point = BN_new();
        if (!sesskey->params.ecdh.ephemeral_point) {
            goto done;
        }

        const rnp_result err = pgp_ecdh_encrypt_pkcs5(encoded_key,
                                                      sz_encoded_key,
                                                      encmpibuf,
                                                      &out_len,
                                                      sesskey->params.ecdh.ephemeral_point->mp,
                                                      &pubkey->key.ecdh,
                                                      &fingerprint);
        if (RNP_SUCCESS != err) {
            RNP_LOG("Encryption failed %d\n", err);
            goto error;
        }
        memcpy(sesskey->params.ecdh.encrypted_m, encmpibuf, out_len);
        sesskey->params.ecdh.encrypted_m_size = out_len;
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "encrypted mpi", encmpibuf, out_len);
        }
    } break;

    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN: {
        uint8_t encmpibuf[RNP_BUFSIZ];
        uint8_t g_to_k[RNP_BUFSIZ];
        int     n;

        n = pgp_elgamal_public_encrypt_pkcs1(
          g_to_k, encmpibuf, encoded_key, sz_encoded_key, &pubkey->key.elgamal);
        if (n <= 0) {
            (void) fprintf(stderr, "pgp_elgamal_public_encrypt failure\n");
            goto error;
        }

        sesskey->params.elgamal.g_to_k = BN_bin2bn(g_to_k, n / 2, NULL);
        sesskey->params.elgamal.encrypted_m = BN_bin2bn(encmpibuf, n / 2, NULL);

        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "elgamal g^k", g_to_k, n / 2);
            hexdump(stderr, "encrypted mpi", encmpibuf, n / 2);
        }
    } break;

    default:
        RNP_LOG("unsupported alg: %d", pubkey->alg);
        goto error;
        break;
    }

done:
    free(encoded_key);
    return sesskey;

error:
    free(encoded_key);
    free(sesskey);
    return NULL;
}

/**
\ingroup Core_WritePackets
\brief Writes Public Key Session Key packet
\param info Write settings
\param pksk Public Key Session Key to write out
\return 1 if OK; else 0
*/
bool
pgp_write_pk_sesskey(pgp_output_t *output, pgp_pk_sesskey_t *pksk)
{
    /* XXX - Flexelint - Pointer parameter 'pksk' (line 1076) could be declared as pointing to
     * const */
    if (pksk == NULL) {
        (void) fprintf(stderr, "pgp_write_pk_sesskey: NULL pksk\n");
        return false;
    }
    switch (pksk->alg) {
    case PGP_PKA_RSA:
        return pgp_write_ptag(output, PGP_PTAG_CT_PK_SESSION_KEY) &&
               pgp_write_length(
                 output,
                 (unsigned) (1 + 8 + 1 + BN_num_bytes(pksk->params.rsa.encrypted_m) + 2)) &&
               pgp_write_scalar(output, (unsigned) pksk->version, 1) &&
               pgp_write(output, pksk->key_id, 8) &&
               pgp_write_scalar(output, (unsigned) pksk->alg, 1) &&
               pgp_write_mpi(output, pksk->params.rsa.encrypted_m)
          /* ??    && pgp_write_scalar(output, 0, 2); */
          ;
    case PGP_PKA_SM2_ENCRYPT:
        return pgp_write_ptag(output, PGP_PTAG_CT_PK_SESSION_KEY) &&
               pgp_write_length(
                 output,
                 (unsigned) (1 + 8 + 1 + BN_num_bytes(pksk->params.rsa.encrypted_m) + 2)) &&
               pgp_write_scalar(output, (unsigned) pksk->version, 1) &&
               pgp_write(output, pksk->key_id, 8) &&
               pgp_write_scalar(output, (unsigned) pksk->alg, 1) &&
               pgp_write_mpi(output, pksk->params.sm2.encrypted_m);

    case PGP_PKA_DSA:
    case PGP_PKA_ELGAMAL:
        return pgp_write_ptag(output, PGP_PTAG_CT_PK_SESSION_KEY) &&
               pgp_write_length(
                 output,
                 (unsigned) (1 + 8 + 1 + BN_num_bytes(pksk->params.elgamal.g_to_k) + 2 +
                             BN_num_bytes(pksk->params.elgamal.encrypted_m) + 2)) &&
               pgp_write_scalar(output, (unsigned) pksk->version, 1) &&
               pgp_write(output, pksk->key_id, 8) &&
               pgp_write_scalar(output, (unsigned) pksk->alg, 1) &&
               pgp_write_mpi(output, pksk->params.elgamal.g_to_k) &&
               pgp_write_mpi(output, pksk->params.elgamal.encrypted_m);
    /* ??    && pgp_write_scalar(output, 0, 2); */
    case PGP_PKA_ECDH:
        return pgp_write_ptag(output, PGP_PTAG_CT_PK_SESSION_KEY) &&
               pgp_write_length(output,
                                (unsigned) (1 + 8 + 1 +
                                            BN_num_bytes(pksk->params.ecdh.ephemeral_point) +
                                            2 + 1 + pksk->params.ecdh.encrypted_m_size)) &&
               pgp_write_scalar(output, (unsigned) pksk->version, 1) &&
               pgp_write(output, pksk->key_id, 8) &&
               pgp_write_scalar(output, (unsigned) pksk->alg, 1) &&
               pgp_write_mpi(output, pksk->params.ecdh.ephemeral_point) &&
               pgp_write_scalar(output, pksk->params.ecdh.encrypted_m_size, 1) &&
               pgp_write(
                 output, pksk->params.ecdh.encrypted_m, pksk->params.ecdh.encrypted_m_size);
    default:
        (void) fprintf(stderr, "pgp_write_pk_sesskey: bad algorithm\n");
        return false;
    }
}

/**
\ingroup Core_WritePackets
\brief Writes MDC packet
\param hashed Hash for MDC
\param output Write settings
\return 1 if OK; else 0
*/

unsigned
pgp_write_mdc(pgp_output_t *output, const uint8_t *hashed)
{
    /* write it out */
    return pgp_write_ptag(output, PGP_PTAG_CT_MDC) &&
           pgp_write_length(output, PGP_SHA1_HASH_SIZE) &&
           pgp_write(output, hashed, PGP_SHA1_HASH_SIZE);
}

/**
\ingroup Core_WritePackets
\brief Writes Literal Data packet from buffer
\param output Write settings
\param data Buffer to write out
\param maxlen Max length of buffer
\param type Literal Data Type
\return 1 if OK; else 0
*/
unsigned
pgp_write_litdata(pgp_output_t *         output,
                  const uint8_t *        data,
                  const int              maxlen,
                  const pgp_litdata_enum type)
{
    char *   filename = NULL;
    uint64_t modtime = 0;
    unsigned flen = 0;
    /* \todo do we need to check text data for <cr><lf> line endings ? - Yes, we need.
    For non-PGP_LDT_BINARY we should convert line endings to the canonical CRLF style. */

    if (output->ctx) {
        filename = output->ctx->filename;
        modtime = output->ctx->filemtime;
        flen = filename ? strlen(filename) : 0;
        if (flen > 255) {
            (void) fprintf(stderr, "pgp_write_litdata : filename %s too long\n", filename);
            return false;
        }
    }

    return pgp_write_ptag(output, PGP_PTAG_CT_LITDATA) &&
           pgp_write_length(output, (unsigned) (1 + 1 + flen + 4 + maxlen)) &&
           pgp_write_scalar(output, (unsigned) type, 1) && pgp_write_scalar(output, flen, 1) &&
           ((flen > 0) ? pgp_write(output, filename, flen) : 1) &&
           pgp_write_scalar(output, modtime, 4) && pgp_write(output, data, (unsigned) maxlen);
}

/**
\ingroup Core_WritePackets
\brief Writes Literal Data packet from contents of file
\param filename Name of file to read from
\param type Literal Data Type
\param output Write settings
\return 1 if OK; else 0
*/

unsigned
pgp_fileread_litdata(const char *filename, const pgp_litdata_enum type, pgp_output_t *output)
{
    pgp_memory_t *mem;
    unsigned      ret;
    int           len;

    mem = pgp_memory_new();
    if (mem == NULL) {
        (void) fprintf(stderr, "can't allocate mem\n");
        return false;
    }
    if (!pgp_mem_readfile(mem, filename)) {
        (void) fprintf(stderr, "pgp_mem_readfile of '%s' failed\n", filename);
        pgp_memory_free(mem);
        return false;
    }

    len = (int) pgp_mem_len(mem);
    ret = pgp_write_litdata(output, pgp_mem_data(mem), len, type);
    pgp_memory_free(mem);
    return ret;
}

/**
   \ingroup HighLevel_General

   \brief Writes contents of buffer into file

   \param filename Filename to write to
   \param buf Buffer to write to file
   \param len Size of buffer
   \param overwrite Flag to set whether to overwrite an existing file
   \return 1 if OK; 0 if error
*/

int
pgp_filewrite(const char *   filename,
              const char *   buf,
              const size_t   len,
              const unsigned overwrite)
{
    int flags;
    int fd;

    flags = O_WRONLY | O_CREAT;
    if (overwrite) {
        flags |= O_TRUNC;
    } else {
        flags |= O_EXCL;
    }
#ifdef O_BINARY
    flags |= O_BINARY;
#endif
    fd = open(filename, flags, 0600);
    if (fd < 0) {
        (void) fprintf(stderr, "can't open '%s'\n", filename);
        return false;
    }
    if (write(fd, buf, len) != (int) len) {
        (void) close(fd);
        return false;
    }

    return (close(fd) == 0);
}

/**
\ingroup Core_WritePackets
\brief Write Symmetrically Encrypted packet
\param data Data to encrypt
\param len Length of data
\param output Write settings
\return 1 if OK; else 0
\note Hard-coded to use AES256
*/
unsigned
pgp_write_symm_enc_data(const uint8_t *data, const int len, pgp_output_t *output)
{
    pgp_crypt_t crypt_info;
    uint8_t *   encrypted = (uint8_t *) NULL;
    size_t      encrypted_sz;
    int         done = 0;

    /* \todo assume AES256 for now */
    pgp_crypt_any(&crypt_info, PGP_SA_AES_256);
    pgp_encrypt_init(&crypt_info);

    encrypted_sz = (size_t)(len + crypt_info.blocksize + 2);
    if ((encrypted = calloc(1, encrypted_sz)) == NULL) {
        (void) fprintf(stderr, "can't allocate %" PRIsize "d\n", encrypted_sz);
        return false;
    }

    done = (int) pgp_encrypt_se(&crypt_info, encrypted, data, (unsigned) len);
    if (done != len) {
        (void) fprintf(stderr, "pgp_write_symm_enc_data: done != len\n");
        free(encrypted);
        return false;
    }

    return pgp_write_ptag(output, PGP_PTAG_CT_SE_DATA) &&
           pgp_write_length(output, (unsigned) (1 + encrypted_sz)) &&
           pgp_write(output, data, (unsigned) len);
}

/**
\ingroup Core_WritePackets
\brief Write a One Pass Signature packet
\param seckey Secret Key to use
\param hash_alg Hash Algorithm to use
\param sig_type Signature type
\param output Write settings
\return 1 if OK; else 0
*/
unsigned
pgp_write_one_pass_sig(pgp_output_t *       output,
                       const pgp_seckey_t * seckey,
                       const pgp_hash_alg_t hash_alg,
                       const pgp_sig_type_t sig_type)
{
    uint8_t keyid[PGP_KEY_ID_SIZE];

    pgp_keyid(keyid, PGP_KEY_ID_SIZE, &seckey->pubkey);
    return pgp_write_ptag(output, PGP_PTAG_CT_1_PASS_SIG) &&
           pgp_write_length(output, 1 + 1 + 1 + 1 + 8 + 1) &&
           pgp_write_scalar(output, 3, 1) /* version */ &&
           pgp_write_scalar(output, (unsigned) sig_type, 1) &&
           pgp_write_scalar(output, (unsigned) hash_alg, 1) &&
           pgp_write_scalar(output, (unsigned) seckey->pubkey.alg, 1) &&
           pgp_write(output, keyid, 8) && pgp_write_scalar(output, 1, 1);
}

bool
pgp_write_selfsig_cert(pgp_output_t *               output,
                       const pgp_seckey_t *         seckey,
                       const pgp_hash_alg_t         hash_alg,
                       const rnp_selfsig_cert_info *cert)
{
    pgp_create_sig_t *sig = NULL;
    bool              ok = false;
    uint8_t           keyid[PGP_KEY_ID_SIZE];

    if (!output || !seckey || !cert) {
        RNP_LOG("invalid parameters");
        goto end;
    }

    if (!pgp_keyid(keyid, sizeof(keyid), &seckey->pubkey)) {
        RNP_LOG("failed to calculate keyid");
        goto end;
    }

    sig = pgp_create_sig_new();
    if (!sig) {
        RNP_LOG("create sig failed");
        goto end;
    }
    pgp_sig_start_key_sig(sig, &seckey->pubkey, cert->userid, PGP_CERT_POSITIVE, hash_alg);
    if (!pgp_sig_add_time(sig, (int64_t) time(NULL), PGP_PTAG_SS_CREATION_TIME)) {
        RNP_LOG("failed to add creation time");
        goto end;
    }
    if (cert->key_expiration &&
        !pgp_sig_add_time(sig, cert->key_expiration, PGP_PTAG_SS_KEY_EXPIRY)) {
        RNP_LOG("failed to add key expiration time");
        goto end;
    }
    if (cert->key_flags && !pgp_sig_add_key_flags(sig, &cert->key_flags, 1)) {
        RNP_LOG("failed to add key flags");
        goto end;
    }
    if (cert->primary) {
        pgp_sig_add_primary_userid(sig, 1);
    }
    const pgp_user_prefs_t *prefs = &cert->prefs;
    if (!DYNARRAY_IS_EMPTY(prefs, symm_alg) &&
        !pgp_sig_add_pref_symm_algs(sig, prefs->symm_algs, prefs->symm_algc)) {
        RNP_LOG("failed to add symm alg prefs");
        goto end;
    }
    if (!DYNARRAY_IS_EMPTY(prefs, hash_alg) &&
        !pgp_sig_add_pref_hash_algs(sig, prefs->hash_algs, prefs->hash_algc)) {
        RNP_LOG("failed to add hash alg prefs");
        goto end;
    }
    if (!DYNARRAY_IS_EMPTY(prefs, compress_alg) &&
        !pgp_sig_add_pref_compress_algs(sig, prefs->compress_algs, prefs->compress_algc)) {
        RNP_LOG("failed to add compress alg prefs");
        goto end;
    }
    if (!DYNARRAY_IS_EMPTY(prefs, key_server_pref) &&
        !pgp_sig_add_key_server_prefs(sig, prefs->key_server_prefs, prefs->key_server_prefc)) {
        RNP_LOG("failed to add key server prefs");
        goto end;
    }
    if (prefs->key_server && !pgp_sig_add_preferred_key_server(sig, prefs->key_server)) {
        RNP_LOG("failed to add preferred key server");
        goto end;
    }
    if (!pgp_sig_add_issuer_keyid(sig, keyid)) {
        RNP_LOG("failed to add issuer key id");
        goto end;
    }
    if (!pgp_sig_end_hashed_subpkts(sig)) {
        RNP_LOG("failed to finalize hashed subpkts");
        goto end;
    }

    if (!pgp_sig_write(output, sig, &seckey->pubkey, seckey)) {
        RNP_LOG("failed to write signature");
        goto end;
    }
    ok = true;
end:
    pgp_create_sig_delete(sig);
    return ok;
}

bool
pgp_write_selfsig_binding(pgp_output_t *                  output,
                          const pgp_seckey_t *            primary_sec,
                          const pgp_hash_alg_t            hash_alg,
                          const pgp_pubkey_t *            subkey,
                          const rnp_selfsig_binding_info *binding)
{
    pgp_create_sig_t *sig = NULL;
    bool              ok = false;
    uint8_t           keyid[PGP_KEY_ID_SIZE];

    if (!output || !primary_sec || !subkey || !binding) {
        RNP_LOG("invalid parameters");
        goto end;
    }

    if (!pgp_keyid(keyid, sizeof(keyid), &primary_sec->pubkey)) {
        RNP_LOG("failed to calculate keyid");
        goto end;
    }

    sig = pgp_create_sig_new();
    if (!sig) {
        RNP_LOG("create sig failed");
        goto end;
    }
    pgp_sig_start_subkey_sig(sig, &primary_sec->pubkey, subkey, PGP_SIG_SUBKEY, hash_alg);
    if (!pgp_sig_add_time(sig, (int64_t) time(NULL), PGP_PTAG_SS_CREATION_TIME)) {
        RNP_LOG("failed to add creation time");
        goto end;
    }
    if (binding->key_expiration &&
        !pgp_sig_add_time(sig, binding->key_expiration, PGP_PTAG_SS_KEY_EXPIRY)) {
        RNP_LOG("failed to add key expiration time");
        goto end;
    }
    if (binding->key_flags && !pgp_sig_add_key_flags(sig, &binding->key_flags, 1)) {
        RNP_LOG("failed to add key flags");
        goto end;
    }
    if (!pgp_sig_add_issuer_keyid(sig, keyid)) {
        RNP_LOG("failed to add issuer key id");
        goto end;
    }
    if (!pgp_sig_end_hashed_subpkts(sig)) {
        RNP_LOG("failed to finalize hashed subpkts");
        goto end;
    }

    if (!pgp_sig_write(output, sig, &primary_sec->pubkey, primary_sec)) {
        RNP_LOG("failed to write signature");
        goto end;
    }
    ok = true;
end:
    pgp_create_sig_delete(sig);
    return ok;
}
