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
#include <stdlib.h>
#include <stdbool.h>

#include "types.h"
#include "bn.h"
#include "rsa.h"
#include "elgamal.h"
#include "eddsa.h"
#include "ecdh.h"
#include "crypto.h"
#include "readerwriter.h"
#include "memory.h"
#include "utils.h"
#include "signature.h"
#include "pgp-key.h"
#include "s2k.h"
#include "ecdsa.h"
#include "sm2.h"
#include "utils.h"
#include <rnp/rnp_def.h>

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
pgp_decrypt_decode_mpi(uint8_t *           buf,
                       unsigned            buflen,
                       const BIGNUM *      g_to_k,
                       const BIGNUM *      encmpi,
                       const pgp_seckey_t *seckey)
{
    unsigned mpisize;
    uint8_t  encmpibuf[RNP_BUFSIZ] = {0};
    uint8_t  gkbuf[RNP_BUFSIZ] = {0};
    int      n;

    mpisize = (unsigned) BN_num_bytes(encmpi);
    /* MPI can't be more than 65,536 */
    if (mpisize > sizeof(encmpibuf)) {
        RNP_LOG("mpisize too big %u", mpisize);
        return -1;
    }
    switch (seckey->pubkey.alg) {
    case PGP_PKA_RSA:
        BN_bn2bin(encmpi, encmpibuf);
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "encrypted", encmpibuf, 16);
        }
        n = pgp_rsa_decrypt_pkcs1(buf,
                                  buflen,
                                  encmpibuf,
                                  (unsigned) (BN_num_bits(encmpi) + 7) / 8,
                                  &seckey->key.rsa,
                                  &seckey->pubkey.key.rsa);
        if (n <= 0) {
            (void) fprintf(stderr, "ops_rsa_private_decrypt failure\n");
            return -1;
        }
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "decoded m", buf, n);
        }
        return n;
    case PGP_PKA_DSA:
    case PGP_PKA_ELGAMAL:
        (void) BN_bn2bin(g_to_k, gkbuf);
        (void) BN_bn2bin(encmpi, encmpibuf);
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "encrypted", encmpibuf, 16);
        }
        n = pgp_elgamal_private_decrypt_pkcs1(buf,
                                              gkbuf,
                                              encmpibuf,
                                              (unsigned) BN_num_bytes(encmpi),
                                              &seckey->key.elgamal,
                                              &seckey->pubkey.key.elgamal);
        if (n <= 0) {
            (void) fprintf(stderr, "ops_elgamal_private_decrypt failure\n");
            return -1;
        }

        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "decoded m", buf, n);
        }
        return n;
    case PGP_PKA_ECDH: {
        pgp_fingerprint_t fingerprint;
        size_t            out_len = buflen;
        const size_t      encmpi_len = BN_num_bytes(encmpi);
        if (BN_bn2bin(encmpi, encmpibuf)) {
            RNP_LOG("Can't find session key");
            return -1;
        }

        if (!pgp_fingerprint(&fingerprint, &seckey->pubkey)) {
            RNP_LOG("ECDH fingerprint calculation failed");
            return -1;
        }

        const rnp_result ret = pgp_ecdh_decrypt_pkcs5(buf,
                                                      &out_len,
                                                      encmpibuf,
                                                      encmpi_len,
                                                      g_to_k->mp,
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

/**
\ingroup Core_MPI
\brief Elgamal-encrypt an MPI
*/
bool
pgp_elgamal_encrypt_mpi(const uint8_t *          encoded_m_buf,
                        const size_t             sz_encoded_m_buf,
                        const pgp_pubkey_t *     pubkey,
                        pgp_pk_sesskey_params_t *skp)
{
    uint8_t encmpibuf[RNP_BUFSIZ];
    uint8_t g_to_k[RNP_BUFSIZ];
    int     n;

    if (sz_encoded_m_buf != (size_t) BN_num_bytes(pubkey->key.elgamal.p)) {
        (void) fprintf(stderr, "sz_encoded_m_buf wrong\n");
        return false;
    }

    n = pgp_elgamal_public_encrypt_pkcs1(
      g_to_k, encmpibuf, encoded_m_buf, sz_encoded_m_buf, &pubkey->key.elgamal);
    if (n == -1) {
        (void) fprintf(stderr, "pgp_elgamal_public_encrypt failure\n");
        return false;
    }

    if (n <= 0) {
        return false;
    }

    skp->elgamal.g_to_k = BN_bin2bn(g_to_k, n / 2, NULL);
    skp->elgamal.encrypted_m = BN_bin2bn(encmpibuf, n / 2, NULL);

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "encrypted mpi", encmpibuf, 16);
    }
    return true;
}

bool
pgp_generate_seckey(const rnp_keygen_crypto_params_t *crypto, pgp_seckey_t *seckey)
{
    pgp_output_t *output = NULL;
    pgp_memory_t *mem = NULL;
    bool          ok = false;

    if (!crypto || !seckey) {
        RNP_LOG("NULL args");
        goto end;
    }
    /* populate pgp key structure */
    seckey->pubkey.version = PGP_V4;
    seckey->pubkey.birthtime = time(NULL);
    seckey->pubkey.alg = crypto->key_alg;
    seckey->hash_alg =
      (PGP_HASH_UNKNOWN == crypto->hash_alg) ? PGP_HASH_SHA1 : crypto->hash_alg;

    switch (seckey->pubkey.alg) {
    case PGP_PKA_RSA:
        if (pgp_genkey_rsa(seckey, crypto->rsa.modulus_bit_len) != 1) {
            RNP_LOG("failed to generate RSA key");
            goto end;
        }
        break;

    case PGP_PKA_EDDSA:
        if (pgp_genkey_eddsa(seckey, ec_curves[PGP_CURVE_ED25519].bitlen) != 1) {
            RNP_LOG("failed to generate EDDSA key");
            goto end;
        }
        break;

    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
        seckey->pubkey.key.ecc.curve = crypto->ecc.curve;
        if (pgp_ecdh_ecdsa_genkeypair(seckey, seckey->pubkey.key.ecc.curve) != PGP_E_OK) {
            RNP_LOG("failed to generate ECDSA key");
            goto end;
        }
        break;
    case PGP_PKA_SM2:
        seckey->pubkey.key.ecc.curve = crypto->ecc.curve;
        if (pgp_sm2_genkeypair(seckey, seckey->pubkey.key.ecc.curve) != PGP_E_OK) {
            RNP_LOG("failed to generate SM2 key");
            goto end;
        }
        break;

    default:
        RNP_LOG("key generation not implemented for PK alg: %d", seckey->pubkey.alg);
        goto end;
        break;
    }

    seckey->s2k_usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
    seckey->s2k_specifier = PGP_S2KS_ITERATED_AND_SALTED;
    seckey->s2k_iterations = pgp_s2k_round_iterations(65536);
    seckey->alg = crypto->sym_alg;
    if (pgp_random(&seckey->iv[0], pgp_block_size(seckey->alg))) {
        RNP_LOG("pgp_random failed");
        goto end;
    }
    seckey->checksum = 0;

    /* Generate checksum */
    if (!pgp_setup_memory_write(NULL, &output, &mem, 128)) {
        RNP_LOG("can't setup memory write");
        goto end;
    }
    pgp_push_checksum_writer(output, seckey);

    switch (seckey->pubkey.alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!pgp_write_mpi(output, seckey->key.rsa.d) ||
            !pgp_write_mpi(output, seckey->key.rsa.p) ||
            !pgp_write_mpi(output, seckey->key.rsa.q) ||
            !pgp_write_mpi(output, seckey->key.rsa.u)) {
            RNP_LOG("failed to write MPIs");
            goto end;
        }
        break;
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
        if (!pgp_write_mpi(output, seckey->key.ecc.x)) {
            RNP_LOG("failed to write MPIs");
            goto end;
        }
        break;

    default:
        RNP_LOG("key generation not implemented for PK alg: %d", seckey->pubkey.alg);
        goto end;
        break;
    }

    ok = true;
end:
    if (output && mem) {
        pgp_teardown_memory_write(output, mem);
    }
    if (!ok && seckey) {
        RNP_LOG("failed, freeing internal seckey data");
        pgp_seckey_free(seckey);
    }
    return ok;
}

static pgp_cb_ret_t
write_parsed_cb(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;

    if (rnp_get_debug(__FILE__)) {
        printf("write_parsed_cb: ");
        pgp_print_packet(&cbinfo->printstate, pkt);
    }
    if (pkt->tag != PGP_PTAG_CT_UNARMOURED_TEXT && cbinfo->printstate.skipping) {
        puts("...end of skip");
        cbinfo->printstate.skipping = 0;
    }
    switch (pkt->tag) {
    case PGP_PTAG_CT_UNARMOURED_TEXT:
        printf("PGP_PTAG_CT_UNARMOURED_TEXT\n");
        if (!cbinfo->printstate.skipping) {
            puts("Skipping...");
            cbinfo->printstate.skipping = 1;
        }
        if (fwrite(
              content->unarmoured_text.data, 1, content->unarmoured_text.length, stdout) !=
            content->unarmoured_text.length) {
            fprintf(stderr, "unable to write unarmoured text data\n");
            cbinfo->printstate.skipping = 1;
        }
        break;

    case PGP_PTAG_CT_PK_SESSION_KEY:
        return pgp_pk_sesskey_cb(pkt, cbinfo);

    case PGP_GET_SECKEY:
        if (cbinfo->sshseckey) {
            *content->get_seckey.seckey = cbinfo->sshseckey;
            return PGP_KEEP_MEMORY;
        }
        return pgp_get_seckey_cb(pkt, cbinfo);

    case PGP_GET_PASSPHRASE:
        return cbinfo->cryptinfo.getpassphrase(pkt, cbinfo);

    case PGP_PTAG_CT_LITDATA_BODY:
        return pgp_litdata_cb(pkt, cbinfo);

    case PGP_PTAG_CT_ARMOUR_HEADER:
    case PGP_PTAG_CT_ARMOUR_TRAILER:
    case PGP_PTAG_CT_ENCRYPTED_PK_SESSION_KEY:
    case PGP_PTAG_CT_COMPRESSED:
    case PGP_PTAG_CT_LITDATA_HEADER:
    case PGP_PTAG_CT_SE_IP_DATA_BODY:
    case PGP_PTAG_CT_SE_IP_DATA_HEADER:
    case PGP_PTAG_CT_SE_DATA_BODY:
    case PGP_PTAG_CT_SE_DATA_HEADER:
        /* Ignore these packets  */
        /* They're handled in parse_packet() */
        /* and nothing else needs to be done */
        break;

    default:
        if (rnp_get_debug(__FILE__)) {
            fprintf(stderr, "Unexpected packet tag=%d (0x%x)\n", pkt->tag, pkt->tag);
        }
        break;
    }

    return PGP_RELEASE_MEMORY;
}

/**
\ingroup HighLevel_Crypto
Encrypt a file
\param ctx Rnp context, holding additional information about the operation
\param io I/O structure
\param infile Name of file to be encrypted
\param outfile Name of file to write to. If NULL, name is constructed from infile
\param key Public Key to encrypt file for
\return true if OK
*/
bool
pgp_encrypt_file(rnp_ctx_t *         ctx,
                 pgp_io_t *          io,
                 const char *        infile,
                 const char *        outfile,
                 const pgp_pubkey_t *pubkey)
{
    pgp_output_t *output;
    pgp_memory_t *inmem;
    int           fd_out;

    __PGP_USED(io);
    inmem = pgp_memory_new();
    if (inmem == NULL) {
        (void) fprintf(stderr, "can't allocate mem\n");
        return false;
    }
    if (!pgp_mem_readfile(inmem, infile)) {
        pgp_memory_free(inmem);
        return false;
    }
    fd_out = pgp_setup_file_write(ctx, &output, outfile, ctx->overwrite);
    if (fd_out < 0) {
        pgp_memory_free(inmem);
        return false;
    }

    /* set armoured/not armoured here */
    if (ctx->armour) {
        pgp_writer_push_armoured(output, PGP_PGP_MESSAGE);
    }

    /* Push the encrypted writer */
    if (!pgp_push_enc_se_ip(output, pubkey, ctx->ealg)) {
        pgp_memory_free(inmem);
        return false;
    }

    /* This does the writing */
    pgp_write(output, pgp_mem_data(inmem), (unsigned) pgp_mem_len(inmem));

    /* tidy up */
    pgp_memory_free(inmem);
    pgp_teardown_file_write(output, fd_out);

    return true;
}

/* encrypt the contents of the input buffer, and return the mem structure */
pgp_memory_t *
pgp_encrypt_buf(rnp_ctx_t *         ctx,
                pgp_io_t *          io,
                const void *        input,
                const size_t        insize,
                const pgp_pubkey_t *pubkey)
{
    pgp_output_t *output;
    pgp_memory_t *outmem;

    __PGP_USED(io);
    if (input == NULL) {
        (void) fprintf(io->errs, "pgp_encrypt_buf: null memory\n");
        return false;
    }

    if (!pgp_setup_memory_write(ctx, &output, &outmem, insize)) {
        (void) fprintf(io->errs, "can't setup memory write\n");
        return false;
    }

    /* set armoured/not armoured here */
    if (ctx->armour) {
        pgp_writer_push_armoured(output, PGP_PGP_MESSAGE);
    }

    /* Push the encrypted writer */
    pgp_push_enc_se_ip(output, pubkey, ctx->ealg);

    /* This does the writing */
    pgp_write(output, input, (unsigned) insize);

    /* tidy up */
    pgp_writer_close(output);
    pgp_output_delete(output);

    return outmem;
}

/**
   \ingroup HighLevel_Crypto
   \brief Decrypt a file.
   \param infile Name of file to be decrypted
   \param outfile Name of file to write to. If NULL, the filename is constructed from the input
   filename, following GPG conventions.
   \param keyring Keyring to use
   \param use_armour Expect armoured text, if set
   \param allow_overwrite Allow output file to overwritten, if set.
   \param getpassfunc Callback to use to get passphrase
*/

bool
pgp_decrypt_file(pgp_io_t *       io,
                 const char *     infile,
                 const char *     outfile,
                 rnp_key_store_t *secring,
                 rnp_key_store_t *pubring,
                 const unsigned   use_armour,
                 const unsigned   allow_overwrite,
                 const unsigned   sshkeys,
                 void *           passfp,
                 int              numtries,
                 pgp_cbfunc_t *   getpassfunc)
{
    pgp_stream_t *parse = NULL;
    const int     printerrors = 1;
    char *        filename = NULL;
    int           fd_in;
    int           fd_out;
    int           ret;

    /* setup for reading from given input file */
    fd_in = pgp_setup_file_read(io, &parse, infile, NULL, write_parsed_cb, 0);
    if (fd_in < 0) {
        perror(infile);
        return false;
    }
    /* setup output filename */
    if (outfile) {
        fd_out = pgp_setup_file_write(NULL, &parse->cbinfo.output, outfile, allow_overwrite);
        if (fd_out < 0) {
            perror(outfile);
            pgp_teardown_file_read(parse, fd_in);
            return false;
        }
    } else {
        const int   suffixlen = 4;
        const char *suffix = infile + strlen(infile) - suffixlen;
        unsigned    filenamelen;

        if (strcmp(suffix, ".gpg") == 0 || strcmp(suffix, ".asc") == 0) {
            filenamelen = (unsigned) (strlen(infile) - strlen(suffix));
            if ((filename = calloc(1, filenamelen + 1)) == NULL) {
                (void) fprintf(
                  stderr, "can't allocate %" PRIsize "d bytes\n", (size_t)(filenamelen + 1));
                pgp_teardown_file_read(parse, fd_in);
                return false;
            }
            (void) strncpy(filename, infile, filenamelen);
            filename[filenamelen] = 0x0;
        }

        fd_out = pgp_setup_file_write(NULL, &parse->cbinfo.output, filename, allow_overwrite);
        if (fd_out < 0) {
            perror(filename);
            free(filename);
            pgp_teardown_file_read(parse, fd_in);
            return false;
        }
    }

    /* \todo check for suffix matching armour param */

    /* setup for writing decrypted contents to given output file */

    /* setup keyring and passphrase callback */
    parse->cbinfo.cryptinfo.secring = secring;
    parse->cbinfo.passfp = passfp;
    parse->cbinfo.cryptinfo.getpassphrase = getpassfunc;
    parse->cbinfo.cryptinfo.pubring = pubring;
    parse->cbinfo.sshseckey = (sshkeys) ? &secring->keys[0].key.seckey : NULL;
    parse->cbinfo.numtries = numtries;

    /* Set up armour/passphrase options */
    if (use_armour) {
        pgp_reader_push_dearmour(parse);
    }

    /* Do it */
    ret = pgp_parse(parse, printerrors);

    /* Unsetup */
    if (use_armour) {
        pgp_reader_pop_dearmour(parse);
    }

    /* if we didn't get the passphrase, unlink output file */
    if (!parse->cbinfo.gotpass) {
        (void) unlink((filename) ? filename : outfile);
    }

    if (filename) {
        pgp_teardown_file_write(parse->cbinfo.output, fd_out);
        free(filename);
    }

    /* \todo cleardown crypt */
    ret = (ret && parse->cbinfo.gotpass);

    pgp_teardown_file_read(parse, fd_in);
    return ret;
}

/* decrypt an area of memory */
pgp_memory_t *
pgp_decrypt_buf(pgp_io_t *       io,
                const void *     input,
                const size_t     insize,
                rnp_key_store_t *secring,
                rnp_key_store_t *pubring,
                const unsigned   use_armour,
                const unsigned   sshkeys,
                void *           passfp,
                int              numtries,
                pgp_cbfunc_t *   getpassfunc)
{
    pgp_stream_t *parse = NULL;
    pgp_memory_t *outmem;
    pgp_memory_t *inmem;
    const int     printerrors = 1;

    if (input == NULL) {
        RNP_LOG_FD(io->errs, "null memory");
        return false;
    }

    inmem = pgp_memory_new();
    if (inmem == NULL) {
        RNP_LOG("can't allocate mem");
        return NULL;
    }

    if (!pgp_memory_add(inmem, input, insize)) {
        return NULL;
    }

    /* set up to read from memory */
    if (!pgp_setup_memory_read(io, &parse, inmem, NULL, write_parsed_cb, 0)) {
        RNP_LOG_FD(io->errs, "can't setup memory read");
        return NULL;
    }

    /* setup for writing decrypted contents to given output file */
    if (!pgp_setup_memory_write(NULL, &parse->cbinfo.output, &outmem, insize)) {
        RNP_LOG_FD(io->errs, "can't setup memory write");
        return NULL;
    }

    /* setup keyring and passphrase callback */
    parse->cbinfo.cryptinfo.secring = secring;
    parse->cbinfo.cryptinfo.pubring = pubring;
    parse->cbinfo.passfp = passfp;
    parse->cbinfo.cryptinfo.getpassphrase = getpassfunc;
    parse->cbinfo.sshseckey = (sshkeys) ? &secring->keys[0].key.seckey : NULL;
    parse->cbinfo.numtries = numtries;

    /* Set up armour/passphrase options */
    if (use_armour) {
        pgp_reader_push_dearmour(parse);
    }

    /* Do it */
    pgp_parse(parse, printerrors);

    /* Unsetup */
    if (use_armour) {
        pgp_reader_pop_dearmour(parse);
    }

    /* tidy up */
    const bool gotpass = parse->cbinfo.gotpass;
    pgp_writer_close(parse->cbinfo.output);
    pgp_output_delete(parse->cbinfo.output);
    pgp_teardown_memory_read(parse, inmem);

    /* if we didn't get the passphrase, return NULL */
    return gotpass ? outmem : NULL;
}

void
pgp_crypto_finish(void)
{
    // currently empty implementation
}
