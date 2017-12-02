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
#include "crypto/sm2.h"
#include "crypto.h"
#include "fingerprint.h"
#include "readerwriter.h"
#include "memory.h"
#include "utils.h"
#include "signature.h"
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
pgp_decrypt_decode_mpi(uint8_t *           buf,
                       unsigned            buflen,
                       const BIGNUM *      g_to_k,
                       const BIGNUM *      encmpi,
                       const pgp_seckey_t *seckey)
{
    uint8_t encmpibuf[RNP_BUFSIZ] = {0};
    uint8_t gkbuf[RNP_BUFSIZ] = {0};
    int     n;
    size_t  encmpi_byte_len;

    if (!BN_num_bytes(encmpi, &encmpi_byte_len)) {
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
        BN_bn2bin(encmpi, encmpibuf);
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "encrypted", encmpibuf, 16);
        }

        n = pgp_rsa_decrypt_pkcs1(
          buf, buflen, encmpibuf, encmpi_byte_len, &seckey->key.rsa, &seckey->pubkey.key.rsa);
        if (n <= 0) {
            (void) fprintf(stderr, "ops_rsa_private_decrypt failure\n");
            return -1;
        }
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "decoded m", buf, n);
        }
        return n;
    case PGP_PKA_SM2:
        BN_bn2bin(encmpi, encmpibuf);

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
    case PGP_PKA_ELGAMAL:
        (void) BN_bn2bin(g_to_k, gkbuf);
        (void) BN_bn2bin(encmpi, encmpibuf);
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "encrypted", encmpibuf, 16);
        }
        n = pgp_elgamal_private_decrypt_pkcs1(buf,
                                              gkbuf,
                                              encmpibuf,
                                              encmpi_byte_len,
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
        if (BN_bn2bin(encmpi, encmpibuf)) {
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
    seckey->pubkey.birthtime = time(NULL);
    seckey->pubkey.alg = crypto->key_alg;

    switch (seckey->pubkey.alg) {
    case PGP_PKA_RSA:
        if (pgp_genkey_rsa(seckey, crypto->rsa.modulus_bit_len) != 1) {
            RNP_LOG("failed to generate RSA key");
            goto end;
        }
        break;

    case PGP_PKA_EDDSA:
        if (!pgp_genkey_eddsa(seckey, get_curve_desc(PGP_CURVE_ED25519)->bitlen)) {
            RNP_LOG("failed to generate EDDSA key");
            goto end;
        }
        break;
    case PGP_PKA_ECDH:
        if (!set_ecdh_params(seckey, crypto->ecc.curve)) {
            RNP_LOG("Unsupoorted curve [ID=%d]", crypto->ecc.curve);
            goto end;
        }
    /* FALLTHROUGH */
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
        if (pgp_genkey_ec_uncompressed(seckey, seckey->pubkey.alg, crypto->ecc.curve) !=
            RNP_SUCCESS) {
            RNP_LOG("failed to generate EC key");
            goto end;
        }
        seckey->pubkey.key.ecc.curve = crypto->ecc.curve;
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

static pgp_cb_ret_t
write_parsed_cb(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;

    if (rnp_get_debug(__FILE__)) {
        printf("write_parsed_cb: ");
        pgp_print_packet(cbinfo, pkt);
    }
    if (pkt->tag != PGP_PTAG_CT_UNARMORED_TEXT && cbinfo->printstate.skipping) {
        puts("...end of skip");
        cbinfo->printstate.skipping = 0;
    }
    switch (pkt->tag) {
    case PGP_PTAG_CT_UNARMORED_TEXT:
        printf("PGP_PTAG_CT_UNARMORED_TEXT\n");
        if (!cbinfo->printstate.skipping) {
            puts("Skipping...");
            cbinfo->printstate.skipping = 1;
        }
        if (fwrite(content->unarmored_text.data, 1, content->unarmored_text.length, stdout) !=
            content->unarmored_text.length) {
            fprintf(stderr, "unable to write unarmored text data\n");
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

    case PGP_PTAG_CT_LITDATA_BODY:
        return pgp_litdata_cb(pkt, cbinfo);

    case PGP_PTAG_CT_ARMOR_HEADER:
    case PGP_PTAG_CT_ARMOR_TRAILER:
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

    RNP_USED(io);
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

    /* set armored/not armored here */
    if (ctx->armor) {
        pgp_writer_push_armored(output, PGP_PGP_MESSAGE);
    }

    /* Push the encrypted writer */
    if (!pgp_push_enc_se_ip(output, pubkey, ctx->ealg, pgp_mem_len(inmem))) {
        pgp_memory_free(inmem);
        return false;
    }

    /* This does the writing */
    if (!pgp_write(output, pgp_mem_data(inmem), pgp_mem_len(inmem))) {
        pgp_memory_free(inmem);
        return false;
    }

    /* tidy up */
    pgp_teardown_file_write(output, fd_out);
    pgp_memory_free(inmem);

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

    RNP_USED(io);
    if (input == NULL) {
        (void) fprintf(io->errs, "pgp_encrypt_buf: null memory\n");
        return false;
    }

    if (!pgp_setup_memory_write(ctx, &output, &outmem, insize)) {
        (void) fprintf(io->errs, "can't setup memory write\n");
        return false;
    }

    /* set armored/not armored here */
    if (ctx->armor) {
        pgp_writer_push_armored(output, PGP_PGP_MESSAGE);
    }

    /* Push the encrypted writer */
    if (!pgp_push_enc_se_ip(output, pubkey, ctx->ealg, insize)) {
        pgp_writer_close(output);
        pgp_output_delete(output);
        return false;
    }

    /* This does the writing */
    if (!pgp_write(output, input, insize)) {
        pgp_writer_close(output);
        pgp_output_delete(output);
        return false;
    }

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
   \param use_armor Expect armored text, if set
   \param allow_overwrite Allow output file to overwritten, if set.
   \param getpassfunc Callback to use to get password
*/

bool
pgp_decrypt_file(pgp_io_t *                     io,
                 const char *                   infile,
                 const char *                   outfile,
                 rnp_key_store_t *              secring,
                 rnp_key_store_t *              pubring,
                 const unsigned                 use_armor,
                 const unsigned                 allow_overwrite,
                 const unsigned                 sshkeys,
                 int                            numtries,
                 const pgp_password_provider_t *password_provider)
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

    /* \todo check for suffix matching armor param */

    /* setup for writing decrypted contents to given output file */

    /* setup keyring and password callback */
    parse->cbinfo.cryptinfo.secring = secring;
    parse->cbinfo.cryptinfo.password_provider = *password_provider;
    parse->cbinfo.cryptinfo.pubring = pubring;
    parse->cbinfo.sshseckey = (sshkeys) ? &secring->keys[0].key.seckey : NULL;
    parse->cbinfo.numtries = numtries;

    /* Set up armor/password options */
    if (use_armor) {
        pgp_reader_push_dearmor(parse);
    }

    /* Do it */
    ret = repgp_parse(parse, printerrors);

    /* Unsetup */
    if (use_armor) {
        pgp_reader_pop_dearmor(parse);
    }

    /* if we didn't get the password, unlink output file */
    const bool gotpass = parse->cbinfo.gotpass;
    if (!gotpass) {
        (void) unlink((filename) ? filename : outfile);
    }

    if (filename) {
        pgp_teardown_file_write(parse->cbinfo.output, fd_out);
        free(filename);
    }

    /* \todo cleardown crypt */
    ret = (ret && gotpass);

    pgp_teardown_file_read(parse, fd_in);
    return ret;
}

/* decrypt an area of memory */
pgp_memory_t *
pgp_decrypt_buf(pgp_io_t *                     io,
                const void *                   input,
                const size_t                   insize,
                rnp_key_store_t *              secring,
                rnp_key_store_t *              pubring,
                const unsigned                 use_armor,
                const unsigned                 sshkeys,
                int                            numtries,
                const pgp_password_provider_t *password_provider)
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

    /* setup keyring and password callback */
    parse->cbinfo.cryptinfo.secring = secring;
    parse->cbinfo.cryptinfo.pubring = pubring;
    parse->cbinfo.cryptinfo.password_provider = *password_provider;
    parse->cbinfo.sshseckey = (sshkeys) ? &secring->keys[0].key.seckey : NULL;
    parse->cbinfo.numtries = numtries;

    /* Set up armor/password options */
    if (use_armor) {
        pgp_reader_push_dearmor(parse);
    }

    /* Do it */
    repgp_parse(parse, printerrors);

    /* Unsetup */
    if (use_armor) {
        pgp_reader_pop_dearmor(parse);
    }

    /* tidy up */
    const bool gotpass = parse->cbinfo.gotpass;
    pgp_writer_close(parse->cbinfo.output);
    pgp_output_delete(parse->cbinfo.output);
    pgp_teardown_memory_read(parse, inmem);

    /* if we didn't get the password, return NULL */
    return gotpass ? outmem : NULL;
}
