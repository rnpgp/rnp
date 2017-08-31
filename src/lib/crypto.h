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

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <limits.h>
#include <botan/ffi.h>

#include <librepgp/packet-parse.h>
#include <librepgp/packet-print.h>
#include <librepgp/reader.h>

#include "hash.h"
#include "memory.h"
#include "symmetric.h"
#include "crypto/bn.h"
#include <rekey/rnp_key_store.h>

#define PGP_MIN_HASH_SIZE 16
/* Maximal byte size of elliptic curve order (NIST P-521) */
#define MAX_CURVE_BYTELEN BITS_TO_BYTES(521)
/* Maximal size of symmetric key */
#define MAX_SYMM_KEY_SIZE 32
#define NTAGS 0x100 /* == 256 */

/* raw key generation */
bool pgp_generate_seckey(const rnp_keygen_crypto_params_t *params, pgp_seckey_t *seckey);

/** generate a new primary key
 *
 *  @param desc keygen description
 *  @param merge_defaults true if you want defaults to be set for unset
 *         keygen description parameters.
 *  @param primary_sec pointer to store the generated secret key, must not be NULL
 *  @param primary_pub pointer to store the generated public key, must not be NULL
 *  @return true if successful, false otherwise.
 **/
bool pgp_generate_primary_key(rnp_keygen_primary_desc_t *desc,
                              bool                       merge_defaults,
                              pgp_key_t *                primary_sec,
                              pgp_key_t *                primary_pub);

/** generate a new subkey
 *
 *  @param desc keygen description
 *  @param merge_defaults true if you want defaults to be set for unset
 *         keygen description parameters.
 *  @param primary_sec pointer to the primary secret key that will own this
 *         subkey, must not be NULL
 *  @param primary_pub pointer to the primary public key that will own this
 *         subkey, must not be NULL
 *  @param subkey_sec pointer to store the generated secret key, must not be NULL
 *  @param subkey_pub pointer to store the generated public key, must not be NULL
 *  @param passphrase_provider the passphrase provider that will be used to
 *         decrypt the primary key, may be NULL if primary key is unlocked
 *  @return true if successful, false otherwise.
 **/
bool pgp_generate_subkey(rnp_keygen_subkey_desc_t *       desc,
                         bool                             merge_defaults,
                         pgp_key_t *                      primary_sec,
                         pgp_key_t *                      primary_pub,
                         pgp_key_t *                      subkey_sec,
                         pgp_key_t *                      subkey_pub,
                         const pgp_passphrase_provider_t *passphrase_provider);

/** generate a new primary key and subkey
 *
 *  @param desc keygen description
 *  @param merge_defaults true if you want defaults to be set for unset
 *         keygen description parameters.
 *  @param primary_sec pointer to store the generated secret key, must not be NULL
 *  @param primary_pub pointer to store the generated public key, must not be NULL
 *  @param subkey_sec pointer to store the generated secret key, must not be NULL
 *  @param subkey_pub pointer to store the generated public key, must not be NULL
 *  @return true if successful, false otherwise.
 **/
bool pgp_generate_keypair(rnp_keygen_desc_t *desc,
                          bool               merge_defaults,
                          pgp_key_t *        primary_sec,
                          pgp_key_t *        primary_pub,
                          pgp_key_t *        subkey_sec,
                          pgp_key_t *        subkey_pub);

void pgp_reader_push_decrypt(pgp_stream_t *, pgp_crypt_t *, pgp_region_t *);
void pgp_reader_pop_decrypt(pgp_stream_t *);

/* Hash everything that's read */
int  pgp_reader_push_hash(pgp_stream_t *, pgp_hash_t *);
void pgp_reader_pop_hash(pgp_stream_t *);

int pgp_decrypt_decode_mpi(
  uint8_t *, unsigned, const BIGNUM *, const BIGNUM *, const pgp_seckey_t *);

/* Encrypt everything that's written */
struct pgp_key_data;
void pgp_writer_push_encrypt(pgp_output_t *, const struct pgp_key_data *);

bool pgp_encrypt_file(
  rnp_ctx_t *, pgp_io_t *, const char *, const char *, const pgp_pubkey_t *);
bool pgp_decrypt_file(pgp_io_t *,
                      const char *,
                      const char *,
                      rnp_key_store_t *,
                      rnp_key_store_t *,
                      const unsigned,
                      const unsigned,
                      const unsigned,
                      int,
                      const pgp_passphrase_provider_t *);

pgp_memory_t *pgp_encrypt_buf(
  rnp_ctx_t *, pgp_io_t *, const void *, const size_t, const pgp_pubkey_t *);
pgp_memory_t *pgp_decrypt_buf(pgp_io_t *,
                              const void *,
                              const size_t,
                              rnp_key_store_t *,
                              rnp_key_store_t *,
                              const unsigned,
                              const unsigned,
                              int,
                              const pgp_passphrase_provider_t *);

bool read_pem_seckey(const char *, pgp_key_t *, const char *, int);

typedef int pgp_reader_func_t(
  pgp_stream_t *, void *, size_t, pgp_error_t **, pgp_reader_t *, pgp_cbdata_t *);

typedef void pgp_reader_destroyer_t(pgp_reader_t *);

/** pgp_reader_t */
struct pgp_reader_t {
    pgp_reader_func_t *     reader; /* reader func to get parse data */
    pgp_reader_destroyer_t *destroyer;
    void *                  arg;            /* args to pass to reader function */
    unsigned                accumulate : 1; /* set to gather packet data */
    uint8_t *               accumulated;    /* the accumulated data */
    unsigned                asize;          /* size of the buffer */
    unsigned                alength;        /* used buffer */
    unsigned                position;       /* reader-specific offset */
    pgp_reader_t *          next;
    pgp_stream_t *          parent; /* parent parse_info structure */
};

/** pgp_cryptinfo_t
 Encrypt/decrypt settings
*/
typedef struct pgp_cryptinfo_t {
    rnp_key_store_t *         secring;
    const pgp_key_t *         key;
    pgp_passphrase_provider_t passphrase_provider;
    rnp_key_store_t *         pubring;
} pgp_cryptinfo_t;

/** pgp_cbdata_t */
struct pgp_cbdata_t {
    pgp_cbfunc_t *   cbfunc; /* callback function */
    void *           arg;    /* args to pass to callback func */
    pgp_error_t **   errors; /* address of error stack */
    pgp_cbdata_t *   next;
    pgp_output_t *   output;     /* when writing out parsed info */
    pgp_io_t *       io;         /* error/output messages */
    pgp_cryptinfo_t  cryptinfo;  /* used when decrypting */
    pgp_printstate_t printstate; /* used to keep printing state */
    pgp_seckey_t *   sshseckey;  /* secret key for ssh */
    int              numtries;   /* # of passphrase attempts */
    int              gotpass;    /* when passphrase entered */
};

/** pgp_hashtype_t */
typedef struct {
    pgp_hash_t hash; /* hashes we should hash data with */
    uint8_t    keyid[PGP_KEY_ID_SIZE];
} pgp_hashtype_t;

/** \brief Structure to hold information about a packet parse.
 *
 *  This information includes options about the parse:
 *  - whether the packet contents should be accumulated or not
 *  - whether signature subpackets should be parsed or left raw
 *
 *  It contains options specific to the parsing of armoured data:
 *  - whether headers are allowed in armoured data without a gap
 *  - whether a blank line is allowed at the start of the armoured data
 *
 *  It also specifies :
 *  - the callback function to use and its arguments
 *  - the reader function to use and its arguments
 *
 *  It also contains information about the current state of the parse:
 *  - offset from the beginning
 *  - the accumulated data, if any
 *  - the size of the buffer, and how much has been used
 *
 *  It has a linked list of errors.
 * TODO1: Shouldn't this be in some other place than crypto.h?
 * TODO2: This structure contains too many things which are unrelated
 */
struct pgp_stream_t {
    uint8_t ss_raw[NTAGS / 8];
    /* 1 bit / sig-subpkt type; set to get raw data */
    uint8_t ss_parsed[NTAGS / 8];
    /* 1 bit / sig-subpkt type; set to get parsed data */
    pgp_reader_t    readinfo;
    pgp_cbdata_t    cbinfo;
    pgp_error_t *   errors;
    void *          io; /* io streams */
    pgp_crypt_t     decrypt;
    pgp_cryptinfo_t cryptinfo;
    size_t          hashc;
    pgp_hashtype_t *hashes;
    unsigned        reading_v3_secret : 1;
    unsigned        reading_mpi_len : 1;
    unsigned        exact_read : 1;
    unsigned        partial_read : 1;
    unsigned        coalescing : 1;
    /* used for partial length coalescing */
    unsigned virtualc;
    unsigned virtualoff;
    uint8_t *virtualpkt;
};

#endif /* CRYPTO_H_ */
