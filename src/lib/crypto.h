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
#include "hash.h"
#include "key_store_pgp.h"
#include "packet.h"
#include "memory.h"
#include "packet-parse.h"
#include "symmetric.h"
#include "bn.h"

#define PGP_MIN_HASH_SIZE 16
#define MAX_CURVE_BYTELEN BITS_TO_BYTES(521) /* Length of NIST P-521 */

#define NTAGS 0x100 /* == 256 */

void pgp_crypto_finish(void);

/* Key generation */

pgp_key_t *pgp_generate_keypair(const rnp_keygen_desc_t *key_desc, const uint8_t *userid);

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

bool pgp_encrypt_file(rnp_ctx_t *, pgp_io_t *, const char *, const char *, const pgp_key_t *);
bool pgp_decrypt_file(pgp_io_t *,
                      const char *,
                      const char *,
                      rnp_key_store_t *,
                      rnp_key_store_t *,
                      const unsigned,
                      const unsigned,
                      const unsigned,
                      void *,
                      int,
                      pgp_cbfunc_t *);

pgp_memory_t *pgp_encrypt_buf(
  rnp_ctx_t *, pgp_io_t *, const void *, const size_t, const pgp_key_t *);
pgp_memory_t *pgp_decrypt_buf(pgp_io_t *,
                              const void *,
                              const size_t,
                              rnp_key_store_t *,
                              rnp_key_store_t *,
                              const unsigned,
                              const unsigned,
                              void *,
                              int,
                              pgp_cbfunc_t *);

bool read_pem_seckey(const char *, pgp_key_t *, const char *, int);

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
struct pgp_cryptinfo_t {
    char *           passphrase;
    rnp_key_store_t *secring;
    const pgp_key_t *keydata;
    pgp_cbfunc_t *   getpassphrase;
    rnp_key_store_t *pubring;
};

/** pgp_cbdata_t */
struct pgp_cbdata_t {
    pgp_cbfunc_t *   cbfunc; /* callback function */
    void *           arg;    /* args to pass to callback func */
    pgp_error_t **   errors; /* address of error stack */
    pgp_cbdata_t *   next;
    pgp_output_t *   output;     /* when writing out parsed info */
    pgp_io_t *       io;         /* error/output messages */
    void *           passfp;     /* fp for passphrase input */
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

/**
 * Structure holds description of elliptic curve
 */
typedef struct ec_curve_desc_t {
    const pgp_curve_t rnp_curve_id;
    const size_t      bitlen;
    const uint8_t     OIDhex[MAX_CURVE_OID_HEX_LEN];
    const size_t      OIDhex_len;
    const char *      botan_name;
    const char *      pgp_name;
} ec_curve_desc_t;

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
 */
// TODO: Shouldn't this be in some other place than crypto.h?
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
 * @brief   Serialize EC public to octet string
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

#endif /* CRYPTO_H_ */
