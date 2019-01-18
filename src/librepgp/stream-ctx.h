/*
 * Copyright (c) 2019, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef STREAM_CTX_H_
#define STREAM_CTX_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "types.h"

typedef enum rnp_operation_t {
    RNP_OP_UNKNOWN = 0,
    RNP_OP_DECRYPT_VERIFY = 1,
    RNP_OP_ENCRYPT_SIGN = 2,
    RNP_OP_ARMOR = 3
} rnp_operation_t;

/* signature info structure */
typedef struct rnp_signer_info_t {
    pgp_key_t *    key;
    pgp_hash_alg_t halg;
    int64_t        sigcreate;
    uint64_t       sigexpire;
} rnp_signer_info_t;

/** rnp operation context : contains configuration data about the currently ongoing operation.
 *
 *  Common fields which make sense for every operation:
 *  - overwrite : silently overwrite output file if exists
 *  - armor : except cleartext signing, which outputs text in clear and always armor signature,
 *    this controls whether output is armored (base64-encoded). For armor/dearmor operation it
 *    controls the direction of the conversion (true means enarmor, false - dearmor),
 *  - rng : random number generator
 *  - operation : current operation type
 *
 *  For operations with OpenPGP embedded data (i.e. encrypted data and attached signatures):
 *  - filename, filemtime : to specify information about the contents of literal data packet
 *  - zalg, zlevel : compression algorithm and level, zlevel = 0 to disable compression
 *
 *  For encryption operation (including encrypt-and-sign):
 *  - halg : hash algorithm used during key derivation for password-based encryption
 *  - ealg, aalg, abits : symmetric encryption algorithm and AEAD parameters if used
 *  - recipients : list of key ids used to encrypt data to
 *  - passwords : list of passwords used for password-based encryption
 *  - filename, filemtime, zalg, zlevel : see previous
 *
 *  For signing of any kind (attached, detached, cleartext):
 *  - clearsign, detached : controls kind of the signed data. Both are mutually-exclusive.
 *    If both are false then attached signing is used.
 *  - halg : hash algorithm used to calculate signature(s)
 *  - signers : list of rnp_signer_info_t structures describing signing key and parameters
 *  - sigcreate, sigexpire : default signature(s) creation and expiration times
 *  - filename, filemtime, zalg, zlevel : only for attached signatures, see previous
 *
 *  For data decryption and/or verification there is not much of fields:
 *  - on_signatures: callback, called when signature verification information is available.
 *    If we have just encrypted data then it will not be called.
 *  - sig_cb_param: parameter to be passed to on_signatures callback.
 *  - discard: dicard the output data (i.e. just decrypt and/or verify signatures)
 *
 *  For enarmor/dearmor:
 *  - armortype: type of the armor headers (message, key, whatever else)
 */

typedef struct rnp_ctx_t {
    char *          filename;      /* name of the input file to store in literal data packet */
    int64_t         filemtime;     /* file modification time to store in literal data packet */
    int64_t         sigcreate;     /* signature creation time */
    uint64_t        sigexpire;     /* signature expiration time */
    bool            clearsign;     /* cleartext signature */
    bool            detached;      /* detached signature */
    pgp_hash_alg_t  halg;          /* hash algorithm */
    pgp_symm_alg_t  ealg;          /* encryption algorithm */
    int             zalg;          /* compression algorithm used */
    int             zlevel;        /* compression level */
    pgp_aead_alg_t  aalg;          /* non-zero to use AEAD */
    int             abits;         /* AEAD chunk bits */
    bool            overwrite;     /* allow to overwrite output file if exists */
    bool            armor;         /* whether to use ASCII armor on output */
    list            recipients;    /* recipients of the encrypted message */
    list            passwords;     /* list of rnp_symmetric_pass_info_t */
    list            signers;       /* list of rnp_signer_info_t structures */
    unsigned        armortype;     /* type of the armored message, used in enarmor command */
    bool            discard;       /* discard the output */
    void *          on_signatures; /* handler for signed messages */
    void *          sig_cb_param;  /* callback data passed to on_signatures */
    rng_t *         rng;           /* pointer to rng_t */
    rnp_operation_t operation;     /* current operation type */
} rnp_ctx_t;

typedef struct rnp_symmetric_pass_info_t {
    pgp_s2k_t      s2k;
    pgp_symm_alg_t s2k_cipher;
    uint8_t        key[PGP_MAX_KEY_SIZE];
} rnp_symmetric_pass_info_t;

/* init, reset and free rnp operation context */
rnp_result_t     rnp_ctx_init(rnp_ctx_t *, rng_t *);
void             rnp_ctx_reset(rnp_ctx_t *);
void             rnp_ctx_free(rnp_ctx_t *);
struct rng_st_t *rnp_ctx_rng_handle(const rnp_ctx_t *ctx);

rnp_result_t rnp_ctx_add_encryption_password(rnp_ctx_t *    ctx,
                                             const char *   password,
                                             pgp_hash_alg_t halg,
                                             pgp_symm_alg_t ealg,
                                             int            iterations);

#endif