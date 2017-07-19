/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
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

#ifndef  __RNP_TYPES__
#define  __RNP_TYPES__

#include <stdint.h>
#include "packet.h"

/* rnp_result is the type used for return codes from the APIs.*/
typedef uint32_t rnp_result;

enum key_store_format_t { GPG_KEY_STORE, SSH_KEY_STORE, KBX_KEY_STORE };

/* structure used to keep application-wide rnp configuration: keyrings, password io, whatever
 * else */
typedef struct rnp_t {
    void *    pubring;       /* public key ring */
    void *    secring;       /* s3kr1t key ring */
    pgp_io_t *io;            /* the io struct for results/errs */
    void *    user_input_fp; /* file pointer for password input */
    char *    pubpath;       /* path to the public keyring */
    char *    secpath;       /* path to the secret keyring */
    char *    defkey;        /* default key id */
    int       pswdtries;     /* number of password tries, -1 for unlimited */

    enum key_store_format_t key_store_format; /* keyring format */
    union {
        rnp_keygen_desc_t generate_key_ctx;
    } action;
} rnp_t;

/* rnp initialization parameters : keyring pathes, flags, whatever else */
typedef struct rnp_params_t {
    unsigned enable_coredumps; /* enable coredumps: if it is allowed then they are disabled by
                                  default to not leak confidential information */

    int         passfd; /* password file descriptor */
    const char *outs;   /* output stream : may be <stderr> , most likel these are subject for
                           refactoring  */
    const char *errs;   /* error stream : may be <stdout> */
    const char *ress;   /* results stream : maye be <stdout>, <stderr> or file name/path */

    enum key_store_format_t ks_format; /* format of the key store */
    char *                  pubpath;   /* public keystore path */
    char *                  secpath;   /* secret keystore path */
    char *                  defkey;    /* default/preferred key id */
} rnp_params_t;

/* rnp operation context : contains additional data about the currently ongoing operation */
typedef struct rnp_ctx_t {
    rnp_t *        rnp;       /* rnp structure */
    char *         filename;  /* name of the input file to store in literal data packet */
    int64_t        filemtime; /* file modification time to store in literal data packet */
    int64_t        sigcreate; /* signature creation time */
    uint64_t       sigexpire; /* signature expiration time */
    pgp_hash_alg_t halg;      /* hash algorithm */
    pgp_symm_alg_t ealg;      /* encryption algorithm */
    int            zalg;      /* compression algorithm used */
    int            zlevel;    /* compression level */
    int            overwrite; /* allow to overwrite output file if exists */
    int            armour;    /* use ASCII armour on output */
} rnp_ctx_t;


#endif // __RNP_TYPES__