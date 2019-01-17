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

#ifndef __RNP_TYPES__
#define __RNP_TYPES__

#include <stdint.h>

#include "types.h"
#include "pass-provider.h"
#include "key-provider.h"
#include "list.h"
#include "crypto/rng.h"

typedef struct rnp_action_keygen_t {
    struct {
        rnp_keygen_primary_desc_t   keygen;
        rnp_key_protection_params_t protection;
    } primary;
    struct {
        rnp_keygen_subkey_desc_t    keygen;
        rnp_key_protection_params_t protection;
    } subkey;
} rnp_action_keygen_t;

typedef struct rnp_key_store_t rnp_key_store_t;

/* structure used to keep application-wide rnp configuration: keyrings, password io, whatever
 * else */
typedef struct rnp_t {
    rnp_key_store_t *pubring;       /* public key ring */
    rnp_key_store_t *secring;       /* s3kr1t key ring */
    FILE *           resfp;         /* where to put result messages, defaults to stdout */
    FILE *           user_input_fp; /* file pointer for user input */
    FILE *           passfp;        /* file pointer for password input */
    char *           defkey;        /* default key id */
    int              pswdtries;     /* number of password tries, -1 for unlimited */

    union {
        rnp_action_keygen_t generate_key_ctx;
    } action;

    pgp_password_provider_t password_provider;
    pgp_key_provider_t      key_provider;
    rng_t                   rng; /* handle to rng_t */
} rnp_t;

/* rnp initialization parameters : keyring pathes, flags, whatever else */
typedef struct rnp_params_t {
    unsigned enable_coredumps; /* enable coredumps: if it is allowed then they are disabled by
                                  default to not leak confidential information */

    int         passfd; /* password file descriptor */
    int         userinputfd;
    const char *ress; /* results stream : maye be <stdout>, <stderr> or file name/path */

    const char *ks_pub_format;     /* format of the public key store */
    const char *ks_sec_format;     /* format of the secret key store */
    char *      pubpath;           /* public keystore path */
    char *      secpath;           /* secret keystore path */
    char *      defkey;            /* default/preferred key id */
    bool        keystore_disabled; /* indicates wether keystore must be initialized */
    pgp_password_provider_t password_provider;
} rnp_params_t;

#endif // __RNP_TYPES__
