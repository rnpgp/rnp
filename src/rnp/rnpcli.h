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
#ifndef RNP_H_
#define RNP_H_

#include <stddef.h>
#include <stdbool.h>
#include "rnp.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct rnp_ctx_t       rnp_ctx_t;
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

/* initialize rnp using the init structure  */
rnp_result_t rnp_init(rnp_t *, const rnp_params_t *);
/* finish work with rnp and cleanup the memory */
void rnp_end(rnp_t *);
/* load keys */
bool rnp_load_keyrings(rnp_t *rnp, bool loadsecret);

/* rnp initialization parameters : init and free */
void rnp_params_init(rnp_params_t *);
void rnp_params_free(rnp_params_t *);

/* set key store format information */
int rnp_set_key_store_format(rnp_t *, const char *);

/* key management */
void       rnp_print_key_info(FILE *, rnp_key_store_t *, const pgp_key_t *, bool);
bool       rnp_find_key(rnp_t *, const char *);
char *     rnp_export_key(rnp_t *, const char *, bool);
bool       rnp_add_key(rnp_t *rnp, const char *path, bool print);
bool       rnp_import_key(rnp_t *, const char *);
pgp_key_t *resolve_userid(rnp_t *rnp, const rnp_key_store_t *keyring, const char *userid);

/**
 * @brief Generate key, based on information passed in rnp->action.generate_key_ctx
 *
 * @param rnp initialized and filled rnp_t structure.
 * @return generated secret key or NULL in case of generation error.
 */
pgp_key_t *rnp_generate_key(rnp_t *rnp);
size_t     rnp_secret_count(rnp_t *);
size_t     rnp_public_count(rnp_t *);

/* file management */
rnp_result_t rnp_process_file(rnp_t *, rnp_ctx_t *, const char *, const char *);
rnp_result_t rnp_protect_file(rnp_t *, rnp_ctx_t *, const char *, const char *);
rnp_result_t rnp_dump_file(rnp_ctx_t *, const char *, const char *);

/* memory signing and encryption */
rnp_result_t rnp_process_mem(
  rnp_t *, rnp_ctx_t *, const void *, size_t, void *, size_t, size_t *);
rnp_result_t rnp_protect_mem(
  rnp_t *, rnp_ctx_t *, const void *, size_t, void *, size_t, size_t *);

/**
 * @brief   Armor (convert to ASCII) or dearmor (convert back to binary) PGP data
 *
 * @param   ctx  Initialized rnp context. Field armortype may specify the type of armor
 *               header used, otherwise it will be detected automatically from the source.
 * @param   in   Input file path
 * @param   out  Output file path
 *
 * @return  RNP_SUCCESS on success, error code on failure
 */
rnp_result_t rnp_armor_stream(rnp_ctx_t *ctx, bool armor, const char *in, const char *out);

rnp_result_t rnp_validate_keys_signatures(rnp_t *rnp);

rnp_result_t rnp_encrypt_add_password(rnp_t *rnp, rnp_ctx_t *ctx);

#if defined(__cplusplus)
}
#endif

#endif /* !RNP_H_ */
