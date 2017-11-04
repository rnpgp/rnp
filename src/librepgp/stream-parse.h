/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#ifndef STREAM_PARSE_H_
#define STREAM_PARSE_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "errors.h"
#include <repgp/repgp.h>
#include <rnp/rnp.h>
#include "stream-common.h"

typedef struct pgp_parse_handler_t  pgp_parse_handler_t;
typedef struct pgp_signature_info_t pgp_signature_info_t;
typedef bool pgp_destination_func_t(pgp_parse_handler_t *handler,
                                    pgp_dest_t *         dst,
                                    const char *         filename);
typedef bool pgp_source_func_t(pgp_parse_handler_t *handler, pgp_source_t *src);
typedef void pgp_signatures_func_t(pgp_parse_handler_t * handler,
                                   pgp_signature_info_t *sigs,
                                   int                   count);

/* handler used to return needed information during pgp source processing */
typedef struct pgp_parse_handler_t {
    pgp_password_provider_t *password_provider;
    pgp_key_provider_t *     key_provider;
    pgp_destination_func_t * dest_provider;
    pgp_source_func_t *      src_provider;
    pgp_signatures_func_t *  on_signatures;

    void *param;
} pgp_parse_handler_t;

/* information about the signature */
typedef struct pgp_signature_info_t {
    pgp_signature_t *sig;       /* signature, or NULL if there were parsing error */
    pgp_pubkey_t *   signer;    /* signer's public key if found */
    bool             valid;     /* signature is cryptographically valid (but may be expired) */
    bool             unknown;   /* signature is unknown - parsing error, wrong version, etc */
    bool             no_signer; /* no signer's public key available */
    bool             expired;   /* signature is expired */
} pgp_signature_info_t;

/* @brief Process the OpenPGP source: file, memory, stdin
 * Function will parse input data, provided by any source conforming to pgp_source_t,
 * autodetecting whether it is armored, cleartext or binary.
 * @param handler handler to respond on stream reader callbacks
 * @param src initialized source with cache
 * @return RNP_SUCCESS on success or error code otherwise
 **/
rnp_result_t process_pgp_source(pgp_parse_handler_t *handler, pgp_source_t *src);

#endif
