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
#ifndef RNP_KEY_PROVIDER_H
#define RNP_KEY_PROVIDER_H

#include <rnp/rnp_types.h>
#include <rnp/rnp_sdk.h>
#include "pass-provider.h"

typedef struct pgp_key_t pgp_key_t;

typedef enum {
    PGP_KEY_SEARCH_KEYID,
    PGP_KEY_SEARCH_GRIP,
    PGP_KEY_SEARCH_USERID
} pgp_key_search_t;

typedef struct pgp_key_request_ctx_t {
    uint8_t          op;
    bool             secret;
    pgp_key_search_t stype;
    union {
        uint8_t id[PGP_KEY_ID_SIZE];
        uint8_t grip[PGP_FINGERPRINT_SIZE];
        char *  userid;
    } search;
} pgp_key_request_ctx_t;

typedef bool pgp_key_callback_t(const pgp_key_request_ctx_t *ctx,
                                pgp_key_t **                 key,
                                void *                       userdata);

typedef struct pgp_key_provider_t {
    pgp_key_callback_t *callback;
    void *              userdata;
} pgp_key_provider_t;

/** @brief request public or secret pgp key, according to information stored in ctx
 *  @param provider key provider structure
 *  @param ctx information about the request - which operation requested the key, which search
 *  criteria should be used and whether secret or public key is needed
 *  @param key pointer to the key structure will be stored here on success
 *  @return true on success, or false if key was not found otherwise
 **/
bool pgp_request_key(const pgp_key_provider_t *   provider,
                     const pgp_key_request_ctx_t *ctx,
                     pgp_key_t **                 key);

/** @brief key provider callback which searches for key in rnp_key_store_t. userdata must be
  *pointer to the rnp_t structure
 **/
bool rnp_key_provider_keyring(const pgp_key_request_ctx_t *ctx,
                              pgp_key_t **                 key,
                              void *                       userdata);

#endif
