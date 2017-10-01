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

typedef struct pgp_key_request_ctx_t {
    pgp_passphrase_provider_t *pass_provider;
    uint8_t op;
    bool    secret;
    unsigned has_keyid : 1;
    unsigned has_keygrip : 1;
    unsigned has_userid : 1;
    uint8_t keyid[PGP_KEY_ID_SIZE];
    uint8_t keygrip[PGP_FINGERPRINT_SIZE];
    char *  userid;
} pgp_key_request_ctx_t;

typedef bool pgp_key_callback_t(const pgp_key_request_ctx_t *ctx, pgp_key_t **key, void *userdata);

typedef struct pgp_key_provider_t {
    pgp_key_callback_t *callback;
    void *              userdata;
} pgp_key_provider_t;

bool pgp_key_needed(const pgp_key_provider_t *provider, const pgp_key_request_ctx_t *ctx, pgp_key_t **key);

bool rnp_key_provider_keyring(const pgp_key_request_ctx_t *ctx, pgp_key_t **key, void *userdata);

#endif
