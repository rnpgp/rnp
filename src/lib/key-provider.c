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

#include "key-provider.h"
#include "pgp-key.h"
#include <rekey/rnp_key_store.h>

bool
pgp_request_key(const pgp_key_provider_t *   provider,
                const pgp_key_request_ctx_t *ctx,
                pgp_key_t **                 key)
{
    if (!provider || !provider->callback || !ctx || !key) {
        return false;
    }
    return provider->callback(ctx, key, provider->userdata);
}

bool
rnp_key_provider_keyring(const pgp_key_request_ctx_t *ctx, pgp_key_t **key, void *userdata)
{
    rnp_t *    rnp = (rnp_t *) userdata;
    pgp_key_t *ks_key;
    unsigned   from = 0;

    *key = NULL;
    if (ctx->stype == PGP_KEY_SEARCH_KEYID) {
        if (ctx->secret) {
            ks_key =
              rnp_key_store_get_key_by_id(rnp->io, rnp->secring, ctx->search.id, &from, NULL);
            if (ks_key && pgp_key_unlock(ks_key, ctx->pass_provider)) {
                *key = ks_key;
            }
        } else {
            ks_key =
              rnp_key_store_get_key_by_id(rnp->io, rnp->pubring, ctx->search.id, &from, NULL);
            if (ks_key) {
                *key = ks_key;
            } else {
                /* searching for public key in secret keyring as well */
                from = 0;
                ks_key = rnp_key_store_get_key_by_id(
                  rnp->io, rnp->pubring, ctx->search.id, &from, NULL);
                if (ks_key) {
                    *key = ks_key;
                }
            }
        }
    }

    return (*key != NULL);
}
