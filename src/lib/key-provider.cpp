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

#include <assert.h>
#include <string.h>
#include "key-provider.h"
#include "pgp-key.h"
#include "fingerprint.h"
#include "types.h"
#include "utils.h"
#include <rekey/rnp_key_store.h>

namespace rnp {
pgp_key_t *
KeyProvider::request_key(const pgp_key_request_ctx_t &ctx) const
{
    pgp_key_t *key = nullptr;
    if (!callback) {
        return key;
    }
    if (!(key = callback(&ctx, userdata))) {
        return nullptr;
    }
    // confirm that the key actually matches the search criteria
    if (!key->matches(ctx.search) || (key->is_secret() != ctx.secret)) {
        return nullptr;
    }
    return key;
}
} // namespace rnp

pgp_key_t *
rnp_key_provider_key_ptr_list(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    std::vector<pgp_key_t *> *key_list = (std::vector<pgp_key_t *> *) userdata;
    for (auto key : *key_list) {
        if (key->matches(ctx->search) && (key->is_secret() == ctx->secret)) {
            return key;
        }
    }
    return NULL;
}

pgp_key_t *
rnp_key_provider_chained(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    for (rnp::KeyProvider **pprovider = (rnp::KeyProvider **) userdata;
         pprovider && *pprovider;
         pprovider++) {
        auto       provider = *pprovider;
        pgp_key_t *key = nullptr;
        if ((key = provider->callback(ctx, provider->userdata))) {
            return key;
        }
    }
    return NULL;
}

pgp_key_t *
rnp_key_provider_store(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    auto ks = (rnp::KeyStore *) userdata;

    for (pgp_key_t *key = ks->search(ctx->search); key; key = ks->search(ctx->search, key)) {
        if (key->is_secret() == ctx->secret) {
            return key;
        }
    }
    return NULL;
}
