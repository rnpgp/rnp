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

#include <string.h>
#include <assert.h>
#include "stream-ctx.h"

/* rnp_ctx_t : init, reset, free internal pointers */
rnp_result_t
rnp_ctx_init(rnp_ctx_t *ctx, rng_t *rng)
{
    memset(ctx, '\0', sizeof(*ctx));
    ctx->rng = rng;
    return RNP_SUCCESS;
}

rng_t *
rnp_ctx_rng_handle(const rnp_ctx_t *ctx)
{
    assert(ctx->rng);
    return ctx->rng;
}

void
rnp_ctx_reset(rnp_ctx_t *ctx)
{
    rnp_ctx_free(ctx);
    memset(ctx, '\0', sizeof(*ctx));
}

/* free operation context */
void
rnp_ctx_free(rnp_ctx_t *ctx)
{
    free(ctx->filename);
    list_destroy(&ctx->recipients);
    list_destroy(&ctx->signers);
    list_destroy(&ctx->passwords);
}
