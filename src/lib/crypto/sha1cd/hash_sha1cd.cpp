/*
 * Copyright (c) 2021 Ribose Inc.
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "hash_sha1cd.h"
#include "sha1.h"
#include "logging.h"

void *
hash_sha1cd_create()
{
    SHA1_CTX *res = (SHA1_CTX *) calloc(1, sizeof(SHA1_CTX));
    if (res) {
        SHA1DCInit(res);
    }
    return res;
}

/* This produces runtime error: load of misaligned address 0x60d0000030a9 for type 'const
 * uint32_t' (aka 'const unsigned int'), which requires 4 byte alignment */
#if defined(__clang__)
__attribute__((no_sanitize("undefined")))
#endif
void
hash_sha1cd_add(void *ctx, const void *buf, size_t len)
{
    SHA1DCUpdate((SHA1_CTX *) ctx, (const char *) buf, len);
}

void *
hash_sha1cd_clone(void *ctx)
{
    SHA1_CTX *res = (SHA1_CTX *) calloc(1, sizeof(SHA1_CTX));
    if (res) {
        *res = *((SHA1_CTX *) ctx);
    }
    return res;
}

#if defined(__clang__)
__attribute__((no_sanitize("undefined")))
#endif
int
hash_sha1cd_finish(void *ctx, uint8_t *digest)
{
    unsigned char fixed_digest[20];
    int           res = 0;
    if ((res = SHA1DCFinal(fixed_digest, (SHA1_CTX *) ctx)) && digest) {
        /* Show warning only if digest is non-null */
        RNP_LOG("Warning! SHA1 collision detected and mitigated.");
    }
    if (digest) {
        memcpy(digest, fixed_digest, 20);
    }
    free(ctx);
    return res;
}
