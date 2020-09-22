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
 * THIS SOFTWARE IS PROVIDED BY THE RIBOSE, INC. AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RNP_KEY_STORE_G10_H
#define RNP_KEY_STORE_G10_H

#include <rekey/rnp_key_store.h>
#include <librepgp/stream-common.h>

#define SXP_MAX_DEPTH 30

typedef struct {
    size_t   len;
    uint8_t *bytes;
} s_exp_block_t;

typedef struct sub_element_t sub_element_t;

typedef struct {
    list sub_elements; // list of sub_element_t
} s_exp_t;

struct sub_element_t {
    bool is_block;
    union {
        s_exp_t       s_exp;
        s_exp_block_t block;
    };
};

bool rnp_key_store_g10_from_src(rnp_key_store_t *, pgp_source_t *, const pgp_key_provider_t *);
bool rnp_key_store_g10_key_to_dst(pgp_key_t *, pgp_dest_t *);
bool g10_write_seckey(pgp_dest_t *dst, pgp_key_pkt_t *seckey, const char *password);
pgp_key_pkt_t *g10_decrypt_seckey(const uint8_t *      data,
                                  size_t               data_len,
                                  const pgp_key_pkt_t *pubkey,
                                  const char *         password);
bool parse_sexp(s_exp_t *s_exp, const char **r_bytes, size_t *r_length, size_t depth = 1);
void destroy_s_exp(s_exp_t *s_exp);

#endif // RNP_KEY_STORE_G10_H
