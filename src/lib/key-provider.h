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

#include "types.h"
#include "fingerprint.h"

typedef struct pgp_key_t pgp_key_t;

typedef enum {
    PGP_KEY_SEARCH_UNKNOWN,
    PGP_KEY_SEARCH_KEYID,
    PGP_KEY_SEARCH_FINGERPRINT,
    PGP_KEY_SEARCH_GRIP,
    PGP_KEY_SEARCH_USERID
} pgp_key_search_type_t;

typedef struct pgp_key_search_t {
    pgp_key_search_type_t type;
    union {
        pgp_key_id_t      keyid;
        pgp_key_grip_t    grip;
        pgp_fingerprint_t fingerprint;
        char              userid[MAX_ID_LENGTH + 1];
    } by;

    pgp_key_search_t(pgp_key_search_type_t atype = PGP_KEY_SEARCH_UNKNOWN) : type(atype){};
} pgp_key_search_t;

typedef struct pgp_key_request_ctx_t {
    pgp_op_t         op;
    bool             secret;
    pgp_key_search_t search;

    pgp_key_request_ctx_t(pgp_op_t              anop = PGP_OP_UNKNOWN,
                          bool                  sec = false,
                          pgp_key_search_type_t tp = PGP_KEY_SEARCH_UNKNOWN)
        : op(anop), secret(sec), search(tp)
    {
    }
} pgp_key_request_ctx_t;

typedef pgp_key_t *pgp_key_callback_t(const pgp_key_request_ctx_t *ctx, void *userdata);

namespace rnp {
class KeyProvider {
  public:
    pgp_key_callback_t *callback;
    void *              userdata;

    KeyProvider(pgp_key_callback_t *cb = nullptr, void *ud = nullptr)
        : callback(cb), userdata(ud){};

    /** @brief request public or secret pgp key, according to information stored in ctx
     *  @param ctx information about the request - which operation requested the key, which
     *search criteria should be used and whether secret or public key is needed
     *  @return a key pointer on success, or nullptr if key was not found otherwise
     **/
    pgp_key_t *request_key(const pgp_key_request_ctx_t &ctx) const;
};
} // namespace rnp

/** key provider callback that searches a list of pgp_key_t pointers
 *
 *  @param ctx
 *  @param userdata must be a list of key pgp_key_t**
 */
pgp_key_t *rnp_key_provider_key_ptr_list(const pgp_key_request_ctx_t *ctx, void *userdata);

/** key provider callback that searches a given store
 *
 *  @param ctx
 *  @param userdata must be a pointer to rnp::KeyStore
 */
pgp_key_t *rnp_key_provider_store(const pgp_key_request_ctx_t *ctx, void *userdata);

/** key provider that calls other key providers
 *
 *  @param ctx
 *  @param userdata must be an array rnp::KeyProvider pointers,
 *         ending with a nullptr.
 */
pgp_key_t *rnp_key_provider_chained(const pgp_key_request_ctx_t *ctx, void *userdata);

#endif
