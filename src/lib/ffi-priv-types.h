/*-
 * Copyright (c) 2019 Ribose Inc.
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
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <rnp/rnp.h>
#include <json.h>
#include "utils.h"

struct rnp_key_handle_st {
    rnp_ffi_t        ffi;
    pgp_key_search_t locator;
    pgp_key_t *      pub;
    pgp_key_t *      sec;
};

struct rnp_uid_handle_st {
    rnp_ffi_t  ffi;
    pgp_key_t *key;
    size_t     idx;
};

struct rnp_signature_handle_st {
    rnp_ffi_t     ffi;
    pgp_key_t *   key;
    pgp_subsig_t *sig;
    bool own_sig;
};

struct rnp_ffi_st {
    FILE *                  errs;
    rnp_key_store_t *       pubring;
    rnp_key_store_t *       secring;
    rnp_get_key_cb          getkeycb;
    void *                  getkeycb_ctx;
    rnp_password_cb         getpasscb;
    void *                  getpasscb_ctx;
    rng_t                   rng;
    pgp_key_provider_t      key_provider;
    pgp_password_provider_t pass_provider;
};

struct rnp_input_st {
    /* either src or src_directory are valid, not both */
    pgp_source_t        src;
    char *              src_directory;
    rnp_input_reader_t *reader;
    rnp_input_closer_t *closer;
    void *              app_ctx;
};

struct rnp_output_st {
    /* either dst or dst_directory are valid, not both */
    pgp_dest_t           dst;
    char *               dst_directory;
    rnp_output_writer_t *writer;
    rnp_output_closer_t *closer;
    void *               app_ctx;
    bool                 keep;
};

struct rnp_op_generate_st {
    rnp_ffi_t  ffi;
    bool       primary;
    pgp_key_t *primary_sec;
    pgp_key_t *primary_pub;
    pgp_key_t *gen_sec;
    pgp_key_t *gen_pub;
    /* password used to encrypt the key, if specified */
    char *password;
    /* request password for key encryption via ffi's password provider */
    bool request_password;
    /* we don't use top-level keygen action here for easier fields access */
    rnp_keygen_crypto_params_t  crypto;
    rnp_key_protection_params_t protection;
    rnp_selfsig_cert_info_t     cert;
    rnp_selfsig_binding_info_t  binding;
};

struct rnp_op_sign_st {
    rnp_ffi_t    ffi;
    rnp_input_t  input;
    rnp_output_t output;
    rnp_ctx_t    rnpctx;
    list         signatures;
};

struct rnp_op_sign_signature_st {
    rnp_ffi_t         ffi;
    rnp_signer_info_t signer;
    bool              expiry_set : 1;
    bool              create_set : 1;
    bool              hash_set : 1;
};

struct rnp_op_verify_signature_st {
    rnp_ffi_t      ffi;
    rnp_result_t   verify_status;
    pgp_signature_t sig_pkt;
};

struct rnp_op_verify_st {
    rnp_ffi_t    ffi;
    rnp_input_t  input;
    rnp_input_t  detached_input; /* for detached signature will be source file/data */
    rnp_output_t output;
    rnp_ctx_t    rnpctx;
    /* these fields are filled after operation execution */
    rnp_op_verify_signature_t signatures;
    size_t                    signature_count;
    char *                    filename;
    uint32_t                  file_mtime;
};

struct rnp_op_encrypt_st {
    rnp_ffi_t    ffi;
    rnp_input_t  input;
    rnp_output_t output;
    rnp_ctx_t    rnpctx;
    list         signatures;
};

struct rnp_identifier_iterator_st {
    rnp_ffi_t             ffi;
    pgp_key_search_type_t type;
    rnp_key_store_t *     store;
    pgp_key_t *           keyp;
    unsigned              uididx;
    json_object *         tbl;
    char
      buf[1 + MAX(MAX(MAX(PGP_KEY_ID_SIZE * 2, PGP_KEY_GRIP_SIZE), PGP_FINGERPRINT_SIZE * 2),
                  MAX_ID_LENGTH)];
};

/* This is just for readability at the call site and will hopefully reduce mistakes.
 *
 * Instead of:
 *  void do_something(rnp_ffi_t ffi, bool with_secret_keys);
 *  do_something(ffi, true);
 *  do_something(ffi, false);
 *
 * You can have something a bit clearer:
 *  void do_something(rnp_ffi_t ffi, key_type_t key_type);
 *  do_something(ffi, KEY_TYPE_PUBLIC);
 *  do_something(ffi, KEY_TYPE_SECRET);
 */
typedef enum key_type_t {
    KEY_TYPE_NONE,
    KEY_TYPE_PUBLIC,
    KEY_TYPE_SECRET,
    KEY_TYPE_ANY
} key_type_t;
