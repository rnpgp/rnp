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
#include <list>
#include <crypto/mem.h>
#include "sec_profile.hpp"

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
    rnp_ffi_t        ffi;
    const pgp_key_t *key;
    pgp_subsig_t *   sig;
    bool             own_sig;
};

struct rnp_recipient_handle_st {
    rnp_ffi_t        ffi;
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    pgp_pubkey_alg_t palg;
};

struct rnp_symenc_handle_st {
    rnp_ffi_t           ffi;
    pgp_symm_alg_t      alg;
    pgp_hash_alg_t      halg;
    pgp_s2k_specifier_t s2k_type;
    uint32_t            iterations;
    pgp_aead_alg_t      aalg;
};

struct rnp_ffi_st {
    FILE *                  errs;
    rnp_key_store_t *       pubring;
    rnp_key_store_t *       secring;
    rnp_get_key_cb          getkeycb;
    void *                  getkeycb_ctx;
    rnp_password_cb         getpasscb;
    void *                  getpasscb_ctx;
    pgp_key_provider_t      key_provider;
    pgp_password_provider_t pass_provider;
    rnp::SecurityContext    context;

    rnp_ffi_st(pgp_key_store_format_t pub_fmt, pgp_key_store_format_t sec_fmt);
    ~rnp_ffi_st();

    rnp::RNG &            rng() noexcept;
    rnp::SecurityProfile &profile() noexcept;
};

struct rnp_input_st {
    /* either src or src_directory are valid, not both */
    pgp_source_t        src;
    std::string         src_directory;
    rnp_input_reader_t *reader;
    rnp_input_closer_t *closer;
    void *              app_ctx;

    rnp_input_st();
    rnp_input_st(const rnp_input_st &) = delete;
    rnp_input_st(rnp_input_st &&) = delete;
    ~rnp_input_st();

    rnp_input_st &operator=(const rnp_input_st &) = delete;
    rnp_input_st &operator=(rnp_input_st &&src);
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
    rnp_ffi_t  ffi{};
    bool       primary{};
    pgp_key_t *primary_sec{};
    pgp_key_t *primary_pub{};
    pgp_key_t *gen_sec{};
    pgp_key_t *gen_pub{};
    /* password used to encrypt the key, if specified */
    rnp::secure_vector<char> password;
    /* request password for key encryption via ffi's password provider */
    bool request_password{};
    /* we don't use top-level keygen action here for easier fields access */
    rnp_keygen_crypto_params_t  crypto{};
    rnp_key_protection_params_t protection{};
    rnp_selfsig_cert_info_t     cert{};
    rnp_selfsig_binding_info_t  binding{};
};

struct rnp_op_sign_signature_st {
    rnp_ffi_t         ffi{};
    rnp_signer_info_t signer{};
    bool              expiry_set : 1;
    bool              create_set : 1;
    bool              hash_set : 1;
};

typedef std::list<rnp_op_sign_signature_st> rnp_op_sign_signatures_t;

struct rnp_op_sign_st {
    rnp_ffi_t                ffi{};
    rnp_input_t              input{};
    rnp_output_t             output{};
    rnp_ctx_t                rnpctx{};
    rnp_op_sign_signatures_t signatures{};
};

struct rnp_op_verify_signature_st {
    rnp_ffi_t       ffi;
    rnp_result_t    verify_status;
    pgp_signature_t sig_pkt;
};

struct rnp_op_verify_st {
    rnp_ffi_t    ffi{};
    rnp_input_t  input{};
    rnp_input_t  detached_input{}; /* for detached signature will be source file/data */
    rnp_output_t output{};
    rnp_ctx_t    rnpctx{};
    /* these fields are filled after operation execution */
    rnp_op_verify_signature_t signatures{};
    size_t                    signature_count{};
    char *                    filename{};
    uint32_t                  file_mtime{};
    /* encryption information */
    bool           encrypted{};
    bool           mdc{};
    bool           validated{};
    pgp_aead_alg_t aead{};
    pgp_symm_alg_t salg{};
    bool           ignore_sigs{};
    bool           require_all_sigs{};
    bool           allow_hidden{};
    /* recipient/symenc information */
    rnp_recipient_handle_t recipients{};
    size_t                 recipient_count{};
    rnp_recipient_handle_t used_recipient{};
    rnp_symenc_handle_t    symencs{};
    size_t                 symenc_count{};
    rnp_symenc_handle_t    used_symenc{};
    size_t                 encrypted_layers{};

    ~rnp_op_verify_st();
};

struct rnp_op_encrypt_st {
    rnp_ffi_t                ffi{};
    rnp_input_t              input{};
    rnp_output_t             output{};
    rnp_ctx_t                rnpctx{};
    rnp_op_sign_signatures_t signatures{};
};

#define RNP_LOCATOR_MAX_SIZE (MAX_ID_LENGTH + 1)
static_assert(RNP_LOCATOR_MAX_SIZE > PGP_FINGERPRINT_SIZE * 2, "Locator size mismatch.");
static_assert(RNP_LOCATOR_MAX_SIZE > PGP_KEY_ID_SIZE * 2, "Locator size mismatch.");
static_assert(RNP_LOCATOR_MAX_SIZE > PGP_KEY_GRIP_SIZE * 2, "Locator size mismatch.");
static_assert(RNP_LOCATOR_MAX_SIZE > MAX_ID_LENGTH, "Locator size mismatch.");

struct rnp_identifier_iterator_st {
    rnp_ffi_t                       ffi;
    pgp_key_search_type_t           type;
    rnp_key_store_t *               store;
    std::list<pgp_key_t>::iterator *keyp;
    unsigned                        uididx;
    json_object *                   tbl;
    char                            buf[RNP_LOCATOR_MAX_SIZE];
};

struct rnp_decryption_kp_param_t {
    rnp_op_verify_t op;
    bool            has_hidden; /* key provider had hidden keyid request */
    pgp_key_t *     last;       /* last key, returned in hidden keyid request */

    rnp_decryption_kp_param_t(rnp_op_verify_t opobj)
        : op(opobj), has_hidden(false), last(NULL){};
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
