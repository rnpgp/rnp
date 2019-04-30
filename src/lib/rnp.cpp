/*-
 * Copyright (c) 2017-2018 Ribose Inc.
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

#include "crypto.h"
#include "crypto/common.h"
#include "list.h"
#include "pgp-key.h"
#include "defaults.h"
#include <assert.h>
#include <json_object.h>
#include <json.h>
#include <librepgp/packet-show.h>
#include <librepgp/stream-ctx.h>
#include <librepgp/stream-common.h>
#include <librepgp/stream-armor.h>
#include <librepgp/stream-parse.h>
#include <librepgp/stream-write.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>
#include <librepgp/stream-dump.h>
#include "packet-create.h"
#include <rnp/rnp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include "utils.h"
#include "version.h"

struct rnp_key_handle_st {
    rnp_ffi_t        ffi;
    pgp_key_search_t locator;
    pgp_key_t *      pub;
    pgp_key_t *      sec;
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
    uint8_t        keyid[PGP_KEY_ID_SIZE];
    pgp_hash_alg_t halg;
    uint32_t       sig_create;
    uint32_t       sig_expires;
    rnp_result_t   verify_status;
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

#define FFI_LOG(ffi, ...)            \
    do {                             \
        FILE *fp = stderr;           \
        if (ffi && ffi->errs) {      \
            fp = ffi->errs;          \
        }                            \
        RNP_LOG_FD(fp, __VA_ARGS__); \
    } while (0)

static pgp_key_t *get_key_require_public(rnp_key_handle_t handle);
static pgp_key_t *get_key_prefer_public(rnp_key_handle_t handle);
static pgp_key_t *get_key_require_secret(rnp_key_handle_t handle);

static bool locator_to_str(const pgp_key_search_t *locator,
                           const char **           identifier_type,
                           char *                  identifier,
                           size_t                  identifier_size);

static bool rnp_password_cb_bounce(const pgp_password_ctx_t *ctx,
                                   char *                    password,
                                   size_t                    password_size,
                                   void *                    userdata_void);

static pgp_key_t *
find_key(rnp_ffi_t               ffi,
         const pgp_key_search_t *search,
         key_type_t              key_type,
         bool                    try_key_provider)
{
    pgp_key_t *key = NULL;

    switch (key_type) {
    case KEY_TYPE_PUBLIC:
        key = rnp_key_store_search(ffi->pubring, search, NULL);
        break;
    case KEY_TYPE_SECRET:
        key = rnp_key_store_search(ffi->secring, search, NULL);
        break;
    default:
        assert(false);
        break;
    }
    if (!key && ffi->getkeycb && try_key_provider) {
        char        identifier[1 + MAX(MAX(MAX(PGP_KEY_ID_SIZE * 2, PGP_KEY_GRIP_SIZE),
                                    PGP_FINGERPRINT_SIZE * 2),
                                MAX_ID_LENGTH)];
        const char *identifier_type = NULL;

        if (locator_to_str(search, &identifier_type, identifier, sizeof(identifier))) {
            ffi->getkeycb(ffi,
                          ffi->getkeycb_ctx,
                          identifier_type,
                          identifier,
                          key_type == KEY_TYPE_SECRET);
            // recurse and try the store search above once more
            return find_key(ffi, search, key_type, false);
        }
    }
    return key;
}

static pgp_key_t *
ffi_key_provider(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    rnp_ffi_t ffi = (rnp_ffi_t) userdata;
    return find_key(ffi, &ctx->search, ctx->secret ? KEY_TYPE_SECRET : KEY_TYPE_PUBLIC, true);
}

static void
rnp_ctx_init_ffi(rnp_ctx_t *ctx, rnp_ffi_t ffi)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->rng = &ffi->rng;
    ctx->ealg = DEFAULT_PGP_SYMM_ALG;
}

static const pgp_map_t sig_type_map[] = {{PGP_SIG_BINARY, "binary"},
                                         {PGP_SIG_TEXT, "text"},
                                         {PGP_SIG_STANDALONE, "standalone"},
                                         {PGP_CERT_GENERIC, "certification (generic)"},
                                         {PGP_CERT_PERSONA, "certification (persona)"},
                                         {PGP_CERT_CASUAL, "certification (casual)"},
                                         {PGP_CERT_POSITIVE, "certification (positive)"},
                                         {PGP_SIG_SUBKEY, "subkey binding"},
                                         {PGP_SIG_PRIMARY, "primary key binding"},
                                         {PGP_SIG_DIRECT, "direct"},
                                         {PGP_SIG_REV_KEY, "key revocation"},
                                         {PGP_SIG_REV_SUBKEY, "subkey revocation"},
                                         {PGP_SIG_REV_CERT, "certification revocation"},
                                         {PGP_SIG_TIMESTAMP, "timestamp"},
                                         {PGP_SIG_3RD_PARTY, "third-party"}};

static const pgp_map_t pubkey_alg_map[] = {{PGP_PKA_RSA, "RSA"},
                                           {PGP_PKA_RSA_ENCRYPT_ONLY, "RSA"},
                                           {PGP_PKA_RSA_SIGN_ONLY, "RSA"},
                                           {PGP_PKA_ELGAMAL, "ELGAMAL"},
                                           {PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN, "ELGAMAL"},
                                           {PGP_PKA_DSA, "DSA"},
                                           {PGP_PKA_ECDH, "ECDH"},
                                           {PGP_PKA_ECDSA, "ECDSA"},
                                           {PGP_PKA_EDDSA, "EDDSA"},
                                           {PGP_PKA_SM2, "SM2"}};

static const pgp_map_t symm_alg_map[] = {{PGP_SA_IDEA, "IDEA"},
                                         {PGP_SA_TRIPLEDES, "TRIPLEDES"},
                                         {PGP_SA_CAST5, "CAST5"},
                                         {PGP_SA_BLOWFISH, "BLOWFISH"},
                                         {PGP_SA_AES_128, "AES128"},
                                         {PGP_SA_AES_192, "AES192"},
                                         {PGP_SA_AES_256, "AES256"},
                                         {PGP_SA_TWOFISH, "TWOFISH"},
                                         {PGP_SA_CAMELLIA_128, "CAMELLIA128"},
                                         {PGP_SA_CAMELLIA_192, "CAMELLIA192"},
                                         {PGP_SA_CAMELLIA_256, "CAMELLIA256"},
                                         {PGP_SA_SM4, "SM4"}};

static const pgp_map_t aead_alg_map[] = {
  {PGP_AEAD_NONE, "None"}, {PGP_AEAD_EAX, "EAX"}, {PGP_AEAD_OCB, "OCB"}};

static const pgp_map_t cipher_mode_map[] = {
  {PGP_CIPHER_MODE_CFB, "CFB"}, {PGP_CIPHER_MODE_CBC, "CBC"}, {PGP_CIPHER_MODE_OCB, "OCB"}};

static const pgp_map_t compress_alg_map[] = {{PGP_C_NONE, "Uncompressed"},
                                             {PGP_C_ZIP, "ZIP"},
                                             {PGP_C_ZLIB, "ZLIB"},
                                             {PGP_C_BZIP2, "BZip2"}};

static const pgp_map_t hash_alg_map[] = {{PGP_HASH_MD5, "MD5"},
                                         {PGP_HASH_SHA1, "SHA1"},
                                         {PGP_HASH_RIPEMD, "RIPEMD160"},
                                         {PGP_HASH_SHA256, "SHA256"},
                                         {PGP_HASH_SHA384, "SHA384"},
                                         {PGP_HASH_SHA512, "SHA512"},
                                         {PGP_HASH_SHA224, "SHA224"},
                                         {PGP_HASH_SM3, "SM3"},
                                         {PGP_HASH_CRC24, "CRC24"}};

static const pgp_bit_map_t key_usage_map[] = {{PGP_KF_SIGN, "sign"},
                                              {PGP_KF_CERTIFY, "certify"},
                                              {PGP_KF_ENCRYPT, "encrypt"},
                                              {PGP_KF_AUTH, "authenticate"}};

static const pgp_bit_map_t key_flags_map[] = {{PGP_KF_SPLIT, "split"},
                                              {PGP_KF_SHARED, "shared"}};

static const pgp_map_t identifier_type_map[] = {{PGP_KEY_SEARCH_USERID, "userid"},
                                                {PGP_KEY_SEARCH_KEYID, "keyid"},
                                                {PGP_KEY_SEARCH_FINGERPRINT, "fingerprint"},
                                                {PGP_KEY_SEARCH_GRIP, "grip"}};

static const pgp_map_t key_server_prefs_map[] = {{PGP_KEY_SERVER_NO_MODIFY, "no-modify"}};

static const pgp_map_t armor_type_map[] = {{PGP_ARMORED_MESSAGE, "message"},
                                           {PGP_ARMORED_PUBLIC_KEY, "public key"},
                                           {PGP_ARMORED_SECRET_KEY, "secret key"},
                                           {PGP_ARMORED_SIGNATURE, "signature"},
                                           {PGP_ARMORED_CLEARTEXT, "cleartext"}};

static bool
curve_str_to_type(const char *str, pgp_curve_t *value)
{
    *value = find_curve_by_name(str);
    return *value != PGP_CURVE_MAX;
}

static bool
curve_type_to_str(pgp_curve_t type, const char **str)
{
    const ec_curve_desc_t *desc = get_curve_desc(type);
    if (!desc) {
        return false;
    }
    *str = desc->pgp_name;
    return true;
}

static bool
str_to_cipher(const char *str, pgp_symm_alg_t *cipher)
{
    pgp_symm_alg_t alg = PGP_SA_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(symm_alg_map, string, type, str, alg);
    if (alg == PGP_SA_UNKNOWN) {
        return false;
    }

    *cipher = alg;
    return true;
}

static bool
str_to_hash_alg(const char *str, pgp_hash_alg_t *hash_alg)
{
    pgp_hash_alg_t alg = PGP_HASH_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(hash_alg_map, string, type, str, alg);
    if (alg == PGP_HASH_UNKNOWN) {
        return false;
    }

    *hash_alg = alg;
    return true;
}

static bool
str_to_cipher_mode(const char *str, pgp_cipher_mode_t *mode)
{
    pgp_cipher_mode_t c_mode = PGP_CIPHER_MODE_NONE;
    ARRAY_LOOKUP_BY_STRCASE(cipher_mode_map, string, type, str, c_mode);
    if (c_mode == PGP_CIPHER_MODE_NONE) {
        return false;
    }

    *mode = c_mode;
    return true;
}

static bool
str_to_pubkey_alg(const char *str, pgp_pubkey_alg_t *pub_alg)
{
    pgp_pubkey_alg_t alg = PGP_PKA_NOTHING;
    ARRAY_LOOKUP_BY_STRCASE(pubkey_alg_map, string, type, str, alg);
    if (alg == PGP_PKA_NOTHING) {
        return false;
    }

    *pub_alg = alg;
    return true;
}

static bool
str_to_key_flag(const char *str, uint8_t *flag)
{
    uint8_t _flag = 0;
    ARRAY_LOOKUP_BY_STRCASE(key_usage_map, string, mask, str, _flag);
    if (!_flag) {
        return false;
    }
    *flag = _flag;
    return true;
}

rnp_result_t
rnp_ffi_create(rnp_ffi_t *ffi, const char *pub_format, const char *sec_format)
{
    struct rnp_ffi_st *ob = NULL;
    rnp_result_t       ret = RNP_ERROR_GENERIC;

    // checks
    if (!ffi) {
        return RNP_ERROR_NULL_POINTER;
    }

    ob = (rnp_ffi_st *) calloc(1, sizeof(struct rnp_ffi_st));
    if (!ob) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // default to all stderr
    ob->errs = stderr;
    ob->pubring = rnp_key_store_new(pub_format, "");
    if (!ob->pubring) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    ob->secring = rnp_key_store_new(sec_format, "");
    if (!ob->secring) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    ob->key_provider = (pgp_key_provider_t){.callback = ffi_key_provider, .userdata = ob};
    ob->pass_provider =
      (pgp_password_provider_t){.callback = rnp_password_cb_bounce, .userdata = ob};
    if (!rng_init(&ob->rng, RNG_DRBG)) {
        ret = RNP_ERROR_RNG;
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    if (ret) {
        rnp_ffi_destroy(ob);
        ob = NULL;
    }
    *ffi = ob;
    return ret;
}

static bool
is_std_file(FILE *fp)
{
    return fp == stdout || fp == stderr;
}

static void
close_io_file(FILE **fp)
{
    if (*fp && !is_std_file(*fp)) {
        fclose(*fp);
    }
    *fp = NULL;
}

rnp_result_t
rnp_ffi_destroy(rnp_ffi_t ffi)
{
    if (ffi) {
        close_io_file(&ffi->errs);
        rnp_key_store_free(ffi->pubring);
        rnp_key_store_free(ffi->secring);
        rng_destroy(&ffi->rng);
        free(ffi);
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_ffi_set_log_fd(rnp_ffi_t ffi, int fd)
{
    FILE *errs = NULL;

    // checks
    if (!ffi) {
        return RNP_ERROR_NULL_POINTER;
    }

    // open
    errs = fdopen(fd, "a");
    if (!errs) {
        close_io_file(&errs);
        return RNP_ERROR_ACCESS;
    }
    // close previous streams and replace them
    close_io_file(&ffi->errs);
    ffi->errs = errs;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_ffi_set_key_provider(rnp_ffi_t ffi, rnp_get_key_cb getkeycb, void *getkeycb_ctx)
{
    if (!ffi) {
        return RNP_ERROR_NULL_POINTER;
    }
    ffi->getkeycb = getkeycb;
    ffi->getkeycb_ctx = getkeycb_ctx;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_ffi_set_pass_provider(rnp_ffi_t ffi, rnp_password_cb getpasscb, void *getpasscb_ctx)
{
    if (!ffi) {
        return RNP_ERROR_NULL_POINTER;
    }
    ffi->getpasscb = getpasscb;
    ffi->getpasscb_ctx = getpasscb_ctx;
    return RNP_SUCCESS;
}

static const char *
operation_description(uint8_t op)
{
    switch (op) {
    case PGP_OP_ADD_SUBKEY:
        return "add subkey";
    case PGP_OP_ADD_USERID:
        return "add userid";
    case PGP_OP_SIGN:
        return "sign";
    case PGP_OP_DECRYPT:
        return "decrypt";
    case PGP_OP_UNLOCK:
        return "unlock";
    case PGP_OP_PROTECT:
        return "protect";
    case PGP_OP_UNPROTECT:
        return "unprotect";
    case PGP_OP_DECRYPT_SYM:
        return "decrypt (symmetric)";
    case PGP_OP_ENCRYPT_SYM:
        return "encrypt (symmetric)";
    default:
        return "unknown";
    }
}

static bool
rnp_password_cb_bounce(const pgp_password_ctx_t *ctx,
                       char *                    password,
                       size_t                    password_size,
                       void *                    userdata_void)
{
    rnp_ffi_t ffi = (rnp_ffi_t) userdata_void;

    if (!ffi || !ffi->getpasscb) {
        return false;
    }

    struct rnp_key_handle_st key = {};
    key.ffi = ffi;
    key.sec = (pgp_key_t *) ctx->key;
    return ffi->getpasscb(ffi,
                          ffi->getpasscb_ctx,
                          ctx->key ? &key : NULL,
                          operation_description(ctx->op),
                          password,
                          password_size);
}

const char *
rnp_result_to_string(rnp_result_t result)
{
    switch (result) {
    case RNP_SUCCESS:
        return "Success";

    case RNP_ERROR_GENERIC:
        return "Unknown error";
    case RNP_ERROR_BAD_FORMAT:
        return "Bad format";
    case RNP_ERROR_BAD_PARAMETERS:
        return "Bad parameters";
    case RNP_ERROR_NOT_IMPLEMENTED:
        return "Not implemented";
    case RNP_ERROR_NOT_SUPPORTED:
        return "Not supported";
    case RNP_ERROR_OUT_OF_MEMORY:
        return "Out of memory";
    case RNP_ERROR_SHORT_BUFFER:
        return "Buffer too short";
    case RNP_ERROR_NULL_POINTER:
        return "Null pointer";

    case RNP_ERROR_ACCESS:
        return "Error accessing file";
    case RNP_ERROR_READ:
        return "Error reading file";
    case RNP_ERROR_WRITE:
        return "Error writing file";

    case RNP_ERROR_BAD_STATE:
        return "Bad state";
    case RNP_ERROR_MAC_INVALID:
        return "Invalid MAC";
    case RNP_ERROR_SIGNATURE_INVALID:
        return "Invalid signature";
    case RNP_ERROR_KEY_GENERATION:
        return "Error during key generation";
    case RNP_ERROR_BAD_PASSWORD:
        return "Bad password";
    case RNP_ERROR_KEY_NOT_FOUND:
        return "Key not found";
    case RNP_ERROR_NO_SUITABLE_KEY:
        return "No suitable key";
    case RNP_ERROR_DECRYPT_FAILED:
        return "Decryption failed";
    case RNP_ERROR_NO_SIGNATURES_FOUND:
        return "No signatures found cannot verify";

    case RNP_ERROR_NOT_ENOUGH_DATA:
        return "Not enough data";
    case RNP_ERROR_UNKNOWN_TAG:
        return "Unknown tag";
    case RNP_ERROR_PACKET_NOT_CONSUMED:
        return "Packet not consumed";
    case RNP_ERROR_NO_USERID:
        return "No userid";
    case RNP_ERROR_EOF:
        return "EOF detected";
    }

    return "Unknown error";
}

const char *
rnp_version_string()
{
    return RNP_VERSION_STRING;
}

const char *
rnp_version_string_full()
{
    return RNP_VERSION_STRING_FULL;
}

uint32_t
rnp_version()
{
    return RNP_VERSION_CODE;
}

uint32_t
rnp_version_for(uint32_t major, uint32_t minor, uint32_t patch)
{
    if (major > RNP_VERSION_COMPONENT_MASK || minor > RNP_VERSION_COMPONENT_MASK ||
        patch > RNP_VERSION_COMPONENT_MASK) {
        RNP_LOG("invalid version, out of range: %d.%d.%d", major, minor, patch);
        return 0;
    }
    return RNP_VERSION_CODE_FOR(major, minor, patch);
}

uint32_t
rnp_version_major(uint32_t version)
{
    return (version >> RNP_VERSION_MAJOR_SHIFT) & RNP_VERSION_COMPONENT_MASK;
}

uint32_t
rnp_version_minor(uint32_t version)
{
    return (version >> RNP_VERSION_MINOR_SHIFT) & RNP_VERSION_COMPONENT_MASK;
}

uint32_t
rnp_version_patch(uint32_t version)
{
    return (version >> RNP_VERSION_PATCH_SHIFT) & RNP_VERSION_COMPONENT_MASK;
}

uint64_t
rnp_version_commit_timestamp()
{
    return RNP_VERSION_COMMIT_TIMESTAMP;
}

rnp_result_t
rnp_get_default_homedir(char **homedir)
{
    // checks
    if (!homedir) {
        return RNP_ERROR_NULL_POINTER;
    }

    // get the users home dir
    char *home = getenv("HOME");
    if (!home) {
        return RNP_ERROR_NOT_SUPPORTED;
    }
    if (!rnp_compose_path_ex(homedir, NULL, home, ".rnp", NULL)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_detect_homedir_info(
  const char *homedir, char **pub_format, char **pub_path, char **sec_format, char **sec_path)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;
    char *       path = NULL;
    size_t       path_size = 0;

    // checks
    if (!homedir || !pub_format || !pub_path || !sec_format || !sec_path) {
        return RNP_ERROR_NULL_POINTER;
    }

    // we only support the common cases of GPG+GPG or GPG+G10, we don't
    // support unused combinations like KBX+KBX

    *pub_format = NULL;
    *pub_path = NULL;
    *sec_format = NULL;
    *sec_path = NULL;

    const char *pub_format_guess = NULL;
    const char *pub_path_guess = NULL;
    const char *sec_format_guess = NULL;
    const char *sec_path_guess = NULL;
    // check for pubring.kbx file
    if (!rnp_compose_path_ex(&path, &path_size, homedir, "pubring.kbx", NULL)) {
        goto done;
    }
    if (rnp_file_exists(path)) {
        // we have a pubring.kbx, now check for private-keys-v1.d dir
        if (!rnp_compose_path_ex(&path, &path_size, homedir, "private-keys-v1.d", NULL)) {
            goto done;
        }
        if (rnp_dir_exists(path)) {
            pub_format_guess = "KBX";
            pub_path_guess = "pubring.kbx";
            sec_format_guess = "G10";
            sec_path_guess = "private-keys-v1.d";
        }
    } else {
        // check for pubring.gpg
        if (!rnp_compose_path_ex(&path, &path_size, homedir, "pubring.gpg", NULL)) {
            goto done;
        }
        if (rnp_file_exists(path)) {
            // we have a pubring.gpg, now check for secring.gpg
            if (!rnp_compose_path_ex(&path, &path_size, homedir, "secring.gpg", NULL)) {
                goto done;
            }
            if (rnp_file_exists(path)) {
                pub_format_guess = "GPG";
                pub_path_guess = "pubring.gpg";
                sec_format_guess = "GPG";
                sec_path_guess = "secring.gpg";
            }
        }
    }

    // set our results
    if (pub_format_guess) {
        *pub_format = strdup(pub_format_guess);
        *pub_path = rnp_compose_path(homedir, pub_path_guess, NULL);
        if (!*pub_format || !*pub_path) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }
    if (sec_format_guess) {
        *sec_format = strdup(sec_format_guess);
        *sec_path = rnp_compose_path(homedir, sec_path_guess, NULL);
        if (!*sec_format || !*sec_path) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }
    // we leave the *formats as NULL if we were not able to determine the format
    // (but no error occurred)

    ret = RNP_SUCCESS;
done:
    if (ret) {
        free(*pub_format);
        *pub_format = NULL;
        free(*pub_path);
        *pub_path = NULL;

        free(*sec_format);
        *sec_format = NULL;
        free(*sec_path);
        *sec_path = NULL;
    }
    free(path);
    return ret;
}

rnp_result_t
rnp_detect_key_format(const uint8_t buf[], size_t buf_len, char **format)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!buf || !format) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!buf_len) {
        return RNP_ERROR_SHORT_BUFFER;
    }

    *format = NULL;
    // ordered from most reliable detection to least
    const char *guess = NULL;
    if (buf_len >= 12 && memcmp(buf + 8, "KBXf", 4) == 0) {
        // KBX has a magic KBXf marker
        guess = "KBX";
    } else if (buf_len >= 5 && memcmp(buf, "-----", 5) == 0) {
        // likely armored GPG
        guess = "GPG";
    } else if (buf[0] == '(') {
        // G10 is s-exprs and should start end end with parentheses
        guess = "G10";
    } else if (buf[0] & PGP_PTAG_ALWAYS_SET) {
        // this is harder to reliably determine, but could likely be improved
        guess = "GPG";
    }
    if (guess) {
        *format = strdup(guess);
        if (!*format) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

static rnp_result_t
load_keys_from_input(rnp_ffi_t ffi, rnp_input_t input, rnp_key_store_t *store)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    pgp_key_provider_t chained;
    chained.callback = rnp_key_provider_store;
    chained.userdata = store;

    const pgp_key_provider_t *key_providers[] = {&chained, &ffi->key_provider, NULL};

    const pgp_key_provider_t key_provider = {.callback = rnp_key_provider_chained,
                                             .userdata = key_providers};

    if (input->src_directory) {
        // load the keys
        free((void *) store->path);
        store->path = strdup(input->src_directory);
        if (!store->path) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (!rnp_key_store_load_from_path(store, &key_provider)) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
    } else {
        // load the keys
        if (!rnp_key_store_load_from_src(store, &input->src, &key_provider)) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
    }

    ret = RNP_SUCCESS;
done:
    return ret;
}

static bool
key_needs_conversion(const pgp_key_t *key, const rnp_key_store_t *store)
{
    key_store_format_t key_format = key->format;
    key_store_format_t store_format = store->format;
    /* pgp_key_t->format is only ever GPG or G10.
     *
     * The key store, however, could have a format of KBX, GPG, or G10.
     * A KBX (and GPG) key store can only handle a pgp_key_t with a format of GPG.
     * A G10 key store can only handle a pgp_key_t with a format of G10.
     */
    // should never be the case
    assert(key_format != KBX_KEY_STORE);
    // normalize the store format
    if (store_format == KBX_KEY_STORE) {
        store_format = GPG_KEY_STORE;
    }
    // from here, both the key and store formats can only be GPG or G10
    return key_format != store_format;
}

static rnp_result_t
do_load_keys(rnp_ffi_t ffi, rnp_input_t input, const char *format, key_type_t key_type)
{
    rnp_result_t     ret = RNP_ERROR_GENERIC;
    rnp_key_store_t *tmp_store = NULL;
    pgp_key_t        keycp = {};
    rnp_result_t     tmpret;

    // create a temporary key store to hold the keys
    tmp_store = rnp_key_store_new(format, "");
    if (!tmp_store) {
        // TODO: could also be out of mem
        FFI_LOG(ffi, "Failed to create key store of format: %s", format);
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    // load keys into our temporary store
    tmpret = load_keys_from_input(ffi, input, tmp_store);
    if (tmpret) {
        ret = tmpret;
        goto done;
    }
    // go through all the loaded keys
    for (list_item *key_item = list_front(rnp_key_store_get_keys(tmp_store)); key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        // check that the key is the correct type and has not already been loaded
        // add secret key part if it is and we need it
        if (pgp_key_is_secret(key) &&
            ((key_type == KEY_TYPE_SECRET) || (key_type == KEY_TYPE_ANY))) {
            if (key_needs_conversion(key, ffi->secring)) {
                FFI_LOG(ffi, "This key format conversion is not yet supported");
                ret = RNP_ERROR_NOT_IMPLEMENTED;
                goto done;
            }

            if ((tmpret = pgp_key_copy(&keycp, key, false))) {
                FFI_LOG(ffi, "Failed to copy secret key");
                ret = tmpret;
                goto done;
            }

            if (!rnp_key_store_add_key(ffi->secring, &keycp)) {
                FFI_LOG(ffi, "Failed to add secret key");
                pgp_key_free_data(&keycp);
                ret = RNP_ERROR_GENERIC;
                goto done;
            }
        }

        // add public key part if needed
        if ((key->format == G10_KEY_STORE) ||
            ((key_type != KEY_TYPE_ANY) && (key_type != KEY_TYPE_PUBLIC))) {
            continue;
        }

        if ((tmpret = pgp_key_copy(&keycp, key, true))) {
            ret = tmpret;
            goto done;
        }

        /* TODO: We could do this a few different ways. There isn't an obvious reason
         * to restrict what formats we load, so we don't necessarily need to require a
         * conversion just to load and use a G10 key when using GPG keyrings, for
         * example. We could just convert when saving.
         */

        if (key_needs_conversion(key, ffi->pubring)) {
            FFI_LOG(ffi, "This key format conversion is not yet supported");
            pgp_key_free_data(&keycp);
            ret = RNP_ERROR_NOT_IMPLEMENTED;
            goto done;
        }

        if (!rnp_key_store_add_key(ffi->pubring, &keycp)) {
            FFI_LOG(ffi, "Failed to add public key");
            pgp_key_free_data(&keycp);
            ret = RNP_ERROR_GENERIC;
            goto done;
        }
    }

    // success, even if we didn't actually load any
    ret = RNP_SUCCESS;
done:
    rnp_key_store_free(tmp_store);
    return ret;
}

static key_type_t
flags_to_key_type(uint32_t *flags)
{
    key_type_t type = KEY_TYPE_NONE;
    // figure out what type of keys to operate on, based on flags
    if ((*flags & RNP_LOAD_SAVE_PUBLIC_KEYS) && (*flags & RNP_LOAD_SAVE_SECRET_KEYS)) {
        type = KEY_TYPE_ANY;
        *flags &= ~(RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS);
    } else if (*flags & RNP_LOAD_SAVE_PUBLIC_KEYS) {
        type = KEY_TYPE_PUBLIC;
        *flags &= ~RNP_LOAD_SAVE_PUBLIC_KEYS;
    } else if (*flags & RNP_LOAD_SAVE_SECRET_KEYS) {
        type = KEY_TYPE_SECRET;
        *flags &= ~RNP_LOAD_SAVE_SECRET_KEYS;
    }
    return type;
}

rnp_result_t
rnp_load_keys(rnp_ffi_t ffi, const char *format, rnp_input_t input, uint32_t flags)
{
    // checks
    if (!ffi || !format || !input) {
        return RNP_ERROR_NULL_POINTER;
    }
    key_type_t type = flags_to_key_type(&flags);
    if (!type) {
        FFI_LOG(ffi, "invalid flags - must have public and/or secret keys");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // check for any unrecognized flags (not forward-compat, but maybe still a good idea)
    if (flags) {
        FFI_LOG(ffi, "unexpected flags remaining: 0x%X", flags);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return do_load_keys(ffi, input, format, type);
}

rnp_result_t
rnp_unload_keys(rnp_ffi_t ffi, uint32_t flags)
{
    if (!ffi) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (flags & ~(RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (flags & RNP_KEY_UNLOAD_PUBLIC) {
        rnp_key_store_clear(ffi->pubring);
    }
    if (flags & RNP_KEY_UNLOAD_SECRET) {
        rnp_key_store_clear(ffi->secring);
    }

    return RNP_SUCCESS;
}

static bool
copy_store_keys(rnp_ffi_t ffi, rnp_key_store_t *dest, rnp_key_store_t *src)
{
    pgp_key_t keycp = {};
    for (list_item *key = list_front(rnp_key_store_get_keys(src)); key; key = list_next(key)) {
        if (pgp_key_copy(&keycp, (pgp_key_t *) key, false)) {
            FFI_LOG(ffi, "failed to create key copy");
            return false;
        }
        if (!rnp_key_store_add_key(dest, &keycp)) {
            pgp_key_free_data(&keycp);
            FFI_LOG(ffi, "failed to add key to the store");
            return false;
        }
    }
    return true;
}

static rnp_result_t
do_save_keys(rnp_ffi_t ffi, rnp_output_t output, const char *format, key_type_t key_type)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // create a temporary key store to hold the keys
    rnp_key_store_t *tmp_store = rnp_key_store_new(format, "");
    if (!tmp_store) {
        // TODO: could also be out of mem
        FFI_LOG(ffi, "Failed to create key store of format: %s", format);
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }
    // include the public keys, if desired
    if (key_type == KEY_TYPE_PUBLIC || key_type == KEY_TYPE_ANY) {
        if (!copy_store_keys(ffi, tmp_store, ffi->pubring)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }
    // include the secret keys, if desired
    if (key_type == KEY_TYPE_SECRET || key_type == KEY_TYPE_ANY) {
        if (!copy_store_keys(ffi, tmp_store, ffi->secring)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }
    // preliminary check on the format
    for (list_item *key_item = list_front(rnp_key_store_get_keys(tmp_store)); key_item;
         key_item = list_next(key_item)) {
        if (key_needs_conversion((pgp_key_t *) key_item, tmp_store)) {
            FFI_LOG(ffi, "This key format conversion is not yet supported");
            ret = RNP_ERROR_NOT_IMPLEMENTED;
            goto done;
        }
    }
    // write
    if (output->dst_directory) {
        free((void *) tmp_store->path);
        tmp_store->path = strdup(output->dst_directory);
        if (!tmp_store->path) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (!rnp_key_store_write_to_path(tmp_store)) {
            ret = RNP_ERROR_WRITE;
            goto done;
        }
        ret = RNP_SUCCESS;
    } else {
        if (!rnp_key_store_write_to_dst(tmp_store, &output->dst)) {
            ret = RNP_ERROR_WRITE;
            goto done;
        }
        dst_flush(&output->dst);
        output->keep = (output->dst.werr == RNP_SUCCESS);
        ret = output->dst.werr;
    }

done:
    if (tmp_store) {
        rnp_key_store_free(tmp_store);
    }
    return ret;
}

rnp_result_t
rnp_save_keys(rnp_ffi_t ffi, const char *format, rnp_output_t output, uint32_t flags)
{
    // checks
    if (!ffi || !format || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    key_type_t type = flags_to_key_type(&flags);
    if (!type) {
        FFI_LOG(ffi, "invalid flags - must have public and/or secret keys");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // check for any unrecognized flags (not forward-compat, but maybe still a good idea)
    if (flags) {
        FFI_LOG(ffi, "unexpected flags remaining: 0x%X", flags);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    return do_save_keys(ffi, output, format, type);
}

rnp_result_t
rnp_get_public_key_count(rnp_ffi_t ffi, size_t *count)
{
    if (!ffi || !count) {
        return RNP_ERROR_NULL_POINTER;
    }
    *count = rnp_key_store_get_key_count(ffi->pubring);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_get_secret_key_count(rnp_ffi_t ffi, size_t *count)
{
    if (!ffi || !count) {
        return RNP_ERROR_NULL_POINTER;
    }
    *count = rnp_key_store_get_key_count(ffi->secring);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_input_from_path(rnp_input_t *input, const char *path)
{
    struct rnp_input_st *ob = NULL;
    struct stat          st = {0};

    if (!input || !path) {
        return RNP_ERROR_NULL_POINTER;
    }
    ob = (rnp_input_st *) calloc(1, sizeof(*ob));
    if (!ob) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        // a bit hacky, just save the directory path
        ob->src_directory = strdup(path);
        if (!ob->src_directory) {
            free(ob);
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    } else {
        // simple input from a file
        rnp_result_t ret = init_file_src(&ob->src, path);
        if (ret) {
            free(ob);
            return ret;
        }
    }
    *input = ob;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_input_from_memory(rnp_input_t *input, const uint8_t buf[], size_t buf_len, bool do_copy)
{
    if (!input || !buf) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!buf_len) {
        return RNP_ERROR_SHORT_BUFFER;
    }
    *input = (rnp_input_t) calloc(1, sizeof(**input));
    if (!*input) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    uint8_t *data = (uint8_t *) buf;
    if (do_copy) {
        data = (uint8_t *) malloc(buf_len);
        if (!data) {
            free(*input);
            *input = NULL;
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        memcpy(data, buf, buf_len);
    }
    rnp_result_t ret = init_mem_src(&(*input)->src, data, buf_len, do_copy);
    if (ret) {
        free(*input);
        *input = NULL;
        return ret;
    }
    return RNP_SUCCESS;
}

static ssize_t
input_reader_bounce(pgp_source_t *src, void *buf, size_t len)
{
    rnp_input_t input = (rnp_input_t) src->param;
    if (!input->reader) {
        return -1;
    }
    return input->reader(input->app_ctx, buf, len);
}

static void
input_closer_bounce(pgp_source_t *src)
{
    rnp_input_t input = (rnp_input_t) src->param;
    if (input->closer) {
        input->closer(input->app_ctx);
    }
}

rnp_result_t
rnp_input_from_callback(rnp_input_t *       input,
                        rnp_input_reader_t *reader,
                        rnp_input_closer_t *closer,
                        void *              app_ctx)
{
    struct rnp_input_st *obj = NULL;

    // checks
    if (!input || !reader) {
        return RNP_ERROR_NULL_POINTER;
    }
    obj = (rnp_input_st *) calloc(1, sizeof(*obj));
    if (!obj) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    pgp_source_t *src = &obj->src;
    obj->reader = reader;
    obj->closer = closer;
    obj->app_ctx = app_ctx;
    if (!init_src_common(src, 0)) {
        free(obj);
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    src->param = obj;
    src->read = input_reader_bounce;
    src->close = input_closer_bounce;
    src->type = PGP_STREAM_MEMORY;
    *input = obj;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_input_destroy(rnp_input_t input)
{
    if (input) {
        src_close(&input->src);
        free(input->src_directory);
        free(input);
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_output_to_path(rnp_output_t *output, const char *path)
{
    struct rnp_output_st *ob = NULL;
    struct stat           st = {0};

    if (!output || !path) {
        return RNP_ERROR_NULL_POINTER;
    }
    ob = (rnp_output_st *) calloc(1, sizeof(*ob));
    if (!ob) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        // a bit hacky, just save the directory path
        ob->dst_directory = strdup(path);
        if (!ob->dst_directory) {
            free(ob);
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    } else {
        // simple output to a file
        rnp_result_t ret = init_file_dest(&ob->dst, path, true);
        if (ret) {
            free(ob);
            return ret;
        }
    }
    *output = ob;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_output_to_memory(rnp_output_t *output, size_t max_alloc)
{
    // checks
    if (!output) {
        return RNP_ERROR_NULL_POINTER;
    }

    *output = (rnp_output_t) calloc(1, sizeof(**output));
    if (!*output) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    rnp_result_t ret = init_mem_dest(&(*output)->dst, NULL, max_alloc);
    if (ret) {
        free(*output);
        *output = NULL;
        return ret;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_output_memory_get_buf(rnp_output_t output, uint8_t **buf, size_t *len, bool do_copy)
{
    if (!output || !buf || !len) {
        return RNP_ERROR_NULL_POINTER;
    }

    *len = output->dst.writeb;
    *buf = (uint8_t *) mem_dest_get_memory(&output->dst);
    if (!*buf) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (do_copy) {
        uint8_t *tmp_buf = *buf;
        *buf = (uint8_t *) malloc(*len);
        if (!*buf) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        memcpy(*buf, tmp_buf, *len);
    }
    return RNP_SUCCESS;
}

static rnp_result_t
output_writer_bounce(pgp_dest_t *dst, const void *buf, size_t len)
{
    rnp_output_t output = (rnp_output_t) dst->param;
    if (!output->writer) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!output->writer(output->app_ctx, buf, len)) {
        return RNP_ERROR_WRITE;
    }
    return RNP_SUCCESS;
}

static void
output_closer_bounce(pgp_dest_t *dst, bool discard)
{
    rnp_output_t output = (rnp_output_t) dst->param;
    if (output->closer) {
        output->closer(output->app_ctx, discard);
    }
}

rnp_result_t
rnp_output_to_null(rnp_output_t *output)
{
    // checks
    if (!output) {
        return RNP_ERROR_NULL_POINTER;
    }

    *output = (rnp_output_t) calloc(1, sizeof(**output));
    if (!*output) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    rnp_result_t ret = init_null_dest(&(*output)->dst);
    if (ret) {
        free(*output);
        *output = NULL;
        return ret;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_output_to_callback(rnp_output_t *       output,
                       rnp_output_writer_t *writer,
                       rnp_output_closer_t *closer,
                       void *               app_ctx)
{
    // checks
    if (!output || !writer) {
        return RNP_ERROR_NULL_POINTER;
    }

    *output = (rnp_output_t) calloc(1, sizeof(**output));
    if (!*output) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    (*output)->writer = writer;
    (*output)->closer = closer;
    (*output)->app_ctx = app_ctx;

    pgp_dest_t *dst = &(*output)->dst;
    dst->write = output_writer_bounce;
    dst->close = output_closer_bounce;
    dst->param = *output;
    dst->type = PGP_STREAM_MEMORY;
    dst->writeb = 0;
    dst->werr = RNP_SUCCESS;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_output_destroy(rnp_output_t output)
{
    if (output) {
        dst_close(&output->dst, !output->keep);
        free(output->dst_directory);
        free(output);
    }
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_add_signature(rnp_ffi_t                ffi,
                     list *                   signatures,
                     rnp_key_handle_t         key,
                     rnp_ctx_t *              ctx,
                     rnp_op_sign_signature_t *sig)
{
    rnp_op_sign_signature_t newsig = NULL;

    if (!signatures || !key) {
        return RNP_ERROR_NULL_POINTER;
    }

    newsig = (rnp_op_sign_signature_t) list_append(signatures, NULL, sizeof(*newsig));
    if (!newsig) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    newsig->signer.key = find_suitable_key(
      PGP_OP_SIGN, get_key_prefer_public(key), &key->ffi->key_provider, PGP_KF_SIGN);
    if (newsig->signer.key && !pgp_key_is_secret(newsig->signer.key)) {
        pgp_key_request_ctx_t ctx = {.op = PGP_OP_SIGN, .secret = true};
        ctx.search.type = PGP_KEY_SEARCH_GRIP;
        memcpy(ctx.search.by.grip, pgp_key_get_grip(newsig->signer.key), PGP_KEY_GRIP_SIZE);
        newsig->signer.key = pgp_request_key(&key->ffi->key_provider, &ctx);
    }
    if (!newsig->signer.key) {
        list_remove((list_item *) newsig);
        return RNP_ERROR_NO_SUITABLE_KEY;
    }

    /* set default create/expire times */
    newsig->signer.sigcreate = ctx->sigcreate;
    newsig->signer.sigexpire = ctx->sigexpire;
    newsig->ffi = ffi;

    if (sig) {
        *sig = newsig;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_armor(rnp_ctx_t *ctx, bool armored)
{
    if (!ctx) {
        return RNP_ERROR_NULL_POINTER;
    }
    ctx->armor = armored;
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_compression(rnp_ffi_t ffi, rnp_ctx_t *ctx, const char *compression, int level)
{
    if (!ctx) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_compression_type_t zalg = PGP_C_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(compress_alg_map, string, type, compression, zalg);
    if (zalg == PGP_C_UNKNOWN) {
        FFI_LOG(ffi, "Invalid compression: %s", compression);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    ctx->zalg = (int) zalg;
    ctx->zlevel = level;
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_hash(rnp_ffi_t ffi, rnp_ctx_t *ctx, const char *hash)
{
    if (!ctx) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!str_to_hash_alg(hash, &ctx->halg)) {
        FFI_LOG(ffi, "Invalid hash: %s", hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_creation_time(rnp_ctx_t *ctx, uint32_t create)
{
    if (!ctx) {
        return RNP_ERROR_NULL_POINTER;
    }
    ctx->sigcreate = create;
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_expiration_time(rnp_ctx_t *ctx, uint32_t expire)
{
    if (!ctx) {
        return RNP_ERROR_NULL_POINTER;
    }
    ctx->sigexpire = expire;
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_file_name(rnp_ctx_t *ctx, const char *filename)
{
    if (!ctx) {
        return RNP_ERROR_NULL_POINTER;
    }
    return RNP_ERROR_NOT_IMPLEMENTED;
}

static rnp_result_t
rnp_op_set_file_mtime(rnp_ctx_t *ctx, uint32_t mtime)
{
    if (!ctx) {
        return RNP_ERROR_NULL_POINTER;
    }
    return RNP_ERROR_NOT_IMPLEMENTED;
}

static void
rnp_op_signatures_destroy(list *signatures)
{
    list_destroy(signatures);
}

rnp_result_t
rnp_op_encrypt_create(rnp_op_encrypt_t *op,
                      rnp_ffi_t         ffi,
                      rnp_input_t       input,
                      rnp_output_t      output)
{
    // checks
    if (!op || !ffi || !input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }

    *op = (rnp_op_encrypt_t) calloc(1, sizeof(**op));
    if (!*op) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    rnp_ctx_init_ffi(&(*op)->rnpctx, ffi);
    (*op)->ffi = ffi;
    (*op)->input = input;
    (*op)->output = output;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_encrypt_add_recipient(rnp_op_encrypt_t op, rnp_key_handle_t handle)
{
    // checks
    if (!op || !handle) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = find_suitable_key(PGP_OP_ENCRYPT,
                                       get_key_prefer_public(handle),
                                       &handle->ffi->key_provider,
                                       PGP_KF_ENCRYPT);
    if (!list_append(&op->rnpctx.recipients, &key, sizeof(key))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_encrypt_add_signature(rnp_op_encrypt_t         op,
                             rnp_key_handle_t         key,
                             rnp_op_sign_signature_t *sig)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_add_signature(op->ffi, &op->signatures, key, &op->rnpctx, sig);
}

rnp_result_t
rnp_op_encrypt_set_hash(rnp_op_encrypt_t op, const char *hash)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_hash(op->ffi, &op->rnpctx, hash);
}

rnp_result_t
rnp_op_encrypt_set_creation_time(rnp_op_encrypt_t op, uint32_t create)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_creation_time(&op->rnpctx, create);
}

rnp_result_t
rnp_op_encrypt_set_expiration_time(rnp_op_encrypt_t op, uint32_t expire)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_expiration_time(&op->rnpctx, expire);
}

rnp_result_t
rnp_op_encrypt_add_password(rnp_op_encrypt_t op,
                            const char *     password,
                            const char *     s2k_hash,
                            size_t           iterations,
                            const char *     s2k_cipher)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!op || !password) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!*password) {
        // no blank passwords
        FFI_LOG(op->ffi, "Blank password");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // set some defaults
    if (!s2k_hash) {
        s2k_hash = DEFAULT_HASH_ALG;
    }
    if (!s2k_cipher) {
        s2k_cipher = DEFAULT_SYMM_ALG;
    }
    // parse
    pgp_hash_alg_t hash_alg = PGP_HASH_UNKNOWN;
    if (!str_to_hash_alg(s2k_hash, &hash_alg)) {
        FFI_LOG(op->ffi, "Invalid hash: %s", s2k_hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_symm_alg_t symm_alg = PGP_SA_UNKNOWN;
    if (!str_to_cipher(s2k_cipher, &symm_alg)) {
        FFI_LOG(op->ffi, "Invalid cipher: %s", s2k_hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    // derive key, etc
    ret = rnp_ctx_add_encryption_password(&op->rnpctx, password, hash_alg, symm_alg, 0);
    return ret;
}

rnp_result_t
rnp_op_encrypt_set_armor(rnp_op_encrypt_t op, bool armored)
{
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_armor(&op->rnpctx, armored);
}

rnp_result_t
rnp_op_encrypt_set_cipher(rnp_op_encrypt_t op, const char *cipher)
{
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_cipher(cipher, &op->rnpctx.ealg)) {
        FFI_LOG(op->ffi, "Invalid cipher: %s", cipher);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_encrypt_set_aead(rnp_op_encrypt_t op, const char *alg)
{
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    op->rnpctx.aalg = PGP_AEAD_NONE;
    ARRAY_LOOKUP_BY_STRCASE(aead_alg_map, string, type, alg, op->rnpctx.aalg);

    if ((op->rnpctx.aalg == PGP_AEAD_NONE) && strcmp(alg, aead_alg_map[0].string)) {
        FFI_LOG(op->ffi, "Invalid AEAD algorithm: %s", alg);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_encrypt_set_compression(rnp_op_encrypt_t op, const char *compression, int level)
{
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_compression(op->ffi, &op->rnpctx, compression, level);
}

rnp_result_t
rnp_op_encrypt_set_file_name(rnp_op_encrypt_t op, const char *filename)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_file_name(&op->rnpctx, filename);
}

rnp_result_t
rnp_op_encrypt_set_file_mtime(rnp_op_encrypt_t op, uint32_t mtime)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_file_mtime(&op->rnpctx, mtime);
}

static pgp_write_handler_t
pgp_write_handler(pgp_password_provider_t *pass_provider,
                  rnp_ctx_t *              rnpctx,
                  void *                   param,
                  pgp_key_provider_t *     key_provider)
{
    pgp_write_handler_t handler;
    memset(&handler, 0, sizeof(handler));
    handler.password_provider = pass_provider;
    handler.ctx = rnpctx;
    handler.param = param;
    handler.key_provider = key_provider;
    return handler;
}

static rnp_result_t
rnp_op_add_signatures(list opsigs, rnp_ctx_t *ctx)
{
    for (list_item *sig = list_front(opsigs); sig; sig = list_next(sig)) {
        rnp_signer_info_t       sinfo = {};
        rnp_op_sign_signature_t osig = (rnp_op_sign_signature_t) sig;

        if (!osig->signer.key) {
            return RNP_ERROR_NO_SUITABLE_KEY;
        }

        sinfo = osig->signer;
        if (!osig->hash_set) {
            sinfo.halg = ctx->halg;
        }
        if (!osig->expiry_set) {
            sinfo.sigexpire = ctx->sigexpire;
        }
        if (!osig->create_set) {
            sinfo.sigcreate = ctx->sigcreate;
        }

        if (!list_append(&ctx->signers, &sinfo, sizeof(sinfo))) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }

    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_encrypt_execute(rnp_op_encrypt_t op)
{
    // checks
    if (!op || !op->input || !op->output) {
        return RNP_ERROR_NULL_POINTER;
    }

    // set the default hash alg if none was specified
    if (!op->rnpctx.halg) {
        op->rnpctx.halg = DEFAULT_PGP_HASH_ALG;
    }
    pgp_write_handler_t handler =
      pgp_write_handler(&op->ffi->pass_provider, &op->rnpctx, NULL, &op->ffi->key_provider);

    rnp_result_t ret;
    if (list_length(op->signatures)) {
        if ((ret = rnp_op_add_signatures(op->signatures, &op->rnpctx))) {
            return ret;
        }
        ret = rnp_encrypt_sign_src(&handler, &op->input->src, &op->output->dst);
    } else {
        ret = rnp_encrypt_src(&handler, &op->input->src, &op->output->dst);
    }

    dst_flush(&op->output->dst);
    op->output->keep = ret == RNP_SUCCESS;
    op->input = NULL;
    op->output = NULL;
    return ret;
}

rnp_result_t
rnp_op_encrypt_destroy(rnp_op_encrypt_t op)
{
    if (op) {
        rnp_ctx_free(&op->rnpctx);
        rnp_op_signatures_destroy(&op->signatures);
        free(op);
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_sign_create(rnp_op_sign_t *op, rnp_ffi_t ffi, rnp_input_t input, rnp_output_t output)
{
    // checks
    if (!op || !ffi || !input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }

    *op = (rnp_op_sign_t) calloc(1, sizeof(**op));
    if (!*op) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    rnp_ctx_init_ffi(&(*op)->rnpctx, ffi);
    (*op)->ffi = ffi;
    (*op)->input = input;
    (*op)->output = output;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_sign_cleartext_create(rnp_op_sign_t *op,
                             rnp_ffi_t      ffi,
                             rnp_input_t    input,
                             rnp_output_t   output)
{
    rnp_result_t res = rnp_op_sign_create(op, ffi, input, output);
    if (!res) {
        (*op)->rnpctx.clearsign = true;
    }
    return res;
}

rnp_result_t
rnp_op_sign_detached_create(rnp_op_sign_t *op,
                            rnp_ffi_t      ffi,
                            rnp_input_t    input,
                            rnp_output_t   signature)
{
    rnp_result_t res = rnp_op_sign_create(op, ffi, input, signature);
    if (!res) {
        (*op)->rnpctx.detached = true;
    }
    return res;
}

rnp_result_t
rnp_op_sign_add_signature(rnp_op_sign_t op, rnp_key_handle_t key, rnp_op_sign_signature_t *sig)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_add_signature(op->ffi, &op->signatures, key, &op->rnpctx, sig);
}

rnp_result_t
rnp_op_sign_signature_set_hash(rnp_op_sign_signature_t sig, const char *hash)
{
    if (!sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_hash_alg(hash, &sig->signer.halg)) {
        FFI_LOG(sig->ffi, "Invalid hash: %s", hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    sig->hash_set = true;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_sign_signature_set_creation_time(rnp_op_sign_signature_t sig, uint32_t create)
{
    if (!sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    sig->signer.sigcreate = create;
    sig->create_set = true;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_sign_signature_set_expiration_time(rnp_op_sign_signature_t sig, uint32_t expires)
{
    if (!sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    sig->signer.sigexpire = expires;
    sig->expiry_set = true;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_sign_set_armor(rnp_op_sign_t op, bool armored)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_armor(&op->rnpctx, armored);
}

rnp_result_t
rnp_op_sign_set_compression(rnp_op_sign_t op, const char *compression, int level)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_compression(op->ffi, &op->rnpctx, compression, level);
}

rnp_result_t
rnp_op_sign_set_hash(rnp_op_sign_t op, const char *hash)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_hash(op->ffi, &op->rnpctx, hash);
}

rnp_result_t
rnp_op_sign_set_creation_time(rnp_op_sign_t op, uint32_t create)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_creation_time(&op->rnpctx, create);
}

rnp_result_t
rnp_op_sign_set_expiration_time(rnp_op_sign_t op, uint32_t expire)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_expiration_time(&op->rnpctx, expire);
}

rnp_result_t
rnp_op_sign_set_file_name(rnp_op_sign_t op, const char *filename)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_file_name(&op->rnpctx, filename);
}

rnp_result_t
rnp_op_sign_set_file_mtime(rnp_op_sign_t op, uint32_t mtime)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_file_mtime(&op->rnpctx, mtime);
}

rnp_result_t
rnp_op_sign_execute(rnp_op_sign_t op)
{
    // checks
    if (!op || !op->input || !op->output) {
        return RNP_ERROR_NULL_POINTER;
    }

    // set the default hash alg if none was specified
    if (!op->rnpctx.halg) {
        op->rnpctx.halg = DEFAULT_PGP_HASH_ALG;
    }
    pgp_write_handler_t handler =
      pgp_write_handler(&op->ffi->pass_provider, &op->rnpctx, NULL, &op->ffi->key_provider);

    rnp_result_t ret;
    if ((ret = rnp_op_add_signatures(op->signatures, &op->rnpctx))) {
        return ret;
    }
    ret = rnp_sign_src(&handler, &op->input->src, &op->output->dst);

    dst_flush(&op->output->dst);
    op->output->keep = ret == RNP_SUCCESS;
    op->input = NULL;
    op->output = NULL;
    return ret;
}

rnp_result_t
rnp_op_sign_destroy(rnp_op_sign_t op)
{
    if (op) {
        rnp_ctx_free(&op->rnpctx);
        rnp_op_signatures_destroy(&op->signatures);
        free(op);
    }
    return RNP_SUCCESS;
}

static void
rnp_op_verify_on_signatures(pgp_signature_info_t *sigs, int count, void *param)
{
    struct rnp_op_verify_signature_st res;
    rnp_op_verify_t                   op = (rnp_op_verify_t) param;

    op->signatures = (rnp_op_verify_signature_t) calloc(count, sizeof(*op->signatures));
    if (!op->signatures) {
        // TODO: report allocation error?
        return;
    }
    op->signature_count = count;

    for (int i = 0; i < count; i++) {
        memset(&res, 0, sizeof(res));

        res.sig_create = signature_get_creation(sigs[i].sig);
        res.sig_expires = signature_get_expiration(sigs[i].sig);
        signature_get_keyid(sigs[i].sig, res.keyid);
        res.halg = sigs[i].sig->halg;

        if (sigs[i].unknown) {
            res.verify_status = RNP_ERROR_KEY_NOT_FOUND;
        } else if (sigs[i].valid) {
            res.verify_status = sigs[i].expired ? RNP_ERROR_SIGNATURE_EXPIRED : RNP_SUCCESS;
        } else {
            res.verify_status =
              sigs[i].no_signer ? RNP_ERROR_KEY_NOT_FOUND : RNP_ERROR_SIGNATURE_INVALID;
        }

        res.ffi = op->ffi;
        op->signatures[i] = res;
    }
}

static bool
rnp_verify_src_provider(pgp_parse_handler_t *handler, pgp_source_t *src)
{
    /* this one is called only when input for detached signature is needed */
    rnp_op_verify_t op = (rnp_op_verify_t) handler->param;
    *src = op->detached_input->src;
    /* we should give ownership on src to caller */
    memset(&op->detached_input->src, 0, sizeof(op->detached_input->src));
    return true;
};

static bool
rnp_verify_dest_provider(pgp_parse_handler_t *handler,
                         pgp_dest_t **        dst,
                         bool *               closedst,
                         const char *         filename)
{
    rnp_op_verify_t op = (rnp_op_verify_t) handler->param;
    *dst = &(op->output->dst);
    *closedst = false;
    op->filename = filename ? strdup(filename) : NULL;

    return true;
}

rnp_result_t
rnp_op_verify_create(rnp_op_verify_t *op,
                     rnp_ffi_t        ffi,
                     rnp_input_t      input,
                     rnp_output_t     output)
{
    if (!op || !ffi || !input) {
        return RNP_ERROR_NULL_POINTER;
    }

    *op = (rnp_op_verify_t) calloc(1, sizeof(**op));
    if (!*op) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    rnp_ctx_init_ffi(&(*op)->rnpctx, ffi);
    (*op)->ffi = ffi;
    (*op)->input = input;
    (*op)->output = output;

    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_verify_detached_create(rnp_op_verify_t *op,
                              rnp_ffi_t        ffi,
                              rnp_input_t      input,
                              rnp_input_t      signature)
{
    if (!op || !ffi || !input || !signature) {
        return RNP_ERROR_NULL_POINTER;
    }

    *op = (rnp_op_verify_t) calloc(1, sizeof(**op));
    if (!*op) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    rnp_ctx_init_ffi(&(*op)->rnpctx, ffi);
    (*op)->ffi = ffi;
    (*op)->input = signature;
    (*op)->detached_input = input;

    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_verify_execute(rnp_op_verify_t op)
{
    pgp_parse_handler_t handler;

    handler.password_provider = &op->ffi->pass_provider;
    handler.key_provider = &op->ffi->key_provider;
    handler.on_signatures = rnp_op_verify_on_signatures;
    handler.src_provider = rnp_verify_src_provider;
    handler.dest_provider = rnp_verify_dest_provider;
    handler.param = op;
    handler.ctx = &op->rnpctx;

    rnp_result_t ret = process_pgp_source(&handler, &op->input->src);
    if (op->output) {
        dst_flush(&op->output->dst);
        op->output->keep = ret == RNP_SUCCESS;
    }
    return ret;
}

rnp_result_t
rnp_op_verify_get_signature_count(rnp_op_verify_t op, size_t *count)
{
    if (!op || !count) {
        return RNP_ERROR_NULL_POINTER;
    }

    *count = op->signature_count;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_verify_get_signature_at(rnp_op_verify_t op, size_t idx, rnp_op_verify_signature_t *sig)
{
    if (!op || !sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (idx >= op->signature_count) {
        FFI_LOG(op->ffi, "Invalid signature index: %zu", idx);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *sig = &op->signatures[idx];
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_verify_get_file_info(rnp_op_verify_t op, char **filename, uint32_t *mtime)
{
    if (mtime) {
        *mtime = op->file_mtime;
    }
    if (filename) {
        if (op->filename) {
            *filename = strdup(op->filename);
        } else {
            *filename = NULL;
        }
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_verify_destroy(rnp_op_verify_t op)
{
    if (op) {
        rnp_ctx_free(&op->rnpctx);
        free(op->signatures);
        free(op->filename);
        free(op);
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_verify_signature_get_status(rnp_op_verify_signature_t sig)
{
    if (!sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    return sig->verify_status;
}

rnp_result_t
rnp_op_verify_signature_get_hash(rnp_op_verify_signature_t sig, char **hash)
{
    if (!sig || !hash) {
        return RNP_ERROR_NULL_POINTER;
    }

    const char *hname = NULL;
    ARRAY_LOOKUP_BY_ID(hash_alg_map, type, string, sig->halg, hname);
    if (hname) {
        *hash = strdup(hname);
        return RNP_SUCCESS;
    }
    return RNP_ERROR_BAD_STATE;
}

rnp_result_t
rnp_op_verify_signature_get_key(rnp_op_verify_signature_t sig, rnp_key_handle_t *key)
{
    rnp_ffi_t        ffi = sig->ffi;
    pgp_key_search_t search;

    // create a search (since we'll use this later anyways)
    search.type = PGP_KEY_SEARCH_KEYID;
    memcpy(search.by.keyid, sig->keyid, PGP_KEY_ID_SIZE);

    // search the stores
    pgp_key_t *pub = rnp_key_store_search(ffi->pubring, &search, NULL);
    pgp_key_t *sec = rnp_key_store_search(ffi->secring, &search, NULL);
    if (!pub && !sec) {
        return RNP_ERROR_KEY_NOT_FOUND;
    }

    struct rnp_key_handle_st *handle = (rnp_key_handle_st *) calloc(1, sizeof(*handle));
    if (!handle) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    handle->ffi = ffi;
    handle->pub = pub;
    handle->sec = sec;
    handle->locator = search;
    *key = handle;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_verify_signature_get_times(rnp_op_verify_signature_t sig,
                                  uint32_t *                create,
                                  uint32_t *                expires)
{
    if (create) {
        *create = sig->sig_create;
    }
    if (expires) {
        *expires = sig->sig_expires;
    }

    return RNP_SUCCESS;
}

static bool
rnp_decrypt_dest_provider(pgp_parse_handler_t *handler,
                          pgp_dest_t **        dst,
                          bool *               closedst,
                          const char *         filename)
{
    *dst = &((rnp_output_t) handler->param)->dst;
    *closedst = false;
    return true;
}

rnp_result_t
rnp_decrypt(rnp_ffi_t ffi, rnp_input_t input, rnp_output_t output)
{
    rnp_ctx_t rnpctx;

    // checks
    if (!ffi || !input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }

    rnp_ctx_init_ffi(&rnpctx, ffi);
    pgp_parse_handler_t handler;
    memset(&handler, 0, sizeof(handler));
    handler.password_provider = &ffi->pass_provider;
    handler.key_provider = &ffi->key_provider;
    handler.dest_provider = rnp_decrypt_dest_provider;
    handler.param = output;
    handler.ctx = &rnpctx;

    rnp_result_t ret = process_pgp_source(&handler, &input->src);
    dst_flush(&output->dst);
    output->keep = (ret == RNP_SUCCESS);
    return ret;
}

static rnp_result_t
str_to_locator(rnp_ffi_t         ffi,
               pgp_key_search_t *locator,
               const char *      identifier_type,
               const char *      identifier)
{
    // parse the identifier type
    locator->type = PGP_KEY_SEARCH_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(identifier_type_map, string, type, identifier_type, locator->type);
    if (locator->type == PGP_KEY_SEARCH_UNKNOWN) {
        FFI_LOG(ffi, "Invalid identifier type: %s", identifier_type);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    // see what type we have
    switch (locator->type) {
    case PGP_KEY_SEARCH_USERID:
        if (snprintf(locator->by.userid, sizeof(locator->by.userid), "%s", identifier) >=
            (int) sizeof(locator->by.userid)) {
            FFI_LOG(ffi, "UserID too long");
            return RNP_ERROR_BAD_PARAMETERS;
        }
        break;
    case PGP_KEY_SEARCH_KEYID: {
        if (strlen(identifier) != (PGP_KEY_ID_SIZE * 2) ||
            !rnp_hex_decode(identifier, locator->by.keyid, sizeof(locator->by.keyid))) {
            FFI_LOG(ffi, "Invalid keyid: %s", identifier);
            return RNP_ERROR_BAD_PARAMETERS;
        }
    } break;
    case PGP_KEY_SEARCH_FINGERPRINT: {
        // TODO: support v5 fingerprints
        if (strlen(identifier) != (PGP_FINGERPRINT_SIZE * 2)) {
            FFI_LOG(ffi, "Invalid fingerprint: %s", identifier);
            return RNP_ERROR_BAD_PARAMETERS;
        }
        locator->by.fingerprint.length = rnp_hex_decode(
          identifier, locator->by.fingerprint.fingerprint, PGP_FINGERPRINT_SIZE);
        if (!locator->by.fingerprint.length) {
            FFI_LOG(ffi, "Invalid fingerprint: %s", identifier);
            return RNP_ERROR_BAD_PARAMETERS;
        }
    } break;
    case PGP_KEY_SEARCH_GRIP: {
        if (strlen(identifier) != (PGP_KEY_GRIP_SIZE * 2) ||
            !rnp_hex_decode(identifier, locator->by.grip, sizeof(locator->by.grip))) {
            FFI_LOG(ffi, "Invalid grip: %s", identifier);
            return RNP_ERROR_BAD_PARAMETERS;
        }
    } break;
    default:
        // should never happen
        assert(false);
        return RNP_ERROR_BAD_STATE;
    }
    return RNP_SUCCESS;
}

static bool
locator_to_str(const pgp_key_search_t *locator,
               const char **           identifier_type,
               char *                  identifier,
               size_t                  identifier_size)
{
    // find the identifier type string with the map
    *identifier_type = NULL;
    ARRAY_LOOKUP_BY_ID(identifier_type_map, type, string, locator->type, *identifier_type);
    if (!*identifier_type) {
        return false;
    }
    // fill in the actual identifier
    switch (locator->type) {
    case PGP_KEY_SEARCH_USERID:
        if (snprintf(identifier, identifier_size, "%s", locator->by.userid) >=
            (int) identifier_size) {
            return false;
        }
        break;
    case PGP_KEY_SEARCH_KEYID:
        if (!rnp_hex_encode(locator->by.keyid,
                            PGP_KEY_ID_SIZE,
                            identifier,
                            identifier_size,
                            RNP_HEX_UPPERCASE)) {
            return false;
        }
        break;
    case PGP_KEY_SEARCH_FINGERPRINT:
        if (!rnp_hex_encode(locator->by.fingerprint.fingerprint,
                            locator->by.fingerprint.length,
                            identifier,
                            identifier_size,
                            RNP_HEX_UPPERCASE)) {
            return false;
        }
        break;
    case PGP_KEY_SEARCH_GRIP:
        if (!rnp_hex_encode(locator->by.grip,
                            PGP_KEY_GRIP_SIZE,
                            identifier,
                            identifier_size,
                            RNP_HEX_UPPERCASE)) {
            return false;
        }
        break;
    default:
        assert(false);
        return false;
    }
    return true;
}

rnp_result_t
rnp_locate_key(rnp_ffi_t         ffi,
               const char *      identifier_type,
               const char *      identifier,
               rnp_key_handle_t *handle)
{
    // checks
    if (!ffi || !identifier_type || !identifier || !handle) {
        return RNP_ERROR_NULL_POINTER;
    }

    // figure out the identifier type
    pgp_key_search_t locator = {(pgp_key_search_type_t) 0};
    rnp_result_t     ret = str_to_locator(ffi, &locator, identifier_type, identifier);
    if (ret) {
        return ret;
    }

    // search pubring
    pgp_key_t *pub = rnp_key_store_search(ffi->pubring, &locator, NULL);
    // search secring
    pgp_key_t *sec = rnp_key_store_search(ffi->secring, &locator, NULL);

    if (pub || sec) {
        *handle = (rnp_key_handle_t) malloc(sizeof(**handle));
        if (!handle) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        (*handle)->ffi = ffi;
        (*handle)->pub = pub;
        (*handle)->sec = sec;
        (*handle)->locator = locator;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_export(rnp_key_handle_t handle, rnp_output_t output, uint32_t flags)
{
    pgp_dest_t *     dst = NULL;
    pgp_dest_t       armordst = {};
    pgp_key_t *      key = NULL;
    rnp_key_store_t *store = NULL;
    bool             export_subs = false;
    bool             armored = false;

    // checks
    if (!handle || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    dst = &output->dst;
    if ((flags & RNP_KEY_EXPORT_PUBLIC) && (flags & RNP_KEY_EXPORT_SECRET)) {
        FFI_LOG(handle->ffi, "Invalid export flags, select only public or secret, not both.");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // handle flags
    if (flags & RNP_KEY_EXPORT_ARMORED) {
        flags &= ~RNP_KEY_EXPORT_ARMORED;
        armored = true;
    }
    if (flags & RNP_KEY_EXPORT_PUBLIC) {
        flags &= ~RNP_KEY_EXPORT_PUBLIC;
        key = get_key_require_public(handle);
        store = handle->ffi->pubring;
    } else if (flags & RNP_KEY_EXPORT_SECRET) {
        flags &= ~RNP_KEY_EXPORT_SECRET;
        key = get_key_require_secret(handle);
        store = handle->ffi->secring;
    } else {
        FFI_LOG(handle->ffi, "must specify public or secret key for export");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (flags & RNP_KEY_EXPORT_SUBKEYS) {
        flags &= ~RNP_KEY_EXPORT_SUBKEYS;
        export_subs = true;
    }
    // check for any unrecognized flags
    if (flags) {
        FFI_LOG(handle->ffi, "unrecognized flags remaining: 0x%X", flags);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    // make sure we found our key
    if (!key) {
        FFI_LOG(handle->ffi, "no suitable key found");
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    // only PGP packets supported for now
    if (key->format != GPG_KEY_STORE && key->format != KBX_KEY_STORE) {
        return RNP_ERROR_NOT_IMPLEMENTED;
    }
    if (armored) {
        rnp_result_t res;
        if ((res = init_armored_dst(&armordst,
                                    &output->dst,
                                    pgp_key_is_secret(key) ? PGP_ARMORED_SECRET_KEY :
                                                             PGP_ARMORED_PUBLIC_KEY))) {
            return res;
        }
        dst = &armordst;
    }
    // write
    if (pgp_key_is_primary_key(key)) {
        // primary key, write just the primary or primary and all subkeys
        if (!pgp_write_xfer_key(dst, key, export_subs ? store : NULL)) {
            return RNP_ERROR_GENERIC;
        }
    } else {
        // subkeys flag is only valid for primary
        if (export_subs) {
            FFI_LOG(handle->ffi, "export with subkeys requested but key is primary");
            return RNP_ERROR_BAD_PARAMETERS;
        }
        // subkey, write the primary + this subkey only
        pgp_key_t *primary;
        if (!(primary = rnp_key_store_get_key_by_grip(store, pgp_key_get_primary_grip(key)))) {
            // shouldn't happen
            return RNP_ERROR_GENERIC;
        }
        if (!pgp_write_xfer_key(dst, primary, NULL)) {
            return RNP_ERROR_GENERIC;
        }
        if (!pgp_write_xfer_key(dst, key, NULL)) {
            return RNP_ERROR_GENERIC;
        }
    }
    if (armored) {
        dst_finish(&armordst);
        dst_close(&armordst, false);
    }
    output->keep = true;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_remove(rnp_key_handle_t key, uint32_t flags)
{
    if (!key || !key->ffi) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (flags == 0) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (flags & RNP_KEY_REMOVE_PUBLIC) {
        if (!key->ffi->pubring || !key->pub) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        pgp_key_free_data(key->pub);
        if (!rnp_key_store_remove_key(key->ffi->pubring, key->pub)) {
            return RNP_ERROR_KEY_NOT_FOUND;
        }
        key->pub = NULL;
    }
    if (flags & RNP_KEY_REMOVE_SECRET) {
        if (!key->ffi->secring || !key->sec) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        pgp_key_free_data(key->sec);
        if (!rnp_key_store_remove_key(key->ffi->secring, key->sec)) {
            return RNP_ERROR_KEY_NOT_FOUND;
        }
        key->sec = NULL;
    }

    return RNP_SUCCESS;
}

static bool
pk_alg_allows_custom_curve(pgp_pubkey_alg_t pkalg)
{
    switch (pkalg) {
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
        return true;
    default:
        return false;
    }
}

static bool
parse_preferences(json_object *jso, pgp_user_prefs_t *prefs)
{
    static const struct {
        const char *   key;
        enum json_type type;
    } properties[] = {{"hashes", json_type_array},
                      {"ciphers", json_type_array},
                      {"compression", json_type_array},
                      {"key server", json_type_string}};

    for (size_t iprop = 0; iprop < ARRAY_SIZE(properties); iprop++) {
        json_object *value = NULL;
        const char * key = properties[iprop].key;

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }

        if (!json_object_is_type(value, properties[iprop].type)) {
            return false;
        }
        if (!rnp_strcasecmp(key, "hashes")) {
            int length = json_object_array_length(value);
            for (int i = 0; i < length; i++) {
                json_object *item = json_object_array_get_idx(value, i);
                if (!json_object_is_type(item, json_type_string)) {
                    return false;
                }
                pgp_hash_alg_t hash_alg = PGP_HASH_UNKNOWN;
                if (!str_to_hash_alg(json_object_get_string(item), &hash_alg)) {
                    return false;
                }
                if (!pgp_user_prefs_add_hash_alg(prefs, hash_alg)) {
                    return false;
                }
            }
        } else if (!rnp_strcasecmp(key, "ciphers")) {
            int length = json_object_array_length(value);
            for (int i = 0; i < length; i++) {
                json_object *item = json_object_array_get_idx(value, i);
                if (!json_object_is_type(item, json_type_string)) {
                    return false;
                }
                pgp_symm_alg_t symm_alg = PGP_SA_UNKNOWN;
                if (!str_to_cipher(json_object_get_string(item), &symm_alg)) {
                    return false;
                }
                if (!pgp_user_prefs_add_symm_alg(prefs, symm_alg)) {
                    return false;
                }
            }
        } else if (!rnp_strcasecmp(key, "compression")) {
            int length = json_object_array_length(value);
            for (int i = 0; i < length; i++) {
                json_object *item = json_object_array_get_idx(value, i);
                if (!json_object_is_type(item, json_type_string)) {
                    return false;
                }
                pgp_compression_type_t z_alg = PGP_C_UNKNOWN;
                ARRAY_LOOKUP_BY_STRCASE(
                  compress_alg_map, string, type, json_object_get_string(item), z_alg);
                if (z_alg == PGP_C_UNKNOWN) {
                    return false;
                }
                if (!pgp_user_prefs_add_z_alg(prefs, z_alg)) {
                    return false;
                }
            }
        } else if (!rnp_strcasecmp(key, "key server")) {
            prefs->key_server = (uint8_t *) strdup(json_object_get_string(value));
            if (!prefs->key_server) {
                return false;
            }
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return true;
}

static bool
parse_keygen_crypto(json_object *jso, rnp_keygen_crypto_params_t *crypto)
{
    static const struct {
        const char *   key;
        enum json_type type;
    } properties[] = {{"type", json_type_string},
                      {"curve", json_type_string},
                      {"length", json_type_int},
                      {"hash", json_type_string}};

    for (size_t i = 0; i < ARRAY_SIZE(properties); i++) {
        json_object *value = NULL;
        const char * key = properties[i].key;

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }

        if (!json_object_is_type(value, properties[i].type)) {
            return false;
        }
        // TODO: make sure there are no duplicate keys in the JSON
        if (!rnp_strcasecmp(key, "type")) {
            if (!str_to_pubkey_alg(json_object_get_string(value), &crypto->key_alg)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "length")) {
            int length = json_object_get_int(value);
            switch (crypto->key_alg) {
            case PGP_PKA_RSA:
                crypto->rsa.modulus_bit_len = length;
                break;
            case PGP_PKA_DSA:
                crypto->dsa.p_bitlen = length;
                break;
            case PGP_PKA_ELGAMAL:
                crypto->elgamal.key_bitlen = length;
                break;
            default:
                return false;
            }
        } else if (!rnp_strcasecmp(key, "curve")) {
            if (!pk_alg_allows_custom_curve(crypto->key_alg)) {
                return false;
            }
            if (!curve_str_to_type(json_object_get_string(value), &crypto->ecc.curve)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "hash")) {
            if (!str_to_hash_alg(json_object_get_string(value), &crypto->hash_alg)) {
                return false;
            }
        } else {
            // shouldn't happen
            return false;
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return true;
}

static bool
parse_protection(json_object *jso, rnp_key_protection_params_t *protection)
{
    static const struct {
        const char *   key;
        enum json_type type;
    } properties[] = {{"cipher", json_type_string},
                      {"mode", json_type_string},
                      {"iterations", json_type_int},
                      {"hash", json_type_string}};

    for (size_t i = 0; i < ARRAY_SIZE(properties); i++) {
        json_object *value = NULL;
        const char * key = properties[i].key;

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }

        if (!json_object_is_type(value, properties[i].type)) {
            return false;
        }
        // TODO: make sure there are no duplicate keys in the JSON
        if (!rnp_strcasecmp(key, "cipher")) {
            if (!str_to_cipher(json_object_get_string(value), &protection->symm_alg)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "mode")) {
            if (!str_to_cipher_mode(json_object_get_string(value), &protection->cipher_mode)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "iterations")) {
            protection->iterations = json_object_get_int(value);
        } else if (!rnp_strcasecmp(key, "hash")) {
            if (!str_to_hash_alg(json_object_get_string(value), &protection->hash_alg)) {
                return false;
            }
        } else {
            // shouldn't happen
            return false;
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return true;
}

static bool
parse_keygen_primary(json_object *jso, rnp_action_keygen_t *desc)
{
    static const char *properties[] = {
      "userid", "usage", "expiration", "preferences", "protection"};
    rnp_selfsig_cert_info_t *cert = &desc->primary.keygen.cert;

    if (!parse_keygen_crypto(jso, &desc->primary.keygen.crypto)) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(properties); i++) {
        json_object *value = NULL;
        const char * key = properties[i];

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }
        if (!rnp_strcasecmp(key, "userid")) {
            if (!json_object_is_type(value, json_type_string)) {
                return false;
            }
            const char *userid = json_object_get_string(value);
            if (strlen(userid) >= sizeof(cert->userid)) {
                return false;
            }
            strcpy((char *) cert->userid, userid);
        } else if (!rnp_strcasecmp(key, "usage")) {
            switch (json_object_get_type(value)) {
            case json_type_array: {
                int length = json_object_array_length(value);
                for (int j = 0; j < length; j++) {
                    json_object *item = json_object_array_get_idx(value, j);
                    if (!json_object_is_type(item, json_type_string)) {
                        return false;
                    }
                    uint8_t flag = 0;
                    if (!str_to_key_flag(json_object_get_string(item), &flag)) {
                        return false;
                    }
                    // check for duplicate
                    if (cert->key_flags & flag) {
                        return false;
                    }
                    cert->key_flags |= flag;
                }
            } break;
            case json_type_string: {
                if (!str_to_key_flag(json_object_get_string(value), &cert->key_flags)) {
                    return false;
                }
            } break;
            default:
                return false;
            }
        } else if (!rnp_strcasecmp(key, "expiration")) {
            if (!json_object_is_type(value, json_type_int)) {
                return false;
            }
            cert->key_expiration = json_object_get_int(value);
        } else if (!rnp_strcasecmp(key, "preferences")) {
            if (!json_object_is_type(value, json_type_object)) {
                return false;
            }
            if (!parse_preferences(value, &cert->prefs)) {
                return false;
            }
            if (json_object_object_length(value) != 0) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "protection")) {
            if (!json_object_is_type(value, json_type_object)) {
                return false;
            }
            if (!parse_protection(value, &desc->primary.protection)) {
                return false;
            }
            if (json_object_object_length(value) != 0) {
                return false;
            }
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return json_object_object_length(jso) == 0;
}

static bool
parse_keygen_sub(json_object *jso, rnp_action_keygen_t *desc)
{
    static const char *         properties[] = {"usage", "expiration", "protection"};
    rnp_selfsig_binding_info_t *binding = &desc->subkey.keygen.binding;

    if (!parse_keygen_crypto(jso, &desc->subkey.keygen.crypto)) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(properties); i++) {
        json_object *value = NULL;
        const char * key = properties[i];

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }
        if (!rnp_strcasecmp(key, "usage")) {
            switch (json_object_get_type(value)) {
            case json_type_array: {
                int length = json_object_array_length(value);
                for (int j = 0; j < length; j++) {
                    json_object *item = json_object_array_get_idx(value, j);
                    if (!json_object_is_type(item, json_type_string)) {
                        return false;
                    }
                    uint8_t flag = 0;
                    if (!str_to_key_flag(json_object_get_string(item), &flag)) {
                        return false;
                    }
                    if (binding->key_flags & flag) {
                        return false;
                    }
                    binding->key_flags |= flag;
                }
            } break;
            case json_type_string: {
                if (!str_to_key_flag(json_object_get_string(value), &binding->key_flags)) {
                    return false;
                }
            } break;
            default:
                return false;
            }
        } else if (!rnp_strcasecmp(key, "expiration")) {
            if (!json_object_is_type(value, json_type_int)) {
                return false;
            }
            binding->key_expiration = json_object_get_int(value);
        } else if (!rnp_strcasecmp(key, "protection")) {
            if (!json_object_is_type(value, json_type_object)) {
                return false;
            }
            if (!parse_protection(value, &desc->subkey.protection)) {
                return false;
            }
            if (json_object_object_length(value) != 0) {
                return false;
            }
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return json_object_object_length(jso) == 0;
}

static bool
gen_json_grips(char **result, const pgp_key_t *primary, const pgp_key_t *sub)
{
    bool         ret = false;
    json_object *jso = NULL;
    char         grip[PGP_KEY_GRIP_SIZE * 2 + 1];

    if (!result) {
        return false;
    }

    jso = json_object_new_object();
    if (!jso) {
        return false;
    }

    if (primary) {
        json_object *jsoprimary = json_object_new_object();
        if (!jsoprimary) {
            goto done;
        }
        json_object_object_add(jso, "primary", jsoprimary);
        if (!rnp_hex_encode(pgp_key_get_grip(primary),
                            PGP_KEY_GRIP_SIZE,
                            grip,
                            sizeof(grip),
                            RNP_HEX_UPPERCASE)) {
            goto done;
        }
        json_object *jsogrip = json_object_new_string(grip);
        if (!jsogrip) {
            goto done;
        }
        json_object_object_add(jsoprimary, "grip", jsogrip);
    }
    if (sub) {
        json_object *jsosub = json_object_new_object();
        if (!jsosub) {
            goto done;
        }
        json_object_object_add(jso, "sub", jsosub);
        if (!rnp_hex_encode(pgp_key_get_grip(sub),
                            PGP_KEY_GRIP_SIZE,
                            grip,
                            sizeof(grip),
                            RNP_HEX_UPPERCASE)) {
            goto done;
        }
        json_object *jsogrip = json_object_new_string(grip);
        if (!jsogrip) {
            goto done;
        }
        json_object_object_add(jsosub, "grip", jsogrip);
    }
    *result = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));

    ret = true;
done:
    json_object_put(jso);
    return ret;
}

rnp_result_t
rnp_generate_key_json(rnp_ffi_t ffi, const char *json, char **results)
{
    rnp_result_t        ret = RNP_ERROR_GENERIC;
    json_object *       jso = NULL;
    rnp_action_keygen_t keygen_desc = {};
    char *              identifier_type = NULL;
    char *              identifier = NULL;
    pgp_key_t           primary_pub = {0};
    pgp_key_t           primary_sec = {0};
    pgp_key_t           sub_pub = {0};
    pgp_key_t           sub_sec = {0};
    json_object *       jsoprimary = NULL;
    json_object *       jsosub = NULL;
    json_tokener_error  error;

    // checks
    if (!ffi || (!ffi->pubring && !ffi->secring) || !json) {
        return RNP_ERROR_NULL_POINTER;
    }

    // parse the JSON
    jso = json_tokener_parse_verbose(json, &error);
    if (!jso) {
        // syntax error or some other issue
        FFI_LOG(ffi, "Invalid JSON: %s", json_tokener_error_desc(error));
        ret = RNP_ERROR_BAD_FORMAT;
        goto done;
    }

    // locate the appropriate sections
    {
        json_object_object_foreach(jso, key, value)
        {
            json_object **dest = NULL;

            if (rnp_strcasecmp(key, "primary") == 0) {
                dest = &jsoprimary;
            } else if (rnp_strcasecmp(key, "sub") == 0) {
                dest = &jsosub;
            } else {
                // unrecognized key in the object
                FFI_LOG(ffi, "Unexpected key in JSON: %s", key);
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }

            // duplicate "primary"/"sub"
            if (*dest) {
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }
            *dest = value;
        }
    }

    if (jsoprimary && jsosub) { // generating primary+sub
        if (!parse_keygen_primary(jsoprimary, &keygen_desc) ||
            !parse_keygen_sub(jsosub, &keygen_desc)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
        if (!pgp_generate_keypair(&ffi->rng,
                                  &keygen_desc.primary.keygen,
                                  &keygen_desc.subkey.keygen,
                                  true,
                                  &primary_sec,
                                  &primary_pub,
                                  &sub_sec,
                                  &sub_pub,
                                  ffi->secring->format)) {
            goto done;
        }
        if (results && !gen_json_grips(results, &primary_pub, &sub_pub)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (ffi->pubring) {
            if (!rnp_key_store_add_key(ffi->pubring, &primary_pub)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
            primary_pub = (pgp_key_t){0};
            if (!rnp_key_store_add_key(ffi->pubring, &sub_pub)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
            sub_pub = (pgp_key_t){0};
        }
        if (ffi->secring) {
            /* add key/subkey protection */
            if (keygen_desc.primary.protection.symm_alg &&
                !rnp_key_add_protection(&primary_sec,
                                        ffi->secring->format,
                                        &keygen_desc.primary.protection,
                                        &ffi->pass_provider)) {
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }

            if (keygen_desc.subkey.protection.symm_alg &&
                !rnp_key_add_protection(&sub_sec,
                                        ffi->secring->format,
                                        &keygen_desc.subkey.protection,
                                        &ffi->pass_provider)) {
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }

            if (!rnp_key_store_add_key(ffi->secring, &primary_sec)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
            primary_sec = (pgp_key_t){0};
            if (!rnp_key_store_add_key(ffi->secring, &sub_sec)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
            sub_sec = (pgp_key_t){0};
        }
    } else if (jsoprimary && !jsosub) { // generating primary only
        keygen_desc.primary.keygen.crypto.rng = &ffi->rng;
        if (!parse_keygen_primary(jsoprimary, &keygen_desc)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
        if (!pgp_generate_primary_key(&keygen_desc.primary.keygen,
                                      true,
                                      &primary_sec,
                                      &primary_pub,
                                      ffi->secring->format)) {
            goto done;
        }
        if (results && !gen_json_grips(results, &primary_pub, NULL)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (ffi->pubring) {
            if (!rnp_key_store_add_key(ffi->pubring, &primary_pub)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
            primary_pub = (pgp_key_t){0};
        }
        if (ffi->secring) {
            /* encrypt secret key if specified */
            if (keygen_desc.primary.protection.symm_alg &&
                !rnp_key_add_protection(&primary_sec,
                                        ffi->secring->format,
                                        &keygen_desc.primary.protection,
                                        &ffi->pass_provider)) {
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }

            if (!rnp_key_store_add_key(ffi->secring, &primary_sec)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
            primary_sec = (pgp_key_t){0};
        }
    } else if (jsosub) { // generating subkey only
        json_object *jsoparent = NULL;
        if (!json_object_object_get_ex(jsosub, "primary", &jsoparent) ||
            json_object_object_length(jsoparent) != 1) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
        json_object_object_foreach(jsoparent, key, value)
        {
            if (!json_object_is_type(value, json_type_string)) {
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }
            identifier_type = strdup(key);
            identifier = strdup(json_object_get_string(value));
        }
        if (!identifier_type || !identifier) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        rnp_strlwr(identifier_type);
        json_object_object_del(jsosub, "primary");

        pgp_key_search_t locator = {(pgp_key_search_type_t) 0};
        rnp_result_t     tmpret = str_to_locator(ffi, &locator, identifier_type, identifier);
        if (tmpret) {
            ret = tmpret;
            goto done;
        }

        pgp_key_t *primary_pub = rnp_key_store_search(ffi->pubring, &locator, NULL);
        pgp_key_t *primary_sec = rnp_key_store_search(ffi->secring, &locator, NULL);
        if (!primary_sec || !primary_pub) {
            ret = RNP_ERROR_KEY_NOT_FOUND;
            goto done;
        }
        if (!parse_keygen_sub(jsosub, &keygen_desc)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
        keygen_desc.subkey.keygen.crypto.rng = &ffi->rng;
        if (!pgp_generate_subkey(&keygen_desc.subkey.keygen,
                                 true,
                                 primary_sec,
                                 primary_pub,
                                 &sub_sec,
                                 &sub_pub,
                                 &ffi->pass_provider,
                                 ffi->secring->format)) {
            goto done;
        }
        if (results && !gen_json_grips(results, NULL, &sub_pub)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (ffi->pubring) {
            if (!rnp_key_store_add_key(ffi->pubring, &sub_pub)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
            sub_pub = (pgp_key_t){0};
        }
        if (ffi->secring) {
            /* encrypt subkey if specified */
            if (keygen_desc.subkey.protection.symm_alg &&
                !rnp_key_add_protection(&sub_sec,
                                        ffi->secring->format,
                                        &keygen_desc.subkey.protection,
                                        &ffi->pass_provider)) {
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }

            if (!rnp_key_store_add_key(ffi->secring, &sub_sec)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
            sub_sec = (pgp_key_t){0};
        }
    } else {
        // nothing to generate...
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    pgp_key_free_data(&primary_pub);
    pgp_key_free_data(&primary_sec);
    pgp_key_free_data(&sub_pub);
    pgp_key_free_data(&sub_sec);
    json_object_put(jso);
    free(identifier_type);
    free(identifier);
    pgp_free_user_prefs(&keygen_desc.primary.keygen.cert.prefs);
    return ret;
}

rnp_result_t
rnp_generate_key_ex(rnp_ffi_t         ffi,
                    const char *      key_alg,
                    const char *      sub_alg,
                    uint32_t          key_bits,
                    uint32_t          sub_bits,
                    const char *      key_curve,
                    const char *      sub_curve,
                    const char *      userid,
                    const char *      password,
                    rnp_key_handle_t *key)
{
    rnp_op_generate_t op = NULL;
    rnp_op_generate_t subop = NULL;
    rnp_key_handle_t  primary = NULL;
    rnp_key_handle_t  subkey = NULL;
    rnp_result_t      ret = RNP_ERROR_KEY_GENERATION;

    /* generate primary key */
    if ((ret = rnp_op_generate_create(&op, ffi, key_alg))) {
        return ret;
    }
    if (key_bits && (ret = rnp_op_generate_set_bits(op, key_bits))) {
        goto done;
    }
    if (key_curve && (ret = rnp_op_generate_set_curve(op, key_curve))) {
        goto done;
    }
    if ((ret = rnp_op_generate_set_userid(op, userid))) {
        goto done;
    }
    if ((ret = rnp_op_generate_add_usage(op, "sign"))) {
        goto done;
    }
    if ((ret = rnp_op_generate_add_usage(op, "certify"))) {
        goto done;
    }
    if ((ret = rnp_op_generate_execute(op))) {
        goto done;
    }
    if ((ret = rnp_op_generate_get_key(op, &primary))) {
        goto done;
    }
    /* generate subkey if requested */
    if (!sub_alg) {
        goto done;
    }
    if ((ret = rnp_op_generate_subkey_create(&subop, ffi, primary, sub_alg))) {
        goto done;
    }
    if (sub_bits && (ret = rnp_op_generate_set_bits(subop, sub_bits))) {
        goto done;
    }
    if (sub_curve && (ret = rnp_op_generate_set_curve(subop, sub_curve))) {
        goto done;
    }
    if (password && (ret = rnp_op_generate_set_protection_password(subop, password))) {
        goto done;
    }
    if ((ret = rnp_op_generate_add_usage(subop, "encrypt"))) {
        goto done;
    }
    if ((ret = rnp_op_generate_execute(subop))) {
        goto done;
    }
    if ((ret = rnp_op_generate_get_key(subop, &subkey))) {
        goto done;
    }
done:
    /* only now will protect the primary key - to not spend time on unlocking to sign subkey */
    if (!ret && password) {
        ret = rnp_key_protect(primary, password, NULL, NULL, NULL, 0);
    }
    if (ret && primary) {
        rnp_key_remove(primary, RNP_KEY_REMOVE_PUBLIC | RNP_KEY_REMOVE_SECRET);
    }
    if (ret && subkey) {
        rnp_key_remove(subkey, RNP_KEY_REMOVE_PUBLIC | RNP_KEY_REMOVE_SECRET);
    }
    if (!ret && key) {
        *key = primary;
    } else {
        rnp_key_handle_destroy(primary);
    }
    rnp_key_handle_destroy(subkey);
    rnp_op_generate_destroy(op);
    rnp_op_generate_destroy(subop);
    return ret;
}

rnp_result_t
rnp_generate_key_rsa(rnp_ffi_t         ffi,
                     uint32_t          bits,
                     uint32_t          subbits,
                     const char *      userid,
                     const char *      password,
                     rnp_key_handle_t *key)
{
    return rnp_generate_key_ex(
      ffi, "RSA", subbits ? "RSA" : NULL, bits, subbits, NULL, NULL, userid, password, key);
}

rnp_result_t
rnp_generate_key_dsa_eg(rnp_ffi_t         ffi,
                        uint32_t          bits,
                        uint32_t          subbits,
                        const char *      userid,
                        const char *      password,
                        rnp_key_handle_t *key)
{
    return rnp_generate_key_ex(ffi,
                               "DSA",
                               subbits ? "ElGamal" : NULL,
                               bits,
                               subbits,
                               NULL,
                               NULL,
                               userid,
                               password,
                               key);
}

rnp_result_t
rnp_generate_key_ec(rnp_ffi_t         ffi,
                    const char *      curve,
                    const char *      userid,
                    const char *      password,
                    rnp_key_handle_t *key)
{
    return rnp_generate_key_ex(
      ffi, "ECDSA", "ECDH", 0, 0, curve, curve, userid, password, key);
}

rnp_result_t
rnp_generate_key_25519(rnp_ffi_t         ffi,
                       const char *      userid,
                       const char *      password,
                       rnp_key_handle_t *key)
{
    return rnp_generate_key_ex(
      ffi, "EDDSA", "ECDH", 0, 0, NULL, "Curve25519", userid, password, key);
}

rnp_result_t
rnp_generate_key_sm2(rnp_ffi_t         ffi,
                     const char *      userid,
                     const char *      password,
                     rnp_key_handle_t *key)
{
    return rnp_generate_key_ex(ffi, "SM2", "SM2", 0, 0, NULL, NULL, userid, password, key);
}

rnp_result_t
rnp_op_generate_create(rnp_op_generate_t *op, rnp_ffi_t ffi, const char *alg)
{
    pgp_pubkey_alg_t key_alg = PGP_PKA_NOTHING;

    if (!op || !ffi || !alg) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!ffi->pubring || !ffi->secring) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!str_to_pubkey_alg(alg, &key_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!(pgp_pk_alg_capabilities(key_alg) & PGP_KF_SIGN)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *op = (rnp_op_generate_t) calloc(1, sizeof(**op));
    if (!*op) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    (*op)->ffi = ffi;
    (*op)->primary = true;
    (*op)->crypto.key_alg = key_alg;
    (*op)->crypto.rng = &ffi->rng;

    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_subkey_create(rnp_op_generate_t *op,
                              rnp_ffi_t          ffi,
                              rnp_key_handle_t   primary,
                              const char *       alg)
{
    if (!op || !ffi || !alg || !primary) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!ffi->pubring || !ffi->secring) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* TODO: should we do these checks here or may leave it up till generate call? */
    bool flag = false;
    if (rnp_key_have_secret(primary, &flag) || !flag) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (rnp_key_is_primary(primary, &flag) || !flag) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!pgp_key_can_sign(primary->sec)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_pubkey_alg_t key_alg = PGP_PKA_NOTHING;
    if (!str_to_pubkey_alg(alg, &key_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *op = (rnp_op_generate_t) calloc(1, sizeof(**op));
    if (!*op) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    (*op)->ffi = ffi;
    (*op)->primary = false;
    (*op)->crypto.key_alg = key_alg;
    (*op)->crypto.rng = &ffi->rng;
    (*op)->primary_sec = primary->sec;
    (*op)->primary_pub = primary->pub;

    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_bits(rnp_op_generate_t op, uint32_t bits)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }

    switch (op->crypto.key_alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        op->crypto.rsa.modulus_bit_len = bits;
        break;
    case PGP_PKA_ELGAMAL:
        op->crypto.elgamal.key_bitlen = bits;
        break;
    case PGP_PKA_DSA:
        op->crypto.dsa.p_bitlen = bits;
        break;
    default:
        return RNP_ERROR_BAD_PARAMETERS;
    }

    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_hash(rnp_op_generate_t op, const char *hash)
{
    if (!op || !hash) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_hash_alg(hash, &op->crypto.hash_alg)) {
        FFI_LOG(op->ffi, "Invalid hash: %s", hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_dsa_qbits(rnp_op_generate_t op, uint32_t qbits)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (op->crypto.key_alg != PGP_PKA_DSA) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    op->crypto.dsa.q_bitlen = qbits;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_curve(rnp_op_generate_t op, const char *curve)
{
    if (!op || !curve) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!pk_alg_allows_custom_curve(op->crypto.key_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!curve_str_to_type(curve, &op->crypto.ecc.curve)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_protection_password(rnp_op_generate_t op, const char *password)
{
    if (!op || !password) {
        return RNP_ERROR_NULL_POINTER;
    }
    free(op->password);
    op->password = strdup(password);
    if (!op->password) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_protection_cipher(rnp_op_generate_t op, const char *cipher)
{
    if (!op || !cipher) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_cipher(cipher, &op->protection.symm_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_protection_hash(rnp_op_generate_t op, const char *hash)
{
    if (!op || !hash) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_hash_alg(hash, &op->protection.hash_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_protection_mode(rnp_op_generate_t op, const char *mode)
{
    if (!op || !mode) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_cipher_mode(mode, &op->protection.cipher_mode)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_protection_iterations(rnp_op_generate_t op, uint32_t iterations)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    op->protection.iterations = iterations;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_add_usage(rnp_op_generate_t op, const char *usage)
{
    if (!op || !usage) {
        return RNP_ERROR_NULL_POINTER;
    }
    uint8_t flag = 0;
    if (!str_to_key_flag(usage, &flag)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!(pgp_pk_alg_capabilities(op->crypto.key_alg) & flag)) {
        return RNP_ERROR_NOT_SUPPORTED;
    }
    if (op->primary) {
        op->cert.key_flags |= flag;
    } else {
        op->binding.key_flags |= flag;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_clear_usage(rnp_op_generate_t op)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (op->primary) {
        op->cert.key_flags = 0;
    } else {
        op->binding.key_flags = 0;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_userid(rnp_op_generate_t op, const char *userid)
{
    if (!op || !userid) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (strlen(userid) >= sizeof(op->cert.userid)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    strcpy((char *) op->cert.userid, userid);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_expiration(rnp_op_generate_t op, uint32_t expiration)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (op->primary) {
        op->cert.key_expiration = expiration;
    } else {
        op->binding.key_expiration = expiration;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_clear_pref_hashes(rnp_op_generate_t op)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!pgp_user_prefs_set_hash_algs(&op->cert.prefs, NULL, 0)) {
        return RNP_ERROR_BAD_STATE;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_add_pref_hash(rnp_op_generate_t op, const char *hash)
{
    if (!op || !hash) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_hash_alg_t hash_alg = PGP_HASH_UNKNOWN;
    if (!str_to_hash_alg(hash, &hash_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!pgp_user_prefs_add_hash_alg(&op->cert.prefs, hash_alg)) {
        return RNP_ERROR_BAD_STATE;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_clear_pref_compression(rnp_op_generate_t op)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!pgp_user_prefs_set_z_algs(&op->cert.prefs, NULL, 0)) {
        return RNP_ERROR_BAD_STATE;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_add_pref_compression(rnp_op_generate_t op, const char *compression)
{
    if (!op || !compression) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_compression_type_t z_alg = PGP_C_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(compress_alg_map, string, type, compression, z_alg);
    if (z_alg == PGP_C_UNKNOWN) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!pgp_user_prefs_add_z_alg(&op->cert.prefs, z_alg)) {
        return RNP_ERROR_BAD_STATE;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_clear_pref_ciphers(rnp_op_generate_t op)
{
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!pgp_user_prefs_set_symm_algs(&op->cert.prefs, NULL, 0)) {
        return RNP_ERROR_BAD_STATE;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_add_pref_cipher(rnp_op_generate_t op, const char *cipher)
{
    if (!op || !cipher) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_symm_alg_t symm_alg = PGP_SA_UNKNOWN;
    if (!str_to_cipher(cipher, &symm_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!pgp_user_prefs_add_symm_alg(&op->cert.prefs, symm_alg)) {
        return RNP_ERROR_BAD_STATE;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_set_pref_keyserver(rnp_op_generate_t op, const char *keyserver)
{
    uint8_t *_keyserver = NULL;
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (keyserver) {
        _keyserver = (uint8_t *) strdup(keyserver);
        if (!_keyserver) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }
    free(op->cert.prefs.key_server);
    op->cert.prefs.key_server = _keyserver;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_execute(rnp_op_generate_t op)
{
    if (!op || !op->ffi) {
        return RNP_ERROR_NULL_POINTER;
    }

    rnp_result_t ret = RNP_ERROR_GENERIC;
    pgp_key_t    pub = {};
    pgp_key_t    sec = {};

    if (op->primary) {
        rnp_keygen_primary_desc_t keygen = {};
        keygen.crypto = op->crypto;
        keygen.cert = op->cert;
        op->cert.prefs = {}; /* generate call will free prefs */

        if (!pgp_generate_primary_key(&keygen, true, &sec, &pub, op->ffi->secring->format)) {
            return RNP_ERROR_KEY_GENERATION;
        }
    } else {
        /* subkey generation */
        rnp_keygen_subkey_desc_t keygen = {};
        keygen.crypto = op->crypto;
        keygen.binding = op->binding;
        if (!pgp_generate_subkey(&keygen,
                                 true,
                                 op->primary_sec,
                                 op->primary_pub,
                                 &sec,
                                 &pub,
                                 &op->ffi->pass_provider,
                                 op->ffi->secring->format)) {
            return RNP_ERROR_KEY_GENERATION;
        }
    }

    /* add public key part to the keyring */
    if (!(op->gen_pub = rnp_key_store_add_key(op->ffi->pubring, &pub))) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    pub = {};

    /* encrypt secret key if requested */
    if (op->password) {
        pgp_password_provider_t prov = {.callback = rnp_password_provider_string,
                                        .userdata = (void *) op->password};
        if (!rnp_key_add_protection(&sec, op->ffi->secring->format, &op->protection, &prov)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
    }

    /* add secret key to the keyring */
    if (!(op->gen_sec = rnp_key_store_add_key(op->ffi->secring, &sec))) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    sec = {};
    ret = RNP_SUCCESS;
done:
    if (op->password) {
        pgp_forget(op->password, strlen(op->password) + 1);
        free(op->password);
        op->password = NULL;
    }
    if (ret && op->gen_pub) {
        pgp_key_free_data(op->gen_pub);
        rnp_key_store_remove_key(op->ffi->pubring, op->gen_pub);
        op->gen_pub = NULL;
    }
    if (ret && op->gen_sec) {
        pgp_key_free_data(op->gen_sec);
        rnp_key_store_remove_key(op->ffi->secring, op->gen_sec);
        op->gen_sec = NULL;
    }
    pgp_key_free_data(&sec);
    pgp_key_free_data(&pub);
    return ret;
}

rnp_result_t
rnp_op_generate_get_key(rnp_op_generate_t op, rnp_key_handle_t *handle)
{
    if (!op || !handle) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->gen_sec || !op->gen_pub) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *handle = (rnp_key_handle_t) malloc(sizeof(**handle));
    if (!handle) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    (*handle)->ffi = op->ffi;
    (*handle)->pub = op->gen_pub;
    (*handle)->sec = op->gen_sec;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_generate_destroy(rnp_op_generate_t op)
{
    if (op) {
        pgp_free_user_prefs(&op->cert.prefs);
        if (op->password) {
            pgp_forget(op->password, strlen(op->password) + 1);
            free(op->password);
            op->password = NULL;
        }
        free(op);
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_handle_destroy(rnp_key_handle_t key)
{
    // This does not free key->key which is owned by the keyring
    free(key);
    return RNP_SUCCESS;
}

void
rnp_buffer_destroy(void *ptr)
{
    free(ptr);
}

static pgp_key_t *
get_key_require_public(rnp_key_handle_t handle)
{
    if (!handle->pub) {
        pgp_key_request_ctx_t request;
        request.secret = false;

        // try fingerprint
        request.search.type = PGP_KEY_SEARCH_FINGERPRINT;
        request.search.by.fingerprint = *pgp_key_get_fp(handle->sec);
        handle->pub = pgp_request_key(&handle->ffi->key_provider, &request);
        if (handle->pub) {
            return handle->pub;
        }

        // try keyid
        request.search.type = PGP_KEY_SEARCH_KEYID;
        memcpy(request.search.by.keyid, pgp_key_get_keyid(handle->sec), PGP_KEY_ID_SIZE);
        handle->pub = pgp_request_key(&handle->ffi->key_provider, &request);
    }
    return handle->pub;
}

static pgp_key_t *
get_key_prefer_public(rnp_key_handle_t handle)
{
    pgp_key_t *pub = get_key_require_public(handle);
    return pub ? pub : get_key_require_secret(handle);
}

static pgp_key_t *
get_key_require_secret(rnp_key_handle_t handle)
{
    if (!handle->sec) {
        pgp_key_request_ctx_t request;
        request.secret = true;

        // try fingerprint
        request.search.type = PGP_KEY_SEARCH_FINGERPRINT;
        request.search.by.fingerprint = *pgp_key_get_fp(handle->pub);
        handle->sec = pgp_request_key(&handle->ffi->key_provider, &request);
        if (handle->sec) {
            return handle->sec;
        }

        // try keyid
        request.search.type = PGP_KEY_SEARCH_KEYID;
        memcpy(request.search.by.keyid, pgp_key_get_keyid(handle->pub), PGP_KEY_ID_SIZE);
        handle->sec = pgp_request_key(&handle->ffi->key_provider, &request);
    }
    return handle->sec;
}

static rnp_result_t
key_get_uid_at(pgp_key_t *key, size_t idx, char **uid)
{
    if (!key || !uid) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (idx >= pgp_key_get_userid_count(key)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    const char *keyuid = pgp_key_get_userid(key, idx);
    size_t      len = strlen(keyuid);
    *uid = (char *) calloc(1, len + 1);
    if (!*uid) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    memcpy(*uid, keyuid, len);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_add_uid(rnp_key_handle_t handle,
                const char *     uid,
                const char *     hash,
                uint32_t         expiration,
                uint8_t          key_flags,
                bool             primary)
{
    rnp_result_t            ret = RNP_ERROR_GENERIC;
    rnp_selfsig_cert_info_t info = {{0}};
    pgp_hash_alg_t          hash_alg = PGP_HASH_UNKNOWN;
    pgp_key_t *             public_key = NULL;
    pgp_key_t *             secret_key = NULL;
    pgp_key_pkt_t *         seckey = NULL;
    pgp_key_pkt_t *         decrypted_seckey = NULL;

    if (!handle || !uid || !hash) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!str_to_hash_alg(hash, &hash_alg)) {
        FFI_LOG(handle->ffi, "Invalid hash: %s", hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (strlen(uid) >= MAX_ID_LENGTH) {
        FFI_LOG(handle->ffi, "UserID too long");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    strcpy((char *) info.userid, uid);

    info.key_flags = key_flags;
    info.key_expiration = expiration;
    info.primary = primary;

    secret_key = get_key_require_secret(handle);
    if (!secret_key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    public_key = get_key_prefer_public(handle);
    if (!public_key && secret_key->format == G10_KEY_STORE) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    seckey = &secret_key->pkt;
    if (!seckey->material.secret) {
        pgp_password_ctx_t ctx = {.op = PGP_OP_ADD_USERID, .key = secret_key};
        decrypted_seckey = pgp_decrypt_seckey(secret_key, &handle->ffi->pass_provider, &ctx);
        if (!decrypted_seckey) {
            return RNP_ERROR_BAD_PASSWORD;
        }
        seckey = decrypted_seckey;
    }
    if (public_key && !pgp_key_add_userid(public_key, seckey, hash_alg, &info)) {
        goto done;
    }
    if ((secret_key && secret_key->format != G10_KEY_STORE) &&
        !pgp_key_add_userid(secret_key, seckey, hash_alg, &info)) {
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    free_key_pkt(decrypted_seckey);
    free(decrypted_seckey);
    return ret;
}

rnp_result_t
rnp_key_get_primary_uid(rnp_key_handle_t handle, char **uid)
{
    if (handle == NULL || uid == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_prefer_public(handle);
    return key_get_uid_at(key, key->uid0_set ? key->uid0 : 0, uid);
}

rnp_result_t
rnp_key_get_uid_count(rnp_key_handle_t handle, size_t *count)
{
    if (handle == NULL || count == NULL) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = get_key_prefer_public(handle);
    *count = pgp_key_get_userid_count(key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_uid_at(rnp_key_handle_t handle, size_t idx, char **uid)
{
    if (handle == NULL || uid == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_prefer_public(handle);
    return key_get_uid_at(key, idx, uid);
}

rnp_result_t
rnp_key_get_subkey_count(rnp_key_handle_t handle, size_t *count)
{
    if (!handle || !count) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    *count = pgp_key_get_subkey_count(key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_subkey_at(rnp_key_handle_t handle, size_t idx, rnp_key_handle_t *subkey)
{
    if (!handle || !subkey) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (idx >= pgp_key_get_subkey_count(key)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    const uint8_t *grip = pgp_key_get_subkey_grip(key, idx);
    char           griphex[PGP_KEY_GRIP_SIZE * 2 + 1] = {0};
    if (!rnp_hex_encode(
          grip, PGP_KEY_GRIP_SIZE, griphex, sizeof(griphex), RNP_HEX_UPPERCASE)) {
        return RNP_ERROR_BAD_STATE;
    }
    return rnp_locate_key(handle->ffi, "grip", griphex, subkey);
}

rnp_result_t
rnp_key_get_alg(rnp_key_handle_t handle, char **alg)
{
    if (!handle || !alg) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t * key = get_key_prefer_public(handle);
    const char *str = NULL;

    ARRAY_LOOKUP_BY_ID(pubkey_alg_map, type, string, pgp_key_get_alg(key), str);
    if (!str) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    char *algcp = strdup(str);
    if (!algcp) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    *alg = algcp;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_bits(rnp_key_handle_t handle, uint32_t *bits)
{
    if (!handle || !bits) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    size_t     _bits = pgp_key_get_bits(key);
    if (!_bits) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *bits = _bits;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_dsa_qbits(rnp_key_handle_t handle, uint32_t *qbits)
{
    if (!handle || !qbits) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    size_t     _qbits = pgp_key_get_dsa_qbits(key);
    if (!_qbits) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *qbits = _qbits;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_curve(rnp_key_handle_t handle, char **curve)
{
    if (!handle || !curve) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t * key = get_key_prefer_public(handle);
    pgp_curve_t _curve = pgp_key_get_curve(key);
    if (_curve == PGP_CURVE_UNKNOWN) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    const char *curvename = NULL;
    if (!curve_type_to_str(_curve, &curvename)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    char *curvenamecp = strdup(curvename);
    if (!curvenamecp) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    *curve = curvenamecp;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_fprint(rnp_key_handle_t handle, char **fprint)
{
    if (handle == NULL || fprint == NULL)
        return RNP_ERROR_NULL_POINTER;

    size_t hex_len = PGP_FINGERPRINT_HEX_SIZE + 1;
    *fprint = (char *) malloc(hex_len);
    if (*fprint == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    pgp_key_t *key = get_key_prefer_public(handle);
    if (!rnp_hex_encode(pgp_key_get_fp(key)->fingerprint,
                        pgp_key_get_fp(key)->length,
                        *fprint,
                        hex_len,
                        RNP_HEX_UPPERCASE)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_keyid(rnp_key_handle_t handle, char **keyid)
{
    if (handle == NULL || keyid == NULL)
        return RNP_ERROR_NULL_POINTER;

    size_t hex_len = PGP_KEY_ID_SIZE * 2 + 1;
    *keyid = (char *) malloc(hex_len);
    if (*keyid == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    pgp_key_t *key = get_key_prefer_public(handle);
    if (!rnp_hex_encode(
          pgp_key_get_keyid(key), PGP_KEY_ID_SIZE, *keyid, hex_len, RNP_HEX_UPPERCASE)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_grip(rnp_key_handle_t handle, char **grip)
{
    if (handle == NULL || grip == NULL)
        return RNP_ERROR_NULL_POINTER;

    size_t hex_len = PGP_KEY_GRIP_SIZE * 2 + 1;
    *grip = (char *) malloc(hex_len);
    if (*grip == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    pgp_key_t *key = get_key_prefer_public(handle);
    if (!rnp_hex_encode(
          pgp_key_get_grip(key), PGP_KEY_GRIP_SIZE, *grip, hex_len, RNP_HEX_UPPERCASE)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_allows_usage(rnp_key_handle_t handle, const char *usage, bool *result)
{
    if (!handle || !usage || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    uint8_t flag = 0;
    if (!str_to_key_flag(usage, &flag)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *result = pgp_key_get_flags(key) & flag;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_creation(rnp_key_handle_t handle, uint32_t *result)
{
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *result = pgp_key_get_creation(key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_expiration(rnp_key_handle_t handle, uint32_t *result)
{
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *result = pgp_key_get_expiration(key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_locked(rnp_key_handle_t handle, bool *result)
{
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    *result = pgp_key_is_locked(key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_lock(rnp_key_handle_t handle)
{
    if (handle == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    if (!pgp_key_lock(key)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_unlock(rnp_key_handle_t handle, const char *password)
{
    if (!handle) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    bool ok = false;
    if (password) {
        pgp_password_provider_t prov = {.callback = rnp_password_provider_string,
                                        .userdata = RNP_UNCONST(password)};
        ok = pgp_key_unlock(key, &prov);
    } else {
        ok = pgp_key_unlock(key, &handle->ffi->pass_provider);
    }
    if (!ok) {
        // likely a bad password
        return RNP_ERROR_BAD_PASSWORD;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_protected(rnp_key_handle_t handle, bool *result)
{
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    *result = pgp_key_is_protected(key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_protect(rnp_key_handle_t handle,
                const char *     password,
                const char *     cipher,
                const char *     cipher_mode,
                const char *     hash,
                size_t           iterations)
{
    rnp_result_t                ret = RNP_ERROR_GENERIC;
    pgp_key_pkt_t *             seckey = NULL;
    pgp_key_pkt_t *             decrypted_seckey = NULL;
    rnp_key_protection_params_t protection = {};

    // checks
    if (!handle || !password) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (cipher && !str_to_cipher(cipher, &protection.symm_alg)) {
        FFI_LOG(handle->ffi, "Invalid cipher: %s", cipher);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (cipher_mode && !str_to_cipher_mode(cipher_mode, &protection.cipher_mode)) {
        FFI_LOG(handle->ffi, "Invalid cipher mode: %s", cipher_mode);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (hash && !str_to_hash_alg(hash, &protection.hash_alg)) {
        FFI_LOG(handle->ffi, "Invalid hash: %s", hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    protection.iterations = iterations;

    // get the key
    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    seckey = &key->pkt;
    if (pgp_key_is_encrypted(key)) {
        pgp_password_ctx_t ctx = {.op = PGP_OP_PROTECT, .key = key};
        decrypted_seckey = pgp_decrypt_seckey(key, &handle->ffi->pass_provider, &ctx);
        if (!decrypted_seckey) {
            goto done;
        }
        seckey = decrypted_seckey;
    }
    if (!pgp_key_protect(key, seckey, key->format, &protection, password)) {
        goto done;
    }
    ret = RNP_SUCCESS;

done:
    free_key_pkt(decrypted_seckey);
    free(decrypted_seckey);
    return ret;
}

rnp_result_t
rnp_key_unprotect(rnp_key_handle_t handle, const char *password)
{
    // checks
    if (!handle) {
        return RNP_ERROR_NULL_POINTER;
    }

    // get the key
    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    bool ok = false;
    if (password) {
        pgp_password_provider_t prov = {.callback = rnp_password_provider_string,
                                        .userdata = RNP_UNCONST(password)};
        ok = pgp_key_unprotect(key, &prov);
    } else {
        ok = pgp_key_unprotect(key, &handle->ffi->pass_provider);
    }
    if (!ok) {
        // likely a bad password
        return RNP_ERROR_BAD_PASSWORD;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_primary(rnp_key_handle_t handle, bool *result)
{
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_prefer_public(handle);
    if (key->format == G10_KEY_STORE) {
        // we can't currently determine this for a G10 secret key
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    *result = pgp_key_is_primary_key(key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_sub(rnp_key_handle_t handle, bool *result)
{
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_prefer_public(handle);
    if (key->format == G10_KEY_STORE) {
        // we can't currently determine this for a G10 secret key
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    *result = pgp_key_is_subkey(key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_have_secret(rnp_key_handle_t handle, bool *result)
{
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    *result = handle->sec != NULL;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_have_public(rnp_key_handle_t handle, bool *result)
{
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = handle->pub != NULL;
    return RNP_SUCCESS;
}

static rnp_result_t
key_to_bytes(pgp_key_t *key, uint8_t **buf, size_t *buf_len)
{
    // get a total byte size
    *buf_len = 0;
    for (size_t i = 0; i < pgp_key_get_rawpacket_count(key); i++) {
        const pgp_rawpacket_t *pkt = pgp_key_get_rawpacket(key, i);
        *buf_len += pkt->length;
    }
    // allocate our buffer
    *buf = (uint8_t *) malloc(*buf_len);
    if (!*buf) {
        *buf_len = 0;
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // copy each packet
    *buf_len = 0;
    for (size_t i = 0; i < pgp_key_get_rawpacket_count(key); i++) {
        const pgp_rawpacket_t *pkt = pgp_key_get_rawpacket(key, i);
        memcpy(*buf + *buf_len, pkt->raw, pkt->length);
        *buf_len += pkt->length;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_get_public_key_data(rnp_key_handle_t handle, uint8_t **buf, size_t *buf_len)
{
    // checks
    if (!handle || !buf || !buf_len) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = handle->pub;
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    return key_to_bytes(key, buf, buf_len);
}

rnp_result_t
rnp_get_secret_key_data(rnp_key_handle_t handle, uint8_t **buf, size_t *buf_len)
{
    // checks
    if (!handle || !buf || !buf_len) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = handle->sec;
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    return key_to_bytes(key, buf, buf_len);
}

static bool
add_json_string_field(json_object *jso, const char *key, const char *value)
{
    json_object *jsostr = json_object_new_string(value);
    if (!jsostr) {
        return false;
    }
    json_object_object_add(jso, key, jsostr);
    return true;
}

static bool
add_json_int_field(json_object *jso, const char *key, int32_t value)
{
    json_object *jsoval = json_object_new_int(value);
    if (!jsoval) {
        return false;
    }
    json_object_object_add(jso, key, jsoval);
    return true;
}

static bool
add_json_key_usage(json_object *jso, uint8_t key_flags)
{
    json_object *jsoarr = json_object_new_array();
    if (!jsoarr) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(key_usage_map); i++) {
        if (key_usage_map[i].mask & key_flags) {
            json_object *jsostr = json_object_new_string(key_usage_map[i].string);
            if (!jsostr) {
                json_object_put(jsoarr);
                return false;
            }
            json_object_array_add(jsoarr, jsostr);
        }
    }
    if (json_object_array_length(jsoarr)) {
        json_object_object_add(jso, "usage", jsoarr);
    } else {
        json_object_put(jsoarr);
    }
    return true;
}

static bool
add_json_key_flags(json_object *jso, uint8_t key_flags)
{
    json_object *jsoarr = json_object_new_array();
    if (!jsoarr) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(key_flags_map); i++) {
        if (key_flags_map[i].mask & key_flags) {
            json_object *jsostr = json_object_new_string(key_flags_map[i].string);
            if (!jsostr) {
                json_object_put(jsoarr);
                return false;
            }
            json_object_array_add(jsoarr, jsostr);
        }
    }
    if (json_object_array_length(jsoarr)) {
        json_object_object_add(jso, "flags", jsoarr);
    } else {
        json_object_put(jsoarr);
    }
    return true;
}

static rnp_result_t
add_json_mpis(json_object *jso, ...)
{
    va_list      ap;
    const char * name;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    va_start(ap, jso);
    while ((name = va_arg(ap, const char *))) {
        pgp_mpi_t *val = va_arg(ap, pgp_mpi_t *);
        if (!val) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
        char *hex = mpi2hex(val);
        if (!hex) {
            // this could probably be other things
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        json_object *jsostr = json_object_new_string(hex);
        free(hex);
        if (!jsostr) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        json_object_object_add(jso, name, jsostr);
    }
    ret = RNP_SUCCESS;

done:
    va_end(ap);
    return ret;
}

static rnp_result_t
add_json_public_mpis(json_object *jso, pgp_key_t *key)
{
    const pgp_key_material_t *km = pgp_key_get_material(key);
    switch (km->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return add_json_mpis(jso, "n", &km->rsa.n, "e", &km->rsa.e, NULL);
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return add_json_mpis(jso, "p", &km->eg.p, "g", &km->eg.g, "y", &km->eg.y, NULL);
    case PGP_PKA_DSA:
        return add_json_mpis(
          jso, "p", &km->dsa.p, "q", &km->dsa.q, "g", &km->dsa.g, "y", &km->dsa.y, NULL);
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        return add_json_mpis(jso, "point", &km->ec.p, NULL);
    default:
        return RNP_ERROR_NOT_SUPPORTED;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
add_json_secret_mpis(json_object *jso, pgp_key_t *key)
{
    const pgp_key_material_t *km = pgp_key_get_material(key);
    switch (pgp_key_get_alg(key)) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return add_json_mpis(
          jso, "d", &km->rsa.d, "p", &km->rsa.p, "q", &km->rsa.q, "u", &km->rsa.u, NULL);
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return add_json_mpis(jso, "x", &km->eg.x, NULL);
    case PGP_PKA_DSA:
        return add_json_mpis(jso, "x", &km->dsa.x, NULL);
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        return add_json_mpis(jso, "x", &km->ec.x, NULL);
    default:
        return RNP_ERROR_NOT_SUPPORTED;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
add_json_sig_mpis(json_object *jso, const pgp_signature_t *sig)
{
    switch (sig->palg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return add_json_mpis(jso, "sig", &sig->material.rsa.s, NULL);
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return add_json_mpis(jso, "r", &sig->material.eg.r, "s", &sig->material.eg.s, NULL);
    case PGP_PKA_DSA:
        return add_json_mpis(jso, "r", &sig->material.dsa.r, "s", &sig->material.dsa.s, NULL);
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        return add_json_mpis(jso, "r", &sig->material.ecc.r, "s", &sig->material.ecc.s, NULL);
    default:
        // TODO: we could use info->unknown and add a hex string of raw data here
        return RNP_ERROR_NOT_SUPPORTED;
    }
    return RNP_SUCCESS;
}

static bool
add_json_user_prefs(json_object *jso, const pgp_user_prefs_t *prefs)
{
    // TODO: instead of using a string "Unknown" as a fallback for these,
    // we could add a string of hex/dec (or even an int)
    if (prefs->symm_alg_count) {
        json_object *jsoarr = json_object_new_array();
        if (!jsoarr) {
            return false;
        }
        json_object_object_add(jso, "ciphers", jsoarr);
        for (unsigned i = 0; i < prefs->symm_alg_count; i++) {
            const char *   name = "Unknown";
            pgp_symm_alg_t alg = (pgp_symm_alg_t) prefs->symm_algs[i];
            ARRAY_LOOKUP_BY_ID(symm_alg_map, type, string, alg, name);
            json_object *jsoname = json_object_new_string(name);
            if (!jsoname || json_object_array_add(jsoarr, jsoname)) {
                return false;
            }
        }
    }
    if (prefs->hash_alg_count) {
        json_object *jsoarr = json_object_new_array();
        if (!jsoarr) {
            return false;
        }
        json_object_object_add(jso, "hashes", jsoarr);
        for (unsigned i = 0; i < prefs->hash_alg_count; i++) {
            const char *   name = "Unknown";
            pgp_hash_alg_t alg = (pgp_hash_alg_t) prefs->hash_algs[i];
            ARRAY_LOOKUP_BY_ID(hash_alg_map, type, string, alg, name);
            json_object *jsoname = json_object_new_string(name);
            if (!jsoname || json_object_array_add(jsoarr, jsoname)) {
                return false;
            }
        }
    }
    if (prefs->z_alg_count) {
        json_object *jsoarr = json_object_new_array();
        if (!jsoarr) {
            return false;
        }
        json_object_object_add(jso, "compression", jsoarr);
        for (unsigned i = 0; i < prefs->z_alg_count; i++) {
            const char *           name = "Unknown";
            pgp_compression_type_t alg = (pgp_compression_type_t) prefs->z_algs[i];
            ARRAY_LOOKUP_BY_ID(compress_alg_map, type, string, alg, name);
            json_object *jsoname = json_object_new_string(name);
            if (!jsoname || json_object_array_add(jsoarr, jsoname)) {
                return false;
            }
        }
    }
    if (prefs->ks_pref_count) {
        json_object *jsoarr = json_object_new_array();
        if (!jsoarr) {
            return false;
        }
        json_object_object_add(jso, "key server preferences", jsoarr);
        for (unsigned i = 0; i < prefs->ks_pref_count; i++) {
            const char *           name = "Unknown";
            pgp_key_server_prefs_t flag = (pgp_key_server_prefs_t) prefs->ks_prefs[i];
            ARRAY_LOOKUP_BY_ID(key_server_prefs_map, type, string, flag, name);
            json_object *jsoname = json_object_new_string(name);
            if (!jsoname || json_object_array_add(jsoarr, jsoname)) {
                return false;
            }
        }
    }
    if (prefs->key_server) {
        if (!add_json_string_field(jso, "key server", (const char *) prefs->key_server)) {
            return false;
        }
    }
    return true;
}

static rnp_result_t
add_json_subsig(json_object *jso, bool is_sub, uint32_t flags, const pgp_subsig_t *subsig)
{
    // userid (if applicable)
    if (!is_sub) {
        json_object *jsouid = json_object_new_int(subsig->uid);
        if (!jsouid) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "userid", jsouid);
    }
    // trust
    json_object *jsotrust = json_object_new_object();
    if (!jsotrust) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "trust", jsotrust);
    // trust (level)
    json_object *jsotrust_level = json_object_new_int(subsig->trustlevel);
    if (!jsotrust_level) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jsotrust, "level", jsotrust_level);
    // trust (amount)
    json_object *jsotrust_amount = json_object_new_int(subsig->trustamount);
    if (!jsotrust_amount) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jsotrust, "amount", jsotrust_amount);
    // key flags (usage)
    if (!add_json_key_usage(jso, subsig->key_flags)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // key flags (other)
    if (!add_json_key_flags(jso, subsig->key_flags)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // preferences
    const pgp_user_prefs_t *prefs = &subsig->prefs;
    if (prefs->symm_alg_count || prefs->hash_alg_count || prefs->z_alg_count ||
        prefs->ks_pref_count || prefs->key_server) {
        json_object *jsoprefs = json_object_new_object();
        if (!jsoprefs) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "preferences", jsoprefs);
        if (!add_json_user_prefs(jsoprefs, prefs)) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }
    const pgp_signature_t *sig = &subsig->sig;
    // version
    json_object *jsoversion = json_object_new_int(sig->version);
    if (!jsoversion) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "version", jsoversion);
    // signature type
    const char *type = "unknown";
    ARRAY_LOOKUP_BY_ID(sig_type_map, type, string, sig->type, type);
    if (!add_json_string_field(jso, "type", type)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // signer key type
    const char *key_type = "unknown";
    ARRAY_LOOKUP_BY_ID(pubkey_alg_map, type, string, sig->palg, key_type);
    if (!add_json_string_field(jso, "key type", key_type)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // hash
    const char *hash = "unknown";
    ARRAY_LOOKUP_BY_ID(hash_alg_map, type, string, sig->halg, hash);
    if (!add_json_string_field(jso, "hash", hash)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // creation time
    json_object *jsocreation_time = json_object_new_int64(signature_get_creation(sig));
    if (!jsocreation_time) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "creation time", jsocreation_time);
    // expiration (seconds)
    json_object *jsoexpiration = json_object_new_int64(signature_get_expiration(sig));
    if (!jsoexpiration) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "expiration", jsoexpiration);
    // signer
    json_object *jsosigner = NULL;
    // TODO: add signer fingerprint as well (no support internally yet)
    if (signature_has_keyid(sig)) {
        jsosigner = json_object_new_object();
        if (!jsosigner) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        char    keyid[PGP_KEY_ID_SIZE * 2 + 1];
        uint8_t signer[PGP_KEY_ID_SIZE] = {0};
        if (!signature_get_keyid(sig, signer) ||
            !rnp_hex_encode(
              signer, PGP_KEY_ID_SIZE, keyid, sizeof(keyid), RNP_HEX_UPPERCASE)) {
            return RNP_ERROR_GENERIC;
        }
        if (!add_json_string_field(jsosigner, "keyid", keyid)) {
            json_object_put(jsosigner);
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }
    json_object_object_add(jso, "signer", jsosigner);
    // mpis
    json_object *jsompis = NULL;
    if (flags & RNP_JSON_SIGNATURE_MPIS) {
        jsompis = json_object_new_object();
        if (!jsompis) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        rnp_result_t tmpret;
        if ((tmpret = add_json_sig_mpis(jsompis, sig))) {
            json_object_put(jsompis);
            return tmpret;
        }
    }
    json_object_object_add(jso, "mpis", jsompis);
    return RNP_SUCCESS;
}

static rnp_result_t
key_to_json(json_object *jso, rnp_key_handle_t handle, uint32_t flags)
{
    bool                      have_sec = handle->sec != NULL;
    bool                      have_pub = handle->pub != NULL;
    pgp_key_t *               key = get_key_prefer_public(handle);
    const char *              str = NULL;
    const pgp_key_material_t *material = pgp_key_get_material(key);

    // type
    ARRAY_LOOKUP_BY_ID(pubkey_alg_map, type, string, pgp_key_get_alg(key), str);
    if (!str) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!add_json_string_field(jso, "type", str)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // length
    if (!add_json_int_field(jso, "length", pgp_key_get_bits(key))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // curve / alg-specific items
    switch (pgp_key_get_alg(key)) {
    case PGP_PKA_ECDH: {
        const char *hash_name = NULL;
        ARRAY_LOOKUP_BY_ID(hash_alg_map, type, string, material->ec.kdf_hash_alg, hash_name);
        if (!hash_name) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        const char *cipher_name = NULL;
        ARRAY_LOOKUP_BY_ID(symm_alg_map, type, string, material->ec.key_wrap_alg, cipher_name);
        if (!cipher_name) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        json_object *jsohash = json_object_new_string(hash_name);
        if (!jsohash) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "kdf hash", jsohash);
        json_object *jsocipher = json_object_new_string(cipher_name);
        if (!jsocipher) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "key wrap cipher", jsocipher);
    } // fall through
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2: {
        const char *curve_name = NULL;
        if (!curve_type_to_str(material->ec.curve, &curve_name)) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        json_object *jsocurve = json_object_new_string(curve_name);
        if (!jsocurve) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "curve", jsocurve);
    } break;
    default:
        break;
    }

    // keyid
    char keyid[PGP_KEY_ID_SIZE * 2 + 1];
    if (!rnp_hex_encode(
          pgp_key_get_keyid(key), PGP_KEY_ID_SIZE, keyid, sizeof(keyid), RNP_HEX_UPPERCASE)) {
        return RNP_ERROR_GENERIC;
    }
    if (!add_json_string_field(jso, "keyid", keyid)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // fingerprint
    char fpr[PGP_FINGERPRINT_SIZE * 2 + 1];
    if (!rnp_hex_encode(pgp_key_get_fp(key)->fingerprint,
                        pgp_key_get_fp(key)->length,
                        fpr,
                        sizeof(fpr),
                        RNP_HEX_UPPERCASE)) {
        return RNP_ERROR_GENERIC;
    }
    if (!add_json_string_field(jso, "fingerprint", fpr)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // grip
    char grip[PGP_KEY_GRIP_SIZE * 2 + 1];
    if (!rnp_hex_encode(
          pgp_key_get_grip(key), PGP_KEY_GRIP_SIZE, grip, sizeof(grip), RNP_HEX_UPPERCASE)) {
        return RNP_ERROR_GENERIC;
    }
    if (!add_json_string_field(jso, "grip", grip)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // revoked
    json_object *jsorevoked = json_object_new_boolean(key->revoked ? TRUE : FALSE);
    if (!jsorevoked) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "revoked", jsorevoked);
    // creation time
    json_object *jsocreation_time = json_object_new_int64(pgp_key_get_creation(key));
    if (!jsocreation_time) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "creation time", jsocreation_time);
    // expiration
    json_object *jsoexpiration = json_object_new_int64(pgp_key_get_expiration(key));
    if (!jsoexpiration) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "expiration", jsoexpiration);
    // key flags (usage)
    if (!add_json_key_usage(jso, pgp_key_get_flags(key))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // key flags (other)
    if (!add_json_key_flags(jso, pgp_key_get_flags(key))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // parent / subkeys
    if (pgp_key_is_primary_key(key)) {
        json_object *jsosubkeys_arr = json_object_new_array();
        if (!jsosubkeys_arr) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "subkey grips", jsosubkeys_arr);
        list_item *subgrip_item = list_front(key->subkey_grips);
        while (subgrip_item) {
            uint8_t *subgrip = (uint8_t *) subgrip_item;
            if (!rnp_hex_encode(
                  subgrip, PGP_KEY_GRIP_SIZE, grip, sizeof(grip), RNP_HEX_UPPERCASE)) {
                return RNP_ERROR_GENERIC;
            }
            json_object *jsostr = json_object_new_string(grip);
            if (!jsostr || json_object_array_add(jsosubkeys_arr, jsostr)) {
                json_object_put(jsostr);
                return RNP_ERROR_OUT_OF_MEMORY;
            }
            subgrip_item = list_next(subgrip_item);
        }
    } else {
        if (!rnp_hex_encode(pgp_key_get_primary_grip(key),
                            PGP_KEY_GRIP_SIZE,
                            grip,
                            sizeof(grip),
                            RNP_HEX_UPPERCASE)) {
            return RNP_ERROR_GENERIC;
        }
        if (!add_json_string_field(jso, "primary key grip", grip)) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }
    // public
    json_object *jsopublic = json_object_new_object();
    if (!jsopublic) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "public key", jsopublic);
    json_object_object_add(
      jsopublic, "present", json_object_new_boolean(have_pub ? TRUE : FALSE));
    if (flags & RNP_JSON_PUBLIC_MPIS) {
        json_object *jsompis = json_object_new_object();
        if (!jsompis) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jsopublic, "mpis", jsompis);
        rnp_result_t tmpret;
        if ((tmpret = add_json_public_mpis(jsompis, key))) {
            return tmpret;
        }
    }
    // secret
    json_object *jsosecret = json_object_new_object();
    if (!jsosecret) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "secret key", jsosecret);
    json_object_object_add(
      jsosecret, "present", json_object_new_boolean(have_sec ? TRUE : FALSE));
    if (have_sec) {
        bool locked = pgp_key_is_locked(handle->sec);
        if (flags & RNP_JSON_SECRET_MPIS) {
            if (locked) {
                json_object_object_add(jsosecret, "mpis", NULL);
            } else {
                json_object *jsompis = json_object_new_object();
                if (!jsompis) {
                    return RNP_ERROR_OUT_OF_MEMORY;
                }
                json_object_object_add(jsosecret, "mpis", jsompis);
                rnp_result_t tmpret;
                if ((tmpret = add_json_secret_mpis(jsompis, handle->sec))) {
                    return tmpret;
                }
            }
        }
        json_object *jsolocked = json_object_new_boolean(locked ? TRUE : FALSE);
        if (!jsolocked) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jsosecret, "locked", jsolocked);
        json_object *jsoprotected =
          json_object_new_boolean(pgp_key_is_protected(handle->sec) ? TRUE : FALSE);
        if (!jsoprotected) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jsosecret, "protected", jsoprotected);
    }
    // userids
    if (pgp_key_is_primary_key(key)) {
        json_object *jsouids_arr = json_object_new_array();
        if (!jsouids_arr) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "userids", jsouids_arr);
        for (unsigned i = 0; i < pgp_key_get_userid_count(key); i++) {
            json_object *jsouid = json_object_new_string(pgp_key_get_userid(key, i));
            if (!jsouid || json_object_array_add(jsouids_arr, jsouid)) {
                json_object_put(jsouid);
                return RNP_ERROR_OUT_OF_MEMORY;
            }
        }
    }
    // signatures
    if (flags & RNP_JSON_SIGNATURES) {
        json_object *jsosigs_arr = json_object_new_array();
        if (!jsosigs_arr) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "signatures", jsosigs_arr);
        for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
            json_object *jsosig = json_object_new_object();
            if (!jsosig || json_object_array_add(jsosigs_arr, jsosig)) {
                json_object_put(jsosig);
                return RNP_ERROR_OUT_OF_MEMORY;
            }
            rnp_result_t tmpret;
            if ((tmpret = add_json_subsig(
                   jsosig, pgp_key_is_subkey(key), flags, pgp_key_get_subsig(key, i)))) {
                return tmpret;
            }
        }
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_to_json(rnp_key_handle_t handle, uint32_t flags, char **result)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;
    json_object *jso = NULL;

    // checks
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    jso = json_object_new_object();
    if (!jso) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    if ((ret = key_to_json(jso, handle, flags))) {
        goto done;
    }
    *result = (char *) json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY);
    if (!*result) {
        goto done;
    }
    *result = strdup(*result);
    if (!*result) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    json_object_put(jso);
    return ret;
}

static rnp_result_t
rnp_dump_src_to_json(pgp_source_t *src, uint32_t flags, char **result)
{
    rnp_dump_ctx_t dumpctx = {};
    json_object *  jso = NULL;
    rnp_result_t   ret = RNP_ERROR_GENERIC;

    if (flags & RNP_JSON_DUMP_MPI) {
        dumpctx.dump_mpi = true;
        flags &= ~RNP_JSON_DUMP_MPI;
    }
    if (flags & RNP_JSON_DUMP_RAW) {
        dumpctx.dump_packets = true;
        flags &= ~RNP_JSON_DUMP_RAW;
    }
    if (flags & RNP_JSON_DUMP_GRIP) {
        dumpctx.dump_grips = true;
        flags &= ~RNP_JSON_DUMP_GRIP;
    }
    if (flags) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    ret = stream_dump_packets_json(&dumpctx, src, &jso);
    if (ret) {
        goto done;
    }

    *result = (char *) json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY);
    if (!*result) {
        goto done;
    }
    *result = strdup(*result);
    if (!*result) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    json_object_put(jso);
    return ret;
}

rnp_result_t
rnp_key_packets_to_json(rnp_key_handle_t handle, bool secret, uint32_t flags, char **result)
{
    pgp_key_t *  key = NULL;
    rnp_result_t ret = RNP_ERROR_GENERIC;
    pgp_dest_t   memdst = {};
    pgp_source_t memsrc = {};

    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }

    key = secret ? handle->sec : handle->pub;
    if (!key || (key->format == G10_KEY_STORE)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (init_mem_dest(&memdst, NULL, 0)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (!pgp_key_write_packets(key, &memdst)) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    if (init_mem_src(&memsrc, mem_dest_get_memory(&memdst), memdst.writeb, false)) {
        ret = RNP_ERROR_BAD_STATE;
        goto done;
    }

    ret = rnp_dump_src_to_json(&memsrc, flags, result);
done:
    dst_close(&memdst, true);
    src_close(&memsrc);
    return ret;
}

rnp_result_t
rnp_dump_packets_to_json(rnp_input_t input, uint32_t flags, char **result)
{
    if (!input || !result) {
        return RNP_ERROR_NULL_POINTER;
    }

    return rnp_dump_src_to_json(&input->src, flags, result);
}

// move to next key
static bool
key_iter_next_key(rnp_identifier_iterator_t it)
{
    it->keyp = (pgp_key_t *) list_next((list_item *) it->keyp);
    it->uididx = 0;
    // check if we reached the end of the ring
    if (!it->keyp) {
        // if we are currently on pubring, switch to secring (if not empty)
        if (it->store == it->ffi->pubring && rnp_key_store_get_key_count(it->ffi->secring)) {
            it->store = it->ffi->secring;
            it->keyp = (pgp_key_t *) list_front(rnp_key_store_get_keys(it->store));
        } else {
            // we've gone through both rings
            return false;
        }
    }
    return true;
}

// move to next item (key or userid)
static bool
key_iter_next_item(rnp_identifier_iterator_t it)
{
    switch (it->type) {
    case PGP_KEY_SEARCH_KEYID:
    case PGP_KEY_SEARCH_FINGERPRINT:
    case PGP_KEY_SEARCH_GRIP:
        return key_iter_next_key(it);
    case PGP_KEY_SEARCH_USERID:
        it->uididx++;
        if (it->keyp) {
            while (it->uididx >= pgp_key_get_userid_count(it->keyp)) {
                if (!key_iter_next_key(it)) {
                    return false;
                }
                it->uididx = 0;
            }
        }
        break;
    default:
        assert(false);
        break;
    }
    return true;
}

static bool
key_iter_first_key(rnp_identifier_iterator_t it)
{
    if (rnp_key_store_get_key_count(it->ffi->pubring)) {
        it->store = it->ffi->pubring;
    } else if (rnp_key_store_get_key_count(it->ffi->secring)) {
        it->store = it->ffi->secring;
    } else {
        it->store = NULL;
        return false;
    }
    it->keyp = (pgp_key_t *) list_front(rnp_key_store_get_keys(it->store));
    it->uididx = 0;
    return true;
}

static bool
key_iter_first_item(rnp_identifier_iterator_t it)
{
    switch (it->type) {
    case PGP_KEY_SEARCH_KEYID:
    case PGP_KEY_SEARCH_FINGERPRINT:
    case PGP_KEY_SEARCH_GRIP:
        return key_iter_first_key(it);
    case PGP_KEY_SEARCH_USERID:
        if (!key_iter_first_key(it)) {
            return false;
        }
        while (it->uididx >= pgp_key_get_userid_count(it->keyp)) {
            if (!key_iter_next_key(it)) {
                it->store = NULL;
                return false;
            }
            it->uididx = 0;
        }
        break;
    default:
        assert(false);
        break;
    }
    return true;
}

static bool
key_iter_get_item(const rnp_identifier_iterator_t it, char *buf, size_t buf_len)
{
    const pgp_key_t *key = it->keyp;
    switch (it->type) {
    case PGP_KEY_SEARCH_KEYID:
        if (!rnp_hex_encode(
              pgp_key_get_keyid(key), PGP_KEY_ID_SIZE, buf, buf_len, RNP_HEX_UPPERCASE)) {
            return false;
        }
        break;
    case PGP_KEY_SEARCH_FINGERPRINT:
        if (!rnp_hex_encode(pgp_key_get_fp(key)->fingerprint,
                            pgp_key_get_fp(key)->length,
                            buf,
                            buf_len,
                            RNP_HEX_UPPERCASE)) {
            return false;
        }
        break;
    case PGP_KEY_SEARCH_GRIP:
        if (!rnp_hex_encode(
              pgp_key_get_grip(key), PGP_KEY_GRIP_SIZE, buf, buf_len, RNP_HEX_UPPERCASE)) {
            return false;
        }
        break;
    case PGP_KEY_SEARCH_USERID: {
        const char *userid = pgp_key_get_userid(key, it->uididx);
        if (strlen(userid) >= buf_len) {
            return false;
        }
        strcpy(buf, userid);
    } break;
    default:
        assert(false);
        break;
    }
    return true;
}

rnp_result_t
rnp_identifier_iterator_create(rnp_ffi_t                  ffi,
                               rnp_identifier_iterator_t *it,
                               const char *               identifier_type)
{
    rnp_result_t                       ret = RNP_ERROR_GENERIC;
    struct rnp_identifier_iterator_st *obj = NULL;

    // checks
    if (!ffi || !it || !identifier_type) {
        return RNP_ERROR_NULL_POINTER;
    }
    // create iterator
    obj = (struct rnp_identifier_iterator_st *) calloc(1, sizeof(*obj));
    if (!obj) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    obj->ffi = ffi;
    // parse identifier type
    obj->type = PGP_KEY_SEARCH_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(identifier_type_map, string, type, identifier_type, obj->type);
    if (obj->type == PGP_KEY_SEARCH_UNKNOWN) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }
    obj->tbl = json_object_new_object();
    if (!obj->tbl) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    // move to first item (if any)
    key_iter_first_item(obj);
    *it = obj;

    ret = RNP_SUCCESS;
done:
    if (ret) {
        rnp_identifier_iterator_destroy(obj);
    }
    return ret;
}

rnp_result_t
rnp_identifier_iterator_next(rnp_identifier_iterator_t it, const char **identifier)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!it || !identifier) {
        return RNP_ERROR_NULL_POINTER;
    }
    // initialize the result to NULL
    *identifier = NULL;
    // this means we reached the end of the rings
    if (!it->store) {
        return RNP_SUCCESS;
    }
    // get the item
    if (!key_iter_get_item(it, it->buf, sizeof(it->buf))) {
        return RNP_ERROR_GENERIC;
    }
    bool exists;
    while ((exists = json_object_object_get_ex(it->tbl, it->buf, NULL))) {
        if (!key_iter_next_item(it)) {
            break;
        }
        if (!key_iter_get_item(it, it->buf, sizeof(it->buf))) {
            return RNP_ERROR_GENERIC;
        }
    }
    // see if we actually found a new entry
    if (!exists) {
        // TODO: Newer json-c has a useful return value for json_object_object_add,
        // which doesn't require the json_object_object_get_ex check below.
        json_object_object_add(it->tbl, it->buf, NULL);
        if (!json_object_object_get_ex(it->tbl, it->buf, NULL)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        *identifier = it->buf;
    }
    // prepare for the next one
    if (!key_iter_next_item(it)) {
        // this means we're done
        it->store = NULL;
    }
    ret = RNP_SUCCESS;

done:
    if (ret) {
        *identifier = NULL;
    }
    return ret;
}

rnp_result_t
rnp_identifier_iterator_destroy(rnp_identifier_iterator_t it)
{
    if (it) {
        json_object_put(it->tbl);
        free(it);
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_enarmor(rnp_input_t input, rnp_output_t output, const char *type)
{
    pgp_armored_msg_t msgtype = PGP_ARMORED_UNKNOWN;
    if (!input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (type) {
        ARRAY_LOOKUP_BY_STRCASE(armor_type_map, string, type, type, msgtype);
        if (!msgtype) {
            RNP_LOG("Unsupported armor type: %s", type);
            return RNP_ERROR_BAD_PARAMETERS;
        }
    } else {
        msgtype = rnp_armor_guess_type(&input->src);
        if (!msgtype) {
            RNP_LOG("Unrecognized data to armor (try specifying a type)");
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }
    return rnp_armor_source(&input->src, &output->dst, msgtype);
}

rnp_result_t
rnp_dearmor(rnp_input_t input, rnp_output_t output)
{
    if (!input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_dearmor_source(&input->src, &output->dst);
}
