/*-
 * Copyright (c) 2017 Ribose Inc.
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

#include <assert.h>
#include <rnp/rnp2.h>
#include "list.h"
#include "crypto.h"
#include "crypto/s2k.h"
#include "crypto/rng.h"
#include "pgp-key.h"
#include <librepgp/validate.h>
#include <librepgp/stream-common.h>
#include <librepgp/stream-write.h>
#include <librepgp/stream-parse.h>
#include "hash.h"
#include <rnp/rnp_types.h>
#include <stdlib.h>
#include <unistd.h>

struct rnp_password_cb_data {
    rnp_password_cb cb_fn;
    void *          cb_data;
    rnp_keyring_t   ring;
};

struct rnp_keyring_st {
    rnp_key_store_t *store;
    rnp_ffi_t        ffi;
};

typedef struct key_locator_t {
    pgp_key_search_t type;
    union {
        uint8_t keyid[PGP_KEY_ID_SIZE];
        uint8_t grip[PGP_FINGERPRINT_SIZE];
        char    userid[MAX_ID_LENGTH];
    } id;
} key_locator_t;

struct rnp_key_handle_st {
    key_locator_t locator;
    pgp_key_t *   pub;
    pgp_key_t *   sec;
};

struct rnp_ffi_st {
    pgp_io_t        io;
    rnp_keyring_t   pubring;
    rnp_keyring_t   secring;
    rnp_get_key_cb  getkeycb;
    void *          getkeycb_ctx;
    rnp_password_cb getpasscb;
    void *          getpasscb_ctx;
    rng_t           rng;
};

struct rnp_input_st {
    pgp_source_t        src;
    rnp_input_reader_t *reader;
    rnp_input_closer_t *closer;
    void *              app_ctx;
};

struct rnp_output_st {
    pgp_dest_t           dst;
    rnp_output_writer_t *writer;
    rnp_output_closer_t *closer;
    void *               app_ctx;
    bool                 keep;
};

struct rnp_op_encrypt_st {
    rnp_ffi_t    ffi;
    rnp_input_t  input;
    rnp_output_t output;
    rnp_ctx_t    rnpctx;
};

#define FFI_LOG(ffi, ...)            \
    do {                             \
        FILE *fp = stderr;           \
        if (ffi && ffi->io.errs) {   \
            fp = ffi->io.errs;       \
        }                            \
        RNP_LOG_FD(fp, __VA_ARGS__); \
    } while (0)

static rnp_result_t rnp_keyring_create(rnp_ffi_t ffi, rnp_keyring_t *ring, const char *format);
static rnp_result_t rnp_keyring_destroy(rnp_keyring_t ring);
static bool parse_symm_alg(const char *name, pgp_symm_alg_t *value);
static bool parse_compress_alg(const char *name, pgp_compression_type_t *value);
static bool parse_hash_alg(const char *name, pgp_hash_alg_t *value);
static bool key_provider_bounce(const pgp_key_request_ctx_t *ctx,
                                pgp_key_t **                 key,
                                void *                       userdata);

static void
rnp_ctx_init_ffi(rnp_ctx_t *ctx, rnp_ffi_t ffi)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->rng = &ffi->rng;
    ctx->ealg = PGP_SA_DEFAULT_CIPHER;
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

    ob = calloc(1, sizeof(struct rnp_ffi_st));
    if (!ob) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // default to all stderr
    const pgp_io_t default_io = {.outs = stderr, .errs = stderr, .res = stderr};
    ob->io = default_io;
    ret = rnp_keyring_create(ob, &ob->pubring, pub_format);
    if (ret) {
        goto done;
    }
    ret = rnp_keyring_create(ob, &ob->secring, sec_format);
    if (ret) {
        goto done;
    }
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

static void
close_io(pgp_io_t *io)
{
    close_io_file(&io->outs);
    close_io_file(&io->errs);
    close_io_file(&io->res);
}

rnp_result_t
rnp_ffi_destroy(rnp_ffi_t ffi)
{
    if (ffi) {
        close_io(&ffi->io);
        rnp_keyring_destroy(ffi->pubring);
        rnp_keyring_destroy(ffi->secring);
        rng_destroy(&ffi->rng);
        free(ffi);
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_ffi_get_pubring(rnp_ffi_t ffi, rnp_keyring_t *ring)
{
    // checks
    if (!ffi || !ring) {
        return RNP_ERROR_NULL_POINTER;
    }
    *ring = ffi->pubring;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_ffi_get_secring(rnp_ffi_t ffi, rnp_keyring_t *ring)
{
    // checks
    if (!ffi || !ring) {
        return RNP_ERROR_NULL_POINTER;
    }
    *ring = ffi->secring;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_ffi_set_log_fd(rnp_ffi_t ffi, int fd)
{
    FILE *outs = NULL;
    FILE *errs = NULL;
    FILE *res = NULL;

    // checks
    if (!ffi) {
        return RNP_ERROR_NULL_POINTER;
    }

    // open
    outs = fdopen(fd, "a");
    errs = fdopen(dup(fd), "a");
    res = fdopen(dup(fd), "a");
    if (!outs || !errs || !res) {
        close_io_file(&outs);
        close_io_file(&errs);
        close_io_file(&res);
        return RNP_ERROR_ACCESS;
    }
    // close previous streams and replace them
    close_io_file(&ffi->io.outs);
    ffi->io.outs = outs;
    close_io_file(&ffi->io.errs);
    ffi->io.errs = errs;
    close_io_file(&ffi->io.res);
    ffi->io.res = res;
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
    struct rnp_password_cb_data *userdata = (struct rnp_password_cb_data *) userdata_void;
    rnp_key_handle_t             key = NULL;

    if (!userdata->cb_fn) {
        return false;
    }

    key = calloc(1, sizeof(*key));
    if (!key) {
        return false;
    }
    key->sec = (pgp_key_t *) ctx->key;
    int rc = userdata->cb_fn(
      userdata->cb_data, key, operation_description(ctx->op), password, password_size);
    free(key);
    return (rc == 0);
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
    case RNP_ERROR_KEY_NOT_FOUND:
        return "Key not found";
    case RNP_ERROR_NO_SUITABLE_KEY:
        return "Not suitable key";
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
        return "Not userid";
    case RNP_ERROR_EOF:
        return "EOF detected";
    }

    return "Unknown error";
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

    char *pub_format_guess = NULL;
    char *pub_path_guess = NULL;
    char *sec_format_guess = NULL;
    char *sec_path_guess = NULL;
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
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *format = NULL;
    // ordered from most reliable detection to least
    char *guess = NULL;
    if (buf_len >= 12 && memcmp(buf + 8, "KBXf", 4) == 0) {
        // KBX has a magic KBXf marker
        guess = "KBX";
    } else if (buf[0] == '(' && buf[buf_len - 1] == ')') {
        // G10 is s-exprs and should start end end with parentheses
        guess = "G10";
    } else if (buf_len >= 5 && memcmp(buf, "-----", 5) == 0) {
        // assume armored GPG
        guess = "GPG";
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
rnp_keyring_create(rnp_ffi_t ffi, rnp_keyring_t *ring, const char *format)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!ffi || !ring || !format) {
        return RNP_ERROR_NULL_POINTER;
    }

    // proceed
    *ring = malloc(sizeof(**ring));
    if (!*ring) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    (*ring)->store = rnp_key_store_new(format, "");
    if (!(*ring)->store) {
        free(*ring);
        *ring = NULL;
        goto done;
    }
    (*ring)->ffi = ffi;

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

static rnp_result_t
rnp_keyring_destroy(rnp_keyring_t ring)
{
    if (ring) {
        rnp_key_store_free(ring->store);
        free(ring);
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_keyring_get_format(rnp_keyring_t ring, char **format)
{
    // checks
    if (!ring || !ring->store || !format) {
        return RNP_ERROR_NULL_POINTER;
    }

    *format = strdup(ring->store->format_label);
    if (!*format) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_keyring_get_path(rnp_keyring_t ring, char **path)
{
    // checks
    if (!ring || !ring->store || !path) {
        return RNP_ERROR_NULL_POINTER;
    }

    *path = strdup(ring->store->path);
    if (!*path) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_keyring_get_key_count(rnp_keyring_t ring, size_t *count)
{
    // checks
    if (!ring || !ring->store || !count) {
        return RNP_ERROR_NULL_POINTER;
    }

    *count = list_length(ring->store->keys);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_keyring_load_from_path(rnp_keyring_t ring, const char *path)
{
    // checks
    if (!ring || !ring->store || !path) {
        return RNP_ERROR_NULL_POINTER;
    }

    const char *oldpath = ring->store->path;
    ring->store->path = strdup(path);
    if (!ring->store->path) {
        ring->store->path = oldpath;
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!rnp_key_store_load_from_file(&ring->ffi->io, ring->store, 0, NULL)) {
        free((void *) ring->store->path);
        ring->store->path = oldpath;
        return RNP_ERROR_GENERIC;
    }
    free((void *) oldpath);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_keyring_load_from_memory(rnp_keyring_t ring, const uint8_t buf[], size_t buf_len)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!ring || !ring->store || !buf) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!buf_len) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_memory_t memory = {.buf = (uint8_t *) buf, .length = buf_len};
    if (!rnp_key_store_load_from_mem(&ring->ffi->io, ring->store, 0, NULL, &memory)) {
        goto done;
    }

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

rnp_result_t
rnp_keyring_save_to_path(rnp_keyring_t ring, const char *path)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!ring || !ring->store || !path) {
        return RNP_ERROR_NULL_POINTER;
    }

    char *newpath = strdup(path);
    if (!newpath) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    free((void *) ring->store->path);
    ring->store->path = newpath;
    if (!rnp_key_store_write_to_file(&ring->ffi->io, ring->store, 0)) {
        goto done;
    }

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}

rnp_result_t
rnp_keyring_save_to_memory(rnp_keyring_t ring, uint8_t *buf[], size_t *buf_len)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;
    pgp_memory_t mem = {0};

    // checks
    if (!ring || !ring->store || !buf) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!buf_len) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!rnp_key_store_write_to_mem(&ring->ffi->io, ring->store, 0, &mem)) {
        goto done;
    }

    // success
    ret = RNP_SUCCESS;
    *buf = mem.buf;
    *buf_len = mem.length;
done:
    if (ret) {
        pgp_memory_release(&mem);
    }
    return ret;
}

rnp_result_t
rnp_input_from_file(rnp_input_t *input, const char *path)
{
    if (!input || !path) {
        return RNP_ERROR_NULL_POINTER;
    }
    *input = calloc(1, sizeof(**input));
    if (!*input) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    rnp_result_t ret = init_file_src(&(*input)->src, path);
    if (ret) {
        free(*input);
        *input = NULL;
        return ret;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_input_from_memory(rnp_input_t *input, const uint8_t buf[], size_t buf_len)
{
    if (!input || !buf) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!buf_len) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_ERROR_NOT_IMPLEMENTED;
}

static ssize_t
input_reader_bounce(pgp_source_t *src, void *buf, size_t len)
{
    rnp_input_t input = src->param;
    if (!input->reader) {
        return -1;
    }
    return input->reader(input->app_ctx, buf, len);
}

static void
input_closer_bounce(pgp_source_t *src)
{
    rnp_input_t input = src->param;
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
    // checks
    if (!input || !reader) {
        return RNP_ERROR_NULL_POINTER;
    }
    *input = calloc(1, sizeof(**input));
    if (!*input) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    pgp_source_t *src = &(*input)->src;
    src->read = input_reader_bounce;
    src->close = input_closer_bounce;
    (*input)->reader = reader;
    (*input)->closer = closer;
    (*input)->app_ctx = app_ctx;
    src->param = *input;
    src->type = PGP_STREAM_MEMORY;
    src->size = 0;
    src->readb = 0;
    src->eof = 0;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_input_destroy(rnp_input_t input)
{
    if (input) {
        // if (input->src.param) {
        src_close(&input->src);
        // input->src.param = NULL;
        //}
        free(input);
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_output_to_file(rnp_output_t *output, const char *path)
{
    // checks
    if (!output || !path) {
        return RNP_ERROR_NULL_POINTER;
    }

    *output = calloc(1, sizeof(**output));
    if (!*output) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    rnp_result_t ret = init_file_dest(&(*output)->dst, path, false);
    if (ret) {
        free(*output);
        *output = NULL;
        return ret;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
output_writer_bounce(pgp_dest_t *dst, const void *buf, size_t len)
{
    rnp_output_t output = dst->param;
    if (!output->writer) {
        return RNP_ERROR_NULL_POINTER;
    }
    return output->writer(output->app_ctx, buf, len);
}

static void
output_closer_bounce(pgp_dest_t *dst, bool discard)
{
    rnp_output_t output = dst->param;
    if (output->closer) {
        output->closer(output->app_ctx, discard);
    }
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

    *output = calloc(1, sizeof(**output));
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
        // if (output->dst.param) {
        dst_close(&output->dst, !output->keep); // TODO
        // output->dst.param = NULL;
        //}
        free(output);
    }
    return RNP_SUCCESS;
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

    *op = calloc(1, sizeof(**op));
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
rnp_op_encrypt_add_recipient(rnp_op_encrypt_t op, rnp_key_handle_t key)
{
    // checks
    if (!op || !key) {
        return RNP_ERROR_NULL_POINTER;
    }

    // TODO: lower layers are currently limited to this
    if (key->locator.type != PGP_KEY_SEARCH_USERID) {
        return RNP_ERROR_NOT_IMPLEMENTED;
    }
    if (!list_append(&op->rnpctx.recipients,
                     key->locator.id.userid,
                     strlen(key->locator.id.userid) + 1)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_encrypt_add_password(rnp_op_encrypt_t op,
                            const char *     password,
                            const char *     s2k_hash,
                            size_t           iterations,
                            const char *     s2k_cipher)
{
    rnp_symmetric_pass_info_t info = {{0}};
    rnp_result_t              ret = RNP_ERROR_GENERIC;

    // checks
    if (!op || !password) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!*password) {
        // no blank passwords
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // set some defaults
    if (!s2k_hash) {
        s2k_hash = DEFAULT_HASH_ALG;
    }
    if (!iterations) {
        iterations = PGP_S2K_DEFAULT_ITERATIONS;
    }
    if (!s2k_cipher) {
        s2k_cipher = "AES256"; // TODO: make this a define somewhere
    }
    // parse
    pgp_hash_alg_t hash_alg;
    if (!parse_hash_alg(s2k_hash, &hash_alg)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    pgp_symm_alg_t symm_alg;
    if (!parse_symm_alg(s2k_cipher, &symm_alg)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    // derive key, etc
    ret = rnp_encrypt_set_pass_info(&info, password, hash_alg, iterations, symm_alg);
    if (!list_append(&op->rnpctx.passwords, &info, sizeof(info))) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    ret = RNP_SUCCESS;

done:
    pgp_forget(&info, sizeof(info));
    return ret;
}

rnp_result_t
rnp_op_encrypt_set_armor(rnp_op_encrypt_t op, bool armored)
{
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    op->rnpctx.armor = armored;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_encrypt_set_cipher(rnp_op_encrypt_t op, const char *cipher)
{
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!parse_symm_alg(cipher, &op->rnpctx.ealg)) {
        return RNP_ERROR_BAD_FORMAT;
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
    pgp_compression_type_t zalg;
    if (!parse_compress_alg(compression, &zalg)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    op->rnpctx.zalg = (int) zalg;
    op->rnpctx.zlevel = level;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_encrypt_set_file_name(rnp_op_encrypt_t op, const char *filename)
{
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
rnp_op_encrypt_set_file_mtime(rnp_op_encrypt_t op, uint32_t mtime)
{
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
rnp_op_encrypt_execute(rnp_op_encrypt_t op)
{
    // checks
    if (!op || !op->input || !op->output) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_password_provider_t provider = {
      .callback = rnp_password_cb_bounce,
      .userdata = &(struct rnp_password_cb_data){.cb_fn = op->ffi->getpasscb,
                                                 .cb_data = op->ffi->getpasscb_ctx}};
    pgp_write_handler_t handler = {
      .password_provider = &provider,
      .ctx = &op->rnpctx,
      .param = NULL,
      .key_provider =
        &(pgp_key_provider_t){.callback = key_provider_bounce, .userdata = op->ffi},
    };
    rnp_result_t ret = rnp_encrypt_src(&handler, &op->input->src, &op->output->dst);
    op->output->keep = ret == RNP_SUCCESS;
    op->input = NULL;
    op->output = NULL;
    return ret;
}

rnp_result_t
rnp_op_encrypt_destroy(rnp_op_encrypt_t op)
{
    if (op) {
        free(op);
    }
    return RNP_SUCCESS;
}

static bool
key_provider_bounce(const pgp_key_request_ctx_t *ctx, pgp_key_t **key, void *userdata)
{
    rnp_ffi_t     ffi = (rnp_ffi_t) userdata;
    rnp_keyring_t ring = ctx->secret ? ffi->secring : ffi->pubring;
    *key = NULL;
    switch (ctx->stype) {
    case PGP_KEY_SEARCH_USERID:
        // TODO: this isn't really a userid search...
        rnp_key_store_get_key_by_name(&ffi->io, ring->store, ctx->search.userid, key);
        break;
    case PGP_KEY_SEARCH_KEYID: {
        *key = rnp_key_store_get_key_by_id(&ffi->io, ring->store, ctx->search.id, NULL, NULL);
    } break;
    case PGP_KEY_SEARCH_GRIP: {
        *key = rnp_key_store_get_key_by_grip(&ffi->io, ring->store, ctx->search.grip);
    } break;
    default:
        // should never happen
        assert(false);
        break;
    }
    // TODO: if still not found, use ffi->getkeycb
    return *key != NULL;
}

static bool
dest_provider(pgp_parse_handler_t *handler,
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
    pgp_password_provider_t password_provider = {
      .callback = rnp_password_cb_bounce,
      .userdata = &(struct rnp_password_cb_data){.cb_fn = ffi->getpasscb,
                                                 .cb_data = ffi->getpasscb_ctx}};
    pgp_parse_handler_t handler = {
      .password_provider = &password_provider,
      .key_provider = &(pgp_key_provider_t){.callback = key_provider_bounce, .userdata = ffi},
      .dest_provider = dest_provider,
      .param = output,
      .ctx = &rnpctx};

    rnp_result_t ret = process_pgp_source(&handler, &input->src);
    if (ret != RNP_SUCCESS) {
        // TODO: should we close output->dst here or leave it to the caller?
        dst_close(&output->dst, true);
        output->dst = (pgp_dest_t){0};
    }
    output->keep = ret == RNP_SUCCESS;
    return ret;
}

static bool
parse_identifier_type(const char *type, pgp_key_search_t *value)
{
    static const struct {
        const char *     key;
        pgp_key_search_t value;
    } map[] = {
      {"userid", PGP_KEY_SEARCH_USERID},
      {"keyid", PGP_KEY_SEARCH_KEYID},
      {"grip", PGP_KEY_SEARCH_GRIP},
    };

    for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
        if (!strcmp(type, map[i].key)) {
            if (value) {
                *value = map[i].value;
            }
            return true;
        }
    }
    return false;
}

static rnp_result_t
parse_locator(key_locator_t *locator, const char *identifier_type, const char *identifier)
{
    if (!parse_identifier_type(identifier_type, &locator->type)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    switch (locator->type) {
    case PGP_KEY_SEARCH_USERID:
        if (snprintf(locator->id.userid, sizeof(locator->id.userid), "%s", identifier) >=
            (int) sizeof(locator->id.userid)) {
            return RNP_ERROR_BAD_FORMAT;
        }
        break;
    case PGP_KEY_SEARCH_KEYID: {
        if (strlen(identifier) != (PGP_KEY_ID_SIZE * 2) ||
            !rnp_hex_decode(identifier, locator->id.keyid, sizeof(locator->id.keyid))) {
            return RNP_ERROR_BAD_FORMAT;
        }
    } break;
    case PGP_KEY_SEARCH_GRIP: {
        if (strlen(identifier) != (PGP_FINGERPRINT_SIZE * 2) ||
            !rnp_hex_decode(identifier, locator->id.grip, sizeof(locator->id.grip))) {
            return RNP_ERROR_BAD_FORMAT;
        }
    } break;
    default:
        // should never happen
        assert(false);
        break;
    }
    return RNP_SUCCESS;
}

static pgp_key_t *
find_key_by_locator(pgp_io_t *io, rnp_key_store_t *store, key_locator_t *locator)
{
    pgp_key_t *key = NULL;
    switch (locator->type) {
    case PGP_KEY_SEARCH_USERID:
        // TODO: this isn't really a userid search...
        rnp_key_store_get_key_by_name(io, store, locator->id.userid, &key);
        break;
    case PGP_KEY_SEARCH_KEYID: {
        key = rnp_key_store_get_key_by_id(io, store, locator->id.keyid, NULL, NULL);
    } break;
    case PGP_KEY_SEARCH_GRIP: {
        key = rnp_key_store_get_key_by_grip(io, store, locator->id.grip);
    } break;
    default:
        // should never happen
        assert(false);
        break;
    }
    return key;
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
    key_locator_t locator = {0};
    rnp_result_t  ret = parse_locator(&locator, identifier_type, identifier);
    if (ret) {
        return ret;
    }

    // search pubring
    pgp_key_t *pub = find_key_by_locator(&ffi->io, ffi->pubring->store, &locator);
    // search secring
    pgp_key_t *sec = find_key_by_locator(&ffi->io, ffi->secring->store, &locator);

    if (pub || sec) {
        *handle = malloc(sizeof(**handle));
        if (!handle) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        (*handle)->pub = pub;
        (*handle)->sec = sec;
        (*handle)->locator = locator;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_export_public_key(rnp_key_handle_t key, uint32_t flags, char **buf, size_t *buf_len)
{
    pgp_output_t *output;
    pgp_memory_t *mem;

    bool armor = (flags & RNP_EXPORT_FLAG_ARMORED);

    if (key == NULL) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!pgp_setup_memory_write(NULL, &output, &mem, 128)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    // TODO: populated pubkey if needed, support export sec as pub
    pgp_write_xfer_pubkey(output, key->pub, NULL, armor);

    *buf_len = pgp_mem_len(mem);
    if (armor)
        *buf_len += 1;

    *buf = malloc(*buf_len);

    if (*buf == NULL) {
        pgp_teardown_memory_write(output, mem);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    memcpy(*buf, pgp_mem_data(mem), pgp_mem_len(mem));

    if (armor)
        (*buf)[*buf_len - 1] = 0;

    return RNP_SUCCESS;
}

static bool
parse_key_flag(const char *usage, uint8_t *value)
{
    static const struct {
        const char *key;
        uint8_t     value;
    } map[] = {
      {"certify", PGP_KF_CERTIFY}, {"sign", PGP_KF_SIGN}, {"encrypt", PGP_KF_ENCRYPT}};

    for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
        if (!rnp_strcasecmp(usage, map[i].key)) {
            *value = map[i].value;
            return true;
        }
    }
    return false;
}

static bool
parse_pubkey_alg(const char *name, pgp_pubkey_alg_t *value)
{
    static const struct {
        const char *key;
        uint8_t     value;
    } map[] = {
      {"RSA", PGP_PKA_RSA},
      {"ECDH", PGP_PKA_ECDH},
      {"ECDSA", PGP_PKA_ECDSA},
      {"EDDSA", PGP_PKA_EDDSA},
      {"SM2", PGP_PKA_SM2},
    };

    for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
        if (!rnp_strcasecmp(name, map[i].key)) {
            *value = map[i].value;
            return true;
        }
    }
    return false;
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
parse_curve_name(const char *name, pgp_curve_t *value)
{
    *value = find_curve_by_name(name);
    return *value != PGP_CURVE_MAX;
}

static bool
parse_hash_alg(const char *name, pgp_hash_alg_t *value)
{
    *value = pgp_str_to_hash_alg(name);
    return *value != PGP_HASH_UNKNOWN;
}

static bool
parse_symm_alg(const char *name, pgp_symm_alg_t *value)
{
    static const struct {
        const char *   key;
        pgp_symm_alg_t value;
    } map[] = {{"idea", PGP_SA_IDEA},
               {"tripledes", PGP_SA_TRIPLEDES},
               {"cast5", PGP_SA_CAST5},
               {"blowfish", PGP_SA_BLOWFISH},
               {"aes128", PGP_SA_AES_128},
               {"aes192", PGP_SA_AES_192},
               {"aes256", PGP_SA_AES_256},
               {"twofish", PGP_SA_TWOFISH},
               {"camellia128", PGP_SA_CAMELLIA_128},
               {"camellia192", PGP_SA_CAMELLIA_192},
               {"camellia256", PGP_SA_CAMELLIA_256},
               {"sm4", PGP_SA_SM4}};

    for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
        if (!rnp_strcasecmp(name, map[i].key)) {
            *value = map[i].value;
            return true;
        }
    }
    return false;
}

static bool
parse_compress_alg(const char *name, pgp_compression_type_t *value)
{
    static const struct {
        const char *           key;
        pgp_compression_type_t value;
    } map[] = {
      {"none", PGP_C_NONE}, {"zip", PGP_C_ZIP}, {"zlib", PGP_C_ZLIB}, {"bzip2", PGP_C_BZIP2}};

    for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
        if (!rnp_strcasecmp(name, map[i].key)) {
            *value = map[i].value;
            return true;
        }
    }
    return false;
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
                pgp_hash_alg_t hash_alg;
                if (!parse_hash_alg(json_object_get_string(item), &hash_alg)) {
                    return false;
                }
                EXPAND_ARRAY(prefs, hash_alg);
                prefs->hash_algs[prefs->hash_algc++] = hash_alg;
            }
        } else if (!rnp_strcasecmp(key, "ciphers")) {
            int length = json_object_array_length(value);
            for (int i = 0; i < length; i++) {
                json_object *item = json_object_array_get_idx(value, i);
                if (!json_object_is_type(item, json_type_string)) {
                    return false;
                }
                pgp_symm_alg_t symm_alg;
                if (!parse_symm_alg(json_object_get_string(item), &symm_alg)) {
                    return false;
                }
                EXPAND_ARRAY(prefs, symm_alg);
                prefs->symm_algs[prefs->symm_algc++] = symm_alg;
            }

        } else if (!rnp_strcasecmp(key, "compression")) {
            int length = json_object_array_length(value);
            for (int i = 0; i < length; i++) {
                json_object *item = json_object_array_get_idx(value, i);
                if (!json_object_is_type(item, json_type_string)) {
                    return false;
                }
                pgp_compression_type_t compression;
                if (!parse_compress_alg(json_object_get_string(item), &compression)) {
                    return false;
                }
                EXPAND_ARRAY(prefs, compress_alg);
                prefs->compress_algs[prefs->compress_algc++] = compression;
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
            if (!parse_pubkey_alg(json_object_get_string(value), &crypto->key_alg)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "length")) {
            // if the key alg is set and isn't RSA, this wouldn't be used
            // (RSA is default, so we have to see if it is set)
            if (crypto->key_alg && crypto->key_alg != PGP_PKA_RSA) {
                return false;
            }
            crypto->rsa.modulus_bit_len = json_object_get_int(value);
        } else if (!rnp_strcasecmp(key, "curve")) {
            if (!pk_alg_allows_custom_curve(crypto->key_alg)) {
                return false;
            }
            if (!parse_curve_name(json_object_get_string(value), &crypto->ecc.curve)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "hash")) {
            if (!parse_hash_alg(json_object_get_string(value), &crypto->hash_alg)) {
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
parse_keygen_primary(json_object *jso, rnp_keygen_primary_desc_t *desc)
{
    static const char *properties[] = {
      "userid", "usage", "expiration", "preferences", "protection"};
    rnp_selfsig_cert_info *cert = &desc->cert;

    if (!parse_keygen_crypto(jso, &desc->crypto)) {
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
                    uint8_t flag;
                    if (!parse_key_flag(json_object_get_string(item), &flag)) {
                        return false;
                    }
                    if (cert->key_flags & flag) {
                        return false;
                    }
                    cert->key_flags |= flag;
                }
            } break;
            case json_type_string:
                if (!parse_key_flag(json_object_get_string(value), &cert->key_flags)) {
                    return false;
                }
                break;
            default:
                return false;
            }
        } else if (!rnp_strcasecmp(key, "expiration")) {
            // TODO: support some strings formats?
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
            // TODO
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return json_object_object_length(jso) == 0;
}

static bool
parse_keygen_sub(json_object *jso, rnp_keygen_subkey_desc_t *desc)
{
    static const char *       properties[] = {"usage", "expiration"};
    rnp_selfsig_binding_info *binding = &desc->binding;

    if (!parse_keygen_crypto(jso, &desc->crypto)) {
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
                    uint8_t flag;
                    if (!parse_key_flag(json_object_get_string(item), &flag)) {
                        return false;
                    }
                    if (binding->key_flags & flag) {
                        return false;
                    }
                    binding->key_flags |= flag;
                }
            } break;
            case json_type_string:
                if (!parse_key_flag(json_object_get_string(value), &binding->key_flags)) {
                    return false;
                }
                break;
            default:
                return false;
            }
        } else if (!rnp_strcasecmp(key, "expiration")) {
            // TODO: support some strings formats?
            if (!json_object_is_type(value, json_type_int)) {
                return false;
            }
            binding->key_expiration = json_object_get_int(value);
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
    char         grip[PGP_FINGERPRINT_SIZE * 2 + 1];

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
        if (!rnp_hex_encode(
              primary->grip, PGP_FINGERPRINT_SIZE, grip, sizeof(grip), RNP_HEX_UPPERCASE)) {
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
        if (!rnp_hex_encode(
              sub->grip, PGP_FINGERPRINT_SIZE, grip, sizeof(grip), RNP_HEX_UPPERCASE)) {
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
    rnp_result_t              ret = RNP_ERROR_GENERIC;
    json_object *             jso = NULL;
    rnp_keygen_primary_desc_t primary_desc = {{0}};
    rnp_keygen_subkey_desc_t  sub_desc = {{0}};
    char *                    identifier_type = NULL;
    char *                    identifier = NULL;

    // checks
    if (!ffi || (!ffi->pubring && !ffi->secring) || !json || !results) {
        return RNP_ERROR_NULL_POINTER;
    }

    // parse the JSON
    jso = json_tokener_parse(json);
    if (!jso) {
        // syntax error or some other issue
        ret = RNP_ERROR_BAD_FORMAT;
        goto done;
    }

    // locate the appropriate sections
    json_object *jsoprimary = NULL;
    json_object *jsosub = NULL;
    json_object_object_foreach(jso, key, value)
    {
        json_object **dest = NULL;

        if (rnp_strcasecmp(key, "primary") == 0) {
            dest = &jsoprimary;
        } else if (rnp_strcasecmp(key, "sub") == 0) {
            dest = &jsosub;
        } else {
            // unrecognized key in the object
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }

        // duplicate "primary"/"sub"
        if (*dest) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
        *dest = value;
    }

    if (jsoprimary && jsosub) { // generating primary+sub
        if (!parse_keygen_primary(jsoprimary, &primary_desc) ||
            !parse_keygen_sub(jsosub, &sub_desc)) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
        pgp_key_t primary_pub = {0};
        pgp_key_t primary_sec = {0};
        pgp_key_t sub_pub = {0};
        pgp_key_t sub_sec = {0};
        if (!pgp_generate_keypair(&ffi->rng,
                                  &primary_desc,
                                  &sub_desc,
                                  true,
                                  &primary_sec,
                                  &primary_pub,
                                  &sub_sec,
                                  &sub_pub,
                                  ffi->secring->store->format)) {
            goto done;
        }
        // TODO: error handling
        gen_json_grips(results, &primary_pub, &sub_pub);
        if (ffi->pubring) {
            // TODO: error handling
            rnp_key_store_add_key(&ffi->io, ffi->pubring->store, &primary_pub);
            rnp_key_store_add_key(&ffi->io, ffi->pubring->store, &sub_pub);
        } else {
            pgp_key_free_data(&primary_pub);
            pgp_key_free_data(&sub_pub);
        }
        if (ffi->secring) {
            // TODO: error handling
            rnp_key_store_add_key(&ffi->io, ffi->secring->store, &primary_sec);
            rnp_key_store_add_key(&ffi->io, ffi->secring->store, &sub_sec);
        } else {
            pgp_key_free_data(&primary_sec);
            pgp_key_free_data(&sub_sec);
        }
    } else if (jsoprimary && !jsosub) { // generating primary only
        primary_desc.crypto.rng = &ffi->rng;
        if (!parse_keygen_primary(jsoprimary, &primary_desc)) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
        pgp_key_t primary_pub = {0};
        pgp_key_t primary_sec = {0};
        if (!pgp_generate_primary_key(
              &primary_desc, true, &primary_sec, &primary_pub, ffi->secring->store->format)) {
            goto done;
        }
        // TODO: error handling
        gen_json_grips(results, &primary_pub, NULL);
        if (ffi->pubring) {
            // TODO: error handling
            rnp_key_store_add_key(&ffi->io, ffi->pubring->store, &primary_pub);
        } else {
            pgp_key_free_data(&primary_pub);
        }
        if (ffi->secring) {
            // TODO: error handling
            rnp_key_store_add_key(&ffi->io, ffi->secring->store, &primary_sec);
        } else {
            pgp_key_free_data(&primary_sec);
        }
    } else if (jsosub) { // generating subkey only
        json_object *jsoparent = NULL;
        if (!json_object_object_get_ex(jsosub, "primary", &jsoparent) ||
            json_object_object_length(jsoparent) != 1) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
        json_object_object_foreach(jsoparent, key, value)
        {
            if (!json_object_is_type(value, json_type_string)) {
                ret = RNP_ERROR_BAD_FORMAT;
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

        key_locator_t locator = {0};
        rnp_result_t  tmpret = parse_locator(&locator, identifier_type, identifier);
        if (tmpret) {
            ret = tmpret;
            goto done;
        }

        pgp_key_t *primary_pub = find_key_by_locator(&ffi->io, ffi->pubring->store, &locator);
        pgp_key_t *primary_sec = find_key_by_locator(&ffi->io, ffi->secring->store, &locator);
        if (!primary_sec || !primary_pub) {
            ret = RNP_ERROR_KEY_NOT_FOUND;
            goto done;
        }
        if (!parse_keygen_sub(jsosub, &sub_desc)) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
        const pgp_password_provider_t provider = {
          .callback = rnp_password_cb_bounce,
          .userdata = &(struct rnp_password_cb_data){.cb_fn = ffi->getpasscb,
                                                     .cb_data = ffi->getpasscb_ctx}};
        pgp_key_t sub_pub = {0};
        pgp_key_t sub_sec = {0};
        sub_desc.crypto.rng = &ffi->rng;
        if (!pgp_generate_subkey(&sub_desc,
                                 true,
                                 primary_sec,
                                 primary_pub,
                                 &sub_sec,
                                 &sub_pub,
                                 &provider,
                                 ffi->secring->store->format)) {
            goto done;
        }
        // TODO: error handling
        gen_json_grips(results, NULL, &sub_pub);
        if (ffi->pubring) {
            // TODO: error handling
            rnp_key_store_add_key(&ffi->io, ffi->pubring->store, &sub_pub);
        } else {
            pgp_key_free_data(&sub_pub);
        }
        if (ffi->secring) {
            // TODO: error handling
            rnp_key_store_add_key(&ffi->io, ffi->secring->store, &sub_sec);
        } else {
            pgp_key_free_data(&sub_sec);
        }
    } else {
        // nothing to generate...
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    json_object_put(jso);
    free(identifier_type);
    free(identifier);
    pgp_free_user_prefs(&primary_desc.cert.prefs);
    return ret;
}

rnp_result_t
rnp_key_handle_free(rnp_key_handle_t *key)
{
    // This does not free key->key which is owned by the keyring
    free(*key);
    *key = NULL;
    return RNP_SUCCESS;
}

void *
rnp_buffer_new(size_t size)
{
    return calloc(1, size);
}

void
rnp_buffer_free(void *ptr)
{
    free(ptr);
}

static pgp_key_t *
get_key_prefer_public(rnp_key_handle_t handle)
{
    return handle->pub ? handle->pub : handle->sec;
}

static pgp_key_t *
get_key_require_secret(rnp_key_handle_t handle)
{
    return handle->sec ? handle->sec : NULL;
}

static rnp_result_t
key_get_uid_at(pgp_key_t *key, size_t idx, char **uid)
{
    if (!key || !uid) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (idx >= key->uidc || DYNARRAY_IS_EMPTY(key, uid)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    size_t len = strlen((const char *) key->uids[idx]);
    *uid = calloc(1, len + 1);
    if (!*uid) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    memcpy(*uid, key->uids[idx], len);
    return RNP_SUCCESS;
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
    if (handle == NULL || count == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_prefer_public(handle);
    *count = key->uidc;
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
rnp_key_get_fprint(rnp_key_handle_t handle, char **fprint)
{
    if (handle == NULL || fprint == NULL)
        return RNP_ERROR_NULL_POINTER;

    size_t hex_len = PGP_FINGERPRINT_HEX_SIZE + 1;
    *fprint = malloc(hex_len);
    if (*fprint == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    pgp_key_t *key = get_key_prefer_public(handle);
    assert(rnp_hex_encode(key->fingerprint.fingerprint,
                          key->fingerprint.length,
                          *fprint,
                          hex_len,
                          RNP_HEX_UPPERCASE));
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_keyid(rnp_key_handle_t handle, char **keyid)
{
    if (handle == NULL || keyid == NULL)
        return RNP_ERROR_NULL_POINTER;

    size_t hex_len = PGP_KEY_ID_SIZE * 2 + 1;
    *keyid = malloc(hex_len);
    if (*keyid == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    pgp_key_t *key = get_key_prefer_public(handle);
    assert(rnp_hex_encode(key->keyid, PGP_KEY_ID_SIZE, *keyid, hex_len, RNP_HEX_UPPERCASE));
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_grip(rnp_key_handle_t handle, char **grip)
{
    if (handle == NULL || grip == NULL)
        return RNP_ERROR_NULL_POINTER;

    size_t hex_len = PGP_FINGERPRINT_HEX_SIZE + 1;
    *grip = malloc(hex_len);
    if (*grip == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    pgp_key_t *key = get_key_prefer_public(handle);
    assert(rnp_hex_encode(key->grip, PGP_FINGERPRINT_SIZE, *grip, hex_len, RNP_HEX_UPPERCASE));
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
    if (handle == NULL || password == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    bool ok =
      pgp_key_unlock(key,
                     &(pgp_password_provider_t){.callback = rnp_password_provider_string,
                                                .userdata = RNP_UNCONST(password)});
    if (ok == false)
        return RNP_ERROR_GENERIC;

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
rnp_key_protect(rnp_key_handle_t handle, const char *password)
{
    // checks
    if (!handle || !password) {
        return RNP_ERROR_NULL_POINTER;
    }

    // get the key
    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    // TODO allow setting protection params
    if (!pgp_key_protect_password(key, key->format, NULL, password)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_unprotect(rnp_key_handle_t handle, const char *password)
{
    // checks
    if (!handle || !password) {
        return RNP_ERROR_NULL_POINTER;
    }

    // get the key
    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    // TODO allow setting protection params
    if (!pgp_key_unprotect(key,
                           &(pgp_password_provider_t){.callback = rnp_password_provider_string,
                                                      .userdata = RNP_UNCONST(password)})) {
        return RNP_ERROR_GENERIC;
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
    for (size_t i = 0; i < key->packetc; i++) {
        const pgp_rawpacket_t *pkt = &key->packets[i];
        *buf_len += pkt->length;
    }
    // allocate our buffer
    *buf = malloc(*buf_len);
    if (!*buf) {
        *buf_len = 0;
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // copy each packet
    *buf_len = 0;
    for (size_t i = 0; i < key->packetc; i++) {
        const pgp_rawpacket_t *pkt = &key->packets[i];
        memcpy(*buf + *buf_len, pkt->raw, pkt->length);
        *buf_len += pkt->length;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_public_key_bytes(rnp_key_handle_t handle, uint8_t **buf, size_t *buf_len)
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
rnp_secret_key_bytes(rnp_key_handle_t handle, uint8_t **buf, size_t *buf_len)
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
