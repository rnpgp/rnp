/*
 * Copyright (c) 2026, [Ribose Inc](https://www.ribose.com).
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
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* FFI-level op-sequence fuzz target. The first input byte selects a
 * high-level operation sequence (key import, verification, decryption with a
 * password, or import followed by verification over the same key store),
 * exercising cross-operation state through the public rnp_ffi_t API rather
 * than a single parse path. */

#include <rnp/rnp.h>
#include <string.h>

#define MAX_PASSWORD_LEN 64

/* Password handed to the provider: taken from the fuzz input, NUL-terminated. */
static char   ffi_ops_password[MAX_PASSWORD_LEN + 1];
static size_t ffi_ops_password_len = 0;

static bool
ffi_ops_password_provider(rnp_ffi_t        ffi,
                          void *           app_ctx,
                          rnp_key_handle_t key,
                          const char *     key_info,
                          char *           buf,
                          size_t           buf_len)
{
    (void) ffi;
    (void) app_ctx;
    (void) key;
    (void) key_info;
    if (!buf || !buf_len) {
        return false;
    }
    size_t len = ffi_ops_password_len;
    if (len > buf_len - 1) {
        len = buf_len - 1;
    }
    memcpy(buf, ffi_ops_password, len);
    buf[len] = '\0';
    return true;
}

static void
ffi_ops_import_keys(rnp_ffi_t ffi, const uint8_t *data, size_t size)
{
    rnp_input_t input = NULL;
    char *      results = NULL;

    if (rnp_input_from_memory(&input, data, size, false)) {
        return;
    }
    (void) rnp_import_keys(
      ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS, &results);
    rnp_buffer_destroy(results);
    rnp_input_destroy(input);

    /* permissive import over the same key store */
    results = NULL;
    if (!rnp_input_from_memory(&input, data, size, false)) {
        (void) rnp_import_keys(ffi,
                               input,
                               RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS |
                                 RNP_LOAD_SAVE_PERMISSIVE,
                               &results);
    }
    rnp_buffer_destroy(results);
    rnp_input_destroy(input);
}

static void
ffi_ops_verify(rnp_ffi_t ffi, const uint8_t *data, size_t size)
{
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;
    rnp_op_verify_t op = NULL;

    if (rnp_input_from_memory(&input, data, size, false)) {
        return;
    }
    if (!rnp_output_to_null(&output) && !rnp_op_verify_create(&op, ffi, input, output)) {
        (void) rnp_op_verify_execute(op);
        rnp_op_verify_destroy(op);
    }
    rnp_output_destroy(output);
    rnp_input_destroy(input);
}

static void
ffi_ops_decrypt(rnp_ffi_t ffi, const uint8_t *data, size_t size)
{
    if (!size) {
        return;
    }
    /* first payload byte: password length (clamped), remainder: password then message */
    size_t pwdlen = data[0];
    if (pwdlen > MAX_PASSWORD_LEN) {
        pwdlen = MAX_PASSWORD_LEN;
    }
    if (size < 1 + pwdlen) {
        pwdlen = size - 1;
    }
    memcpy(ffi_ops_password, data + 1, pwdlen);
    ffi_ops_password_len = pwdlen;
    ffi_ops_password[pwdlen] = '\0';

    if (rnp_ffi_set_pass_provider(ffi, ffi_ops_password_provider, NULL)) {
        return;
    }
    /* decryption of signed/encrypted input runs through the verify operation,
     * which consults the password provider for PKESK / symmetric decryption */
    ffi_ops_verify(ffi, data + 1 + pwdlen, size - 1 - pwdlen);
}

#ifdef RNP_RUN_TESTS
int ffi_ops_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int
ffi_ops_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
#else
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
#endif
{
    if (size < 2) {
        return 0;
    }

    rnp_ffi_t ffi = NULL;
    if (rnp_ffi_create(&ffi, "GPG", "GPG")) {
        return 0;
    }

    const uint8_t *payload = data + 1;
    size_t         payload_size = size - 1;

    switch (data[0] % 4) {
    case 0:
        /* key import (strict + permissive) */
        ffi_ops_import_keys(ffi, payload, payload_size);
        break;
    case 1:
        /* message verification */
        ffi_ops_verify(ffi, payload, payload_size);
        break;
    case 2:
        /* decryption with a fuzzed password */
        ffi_ops_decrypt(ffi, payload, payload_size);
        break;
    default:
        /* op sequence: import keys, then verify a message over the same key store */
        ffi_ops_import_keys(ffi, payload, payload_size);
        ffi_ops_verify(ffi, payload, payload_size);
        break;
    }

    rnp_ffi_destroy(ffi);
    return 0;
}
