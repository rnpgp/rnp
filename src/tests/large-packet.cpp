/*
 * Copyright (c) 2017-2019 [Ribose Inc](https://www.ribose.com).
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

#include <fstream>
#include <vector>
#include <string>

#include <rnp/rnp.h>
#include "rnp_tests.h"
#include "support.h"
#include "librepgp/stream-common.h"
#include "utils.h"
#include <json.h>
#include <vector>
#include <string>

/* code needed to generate the test file
typedef struct {
    uint32_t      remaining;
    uint8_t       dummy;
} dummy_reader_ctx_st;

static ssize_t
dummy_reader(void *app_ctx, void *buf, size_t len)
{
    size_t filled = 0;
    dummy_reader_ctx_st *ctx = NULL;

    ctx = (dummy_reader_ctx_st *)app_ctx;
    filled = (len > ctx->remaining) ? ctx->remaining : len;
    if (filled > 0) {
        memset(buf, ctx->dummy, filled);
        ctx->remaining -= filled;
    }
    return filled;
}

static bool
getpasscb(rnp_ffi_t        ffi,
          void *           app_ctx,
          rnp_key_handle_t key,
          const char *     pgp_context,
          char *           buf,
          size_t           buf_len)
{
    strcpy(buf, (const char *) app_ctx);
    return true;
}
*/

TEST_F(rnp_tests, test_large_packet)
{
    rnp_ffi_t           ffi = NULL;
    rnp_input_t         input = NULL;
    rnp_output_t        output = NULL;
    rnp_op_verify_t     verify;
    /*
    rnp_key_handle_t    key = NULL;
    rnp_op_sign_t       sign;
    dummy_reader_ctx_st reader_ctx;
    */

    /* init ffi and inputs */
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_large_packet/pub.asc"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    assert_rnp_success(rnp_input_destroy(input));

    /* Compress and Sign part 
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_large_packet/sec.asc"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_rnp_success(rnp_input_destroy(input));

    reader_ctx.dummy = 'X';
    reader_ctx.remaining = UINT32_MAX; // gives 4G-1 bytes 
    assert_rnp_success(rnp_input_from_callback(&input, dummy_reader, NULL, &reader_ctx));
    assert_rnp_success(rnp_output_to_path(&output, "data/test_large_packet/4g.bzip2.gpg"));

    // Prepare the signing key
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "5873BD738E575398", &key));
    assert_non_null(key);

    assert_rnp_success(rnp_op_sign_create(&sign, ffi, input, output));
    assert_rnp_success(rnp_op_sign_set_compression(sign, "BZip2", 9));
    assert_rnp_success(rnp_op_sign_add_signature(sign, key, NULL));

    assert_rnp_success(rnp_op_sign_execute(sign));

    assert_rnp_success(rnp_op_sign_destroy(sign));
    assert_rnp_success(rnp_key_handle_destroy(key));
    key = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    assert_rnp_success(rnp_input_destroy(input));
    */

    // Verify part
    assert_rnp_success(rnp_input_from_path(&input, "data/test_large_packet/4g.bzip2.gpg"));
    assert_rnp_success(rnp_output_to_null(&output));
    /* call verify */
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    /* cleanup */
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_output_destroy(output));
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}