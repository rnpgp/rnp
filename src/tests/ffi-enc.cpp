/*
 * Copyright (c) 2020 [Ribose Inc](https://www.ribose.com).
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
#include "librepgp/stream-packet.h"
#include "librepgp/stream-sig.h"
#include <json.h>
#include <vector>
#include <string>
#include "file-utils.h"
#include <librepgp/stream-ctx.h>
#include "pgp-key.h"
#include "ffi-priv-types.h"

TEST_F(rnp_tests, test_ffi_encrypt_pk_subkey_selection)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "data1";

    /* check whether a latest subkey is selected for encryption */
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));

    /* case 1: three encryption subkeys, second expired, third has later creation time */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_load/key0-sub02.pgp"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_memory(&input, (uint8_t *) plaintext, strlen(plaintext), false));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    /* create encrypt operation, add recipient and execute */
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key0-uid0", &key));
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    assert_rnp_success(rnp_op_encrypt_execute(op));
    /* get output */
    uint8_t *buf = NULL;
    size_t   len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, true));
    assert_true(buf && len);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_op_encrypt_destroy(op);
    /* decrypt */
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_memory(&input, buf, len, true));
    rnp_buffer_destroy(buf);
    assert_rnp_success(rnp_output_to_memory(&output, 0));

    rnp_op_verify_t verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));

    /* check whether we used correct subkey */
    size_t count = 0;
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 1);
    rnp_recipient_handle_t recipient = NULL;
    assert_rnp_success(rnp_op_verify_get_recipient_at(verify, 0, &recipient));
    assert_non_null(recipient);
    char *keyid = NULL;
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_non_null(keyid);
    assert_string_equal(keyid, "8A05B89FAD5ADED1");
    rnp_buffer_destroy(keyid);

    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* case 2: only subkeys 1-2, make sure that latest but expired subkey is not selected */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_load/key0-sub01.pgp"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_memory(&input, (uint8_t *) plaintext, strlen(plaintext), false));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    /* create encrypt operation, add recipient and execute */
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    assert_rnp_success(rnp_op_encrypt_execute(op));
    /* get output */
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, true));
    assert_true(buf && len);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_op_encrypt_destroy(op);
    /* decrypt */
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_memory(&input, buf, len, true));
    rnp_buffer_destroy(buf);
    assert_rnp_success(rnp_output_to_memory(&output, 0));

    verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));

    /* check whether we used correct subkey */
    count = 0;
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 1);
    recipient = NULL;
    assert_rnp_success(rnp_op_verify_get_recipient_at(verify, 0, &recipient));
    assert_non_null(recipient);
    keyid = NULL;
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_non_null(keyid);
    assert_string_equal(keyid, "1ED63EE56FADC34D");
    rnp_buffer_destroy(keyid);

    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* case 3: only expired subkey, make sure encryption operation fails */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_load/key0-sub1.pgp"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_memory(&input, (uint8_t *) plaintext, strlen(plaintext), false));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    /* create encrypt operation, add recipient and execute */
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    assert_rnp_failure(rnp_op_encrypt_execute(op));
    rnp_op_encrypt_destroy(op);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    rnp_ffi_destroy(ffi);
}
