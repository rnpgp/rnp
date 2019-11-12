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

static void
test_partial_length_init(rnp_ffi_t *ffi)
{
    rnp_input_t     input = NULL;

    /* init ffi and inputs */
    assert_rnp_success(rnp_ffi_create(ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_rnp_success(rnp_load_keys(*ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    assert_rnp_success(rnp_input_destroy(input));
}

TEST_F(rnp_tests, test_partial_length_public_key)
{
    rnp_input_t     input = NULL;
    rnp_ffi_t       ffi = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_partial_length/pubring.gpg.partial"));
    assert_int_equal(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS), RNP_ERROR_BAD_FORMAT);
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_partial_length_signature)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;

    // init ffi
    test_partial_length_init(&ffi);

    // message having partial length signature packet
    assert_rnp_success(rnp_input_from_path(&input, "data/test_partial_length/message.txt.partial-signed"));
    assert_rnp_success(rnp_output_to_null(&output));
    rnp_op_verify_t verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));

    // cleanup
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_output_destroy(output));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_partial_length_first_packet_256)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;

    // init ffi
    test_partial_length_init(&ffi);

    // message having first partial length packet of 256 bytes
    assert_rnp_success(rnp_input_from_path(&input, "data/test_partial_length/message.txt.partial-256"));
    assert_rnp_success(rnp_output_to_null(&output));
    rnp_op_verify_t verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));

    // cleanup
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_output_destroy(output));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}
