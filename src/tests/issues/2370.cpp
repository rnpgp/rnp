/*
 * Copyright (c) 2026 [Ribose Inc].
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

#include "../rnp_tests.h"
#include "../support.h"
#include <librepgp/stream-packet.h>
#include <string>
#include <vector>

/* Issue #2370: a keyring containing a key with an algorithm unknown to the build
 * (here: algorithm 100 from the private/experimental range, which no build
 * supports) must not abort the whole load - the unsupported key is skipped and
 * other keys load. */
TEST_F(rnp_tests, test_ffi_key_load_unsupported_algorithm)
{
    /* build a v4 public key packet with the unknown algorithm and dummy material */
    pgp_packet_body_t body(PGP_PKT_PUBLIC_KEY);
    body.add_byte(4);                          /* version */
    body.add_uint32(0x5f3f2e10);               /* creation time */
    body.add_byte(100);                        /* algorithm 100: private/experimental */
    body.add(std::vector<uint8_t>(400, 0xab)); /* dummy key material */

    rnp::MemoryDest dst;
    body.write(dst.dst(), true);
    std::vector<uint8_t> unsup = dst.to_vector();

    std::vector<uint8_t> alice = file_to_vec("data/test_key_validity/alice-pub.asc");
    assert_false(alice.empty());

    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    /* 1. importing the unsupported-algorithm key alone must succeed and
     *    simply not add any key (issue #2370: the load used to fail) */
    rnp_input_t input = NULL;
    assert_rnp_success(rnp_input_from_memory(&input, unsup.data(), unsup.size(), false));
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    char *results = NULL;
    assert_rnp_success(
      rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, &results));
    rnp_buffer_destroy(results);
    results = NULL;
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    size_t count = 99;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 0);

    /* 2. a following valid key still loads fine */
    assert_rnp_success(rnp_input_from_memory(&input, alice.data(), alice.size(), false));
    output = NULL;
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(
      rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, &results));
    rnp_buffer_destroy(results);
    results = NULL;
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 1);

    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_non_null(key);
    rnp_key_handle_destroy(key);

    rnp_ffi_destroy(ffi);
}
