/*
 * Copyright (c) 2026 [Ribose Inc](https://www.ribose.com).
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

#include "../rnp_tests.h"
#include "../support.h"

/* Issue #2469: draining a memory output that has written zero bytes must
 * succeed with an empty (NULL, 0) buffer instead of failing with
 * RNP_ERROR_BAD_PARAMETERS. */
TEST_F(rnp_tests, test_ffi_output_memory_get_buf_empty)
{
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_memory(&output, 0));

    uint8_t *buf = (uint8_t *) 0x1; /* sentinel, must be overwritten */
    size_t   len = 123;             /* sentinel, must be overwritten */
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 0);
    assert_null(buf);
    rnp_output_destroy(output);

    /* do_copy=true on an empty output: success without allocating */
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    buf = (uint8_t *) 0x1;
    len = 123;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, true));
    assert_int_equal(len, 0);
    assert_null(buf);
    rnp_output_destroy(output);

    /* a non-memory output must still be rejected */
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_failure(rnp_output_memory_get_buf(output, &buf, &len, false));
    rnp_output_destroy(output);
}
