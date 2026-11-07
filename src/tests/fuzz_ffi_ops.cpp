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
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS AND CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <rnp/rnp.h>
#include "rnp_tests.h"
#include "support.h"

extern "C" int ffi_ops_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void
run_ffi_ops(const std::vector<uint8_t> &op_data)
{
    assert_int_equal(ffi_ops_LLVMFuzzerTestOneInput(op_data.data(), op_data.size()), 0);
}

static std::vector<uint8_t>
with_op(uint8_t op, const std::vector<uint8_t> &payload)
{
    std::vector<uint8_t> data;
    data.reserve(payload.size() + 1);
    data.push_back(op);
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

TEST_F(rnp_tests, test_fuzz_ffi_ops)
{
    /* key import (strict + permissive): public and secret keyrings */
    run_ffi_ops(with_op(0, file_to_vec("data/keyrings/1/pubring.gpg")));
    run_ffi_ops(with_op(0, file_to_vec("data/keyrings/1/secring.gpg")));

    /* message verification */
    run_ffi_ops(
      with_op(1, file_to_vec("data/test_messages/message-trailing-cr.txt.sig-text")));

    /* decryption with a fuzz-provided password over an encrypted message */
    {
        auto                 msg = file_to_vec("data/test_messages/message.enc-password");
        std::vector<uint8_t> payload = {8, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        payload.insert(payload.end(), msg.begin(), msg.end());
        run_ffi_ops(with_op(2, payload));
    }

    /* op sequence: import keys, then verify over the same key store */
    {
        auto keys = file_to_vec("data/keyrings/1/pubring.gpg");
        auto msg = file_to_vec("data/test_messages/message-trailing-cr.txt.sig-text");
        std::vector<uint8_t> payload = keys;
        payload.insert(payload.end(), msg.begin(), msg.end());
        run_ffi_ops(with_op(3, payload));
    }

    /* degenerate inputs */
    const uint8_t tiny[] = {0x02};
    assert_int_equal(ffi_ops_LLVMFuzzerTestOneInput(tiny, 1), 0);
}
