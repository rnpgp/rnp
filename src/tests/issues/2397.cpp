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
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <vector>
#include "../rnp_tests.h"
#include "../support.h"

/* Issue #2397: RFC 4880, section 4.3, states that a packet tag must not have
 * the value 0. The packet parser previously accepted such a header and skipped
 * the packet as unknown, which GnuPG rejects. Both the new-format (0xc0) and
 * the old-format (0x80) header spellings of tag 0 must be rejected. */
TEST_F(rnp_tests, test_issue_2397_tag0)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    const std::vector<uint8_t> nf_tag0 = {0xc0, 0x01, 0x00};
    const std::vector<uint8_t> of_tag0 = {0x80, 0x00};

    for (const auto &pkt : {nf_tag0, of_tag0}) {
        rnp_input_t input = NULL;
        assert_rnp_success(rnp_input_from_memory(&input, pkt.data(), pkt.size(), false));
        char *json = NULL;
        assert_rnp_failure(rnp_dump_packets_to_json(input, 0, &json));
        assert_null(json);
        rnp_input_destroy(input);

        assert_rnp_success(rnp_input_from_memory(&input, pkt.data(), pkt.size(), false));
        char *results = NULL;
        assert_rnp_failure(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, &results));
        rnp_input_destroy(input);
    }

    rnp_ffi_destroy(ffi);
}
