/*
 * Copyright (c) 2020, [Ribose Inc](https://www.ribose.com).
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

#include <rnp/rnp.h>

#ifdef RNP_RUN_TESTS
int dump_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int
dump_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
#else
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
#endif
{
    rnp_input_t input = NULL;
    (void) rnp_input_from_memory(&input, data, size, false);
    rnp_output_t output = NULL;
    (void) rnp_output_to_null(&output);

    (void) rnp_dump_packets_to_output(input, output, RNP_DUMP_RAW);
    rnp_output_destroy(output);
    rnp_input_destroy(input);

    (void) rnp_input_from_memory(&input, data, size, false);
    char *json = NULL;
    (void) rnp_dump_packets_to_json(input, RNP_DUMP_RAW, &json);
    rnp_buffer_destroy(json);
    rnp_input_destroy(input);

    return 0;
}
