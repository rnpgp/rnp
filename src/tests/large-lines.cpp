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
#include "utils.h"
#include <vector>
#include <string>

#define BLANKFILE_ASC "data/test_large_lines/blankfile.txt.asc"
#define BLANKFILE_HEADER_ASC "data/test_large_lines/long_header_blankfile.txt.asc"
#define BLANKFILE_PRE_HEADER_ASC "data/test_large_lines/pre_header_blankfile.txt.asc"

static void
load_test_data(const char *file, char **data, size_t *size)
{
    char *      path = NULL;
    struct stat st = {0};

    assert_non_null(file);
    assert_non_null(data);

    path = rnp_compose_path("data", file, NULL);
    assert_non_null(path);

    assert_int_equal(0, stat(path, &st));
    if (size) {
        *size = st.st_size;
    }
    *data = (char *) calloc(1, st.st_size + 1);
    assert_non_null(*data);

    FILE *fp = fopen(path, "r");
    assert_non_null(fp);
    assert_int_equal(st.st_size, fread(*data, 1, st.st_size, fp));
    assert_int_equal(0, fclose(fp));
    free(path);
}

TEST_F(rnp_tests, test_large_lines_detect_key_format)
{
    char * data = NULL;
    size_t data_size = 0;
    char * format = NULL;

    // GPG (armored)
    data = NULL;
    format = NULL;
    load_test_data(BLANKFILE_ASC, &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);

    // invalid
    format = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) "ABC", 3, &format));
    assert_null(format);
}

TEST_F(rnp_tests, test_large_pre_header_detect_key_format)
{
    char * data = NULL;
    size_t data_size = 0;
    char * format = NULL;

    // GPG (armored)
    data = NULL;
    format = NULL;
    load_test_data(BLANKFILE_PRE_HEADER_ASC, &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);

    // invalid
    format = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) "ABC", 3, &format));
    assert_null(format);
}


TEST_F(rnp_tests, test_large_lines_enarmor_dearmor)
{
    std::string data;

    // enarmor plain message
    const std::string msg("this is a test");
    data.clear();
    // test truncated armored data
    {
        std::ifstream keyf(BLANKFILE_HEADER_ASC,std::ios::binary | std::ios::ate);
        std::string   keystr(keyf.tellg(), ' ');
        keyf.seekg(0);
        keyf.read(&keystr[0], keystr.size());
        keyf.close();
        for (size_t sz = keystr.size() - 2; sz > 0; sz--) {
            rnp_input_t  input = NULL;
            rnp_output_t output = NULL;

            assert_rnp_success(
              rnp_input_from_memory(&input, (const uint8_t *) keystr.data(), sz, true));
            assert_rnp_success(rnp_output_to_memory(&output, 0));
            assert_rnp_failure(rnp_dearmor(input, output));

            rnp_input_destroy(input);
            rnp_output_destroy(output);
        }
    }
}


