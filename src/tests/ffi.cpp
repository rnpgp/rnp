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

TEST_F(rnp_tests, test_ffi_homedir)
{
    rnp_ffi_t   ffi = NULL;
    char *      pub_format = NULL;
    char *      pub_path = NULL;
    char *      sec_format = NULL;
    char *      sec_path = NULL;
    rnp_input_t input = NULL;

    // get the default homedir (not a very thorough test)
    {
        char *homedir = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_get_default_homedir(&homedir));
        assert_non_null(homedir);
        rnp_buffer_destroy(homedir);
    }

    // detect the formats+paths
    assert_int_equal(RNP_SUCCESS,
                     rnp_detect_homedir_info(
                       "data/keyrings/1", &pub_format, &pub_path, &sec_format, &sec_path));
    // check formats
    assert_int_equal(0, strcmp(pub_format, "GPG"));
    assert_int_equal(0, strcmp(sec_format, "GPG"));
    // check paths
    assert_int_equal(0, strcmp(pub_path, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(0, strcmp(sec_path, "data/keyrings/1/secring.gpg"));
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, pub_format, sec_format));
    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // free formats+paths
    rnp_buffer_destroy(pub_format);
    pub_format = NULL;
    rnp_buffer_destroy(pub_path);
    pub_path = NULL;
    rnp_buffer_destroy(sec_format);
    sec_format = NULL;
    rnp_buffer_destroy(sec_path);
    sec_path = NULL;
    // check key counts
    size_t count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    // detect the formats+paths
    assert_int_equal(RNP_SUCCESS,
                     rnp_detect_homedir_info(
                       "data/keyrings/3", &pub_format, &pub_path, &sec_format, &sec_path));
    // check formats
    assert_int_equal(0, strcmp(pub_format, "KBX"));
    assert_int_equal(0, strcmp(sec_format, "G10"));
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, pub_format, sec_format));
    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "KBX", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "G10", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // free formats+paths
    rnp_buffer_destroy(pub_format);
    pub_format = NULL;
    rnp_buffer_destroy(pub_path);
    pub_path = NULL;
    rnp_buffer_destroy(sec_format);
    sec_format = NULL;
    rnp_buffer_destroy(sec_path);
    sec_path = NULL;
    // check key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);
    // check grip (1)
    rnp_key_handle_t key = NULL;
    assert_int_equal(
      RNP_SUCCESS,
      rnp_locate_key(ffi, "grip", "63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59", &key));
    assert_non_null(key);
    char *grip = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_key_get_grip(key, &grip));
    assert_non_null(grip);
    assert_true(strcmp(grip, "63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59") == 0);
    rnp_buffer_destroy(grip);
    grip = NULL;
    rnp_key_handle_destroy(key);
    key = NULL;
    // check grip (2)
    assert_int_equal(
      RNP_SUCCESS,
      rnp_locate_key(ffi, "grip", "7EAB41A2F46257C36F2892696F5A2F0432499AD3", &key));
    assert_non_null(key);
    grip = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_key_get_grip(key, &grip));
    assert_non_null(grip);
    assert_true(strcmp(grip, "7EAB41A2F46257C36F2892696F5A2F0432499AD3") == 0);
    rnp_buffer_destroy(grip);
    grip = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_key_handle_destroy(key));
    key = NULL;
    // cleanup
    rnp_ffi_destroy(ffi);
}

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

TEST_F(rnp_tests, test_ffi_detect_key_format)
{
    char * data = NULL;
    size_t data_size = 0;
    char * format = NULL;

    // GPG
    data = NULL;
    format = NULL;
    load_test_data("keyrings/1/pubring.gpg", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);

    // GPG
    data = NULL;
    format = NULL;
    load_test_data("keyrings/1/secring.gpg", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);
    format = NULL;

    // GPG (armored)
    data = NULL;
    format = NULL;
    load_test_data("keyrings/4/rsav3-p.asc", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);

    // KBX
    data = NULL;
    format = NULL;
    load_test_data("keyrings/3/pubring.kbx", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "KBX"));
    free(data);
    free(format);

    // G10
    data = NULL;
    format = NULL;
    load_test_data("keyrings/3/private-keys-v1.d/63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59.key",
                   &data,
                   &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "G10"));
    free(data);
    free(format);

    // invalid
    format = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) "ABC", 3, &format));
    assert_null(format);
}

TEST_F(rnp_tests, test_ffi_load_keys)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;
    size_t      count;

    /* load public keys from pubring */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // again
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(0, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    /* load public keys from secring */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(0, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    /* load secret keys from secring */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load secring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // again
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check counts
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(0, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    /* load secret keys from pubring */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    // check counts
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(0, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(0, count);
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    /* concatenate the pubring and secrings into a single buffer */
    char * pub_buf = NULL;
    size_t pub_buf_len = 0;
    char * sec_buf = NULL;
    size_t sec_buf_len = 0;
    FILE * fp = fopen("combined-rings.gpg", "wb");
    assert_non_null(fp);
    load_test_data("keyrings/1/pubring.gpg", &pub_buf, &pub_buf_len);
    load_test_data("keyrings/1/secring.gpg", &sec_buf, &sec_buf_len);
    size_t   buf_len = pub_buf_len + sec_buf_len;
    uint8_t *buf = (uint8_t *) malloc(buf_len);
    memcpy(buf, pub_buf, pub_buf_len);
    memcpy(buf + pub_buf_len, sec_buf, sec_buf_len);
    free(pub_buf);
    free(sec_buf);

    /* load secret keys from pubring */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load
    assert_int_equal(RNP_SUCCESS, rnp_input_from_memory(&input, buf, buf_len, true));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // again
    assert_int_equal(RNP_SUCCESS, rnp_input_from_memory(&input, buf, buf_len, true));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check counts
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    free(buf);
}

TEST_F(rnp_tests, test_ffi_clear_keys)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;
    size_t      pub_count;
    size_t      sec_count;

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_non_null(input);
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // load secring
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_non_null(input);
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(7, pub_count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(7, sec_count);
    // clear public keys
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(pub_count, 0);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(sec_count, 7);
    // clear secret keys
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(pub_count, 0);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(sec_count, 0);
    // load public and clear secret keys
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_non_null(input);
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(pub_count, 7);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(sec_count, 0);
    // load secret keys and clear all
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_non_null(input);
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(7, pub_count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(7, sec_count);
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(pub_count, 0);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(sec_count, 0);
    // attempt to clear NULL ffi
    assert_rnp_failure(rnp_unload_keys(NULL, RNP_KEY_UNLOAD_SECRET));
    // attempt to pass wrong flags
    assert_rnp_failure(rnp_unload_keys(ffi, 255));
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
}

TEST_F(rnp_tests, test_ffi_save_keys)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;
    char *       temp_dir = NULL;
    char *       pub_path = NULL;
    char *       sec_path = NULL;
    char *       both_path = NULL;
    size_t       count;

    temp_dir = make_temp_dir();

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // load secring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // save pubring
    pub_path = rnp_compose_path(temp_dir, "pubring.gpg", NULL);
    assert_false(rnp_file_exists(pub_path));
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, pub_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_save_keys(ffi, "GPG", output, RNP_LOAD_SAVE_PUBLIC_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(pub_path));
    // save secring
    sec_path = rnp_compose_path(temp_dir, "secring.gpg", NULL);
    assert_false(rnp_file_exists(sec_path));
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, sec_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_save_keys(ffi, "GPG", output, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(sec_path));
    // save pubring && secring
    both_path = rnp_compose_path(temp_dir, "bothring.gpg", NULL);
    assert_false(rnp_file_exists(both_path));
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, both_path));
    assert_int_equal(
      RNP_SUCCESS,
      rnp_save_keys(
        ffi, "GPG", output, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(both_path));
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    // start over (read from the saved locations)
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // load secring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check the counts
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    // load both keyrings from the single file
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, both_path));
    assert_non_null(input);
    assert_int_equal(
      RNP_SUCCESS,
      rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check the counts. We should get both secret and public keys, since public keys are
    // extracted from the secret ones.
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    free(pub_path);
    free(sec_path);
    free(both_path);

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "KBX", "G10"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/3/pubring.kbx"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "KBX", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // load secring
    assert_int_equal(RNP_SUCCESS,
                     rnp_input_from_path(&input, "data/keyrings/3/private-keys-v1.d"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "G10", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // save pubring
    pub_path = rnp_compose_path(temp_dir, "pubring.kbx", NULL);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, pub_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_save_keys(ffi, "KBX", output, RNP_LOAD_SAVE_PUBLIC_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(pub_path));
    // save secring to file - will fail for G10
    sec_path = rnp_compose_path(temp_dir, "secring.file", NULL);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, sec_path));
    assert_int_not_equal(RNP_SUCCESS,
                         rnp_save_keys(ffi, "G10", output, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    free(sec_path);
    // save secring
    sec_path = rnp_compose_path(temp_dir, "private-keys-v1.d", NULL);
    assert_false(rnp_dir_exists(sec_path));
    assert_int_equal(0, mkdir(sec_path, S_IRWXU));
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, sec_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_save_keys(ffi, "G10", output, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_dir_exists(sec_path));
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    // start over (read from the saved locations)
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "KBX", "G10"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "KBX", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // load secring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "G10", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check the counts
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    free(pub_path);
    free(sec_path);

    // final cleanup
    free(temp_dir);
}

static void
unused_getkeycb(rnp_ffi_t   ffi,
                void *      app_ctx,
                const char *identifier_type,
                const char *identifier,
                bool        secret)
{
    assert_true(false);
}

#define TBL_MAX_USERIDS 4
typedef struct key_tbl_t {
    const uint8_t *key_data;
    size_t         key_data_size;
    bool           secret;
    const char *   keyid;
    const char *   grip;
    const char *   userids[TBL_MAX_USERIDS + 1];
} key_tbl_t;

static void
tbl_getkeycb(rnp_ffi_t   ffi,
             void *      app_ctx,
             const char *identifier_type,
             const char *identifier,
             bool        secret)
{
    key_tbl_t *found = NULL;
    for (key_tbl_t *tbl = (key_tbl_t *) app_ctx; tbl && tbl->key_data && !found; tbl++) {
        if (tbl->secret != secret) {
            continue;
        }
        if (!strcmp(identifier_type, "keyid") && !strcmp(identifier, tbl->keyid)) {
            found = tbl;
            break;
        } else if (!strcmp(identifier_type, "grip") && !strcmp(identifier, tbl->grip)) {
            found = tbl;
            break;
        } else if (!strcmp(identifier_type, "userid")) {
            for (size_t i = 0; i < TBL_MAX_USERIDS; i++) {
                if (!strcmp(identifier, tbl->userids[i])) {
                    found = tbl;
                    break;
                }
            }
        }
    }
    if (found) {
        char *format = NULL;
        assert_rnp_success(
          rnp_detect_key_format(found->key_data, found->key_data_size, &format));
        assert_non_null(format);
        uint32_t    flags = secret ? RNP_LOAD_SAVE_SECRET_KEYS : RNP_LOAD_SAVE_PUBLIC_KEYS;
        rnp_input_t input = NULL;
        assert_rnp_success(
          rnp_input_from_memory(&input, found->key_data, found->key_data_size, true));
        assert_non_null(input);
        assert_rnp_success(rnp_load_keys(ffi, format, input, flags));
        free(format);
        assert_rnp_success(rnp_input_destroy(input));
        input = NULL;
    }
}

static bool
unused_getpasscb(rnp_ffi_t        ffi,
                 void *           app_ctx,
                 rnp_key_handle_t key,
                 const char *     pgp_context,
                 char *           buf,
                 size_t           buf_len)
{
    assert_true(false);
    return false;
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

static bool
getpasscb_once(rnp_ffi_t        ffi,
               void *           app_ctx,
               rnp_key_handle_t key,
               const char *     pgp_context,
               char *           buf,
               size_t           buf_len)
{
    const char **pass = (const char **) app_ctx;
    if (!*pass) {
        return false;
    }
    strcpy(buf, *pass);
    *pass = NULL;
    return true;
}

static bool
getpasscb_inc(rnp_ffi_t        ffi,
               void *           app_ctx,
               rnp_key_handle_t key,
               const char *     pgp_context,
               char *           buf,
               size_t           buf_len)
{
    int *num = (int *) app_ctx;
    std::string pass = "pass" + std::to_string(*num);
    (*num)++;
    strncpy(buf, pass.c_str(), buf_len - 1);
    return true;
}

static void
check_key_properties(rnp_key_handle_t key,
                     bool             primary_exptected,
                     bool             have_public_expected,
                     bool             have_secret_expected)
{
    bool isprimary = !primary_exptected;
    assert_int_equal(RNP_SUCCESS, rnp_key_is_primary(key, &isprimary));
    assert_true(isprimary == primary_exptected);
    bool issub = primary_exptected;
    assert_int_equal(RNP_SUCCESS, rnp_key_is_sub(key, &issub));
    assert_true(issub == !primary_exptected);
    bool have_public = !have_public_expected;
    assert_int_equal(RNP_SUCCESS, rnp_key_have_public(key, &have_public));
    assert_true(have_public == have_public_expected);
    bool have_secret = !have_secret_expected;
    assert_int_equal(RNP_SUCCESS, rnp_key_have_secret(key, &have_secret));
    assert_true(have_secret == have_secret_expected);
}

TEST_F(rnp_tests, test_ffi_keygen_json_pair)
{
    rnp_ffi_t ffi = NULL;
    char *    json = NULL;
    char *    results = NULL;
    size_t    count = 0;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "abc"));

    // load our JSON
    load_test_data("test_ffi_json/generate-pair.json", &json, NULL);

    // generate the keys
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    free(json);
    json = NULL;

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle for the primary
    rnp_key_handle_t primary = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &primary));
        assert_non_null(primary);
    }
    // get a handle for the sub
    rnp_key_handle_t sub = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "sub", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &sub));
        assert_non_null(sub);
    }
    // cleanup
    json_object_put(parsed_results);

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(primary, true, true, true);
    check_key_properties(sub, false, true, true);

    // check sub bit length
    uint32_t length = 0;
    assert_rnp_success(rnp_key_get_bits(sub, &length));
    assert_int_equal(1024, length);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_keygen_json_pair_dsa_elg)
{
    rnp_ffi_t ffi = NULL;
    char *    json = NULL;
    char *    results = NULL;
    size_t    count = 0;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "abc"));

    // load our JSON
    load_test_data("test_ffi_json/generate-pair-dsa-elg.json", &json, NULL);

    // generate the keys
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    free(json);
    json = NULL;

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle for the primary
    rnp_key_handle_t primary = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &primary));
        assert_non_null(primary);
    }
    // get a handle for the sub
    rnp_key_handle_t sub = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "sub", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &sub));
        assert_non_null(sub);
    }
    // cleanup
    json_object_put(parsed_results);

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(primary, true, true, true);
    check_key_properties(sub, false, true, true);

    // check bit lengths
    uint32_t length = 0;
    assert_rnp_success(rnp_key_get_bits(primary, &length));
    assert_int_equal(length, 1024);
    assert_rnp_success(rnp_key_get_bits(sub, &length));
    assert_int_equal(length, 1536);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_keygen_json_primary)
{
    rnp_ffi_t ffi = NULL;
    char *    json = NULL;
    char *    results = NULL;
    size_t    count = 0;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // load our JSON
    load_test_data("test_ffi_json/generate-primary.json", &json, NULL);

    // generate the keys
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    free(json);
    json = NULL;

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle for the primary
    rnp_key_handle_t primary = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &primary));
        assert_non_null(primary);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(1, count);

    // check some key properties
    check_key_properties(primary, true, true, true);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_ffi_destroy(ffi);
}

/* This test generates a primary key, and then a subkey (separately).
 */
TEST_F(rnp_tests, test_ffi_keygen_json_sub)
{
    char *    json = NULL;
    char *    results = NULL;
    size_t    count = 0;
    rnp_ffi_t ffi = NULL;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // generate our primary key
    load_test_data("test_ffi_json/generate-primary.json", &json, NULL);
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    free(json);
    assert_non_null(results);
    // check key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(1, count);

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle+grip for the primary
    rnp_key_handle_t primary = NULL;
    char *           primary_grip = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        primary_grip = strdup(json_object_get_string(jsogrip));
        assert_non_null(primary_grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", primary_grip, &primary));
        assert_non_null(primary);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // load our JSON template
    load_test_data("test_ffi_json/generate-sub.json", &json, NULL);
    // modify our JSON
    {
        // parse
        json_object *jso = json_tokener_parse(json);
        assert_non_null(jso);
        free(json);
        json = NULL;
        // find the relevant fields
        json_object *jsosub = NULL;
        json_object *jsoprimary = NULL;
        assert_true(json_object_object_get_ex(jso, "sub", &jsosub));
        assert_non_null(jsosub);
        assert_true(json_object_object_get_ex(jsosub, "primary", &jsoprimary));
        assert_non_null(jsoprimary);
        // replace the placeholder grip with the correct one
        json_object_object_del(jsoprimary, "grip");
        json_object_object_add(jsoprimary, "grip", json_object_new_string(primary_grip));
        assert_int_equal(1, json_object_object_length(jsoprimary));
        json = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
        assert_non_null(json);
        json_object_put(jso);
    }
    // cleanup
    rnp_buffer_destroy(primary_grip);
    primary_grip = NULL;

    // generate the subkey
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    // cleanup
    free(json);
    json = NULL;

    // parse the results JSON
    parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle for the sub
    rnp_key_handle_t sub = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "sub", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &sub));
        assert_non_null(sub);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(primary, true, true, true);
    check_key_properties(sub, false, true, true);

    // check sub bit length
    uint32_t length = 0;
    assert_rnp_success(rnp_key_get_bits(sub, &length));
    assert_int_equal(length, 1024);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_generate_misc)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));

    /* make sure we do not leak key handle and do not access NULL */
    assert_rnp_success(rnp_generate_key_rsa(ffi, 1024, 1024, "rsa", NULL, NULL));

    /* make sure we do not leak password on failed key generation */
    rnp_key_handle_t key = NULL;
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 768, 2048, "rsa_768", "password", &key));
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 1024, 768, "rsa_768", "password", &key));

    /* make sure we behave correctly and do not leak data on wrong parameters to _generate_ex
     * function */
    assert_rnp_failure(rnp_generate_key_ex(
      ffi, "RSA", "RSA", 1024, 1024, "Curve", NULL, "userid", "password", &key));
    assert_rnp_failure(rnp_generate_key_ex(
      ffi, "RSA", "RSA", 1024, 1024, "Curve", NULL, NULL, "password", &key));
    assert_rnp_failure(rnp_generate_key_ex(
      ffi, "RSA", "RSA", 1024, 768, NULL, "Curve", NULL, "password", &key));
    assert_rnp_failure(rnp_generate_key_ex(
      ffi, "ECDSA", "ECDH", 1024, 0, "Unknown", "Curve", NULL, NULL, &key));
    assert_rnp_failure(rnp_generate_key_ex(
      ffi, "ECDSA", "ECDH", 0, 1024, "Unknown", "Curve", NULL, "password", &key));

    /* generate RSA-RSA key without password */
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "abc"));
    assert_rnp_success(rnp_generate_key_rsa(ffi, 1024, 1024, "rsa_1024", NULL, &key));
    assert_non_null(key);
    bool locked = false;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_false(locked);
    /* check key and subkey flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    /* generate encrypted RSA-RSA key */
    assert_rnp_success(rnp_generate_key_rsa(ffi, 1024, 1024, "rsa_1024", "123", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    /* make sure it can be unlocked with correct password */
    assert_rnp_success(rnp_key_unlock(key, "123"));
    /* do the same for subkey */
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_key_is_locked(subkey, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_unlock(subkey, "123"));
    /* cleanup */
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    /* generate encrypted RSA key (primary only) */
    key = NULL;
    assert_rnp_success(
      rnp_generate_key_ex(ffi, "RSA", NULL, 1024, 0, NULL, NULL, "rsa_1024", "123", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    bool prot = false;
    assert_rnp_success(rnp_key_is_protected(key, &prot));
    assert_true(prot);
    /* cleanup */
    rnp_key_handle_destroy(key);

    /* cleanup */
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_rsa)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    /* make sure we fail to generate too small and too large keys/subkeys */
    rnp_key_handle_t key = NULL;
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 768, 2048, "rsa_768", NULL, &key));
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 1024, 768, "rsa_768", NULL, &key));
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 20480, 1024, "rsa_20480", NULL, &key));
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 1024, 20480, "rsa_20480", NULL, &key));
    /* generate RSA-RSA key */
    assert_rnp_success(rnp_generate_key_rsa(ffi, 1024, 2048, "rsa_1024", NULL, &key));
    assert_non_null(key);
    /* check properties of the generated key */
    bool boolres = false;
    assert_rnp_success(rnp_key_is_primary(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_public(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(key, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(key, &boolres));
    assert_false(boolres);
    /* algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_key_get_alg(key, &alg));
    assert_int_equal(strcasecmp(alg, "RSA"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    uint32_t bits = 0;
    assert_rnp_failure(rnp_key_get_bits(key, NULL));
    assert_rnp_success(rnp_key_get_bits(key, &bits));
    assert_int_equal(bits, 1024);
    assert_rnp_failure(rnp_key_get_dsa_qbits(key, &bits));
    /* key flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* curve - must fail */
    char *curve = NULL;
    assert_rnp_failure(rnp_key_get_curve(key, NULL));
    assert_rnp_failure(rnp_key_get_curve(key, &curve));
    assert_null(curve);
    /* user ids */
    size_t uids = 0;
    char * uid = NULL;
    assert_rnp_success(rnp_key_get_uid_count(key, &uids));
    assert_int_equal(uids, 1);
    assert_rnp_failure(rnp_key_get_uid_at(key, 1, &uid));
    assert_null(uid);
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_int_equal(strcmp(uid, "rsa_1024"), 0);
    rnp_buffer_destroy(uid);
    /* subkey */
    size_t subkeys = 0;
    assert_rnp_failure(rnp_key_get_subkey_count(key, NULL));
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 1);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_failure(rnp_key_get_subkey_at(key, 1, &subkey));
    assert_rnp_failure(rnp_key_get_subkey_at(key, 0, NULL));
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    /* check properties of the generated subkey */
    assert_rnp_success(rnp_key_is_primary(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_have_public(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(subkey, &boolres));
    assert_false(boolres);
    /* algorithm */
    assert_rnp_success(rnp_key_get_alg(subkey, &alg));
    assert_int_equal(strcasecmp(alg, "RSA"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    assert_rnp_success(rnp_key_get_bits(subkey, &bits));
    assert_int_equal(bits, 2048);
    /* subkey flags */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    /* cleanup */
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* generate RSA key without the subkey */
    assert_rnp_success(rnp_generate_key_rsa(ffi, 1024, 0, "rsa_1024", NULL, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 0);
    /* cleanup */
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_dsa)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    /* try to generate keys with invalid sizes */
    rnp_key_handle_t key = NULL;
    assert_rnp_failure(rnp_generate_key_dsa_eg(ffi, 768, 2048, "dsa_768", NULL, &key));
    assert_rnp_failure(rnp_generate_key_dsa_eg(ffi, 1024, 768, "dsa_768", NULL, &key));
    assert_rnp_failure(rnp_generate_key_dsa_eg(ffi, 4096, 1024, "dsa_20480", NULL, &key));
    assert_rnp_failure(rnp_generate_key_dsa_eg(ffi, 1024, 20480, "dsa_20480", NULL, &key));
    /* generate DSA-ElGamal keypair */
    assert_rnp_success(rnp_generate_key_dsa_eg(ffi, 1024, 1024, "dsa_1024", NULL, &key));
    assert_non_null(key);
    /* check properties of the generated key */
    bool boolres = false;
    assert_rnp_success(rnp_key_is_primary(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_public(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(key, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(key, &boolres));
    assert_false(boolres);
    /* algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_key_get_alg(key, &alg));
    assert_int_equal(strcasecmp(alg, "DSA"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    uint32_t bits = 0;
    assert_rnp_success(rnp_key_get_bits(key, &bits));
    assert_int_equal(bits, 1024);
    assert_rnp_success(rnp_key_get_dsa_qbits(key, &bits));
    assert_int_equal(bits, 160);
    /* key flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* user ids */
    size_t uids = 0;
    char * uid = NULL;
    assert_rnp_success(rnp_key_get_uid_count(key, &uids));
    assert_int_equal(uids, 1);
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_int_equal(strcmp(uid, "dsa_1024"), 0);
    rnp_buffer_destroy(uid);
    /* subkey */
    size_t subkeys = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 1);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    /* check properties of the generated subkey */
    assert_rnp_success(rnp_key_is_primary(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_have_public(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(subkey, &boolres));
    assert_false(boolres);
    /* algorithm */
    assert_rnp_success(rnp_key_get_alg(subkey, &alg));
    assert_int_equal(strcasecmp(alg, "ElGamal"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    assert_rnp_success(rnp_key_get_bits(subkey, &bits));
    assert_int_equal(bits, 1024);
    /* subkey flags */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    /* cleanup */
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* generate DSA key without the subkey */
    assert_rnp_success(rnp_generate_key_dsa_eg(ffi, 1024, 0, "dsa_1024", NULL, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 0);
    /* cleanup */
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_ecdsa)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    /* try to generate key with invalid curve */
    rnp_key_handle_t key = NULL;
    assert_rnp_failure(rnp_generate_key_ec(ffi, "curve_wrong", "wrong", NULL, &key));
    assert_null(key);
    /* generate secp256k1 key */
    assert_rnp_success(rnp_generate_key_ec(ffi, "secp256k1", "ec_256k1", NULL, &key));
    assert_non_null(key);
    /* check properties of the generated key */
    bool boolres = false;
    assert_rnp_success(rnp_key_is_primary(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_public(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(key, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(key, &boolres));
    assert_false(boolres);
    /* algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_key_get_alg(key, &alg));
    assert_int_equal(strcasecmp(alg, "ECDSA"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    uint32_t bits = 0;
    assert_rnp_success(rnp_key_get_bits(key, &bits));
    assert_int_equal(bits, 256);
    assert_rnp_failure(rnp_key_get_dsa_qbits(key, &bits));
    /* curve */
    char *curve = NULL;
    assert_rnp_failure(rnp_key_get_curve(key, NULL));
    assert_rnp_success(rnp_key_get_curve(key, &curve));
    assert_int_equal(strcasecmp(curve, "secp256k1"), 0);
    rnp_buffer_destroy(curve);
    /* key flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* user ids */
    size_t uids = 0;
    char * uid = NULL;
    assert_rnp_success(rnp_key_get_uid_count(key, &uids));
    assert_int_equal(uids, 1);
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_int_equal(strcmp(uid, "ec_256k1"), 0);
    rnp_buffer_destroy(uid);
    /* subkey */
    size_t subkeys = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 1);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    /* check properties of the generated subkey */
    assert_rnp_success(rnp_key_is_primary(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_have_public(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(subkey, &boolres));
    assert_false(boolres);
    /* algorithm */
    assert_rnp_success(rnp_key_get_alg(subkey, &alg));
    assert_int_equal(strcasecmp(alg, "ECDH"), 0);
    rnp_buffer_destroy(alg);
    /* bits */
    assert_rnp_success(rnp_key_get_bits(subkey, &bits));
    assert_int_equal(bits, 256);
    /* curve */
    curve = NULL;
    assert_rnp_success(rnp_key_get_curve(subkey, &curve));
    assert_int_equal(strcasecmp(curve, "secp256k1"), 0);
    rnp_buffer_destroy(curve);
    /* subkey flags */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);

    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_eddsa)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    /* generate key with subkey */
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_generate_key_25519(ffi, "eddsa_25519", NULL, &key));
    assert_non_null(key);
    /* check properties of the generated key */
    bool boolres = false;
    assert_rnp_success(rnp_key_is_primary(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_public(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(key, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(key, &boolres));
    assert_false(boolres);
    /* algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_key_get_alg(key, &alg));
    assert_int_equal(strcasecmp(alg, "EDDSA"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    uint32_t bits = 0;
    assert_rnp_success(rnp_key_get_bits(key, &bits));
    assert_int_equal(bits, 255);
    /* curve */
    char *curve = NULL;
    assert_rnp_success(rnp_key_get_curve(key, &curve));
    assert_int_equal(strcasecmp(curve, "ed25519"), 0);
    rnp_buffer_destroy(curve);
    /* key flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* user ids */
    size_t uids = 0;
    char * uid = NULL;
    assert_rnp_success(rnp_key_get_uid_count(key, &uids));
    assert_int_equal(uids, 1);
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_int_equal(strcmp(uid, "eddsa_25519"), 0);
    rnp_buffer_destroy(uid);
    /* subkey */
    size_t subkeys = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 1);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    /* check properties of the generated subkey */
    assert_rnp_success(rnp_key_is_primary(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_have_public(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(subkey, &boolres));
    assert_false(boolres);
    /* algorithm */
    assert_rnp_success(rnp_key_get_alg(subkey, &alg));
    assert_int_equal(strcasecmp(alg, "ECDH"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    assert_rnp_success(rnp_key_get_bits(subkey, &bits));
    assert_int_equal(bits, 255);
    /* curve */
    curve = NULL;
    assert_rnp_success(rnp_key_get_curve(subkey, &curve));
    assert_int_equal(strcasecmp(curve, "Curve25519"), 0);
    rnp_buffer_destroy(curve);
    /* subkey flags */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);

    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_sm2)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));

    /* generate sm2 key */
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_generate_key_sm2(ffi, "sm2", NULL, &key));
    assert_non_null(key);
    /* check properties of the generated key */
    bool boolres = false;
    assert_rnp_success(rnp_key_is_primary(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_public(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(key, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(key, &boolres));
    assert_false(boolres);
    /* algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_key_get_alg(key, &alg));
    assert_int_equal(strcasecmp(alg, "SM2"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    uint32_t bits = 0;
    assert_rnp_success(rnp_key_get_bits(key, &bits));
    assert_int_equal(bits, 256);
    /* curve */
    char *curve = NULL;
    assert_rnp_success(rnp_key_get_curve(key, &curve));
    assert_int_equal(strcasecmp(curve, "SM2 P-256"), 0);
    rnp_buffer_destroy(curve);
    /* key flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* user ids */
    size_t uids = 0;
    char * uid = NULL;
    assert_rnp_success(rnp_key_get_uid_count(key, &uids));
    assert_int_equal(uids, 1);
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_int_equal(strcmp(uid, "sm2"), 0);
    rnp_buffer_destroy(uid);
    /* subkey */
    size_t subkeys = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 1);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    /* check properties of the generated subkey */
    assert_rnp_success(rnp_key_is_primary(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_have_public(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(subkey, &boolres));
    assert_false(boolres);
    /* algorithm */
    assert_rnp_success(rnp_key_get_alg(subkey, &alg));
    assert_int_equal(strcasecmp(alg, "SM2"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    assert_rnp_success(rnp_key_get_bits(subkey, &bits));
    assert_int_equal(bits, 256);
    /* curve */
    curve = NULL;
    assert_rnp_success(rnp_key_get_curve(subkey, &curve));
    assert_int_equal(strcasecmp(curve, "SM2 P-256"), 0);
    rnp_buffer_destroy(curve);
    /* subkey flags */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);

    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_ex)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "123"));

    /* Generate RSA key with misc options set */
    rnp_op_generate_t keygen = NULL;
    assert_rnp_success(rnp_op_generate_create(&keygen, ffi, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_failure(rnp_op_generate_set_dsa_qbits(keygen, 256));
    /* key usage */
    assert_rnp_success(rnp_op_generate_clear_usage(keygen));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "usage"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "encrypt"));
    /* preferred ciphers */
    assert_rnp_success(rnp_op_generate_clear_pref_ciphers(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_cipher(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_add_pref_cipher(keygen, "blowfish"));
    assert_rnp_success(rnp_op_generate_clear_pref_ciphers(keygen));
    assert_rnp_success(rnp_op_generate_add_pref_cipher(keygen, "camellia256"));
    assert_rnp_success(rnp_op_generate_add_pref_cipher(keygen, "aes256"));
    /* preferred compression algorithms */
    assert_rnp_success(rnp_op_generate_clear_pref_compression(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_compression(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_add_pref_compression(keygen, "zlib"));
    assert_rnp_success(rnp_op_generate_clear_pref_compression(keygen));
    assert_rnp_success(rnp_op_generate_add_pref_compression(keygen, "zip"));
    assert_rnp_success(rnp_op_generate_add_pref_compression(keygen, "zlib"));
    /* preferred hash algorithms */
    assert_rnp_success(rnp_op_generate_clear_pref_hashes(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_hash(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_add_pref_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_clear_pref_hashes(keygen));
    assert_rnp_success(rnp_op_generate_add_pref_hash(keygen, "sha512"));
    assert_rnp_success(rnp_op_generate_add_pref_hash(keygen, "sha256"));
    /* key expiration */
    assert_rnp_success(rnp_op_generate_set_expiration(keygen, 60 * 60 * 24 * 100));
    assert_rnp_success(rnp_op_generate_set_expiration(keygen, 60 * 60 * 24 * 300));
    /* preferred key server */
    assert_rnp_success(rnp_op_generate_set_pref_keyserver(keygen, NULL));
    assert_rnp_success(rnp_op_generate_set_pref_keyserver(keygen, "hkp://first.server/"));
    assert_rnp_success(rnp_op_generate_set_pref_keyserver(keygen, "hkp://second.server/"));
    /* user id */
    assert_rnp_failure(rnp_op_generate_set_userid(keygen, NULL));
    assert_rnp_success(rnp_op_generate_set_userid(keygen, "userid_cleared"));
    assert_rnp_success(rnp_op_generate_set_userid(keygen, "userid"));
    /* protection */
    assert_rnp_failure(rnp_op_generate_set_protection_cipher(keygen, NULL));
    assert_rnp_failure(rnp_op_generate_set_protection_cipher(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes256"));
    assert_rnp_failure(rnp_op_generate_set_protection_hash(keygen, NULL));
    assert_rnp_failure(rnp_op_generate_set_protection_hash(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha256"));
    assert_rnp_success(rnp_op_generate_set_protection_iterations(keygen, 65536));
    assert_rnp_failure(rnp_op_generate_set_protection_mode(keygen, NULL));
    assert_rnp_failure(rnp_op_generate_set_protection_mode(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_set_protection_mode(keygen, "cfb"));
    /* now execute keygen operation */
    assert_rnp_success(rnp_op_generate_set_request_password(keygen, true));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check key usage */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* check key creation and expiration */
    uint32_t create = 0;
    assert_rnp_success(rnp_key_get_creation(key, &create));
    assert_true((create != 0) && (create <= time(NULL)));
    uint32_t expiry = 0;
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_true(expiry == 60 * 60 * 24 * 300);
    /* check whether key is encrypted */
    assert_rnp_success(rnp_key_is_protected(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(key, "123"));
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_lock(key));

    /* generate DSA subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "DSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1536));
    assert_rnp_success(rnp_op_generate_set_dsa_qbits(keygen, 224));
    /* key flags */
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "certify"));
    /* these should not work for subkey */
    assert_rnp_failure(rnp_op_generate_clear_pref_ciphers(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_cipher(keygen, "aes256"));
    assert_rnp_failure(rnp_op_generate_clear_pref_compression(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_compression(keygen, "zlib"));
    assert_rnp_failure(rnp_op_generate_clear_pref_hashes(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_hash(keygen, "unknown"));
    assert_rnp_failure(rnp_op_generate_set_pref_keyserver(keygen, "hkp://first.server/"));
    assert_rnp_failure(rnp_op_generate_set_userid(keygen, "userid"));
    /* key expiration */
    assert_rnp_success(rnp_op_generate_set_expiration(keygen, 60 * 60 * 24 * 300));
    /* key protection */
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes256"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha256"));
    assert_rnp_success(rnp_op_generate_set_protection_iterations(keygen, 65536));
    assert_rnp_success(rnp_op_generate_set_request_password(keygen, true));
    /* now generate the subkey */
    assert_rnp_success(rnp_op_generate_execute(keygen));
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    /* check subkey creation and expiration */
    create = 0;
    assert_rnp_success(rnp_key_get_creation(subkey, &create));
    assert_true((create != 0) && (create <= time(NULL)));
    expiry = 0;
    assert_rnp_success(rnp_key_get_expiration(subkey, &expiry));
    assert_true(expiry == 60 * 60 * 24 * 300);
    /* check whether subkey is encrypted */
    assert_rnp_success(rnp_key_is_protected(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(subkey, "123"));
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_lock(subkey));
    /* destroy key handle */
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* generate RSA sign/encrypt subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_expiration(keygen, 0));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    /* set bits for iterations instead of exact iterations number */
    assert_rnp_success(rnp_op_generate_set_protection_iterations(keygen, 12));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    /* check whether subkey is encrypted - it should not */
    assert_rnp_success(rnp_key_is_protected(subkey, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* generate ElGamal subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ElGamal"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_expiration(keygen, 0));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* generate ECDSA subkeys for each curve */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_failure(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_failure(rnp_op_generate_set_dsa_qbits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-256"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-384"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-521"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "brainpoolP256r1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "brainpoolP384r1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "brainpoolP512r1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "secp256k1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* These curves will not work with ECDSA*/
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "Ed25519"));
    assert_rnp_failure(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_destroy(keygen));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "Curve25519"));
    assert_rnp_failure(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_destroy(keygen));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "SM2 P-256"));
    assert_rnp_failure(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_destroy(keygen));

    /* Add EDDSA subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "EDDSA"));
    assert_rnp_failure(rnp_op_generate_set_curve(keygen, "secp256k1"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* Add ECDH subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDH"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-256"));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* Add ECDH x25519 subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDH"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "Curve25519"));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* Add SM2 subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "SM2"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_protection)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "123"));

    /* Generate key and subkey without protection */
    rnp_op_generate_t keygen = NULL;
    assert_rnp_success(rnp_op_generate_create(&keygen, ffi, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* check whether key is encrypted */
    bool flag = true;
    assert_rnp_success(rnp_key_is_protected(key, &flag));
    assert_false(flag);
    /* generate subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_is_protected(subkey, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* Generate RSA key with password */
    assert_rnp_success(rnp_op_generate_create(&keygen, ffi, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_set_protection_password(keygen, "password"));
    /* Line below should not change password from 'password' to '123' */
    assert_rnp_success(rnp_op_generate_set_request_password(keygen, true));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    key = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* check whether key is encrypted */
    assert_rnp_success(rnp_key_is_protected(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(key, "password"));
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_lock(key));
    /* generate subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_set_protection_password(keygen, "password"));
    /* this should fail since primary key is locked */
    assert_rnp_failure(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_key_unlock(key, "password"));
    /* now it should work */
    assert_rnp_success(rnp_op_generate_execute(keygen));
    subkey = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_is_protected(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(subkey, "password"));
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* Generate RSA key via password request */
    assert_rnp_success(rnp_op_generate_create(&keygen, ffi, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_set_request_password(keygen, true));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    key = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* check whether key is encrypted */
    assert_rnp_success(rnp_key_is_protected(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(key, "123"));
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_lock(key));
    /* generate subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_set_request_password(keygen, true));
    /* this should succeed since password for primary key is returned via provider */
    assert_rnp_success(rnp_op_generate_execute(keygen));
    subkey = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_is_protected(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(subkey, "123"));
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_add_userid)
{
    rnp_ffi_t ffi = NULL;
    char *    json = NULL;
    char *    results = NULL;
    size_t    count = 0;

    const char *new_userid = "my new userid <user@example.com>";

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));

    // load our JSON
    load_test_data("test_ffi_json/generate-primary.json", &json, NULL);

    // generate the keys
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    rnp_buffer_destroy(results);
    results = NULL;
    free(json);
    json = NULL;

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(1, count);

    rnp_key_handle_t key_handle = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "test0", &key_handle));
    assert_non_null(key_handle);

    assert_int_equal(RNP_SUCCESS, rnp_key_get_uid_count(key_handle, &count));
    assert_int_equal(1, count);

    // protect+lock the key
    assert_int_equal(RNP_SUCCESS,
                     rnp_key_protect(key_handle, "pass", "SM4", "CFB", "SM3", 999999));
    assert_int_equal(RNP_SUCCESS, rnp_key_lock(key_handle));

    // add the userid (no pass provider, should fail)
    assert_int_equal(
      RNP_ERROR_BAD_PASSWORD,
      rnp_key_add_uid(key_handle, new_userid, "SHA256", 2147317200, 0x00, false));

    // actually add the userid
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "pass"));
    assert_int_equal(
      RNP_SUCCESS, rnp_key_add_uid(key_handle, new_userid, "SHA256", 2147317200, 0x00, false));

    assert_int_equal(RNP_SUCCESS, rnp_key_get_uid_count(key_handle, &count));
    assert_int_equal(2, count);

    rnp_key_handle_t key_handle2 = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", new_userid, &key_handle2));
    assert_non_null(key_handle2);

    rnp_key_handle_destroy(key_handle);
    rnp_key_handle_destroy(key_handle2);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_keygen_json_sub_pass_required)
{
    char *    json = NULL;
    char *    results = NULL;
    size_t    count = 0;
    rnp_ffi_t ffi = NULL;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // generate our primary key
    load_test_data("test_ffi_json/generate-primary.json", &json, NULL);
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    free(json);
    assert_non_null(results);
    // check key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(1, count);

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle+grip for the primary
    rnp_key_handle_t primary = NULL;
    char *           primary_grip = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        primary_grip = strdup(json_object_get_string(jsogrip));
        assert_non_null(primary_grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", primary_grip, &primary));
        assert_non_null(primary);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // protect+lock the primary key
    assert_int_equal(RNP_SUCCESS, rnp_key_protect(primary, "pass123", NULL, NULL, NULL, 0));
    assert_int_equal(RNP_SUCCESS, rnp_key_lock(primary));
    rnp_key_handle_destroy(primary);
    primary = NULL;

    // load our JSON template
    load_test_data("test_ffi_json/generate-sub.json", &json, NULL);
    // modify our JSON
    {
        // parse
        json_object *jso = json_tokener_parse(json);
        assert_non_null(jso);
        free(json);
        json = NULL;
        // find the relevant fields
        json_object *jsosub = NULL;
        json_object *jsoprimary = NULL;
        assert_true(json_object_object_get_ex(jso, "sub", &jsosub));
        assert_non_null(jsosub);
        assert_true(json_object_object_get_ex(jsosub, "primary", &jsoprimary));
        assert_non_null(jsoprimary);
        // replace the placeholder grip with the correct one
        json_object_object_del(jsoprimary, "grip");
        json_object_object_add(jsoprimary, "grip", json_object_new_string(primary_grip));
        assert_int_equal(1, json_object_object_length(jsoprimary));
        json = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
        assert_non_null(json);
        json_object_put(jso);
    }
    // cleanup
    rnp_buffer_destroy(primary_grip);
    primary_grip = NULL;

    // generate the subkey (no getpasscb, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_int_not_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));

    // generate the subkey (wrong pass, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "wrong"));
    assert_int_not_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));

    // generate the subkey
    assert_int_equal(RNP_SUCCESS,
                     rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "pass123"));
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    free(json);
    json = NULL;
    assert_non_null(results);

    // parse the results JSON
    parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle for the sub
    rnp_key_handle_t sub = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "sub", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &sub));
        assert_non_null(sub);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(sub, false, true, true);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
}

static bool
file_equals(const char *filename, const void *data, size_t len)
{
    pgp_source_t msrc = {};
    bool         res = false;

    if (file_to_mem_src(&msrc, filename)) {
        return false;
    }

    res = (msrc.size == len) && !memcmp(mem_src_get_memory(&msrc), data, len);
    src_close(&msrc);
    return res;
}

TEST_F(rnp_tests, test_ffi_encrypt_pass)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "data1";

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // write out some data
    FILE *fp = fopen("plaintext", "w");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));

    // create input+output w/ bad paths (should fail)
    input = NULL;
    assert_int_not_equal(RNP_SUCCESS, rnp_input_from_path(&input, "noexist"));
    assert_null(input);
    assert_int_not_equal(RNP_SUCCESS, rnp_output_to_path(&output, ""));
    assert_null(output);

    // create input+output
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "plaintext"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_create(&op, ffi, input, output));
    // add password (using all defaults)
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_password(op, "pass1", NULL, 0, NULL));
    // add password
    assert_int_equal(RNP_SUCCESS,
                     rnp_op_encrypt_add_password(op, "pass2", "SM3", 12345, "Twofish"));
    // set the data encryption cipher
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_set_cipher(op, "CAST5"));
    // execute the operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_execute(op));

    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));

    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_input_destroy(input));
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_destroy(op));
    op = NULL;

    /* decrypt */

    // decrypt (no pass provider, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt (wrong pass, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    const char *pass = "wrong1";
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb_once, &pass));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt (pass1)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "pass1"));
    assert_int_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // compare the decrypted file
    assert_true(file_equals("decrypted", plaintext, strlen(plaintext)));
    unlink("decrypted");

    // decrypt (pass2)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "pass2"));
    assert_int_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // compare the decrypted file
    assert_true(file_equals("decrypted", plaintext, strlen(plaintext)));
    // final cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_encrypt_pass_provider)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "Data encrypted with password provided via password provider.";

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // write out some data
    FILE *fp = fopen("plaintext", "w");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));
    // create input + output
    assert_rnp_success(rnp_input_from_path(&input, "plaintext"));
    assert_rnp_success(rnp_output_to_path(&output, "encrypted"));
    // create encrypt operation
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    // add password with NULL password provider set - should fail
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_rnp_failure(rnp_op_encrypt_add_password(op, NULL, NULL, 0, NULL));
    // add password with password provider set.
    int pswdnum = 1;
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb_inc, &pswdnum));
    assert_rnp_success(rnp_op_encrypt_add_password(op, NULL, NULL, 0, NULL));
    // add another password with different encryption parameters
    assert_rnp_success(rnp_op_encrypt_add_password(op, NULL, "SM3", 12345, "Twofish"));
    // set the data encryption cipher
    assert_rnp_success(rnp_op_encrypt_set_cipher(op, "Camellia256"));
    // execute the operation
    assert_rnp_success(rnp_op_encrypt_execute(op));
    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_encrypt_destroy(op));
    op = NULL;

    /* decrypt with pass1 */
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "pass1"));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    assert_true(file_equals("decrypted", plaintext, strlen(plaintext)));
    unlink("decrypted");

    /* decrypt with pass2 via provider */
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    pswdnum = 2;
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb_inc, &pswdnum));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    assert_true(file_equals("decrypted", plaintext, strlen(plaintext)));
    unlink("decrypted");

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_encrypt_pk)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "data1";

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // write out some data
    FILE *fp = fopen("plaintext", "w");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));

    // create input+output
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "plaintext"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_create(&op, ffi, input, output));
    // add recipients
    rnp_key_handle_t key = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "key0-uid2", &key));
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    key = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "key1-uid1", &key));
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    key = NULL;
    // set the data encryption cipher
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_set_cipher(op, "CAST5"));
    // execute the operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_execute(op));

    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));

    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_input_destroy(input));
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_destroy(op));
    op = NULL;

    /* decrypt */

    // decrypt (no pass provider, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt (wrong pass, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    const char *pass = "wrong1";
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb_once, &pass));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS,
                     rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));
    assert_int_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // read in the decrypted file
    assert_true(file_equals("decrypted", plaintext, strlen(plaintext)));
    // final cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_encrypt_pk_key_provider)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "data1";
    uint8_t *        primary_sec_key_data = NULL;
    size_t           primary_sec_size = 0;
    uint8_t *        sub_sec_key_data = NULL;
    size_t           sub_sec_size = 0;

    /* first, let's generate some encrypted data */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_non_null(ffi);
    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // write out some data
    FILE *fp = fopen("plaintext", "w");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));
    // create input+output
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "plaintext"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_create(&op, ffi, input, output));
    // add recipient 1
    rnp_key_handle_t key = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "key0-uid2", &key));
    assert_non_null(key);
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_recipient(op, key));
    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_key_handle_destroy(key));
    key = NULL;
    // add recipient 2
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "key1-uid1", &key));
    assert_non_null(key);
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_recipient(op, key));
    // save the primary key data for later
    assert_int_equal(RNP_SUCCESS,
                     rnp_get_secret_key_data(key, &primary_sec_key_data, &primary_sec_size));
    assert_non_null(primary_sec_key_data);
    assert_int_equal(RNP_SUCCESS, rnp_key_handle_destroy(key));
    key = NULL;
    // save the appropriate encrypting subkey for the key provider to use during decryption
    // later
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "keyid", "54505A936A4A970E", &key));
    assert_non_null(key);
    assert_int_equal(RNP_SUCCESS,
                     rnp_get_secret_key_data(key, &sub_sec_key_data, &sub_sec_size));
    assert_non_null(sub_sec_key_data);
    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_key_handle_destroy(key));
    key = NULL;
    // set the data encryption cipher
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_set_cipher(op, "CAST5"));
    // execute the operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_execute(op));
    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));
    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_input_destroy(input));
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_destroy(op));
    op = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_ffi_destroy(ffi));
    ffi = NULL;

    /* decrypt */
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load the primary
    input = NULL;
    assert_int_equal(
      RNP_SUCCESS,
      rnp_input_from_memory(&input, primary_sec_key_data, primary_sec_size, true));
    assert_non_null(input);
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // decrypt (no key to decrypt, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_ERROR_NO_SUITABLE_KEY, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // key_data key_data_size secret keyid grip userids
    const key_tbl_t keydb[] = {
      {sub_sec_key_data, sub_sec_size, true, "54505A936A4A970E", NULL, {NULL}}, {0}};

    // decrypt
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, tbl_getkeycb, (void *) keydb));
    assert_int_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // compare the decrypted file
    assert_true(file_equals("decrypted", plaintext, strlen(plaintext)));
    // final cleanup
    rnp_ffi_destroy(ffi);
    free(sub_sec_key_data);
    free(primary_sec_key_data);
}

TEST_F(rnp_tests, test_ffi_encrypt_and_sign)
{
    rnp_ffi_t               ffi = NULL;
    rnp_input_t             input = NULL;
    rnp_output_t            output = NULL;
    rnp_op_encrypt_t        op = NULL;
    rnp_op_sign_signature_t signsig = NULL;
    const char *            plaintext = "data1";
    rnp_key_handle_t        key = NULL;
    const uint32_t          issued = 1516211899;   // Unix epoch, nowish
    const uint32_t          expires = 1000000000;  // expires later
    const uint32_t          issued2 = 1516211900;  // Unix epoch, nowish
    const uint32_t          expires2 = 2000000000; // expires later

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // write out some data
    FILE *fp = fopen("plaintext", "w");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));

    // create input+output
    assert_rnp_success(rnp_input_from_path(&input, "plaintext"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    // add recipients
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key0-uid2", &key));
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key1-uid1", &key));
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    key = NULL;
    // set the data encryption cipher
    assert_rnp_success(rnp_op_encrypt_set_cipher(op, "CAST5"));
    // enable armoring
    assert_rnp_success(rnp_op_encrypt_set_armor(op, true));
    // add signature
    assert_rnp_success(rnp_op_encrypt_set_hash(op, "SHA1"));
    assert_rnp_success(rnp_op_encrypt_set_creation_time(op, 0));
    assert_rnp_success(rnp_op_encrypt_set_expiration_time(op, 0));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key1-uid1", &key));
    assert_rnp_success(rnp_op_encrypt_add_signature(op, key, NULL));
    rnp_key_handle_destroy(key);
    key = NULL;
    // add second signature with different hash/issued/expiration
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key1-uid2", &key));
    assert_rnp_success(rnp_op_encrypt_add_signature(op, key, &signsig));
    assert_rnp_success(rnp_op_sign_signature_set_creation_time(signsig, issued2));
    assert_rnp_success(rnp_op_sign_signature_set_expiration_time(signsig, expires2));
    assert_rnp_success(rnp_op_sign_signature_set_hash(signsig, "SHA512"));
    rnp_key_handle_destroy(key);
    key = NULL;
    // set default sig parameters after the signature is added - those should be picked up
    assert_rnp_success(rnp_op_encrypt_set_hash(op, "SHA256"));
    assert_rnp_success(rnp_op_encrypt_set_creation_time(op, issued));
    assert_rnp_success(rnp_op_encrypt_set_expiration_time(op, expires));
    // execute the operation
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));
    assert_rnp_success(rnp_op_encrypt_execute(op));

    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_encrypt_destroy(op));
    op = NULL;

    /* decrypt */

    // decrypt (no pass provider, should fail)
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_rnp_failure(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt (wrong pass, should fail)
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    const char *pass = "wrong1";
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb_once, &pass));
    assert_rnp_failure(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // compare the decrypted file
    assert_true(file_equals("decrypted", plaintext, strlen(plaintext)));
    // verify and check signatures
    rnp_op_verify_t verify;
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "verified"));
    assert_non_null(output);
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));

    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    rnp_op_verify_signature_t sig;
    size_t                    sig_count;
    uint32_t                  sig_create;
    uint32_t                  sig_expires;
    char *                    hname = NULL;

    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sig_count));
    assert_int_equal(sig_count, 2);
    // signature 1
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    assert_rnp_success(rnp_op_verify_signature_get_times(sig, &sig_create, &sig_expires));
    assert_int_equal(sig_create, issued);
    assert_int_equal(sig_expires, expires);
    assert_rnp_success(rnp_op_verify_signature_get_hash(sig, &hname));
    assert_string_equal(hname, "SHA256");
    rnp_buffer_destroy(hname);
    hname = NULL;
    // signature 2
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 1, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    assert_rnp_success(rnp_op_verify_signature_get_times(sig, &sig_create, &sig_expires));
    assert_int_equal(sig_create, issued2);
    assert_int_equal(sig_expires, expires2);
    assert_rnp_success(rnp_op_verify_signature_get_hash(sig, &hname));
    assert_string_equal(hname, "SHA512");
    rnp_buffer_destroy(hname);
    hname = NULL;
    // cleanup
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // compare the decrypted file
    assert_true(file_equals("verified", plaintext, strlen(plaintext)));
    // final cleanup
    rnp_ffi_destroy(ffi);
}

static void
test_ffi_init(rnp_ffi_t *ffi)
{
    // setup FFI
    assert_rnp_success(rnp_ffi_create(ffi, "GPG", "GPG"));

    // load our keyrings
    rnp_input_t input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(*ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(*ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
}

static void
test_ffi_init_sign_file_input(rnp_input_t *input, rnp_output_t *output)
{
    const char *plaintext = "this is some data that will be signed";

    // write out some data
    FILE *fp = fopen("plaintext", "w");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));

    // create input+output
    assert_rnp_success(rnp_input_from_path(input, "plaintext"));
    assert_non_null(*input);
    assert_rnp_success(rnp_output_to_path(output, "signed"));
    assert_non_null(*output);
}

static void
test_ffi_init_sign_memory_input(rnp_input_t *input, rnp_output_t *output)
{
    const char *plaintext = "this is some data that will be signed";

    assert_rnp_success(
      rnp_input_from_memory(input, (uint8_t *) plaintext, strlen(plaintext), true));
    assert_non_null(*input);
    if (output) {
        assert_rnp_success(rnp_output_to_memory(output, 0));
        assert_non_null(*output);
    }
}

static void
test_ffi_init_verify_file_input(rnp_input_t *input, rnp_output_t *output)
{
    // create input+output
    assert_rnp_success(rnp_input_from_path(input, "signed"));
    assert_non_null(*input);
    assert_rnp_success(rnp_output_to_path(output, "recovered"));
    assert_non_null(*output);
}

static void
test_ffi_init_verify_detached_file_input(rnp_input_t *input, rnp_input_t *signature)
{
    assert_rnp_success(rnp_input_from_path(input, "plaintext"));
    assert_non_null(*input);
    assert_rnp_success(rnp_input_from_path(signature, "signed"));
    assert_non_null(*signature);
}

static void
test_ffi_init_verify_memory_input(rnp_input_t * input,
                                  rnp_output_t *output,
                                  uint8_t *     signed_buf,
                                  size_t        signed_len)
{
    // create input+output
    assert_rnp_success(rnp_input_from_memory(input, signed_buf, signed_len, false));
    assert_non_null(*input);
    assert_rnp_success(rnp_output_to_memory(output, 0));
    assert_non_null(*output);
}

static void
test_ffi_setup_signatures(rnp_ffi_t *ffi, rnp_op_sign_t *op)
{
    rnp_key_handle_t        key = NULL;
    rnp_op_sign_signature_t sig = NULL;
    // set signature times
    const uint32_t issued = 1516211899;   // Unix epoch, nowish
    const uint32_t expires = 1000000000;  // expires later
    const uint32_t issued2 = 1516211900;  // Unix epoch, nowish
    const uint32_t expires2 = 2000000000; // expires later

    assert_rnp_success(rnp_op_sign_set_armor(*op, true));
    assert_rnp_success(rnp_op_sign_set_hash(*op, "SHA256"));
    assert_rnp_success(rnp_op_sign_set_creation_time(*op, issued));
    assert_rnp_success(rnp_op_sign_set_expiration_time(*op, expires));

    // set pass provider
    assert_rnp_success(rnp_ffi_set_pass_provider(*ffi, getpasscb, (void *) "password"));

    // set first signature key
    assert_rnp_success(rnp_locate_key(*ffi, "userid", "key0-uid2", &key));
    assert_rnp_success(rnp_op_sign_add_signature(*op, key, NULL));
    assert_rnp_success(rnp_key_handle_destroy(key));
    key = NULL;
    // set second signature key
    assert_rnp_success(rnp_locate_key(*ffi, "userid", "key0-uid1", &key));
    assert_rnp_success(rnp_op_sign_add_signature(*op, key, &sig));
    assert_rnp_success(rnp_op_sign_signature_set_creation_time(sig, issued2));
    assert_rnp_success(rnp_op_sign_signature_set_expiration_time(sig, expires2));
    assert_rnp_success(rnp_op_sign_signature_set_hash(sig, "SHA512"));
    assert_rnp_success(rnp_key_handle_destroy(key));
}

static void
test_ffi_check_signatures(rnp_op_verify_t *verify)
{
    rnp_op_verify_signature_t sig;
    size_t                    sig_count;
    uint32_t                  sig_create;
    uint32_t                  sig_expires;
    char *                    hname = NULL;
    const uint32_t            issued = 1516211899;   // Unix epoch, nowish
    const uint32_t            expires = 1000000000;  // expires later
    const uint32_t            issued2 = 1516211900;  // Unix epoch, nowish
    const uint32_t            expires2 = 2000000000; // expires later

    assert_rnp_success(rnp_op_verify_get_signature_count(*verify, &sig_count));
    assert_int_equal(sig_count, 2);
    // first signature
    assert_rnp_success(rnp_op_verify_get_signature_at(*verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    assert_rnp_success(rnp_op_verify_signature_get_times(sig, &sig_create, &sig_expires));
    assert_int_equal(sig_create, issued);
    assert_int_equal(sig_expires, expires);
    assert_rnp_success(rnp_op_verify_signature_get_hash(sig, &hname));
    assert_string_equal(hname, "SHA256");
    rnp_buffer_destroy(hname);
    // second signature
    assert_rnp_success(rnp_op_verify_get_signature_at(*verify, 1, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    assert_rnp_success(rnp_op_verify_signature_get_times(sig, &sig_create, &sig_expires));
    assert_int_equal(sig_create, issued2);
    assert_int_equal(sig_expires, expires2);
    assert_rnp_success(rnp_op_verify_signature_get_hash(sig, &hname));
    assert_string_equal(hname, "SHA512");
    rnp_buffer_destroy(hname);
}

static bool
test_ffi_check_recovered()
{
    pgp_source_t msrc1 = {};
    pgp_source_t msrc2 = {};
    bool         res = false;

    if (file_to_mem_src(&msrc1, "recovered")) {
        return false;
    }

    if (file_to_mem_src(&msrc2, "plaintext")) {
        goto finish;
    }

    res = (msrc1.size == msrc2.size) &&
          !memcmp(mem_src_get_memory(&msrc1), mem_src_get_memory(&msrc2), msrc1.size);
finish:
    src_close(&msrc1);
    src_close(&msrc2);
    return res;
}

TEST_F(rnp_tests, test_ffi_signatures_memory)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    rnp_op_verify_t verify;
    uint8_t *       signed_buf;
    size_t          signed_len;
    uint8_t *       verified_buf;
    size_t          verified_len;

    // init ffi
    test_ffi_init(&ffi);
    // init input
    test_ffi_init_sign_memory_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    // make sure the output file was created
    assert_rnp_success(rnp_output_memory_get_buf(output, &signed_buf, &signed_len, true));
    assert_non_null(signed_buf);
    assert_true(signed_len > 0);

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_sign_destroy(op));
    op = NULL;

    /* now verify */
    // make sure it is correctly armored
    assert_int_equal(memcmp(signed_buf, "-----BEGIN PGP MESSAGE-----", 27), 0);
    // create input and output
    test_ffi_init_verify_memory_input(&input, &output, signed_buf, signed_len);
    // call verify
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(&verify);
    // get output
    assert_rnp_success(rnp_output_memory_get_buf(output, &verified_buf, &verified_len, true));
    assert_non_null(verified_buf);
    assert_true(verified_len > 0);
    // cleanup
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_ffi_destroy(ffi));
    rnp_buffer_destroy(signed_buf);
    rnp_buffer_destroy(verified_buf);
}

TEST_F(rnp_tests, test_ffi_signatures)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    rnp_op_verify_t verify;

    // init ffi
    test_ffi_init(&ffi);
    // init file input
    test_ffi_init_sign_file_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    // make sure the output file was created
    assert_true(rnp_file_exists("signed"));

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_sign_destroy(op));
    op = NULL;

    /* now verify */

    // create input and output
    test_ffi_init_verify_file_input(&input, &output);
    // call verify
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(&verify);
    // cleanup
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_ffi_destroy(ffi));
    // check output
    assert_true(test_ffi_check_recovered());
}

TEST_F(rnp_tests, test_ffi_signatures_detached_memory)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_input_t     signature = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    rnp_op_verify_t verify;
    uint8_t *       signed_buf;
    size_t          signed_len;

    // init ffi
    test_ffi_init(&ffi);
    // init input
    test_ffi_init_sign_memory_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_detached_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    assert_rnp_success(rnp_output_memory_get_buf(output, &signed_buf, &signed_len, true));
    assert_non_null(signed_buf);
    assert_true(signed_len > 0);

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_sign_destroy(op));
    op = NULL;

    /* now verify */
    // make sure it is correctly armored
    assert_int_equal(memcmp(signed_buf, "-----BEGIN PGP SIGNATURE-----", 29), 0);
    // create input and output
    test_ffi_init_sign_memory_input(&input, NULL);
    assert_rnp_success(rnp_input_from_memory(&signature, signed_buf, signed_len, true));
    assert_non_null(signature);
    // call verify
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, input, signature));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(&verify);
    // cleanup
    rnp_buffer_destroy(signed_buf);
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_input_destroy(signature));
    signature = NULL;
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_signatures_detached)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_input_t     signature = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    rnp_op_verify_t verify;

    // init ffi
    test_ffi_init(&ffi);
    // init file input
    test_ffi_init_sign_file_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_detached_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    // make sure the output file was created
    assert_true(rnp_file_exists("signed"));

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_sign_destroy(op));
    op = NULL;

    /* now verify */

    // create input and output
    test_ffi_init_verify_detached_file_input(&input, &signature);
    // call verify
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, input, signature));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(&verify);
    // cleanup
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_input_destroy(signature));
    signature = NULL;
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_signatures_dump)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_input_t     signature = NULL;
    rnp_op_verify_t verify;

    /* init ffi and inputs */
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_signatures/pub.asc"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_signatures/source.txt"));
    assert_rnp_success(rnp_input_from_path(&signature, "data/test_stream_signatures/source.txt.sig"));
    /* call verify detached to obtain signatures */
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, input, signature));
    assert_rnp_success(rnp_op_verify_execute(verify));
    /* get signature and check it */
    rnp_op_verify_signature_t sig;
    size_t                    sig_count;
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sig_count));
    assert_int_equal(sig_count, 1);
    /* get signature handle  */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    rnp_signature_handle_t sighandle = NULL;
    assert_rnp_success(rnp_op_verify_signature_get_handle(sig, &sighandle));
    assert_non_null(sighandle);
    /* cleanup, making sure that sighandle doesn't depend on verify */
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_input_destroy(signature));
    /* check whether getters work on sighandle: algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_signature_get_alg(sighandle, &alg));
    assert_non_null(alg);
    assert_int_equal(strcmp(alg, "RSA"), 0);
    rnp_buffer_destroy(alg);
    /* keyid */
    char *keyid = NULL;
    assert_rnp_success(rnp_signature_get_keyid(sighandle, &keyid));
    assert_non_null(keyid);
    assert_int_equal(strcmp(keyid, "5873BD738E575398"), 0);
    rnp_buffer_destroy(keyid);
    /* creation time */
    uint32_t create = 0;
    assert_rnp_success(rnp_signature_get_creation(sighandle, &create));
    assert_int_equal(create, 1522241943);
    /* hash algorithm */
    assert_rnp_success(rnp_signature_get_hash_alg(sighandle, &alg));
    assert_non_null(alg);
    assert_int_equal(strcmp(alg, "SHA256"), 0);
    rnp_buffer_destroy(alg);
    /* now dump signature packet to json */
    char *json = NULL;
    assert_rnp_success(rnp_signature_packet_to_json(sighandle, 0, &json));
    json_object *jso = json_tokener_parse(json);
    rnp_buffer_destroy(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    assert_int_equal(json_object_array_length(jso), 1);
    /* check the signature packet dump */
    json_object *pkt = json_object_array_get_idx(jso, 0);
    /* check helper functions */
    assert_false(check_json_field_int(pkt, "unknown", 4));
    assert_false(check_json_field_int(pkt, "version", 5));
    assert_true(check_json_field_int(pkt, "version", 4));
    assert_true(check_json_field_int(pkt, "type", 0));
    assert_true(check_json_field_str(pkt, "type.str", "Signature of a binary document"));
    assert_true(check_json_field_int(pkt, "algorithm", 1));
    assert_true(check_json_field_str(pkt, "algorithm.str", "RSA (Encrypt or Sign)"));
    assert_true(check_json_field_int(pkt, "hash algorithm", 8));
    assert_true(check_json_field_str(pkt, "hash algorithm.str", "SHA256"));
    assert_true(check_json_field_str(pkt, "lbits", "816e"));
    json_object *subpkts = NULL;
    assert_true(json_object_object_get_ex(pkt, "subpackets", &subpkts));
    assert_non_null(subpkts);
    assert_true(json_object_is_type(subpkts, json_type_array));
    assert_int_equal(json_object_array_length(subpkts), 3);
    /* subpacket 0 */
    json_object *subpkt = json_object_array_get_idx(subpkts, 0);
    assert_true(check_json_field_int(subpkt, "type", 33));
    assert_true(check_json_field_str(subpkt, "type.str", "issuer fingerprint"));
    assert_true(check_json_field_int(subpkt, "length", 21));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(check_json_field_str(subpkt, "fingerprint", "7a60e671179f9b920f6478a25873bd738e575398"));
    /* subpacket 1 */
    subpkt = json_object_array_get_idx(subpkts, 1);
    assert_true(check_json_field_int(subpkt, "type", 2));
    assert_true(check_json_field_str(subpkt, "type.str", "signature creation time"));
    assert_true(check_json_field_int(subpkt, "length", 4));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(check_json_field_int(subpkt, "creation time", 1522241943));
    /* subpacket 2 */
    subpkt = json_object_array_get_idx(subpkts, 2);
    assert_true(check_json_field_int(subpkt, "type", 16));
    assert_true(check_json_field_str(subpkt, "type.str", "issuer key ID"));
    assert_true(check_json_field_int(subpkt, "length", 8));
    assert_true(check_json_field_bool(subpkt, "hashed", false));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(check_json_field_str(subpkt, "issuer keyid", "5873bd738e575398"));
    json_object_put(jso);
    rnp_signature_handle_destroy(sighandle);
    /* cleanup ffi */
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

/** get the value of a (potentially nested) field in a json object
 *
 *  Note that this does not support JSON arrays, only objects.
 *
 *  @param jso the json object to search within. This should be an object, not a string,
 *         array, etc.
 *  @param field the field to retrieve. The format is "first.second.third".
 *  @return a pointer to the located json object, or NULL
 **/
static json_object *
get_json_obj(json_object *jso, const char *field)
{
    const char *start = field;
    const char *end;
    char        buf[32];

    do {
        end = strchr(start, '.');

        size_t len = end ? (end - start) : strlen(start);
        if (len >= sizeof(buf)) {
            return NULL;
        }
        memcpy(buf, start, len);
        buf[len] = '\0';

        if (!json_object_object_get_ex(jso, buf, &jso)) {
            return NULL;
        }

        start = end + 1;
    } while (end);
    return jso;
}

/* This test loads a keyring and converts the keys to JSON,
 * then validates some properties.
 *
 * We could just do a simple strcmp, but that would depend
 * on json-c sorting the keys consistently, across versions,
 * etc.
 */
TEST_F(rnp_tests, test_ffi_key_to_json)
{
    rnp_ffi_t        ffi = NULL;
    char *           pub_format = NULL;
    char *           pub_path = NULL;
    char *           sec_format = NULL;
    char *           sec_path = NULL;
    rnp_key_handle_t key = NULL;
    char *           json = NULL;
    json_object *    jso = NULL;
    rnp_input_t      input = NULL;

    // detect the formats+paths
    assert_int_equal(RNP_SUCCESS,
                     rnp_detect_homedir_info(
                       "data/keyrings/5", &pub_format, &pub_path, &sec_format, &sec_path));
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, pub_format, sec_format));
    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(ffi, pub_format, input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(ffi, sec_format, input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // free formats+paths
    rnp_buffer_destroy(pub_format);
    pub_format = NULL;
    rnp_buffer_destroy(pub_path);
    pub_path = NULL;
    rnp_buffer_destroy(sec_format);
    sec_format = NULL;
    rnp_buffer_destroy(sec_path);
    sec_path = NULL;

    // locate key (primary)
    key = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "keyid", "0E33FD46FF10F19C", &key));
    assert_non_null(key);
    // convert to JSON
    json = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_key_to_json(key, 0xff, &json));
    assert_non_null(json);
    // parse it back in
    jso = json_tokener_parse(json);
    assert_non_null(jso);
    // validate some properties
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "type")), "ECDSA"), 0);
    assert_int_equal(json_object_get_int(get_json_obj(jso, "length")), 256);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "curve")), "NIST P-256"), 0);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "keyid")), "0E33FD46FF10F19C"),
      0);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "fingerprint")),
                                    "B6B5E497A177551ECB8862200E33FD46FF10F19C"),
                     0);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "grip")),
                                    "20A48B3C61525DCDF8B3B9D82C6BBCF4D8BFB5E5"),
                     0);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "revoked")), FALSE);
    assert_int_equal(json_object_get_int64(get_json_obj(jso, "creation time")), 1511313500);
    assert_int_equal(json_object_get_int64(get_json_obj(jso, "expiration")), 0);
    // usage
    assert_int_equal(json_object_array_length(get_json_obj(jso, "usage")), 2);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(json_object_array_get_idx(
                                      get_json_obj(jso, "usage"), 0)),
                                    "sign"),
                     0);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(json_object_array_get_idx(
                                      get_json_obj(jso, "usage"), 1)),
                                    "certify"),
                     0);
    // primary key grip
    assert_null(get_json_obj(jso, "primary key grip"));
    // subkey grips
    assert_int_equal(json_object_array_length(get_json_obj(jso, "subkey grips")), 1);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(json_object_array_get_idx(
                                      get_json_obj(jso, "subkey grips"), 0)),
                                    "FFFA72FC225214DC712D0127172EE13E88AF93B4"),
                     0);
    // public key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "public key.present")), TRUE);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "public key.mpis.point")),
                     "04B0C6F2F585C1EEDF805C4492CB683839D5EAE6246420780F063D558"
                     "A33F607876BE6F818A665722F8204653CC4DCFAD4F4765521AC8A6E9F"
                     "793CEBAE8600BEEF"),
      0);
    // secret key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.present")), TRUE);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "secret key.mpis.x")),
                     "46DE93CA439735F36B9CF228F10D8586DA824D88BBF4E24566D5312D061802C8"),
      0);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.locked")), FALSE);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.protected")),
                     FALSE);
    // userids
    assert_int_equal(json_object_array_length(get_json_obj(jso, "userids")), 1);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(json_object_array_get_idx(
                                      get_json_obj(jso, "userids"), 0)),
                                    "test0"),
                     0);
    // signatures
    assert_int_equal(json_object_array_length(get_json_obj(jso, "signatures")), 1);
    json_object *jsosig = json_object_array_get_idx(get_json_obj(jso, "signatures"), 0);
    assert_int_equal(json_object_get_int(get_json_obj(jsosig, "userid")), 0);
    // TODO: other properties of signature
    // cleanup
    json_object_put(jso);
    rnp_key_handle_destroy(key);
    key = NULL;
    rnp_buffer_destroy(json);
    json = NULL;

    // locate key (sub)
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "keyid", "074131BC8D16C5C9", &key));
    assert_non_null(key);
    // convert to JSON
    assert_int_equal(RNP_SUCCESS, rnp_key_to_json(key, 0xff, &json));
    assert_non_null(json);
    // parse it back in
    jso = json_tokener_parse(json);
    assert_non_null(jso);
    // validate some properties
    assert_int_equal(rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "type")), "ECDH"),
                     0);
    assert_int_equal(json_object_get_int(get_json_obj(jso, "length")), 256);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "curve")), "NIST P-256"), 0);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "keyid")), "074131BC8D16C5C9"),
      0);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "fingerprint")),
                                    "481E6A41B10ECD71A477DB02074131BC8D16C5C9"),
                     0);
    // ECDH-specific
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "kdf hash")), "SHA256"), 0);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "key wrap cipher")), "AES128"),
      0);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "grip")),
                                    "FFFA72FC225214DC712D0127172EE13E88AF93B4"),
                     0);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "revoked")), FALSE);
    assert_int_equal(json_object_get_int64(get_json_obj(jso, "creation time")), 1511313500);
    assert_int_equal(json_object_get_int64(get_json_obj(jso, "expiration")), 0);
    // usage
    assert_int_equal(json_object_array_length(get_json_obj(jso, "usage")), 1);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(json_object_array_get_idx(
                                      get_json_obj(jso, "usage"), 0)),
                                    "encrypt"),
                     0);
    // primary key grip
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "primary key grip")),
                     "20A48B3C61525DCDF8B3B9D82C6BBCF4D8BFB5E5"),
      0);
    // subkey grips
    assert_null(get_json_obj(jso, "subkey grips"));
    // public key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "public key.present")), TRUE);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "public key.mpis.point")),
                     "04E2746BA4D180011B17A6909EABDBF2F3733674FBE00B20A3B857C2597233651544150B"
                     "896BCE7DCDF47C49FC1E12D5AD86384D26336A48A18845940A3F65F502"),
      0);
    // secret key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.present")), TRUE);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "secret key.mpis.x")),
                     "DF8BEB7272117AD7AFE2B7E882453113059787FBC785C82F78624EE7EF2117FB"),
      0);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.locked")), FALSE);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.protected")),
                     FALSE);
    // userids
    assert_null(get_json_obj(jso, "userids"));
    // signatures
    assert_int_equal(json_object_array_length(get_json_obj(jso, "signatures")), 1);
    jsosig = json_object_array_get_idx(get_json_obj(jso, "signatures"), 0);
    assert_null(get_json_obj(jsosig, "userid"));
    // TODO: other properties of signature
    // cleanup
    json_object_put(jso);
    rnp_key_handle_destroy(key);
    rnp_buffer_destroy(json);

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_iter)
{
    rnp_ffi_t   ffi = NULL;
    char *      pub_format = NULL;
    char *      pub_path = NULL;
    char *      sec_format = NULL;
    char *      sec_path = NULL;
    rnp_input_t input = NULL;

    // detect the formats+paths
    assert_int_equal(RNP_SUCCESS,
                     rnp_detect_homedir_info(
                       "data/keyrings/1", &pub_format, &pub_path, &sec_format, &sec_path));
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, pub_format, sec_format));

    // test invalid identifier type
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_not_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "keyidz"));
        assert_null(it);
    }

    // test empty rings
    // keyid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "keyid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }
    // grip
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "grip"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }
    // userid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "userid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }

    // test with both rings empty
    // keyid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "keyid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }
    // grip
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "grip"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }
    // userid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "userid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(ffi, pub_format, input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(ffi, sec_format, input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // free formats+paths
    rnp_buffer_destroy(pub_format);
    pub_format = NULL;
    rnp_buffer_destroy(pub_path);
    pub_path = NULL;
    rnp_buffer_destroy(sec_format);
    sec_format = NULL;
    rnp_buffer_destroy(sec_path);
    sec_path = NULL;

    // keyid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "keyid"));
        assert_non_null(it);
        {
            static const char *expected[] = {"7BC6709B15C23A4A",
                                             "1ED63EE56FADC34D",
                                             "1D7E8A5393C997A8",
                                             "8A05B89FAD5ADED1",
                                             "2FCADF05FFA501BB",
                                             "54505A936A4A970E",
                                             "326EF111425D14A5"};
            size_t             i = 0;
            const char *       ident = NULL;
            do {
                ident = NULL;
                assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
                if (ident) {
                    assert_int_equal(0, rnp_strcasecmp(expected[i], ident));
                    i++;
                }
            } while (ident);
            assert_int_equal(i, ARRAY_SIZE(expected));
        }
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }

    // grip
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "grip"));
        assert_non_null(it);
        {
            static const char *expected[] = {"66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA",
                                             "D9839D61EDAF0B3974E0A4A341D6E95F3479B9B7",
                                             "B1CC352FEF9A6BD4E885B5351840EF9306D635F0",
                                             "E7C8860B70DC727BED6DB64C633683B41221BB40",
                                             "B2A7F6C34AA2C15484783E9380671869A977A187",
                                             "43C01D6D96BE98C3C87FE0F175870ED92DE7BE45",
                                             "8082FE753013923972632550838A5F13D81F43B9"};
            size_t             i = 0;
            const char *       ident = NULL;
            do {
                ident = NULL;
                assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
                if (ident) {
                    assert_int_equal(0, rnp_strcasecmp(expected[i], ident));
                    i++;
                }
            } while (ident);
            assert_int_equal(i, ARRAY_SIZE(expected));
        }
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }

    // userid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "userid"));
        assert_non_null(it);
        {
            static const char *expected[] = {
              "key0-uid0", "key0-uid1", "key0-uid2", "key1-uid0", "key1-uid2", "key1-uid1"};
            size_t      i = 0;
            const char *ident = NULL;
            do {
                ident = NULL;
                assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
                if (ident) {
                    assert_int_equal(0, rnp_strcasecmp(expected[i], ident));
                    i++;
                }
            } while (ident);
            assert_int_equal(i, ARRAY_SIZE(expected));
        }
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_locate_key)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // keyid
    {
        static const char *ids[] = {"7BC6709B15C23A4A",
                                    "1ED63EE56FADC34D",
                                    "1D7E8A5393C997A8",
                                    "8A05B89FAD5ADED1",
                                    "2FCADF05FFA501BB",
                                    "54505A936A4A970E",
                                    "326EF111425D14A5"};
        for (size_t i = 0; i < ARRAY_SIZE(ids); i++) {
            const char *     id = ids[i];
            rnp_key_handle_t key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "keyid", id, &key));
            assert_non_null(key);
            rnp_key_handle_destroy(key);
        }
        // invalid - value did not change
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_failure(rnp_locate_key(ffi, "keyid", "invalid-keyid", &key));
            assert_true(key == (rnp_key_handle_t) 0x111);
        }
        // valid but non-existent - null returned
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_success(rnp_locate_key(ffi, "keyid", "AAAAAAAAAAAAAAAA", &key));
            assert_null(key);
        }
    }

    // userid
    {
        static const char *ids[] = {
          "key0-uid0", "key0-uid1", "key0-uid2", "key1-uid0", "key1-uid2", "key1-uid1"};
        for (size_t i = 0; i < ARRAY_SIZE(ids); i++) {
            const char *     id = ids[i];
            rnp_key_handle_t key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "userid", id, &key));
            assert_non_null(key);
            rnp_key_handle_destroy(key);
        }
        // valid but non-existent
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_success(rnp_locate_key(ffi, "userid", "bad-userid", &key));
            assert_null(key);
        }
    }

    // fingerprint
    {
        static const char *ids[] = {"E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A",
                                    "E332B27CAF4742A11BAA677F1ED63EE56FADC34D",
                                    "C5B15209940A7816A7AF3FB51D7E8A5393C997A8",
                                    "5CD46D2A0BD0B8CFE0B130AE8A05B89FAD5ADED1",
                                    "BE1C4AB951F4C2F6B604C7F82FCADF05FFA501BB",
                                    "A3E94DE61A8CB229413D348E54505A936A4A970E",
                                    "57F8ED6E5C197DB63C60FFAF326EF111425D14A5"};
        for (size_t i = 0; i < ARRAY_SIZE(ids); i++) {
            const char *     id = ids[i];
            rnp_key_handle_t key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "fingerprint", id, &key));
            assert_non_null(key);
            rnp_key_handle_destroy(key);
        }
        // invalid
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_failure(rnp_locate_key(ffi, "fingerprint", "invalid-fpr", &key));
            assert_true(key == (rnp_key_handle_t) 0x111);
        }
        // valid but non-existent
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_success(rnp_locate_key(
              ffi, "fingerprint", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &key));
            assert_null(key);
        }
    }

    // grip
    {
        static const char *ids[] = {"66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA",
                                    "D9839D61EDAF0B3974E0A4A341D6E95F3479B9B7",
                                    "B1CC352FEF9A6BD4E885B5351840EF9306D635F0",
                                    "E7C8860B70DC727BED6DB64C633683B41221BB40",
                                    "B2A7F6C34AA2C15484783E9380671869A977A187",
                                    "43C01D6D96BE98C3C87FE0F175870ED92DE7BE45",
                                    "8082FE753013923972632550838A5F13D81F43B9"};
        for (size_t i = 0; i < ARRAY_SIZE(ids); i++) {
            const char *     id = ids[i];
            rnp_key_handle_t key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "grip", id, &key));
            assert_non_null(key);
            rnp_key_handle_destroy(key);
        }
        // invalid
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_failure(rnp_locate_key(ffi, "grip", "invalid-fpr", &key));
            assert_true(key == (rnp_key_handle_t) 0x111);
        }
        // valid but non-existent
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_success(
              rnp_locate_key(ffi, "grip", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &key));
            assert_null(key);
        }
    }

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_signatures_detached_memory_g10)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_input_t      input_sig = NULL;
    rnp_output_t     output = NULL;
    rnp_key_handle_t key = NULL;
    rnp_op_sign_t    opsign = NULL;
    rnp_op_verify_t  opverify = NULL;
    const char *     data = "my data";
    uint8_t *        sig = NULL;
    size_t           sig_len = 0;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "KBX", "G10"));
    assert_int_equal(RNP_SUCCESS,
                     rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/3/pubring.kbx"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "KBX", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS,
                     rnp_input_from_path(&input, "data/keyrings/3/private-keys-v1.d"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "G10", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // find our signing key
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "4BE147BB22DF1E60", &key));
    assert_non_null(key);

    // create our input
    assert_rnp_success(rnp_input_from_memory(&input, (uint8_t *) data, strlen(data), false));
    assert_non_null(input);
    // create our output
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_non_null(output);
    // create the signing operation
    assert_rnp_success(rnp_op_sign_detached_create(&opsign, ffi, input, output));
    assert_non_null(opsign);

    // add the signer
    assert_rnp_success(rnp_op_sign_add_signature(opsign, key, NULL));
    // execute the signing operation
    assert_rnp_success(rnp_op_sign_execute(opsign));
    // get the resulting signature
    assert_rnp_success(rnp_output_memory_get_buf(output, &sig, &sig_len, true));
    assert_non_null(sig);
    assert_int_not_equal(0, sig_len);
    // cleanup
    rnp_op_sign_destroy(opsign);
    opsign = NULL;
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // verify
    // create our data input
    assert_rnp_success(rnp_input_from_memory(&input, (uint8_t *) data, strlen(data), false));
    assert_non_null(input);
    // create our signature input
    assert_rnp_success(rnp_input_from_memory(&input_sig, sig, sig_len, true));
    assert_non_null(input_sig);
    // create our operation
    assert_rnp_success(rnp_op_verify_detached_create(&opverify, ffi, input, input_sig));
    assert_non_null(opverify);
    // execute the verification
    assert_rnp_success(rnp_op_verify_execute(opverify));
    // cleanup
    rnp_op_verify_destroy(opverify);
    opverify = NULL;
    rnp_input_destroy(input);
    input = NULL;
    rnp_input_destroy(input_sig);
    input_sig = NULL;

    // verify (tamper with signature)
    // create our data input
    assert_rnp_success(rnp_input_from_memory(&input, (uint8_t *) data, strlen(data), false));
    assert_non_null(input);
    // create our signature input
    sig[sig_len - 5] ^= 0xff;
    assert_rnp_success(rnp_input_from_memory(&input_sig, sig, sig_len, true));
    assert_non_null(input_sig);
    // create our operation
    assert_rnp_success(rnp_op_verify_detached_create(&opverify, ffi, input, input_sig));
    assert_non_null(opverify);
    // execute the verification
    assert_rnp_failure(rnp_op_verify_execute(opverify));
    // cleanup
    rnp_op_verify_destroy(opverify);
    opverify = NULL;
    rnp_input_destroy(input);
    input = NULL;
    rnp_input_destroy(input_sig);
    input_sig = NULL;

    // cleanup
    rnp_buffer_destroy(sig);
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_enarmor_dearmor)
{
    std::string data;

    // enarmor plain message
    const std::string msg("this is a test");
    data.clear();
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        assert_rnp_success(
          rnp_input_from_memory(&input, (const uint8_t *) msg.data(), msg.size(), true));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_enarmor(input, output, "message"));

        rnp_output_memory_get_buf(output, &buf, &buf_size, false);
        data = std::string(buf, buf + buf_size);
        assert_true(starts_with(data, "-----BEGIN PGP MESSAGE-----\r\n"));
        assert_true(ends_with(data, "-----END PGP MESSAGE-----\r\n"));

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        assert_rnp_success(
          rnp_input_from_memory(&input, (const uint8_t *) data.data(), data.size(), true));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_dearmor(input, output));

        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_size, false));
        std::string dearmored(buf, buf + buf_size);
        assert_true(msg == dearmored);

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }

    // enarmor public key
    data.clear();
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        // enarmor
        assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_enarmor(input, output, NULL));

        rnp_output_memory_get_buf(output, &buf, &buf_size, false);
        data = std::string(buf, buf + buf_size);
        assert_true(starts_with(data, "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"));
        assert_true(ends_with(data, "-----END PGP PUBLIC KEY BLOCK-----\r\n"));

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }
    // dearmor public key
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        assert_rnp_success(
          rnp_input_from_memory(&input, (const uint8_t *) data.data(), data.size(), true));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_dearmor(input, output));

        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_size, false));
        std::string   dearmored(buf, buf + buf_size);
        std::ifstream inf("data/keyrings/1/pubring.gpg", std::ios::binary | std::ios::ate);
        std::string   from_disk(inf.tellg(), ' ');
        inf.seekg(0);
        inf.read(&from_disk[0], from_disk.size());
        inf.close();
        assert_true(dearmored == from_disk);

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }
    // test truncated armored data
    {
        std::ifstream keyf("data/test_stream_key_load/rsa-rsa-pub.asc",
                           std::ios::binary | std::ios::ate);
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

TEST_F(rnp_tests, test_ffi_version)
{
    const uint32_t version = rnp_version();
    const uint32_t major = rnp_version_major(version);
    const uint32_t minor = rnp_version_minor(version);
    const uint32_t patch = rnp_version_patch(version);

    // reconstruct the version string
    assert_string_equal(fmt("%d.%d.%d", major, minor, patch).c_str(), rnp_version_string());

    // full version string should probably be at least as long as regular version string
    assert_true(strlen(rnp_version_string_full()) >= strlen(rnp_version_string()));

    // reconstruct the version value
    assert_int_equal(version, rnp_version_for(major, minor, patch));

    // check out-of-range handling
    assert_int_equal(0, rnp_version_for(1024, 0, 0));
    assert_int_equal(0, rnp_version_for(0, 1024, 0));
    assert_int_equal(0, rnp_version_for(0, 0, 1024));

    // check component extraction again
    assert_int_equal(rnp_version_major(rnp_version_for(5, 4, 3)), 5);
    assert_int_equal(rnp_version_minor(rnp_version_for(5, 4, 3)), 4);
    assert_int_equal(rnp_version_patch(rnp_version_for(5, 4, 3)), 3);

    // simple comparisons
    assert_true(rnp_version_for(1, 0, 1) > rnp_version_for(1, 0, 0));
    assert_true(rnp_version_for(1, 1, 0) > rnp_version_for(1, 0, 1023));
    assert_true(rnp_version_for(2, 0, 0) > rnp_version_for(1, 1023, 1023));
}

static void
check_loaded_keys(const char *                    format,
                  bool                            armored,
                  uint8_t *                       buf,
                  size_t                          buf_len,
                  const char *                    id_type,
                  const std::vector<std::string> &expected_ids,
                  bool                            secret)
{
    rnp_ffi_t                 ffi = NULL;
    rnp_input_t               input = NULL;
    rnp_identifier_iterator_t it = NULL;
    const char *              identifier = NULL;

    if (armored) {
        assert_memory_equal("-----", buf, 5);
    } else {
        assert_memory_not_equal("-----", buf, 5);
    }

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, format, format));

    // load our keyrings
    assert_rnp_success(rnp_input_from_memory(&input, buf, buf_len, true));
    assert_rnp_success(rnp_load_keys(
      ffi, format, input, secret ? RNP_LOAD_SAVE_SECRET_KEYS : RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    std::vector<std::string> ids;
    assert_rnp_success(rnp_identifier_iterator_create(ffi, &it, id_type));
    do {
        identifier = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &identifier));
        if (identifier) {
            rnp_key_handle_t key = NULL;
            bool             expected_secret = secret;
            bool             expected_public = !secret;
            bool             result;
            assert_rnp_success(rnp_locate_key(ffi, id_type, identifier, &key));
            assert_non_null(key);
            assert_rnp_success(rnp_key_have_secret(key, &result));
            assert_int_equal(result, expected_secret);
            assert_rnp_success(rnp_key_have_public(key, &result));
            assert_int_equal(result, expected_public);
            assert_rnp_success(rnp_key_handle_destroy(key));
            ids.push_back(identifier);
        }
    } while (identifier);
    assert_true(ids == expected_ids);
    rnp_identifier_iterator_destroy(it);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_export)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_key_handle_t key = NULL;
    uint8_t *        buf = NULL;
    size_t           buf_len = 0;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // primary pub only
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(rnp_key_export(key, output, RNP_KEY_EXPORT_PUBLIC));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys("GPG", false, buf, buf_len, "keyid", {"2FCADF05FFA501BB"}, false);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // primary sec only (armored)
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(
          rnp_key_export(key, output, RNP_KEY_EXPORT_SECRET | RNP_KEY_EXPORT_ARMORED));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys("GPG", true, buf, buf_len, "keyid", {"2FCADF05FFA501BB"}, true);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // primary pub and subs
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(
          rnp_key_export(key, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys("GPG",
                          false,
                          buf,
                          buf_len,
                          "keyid",
                          {"2FCADF05FFA501BB", "54505A936A4A970E", "326EF111425D14A5"},
                          false);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // primary sec and subs (armored)
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(rnp_key_export(key,
                                          output,
                                          RNP_KEY_EXPORT_SECRET | RNP_KEY_EXPORT_SUBKEYS |
                                            RNP_KEY_EXPORT_ARMORED));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys("GPG",
                          true,
                          buf,
                          buf_len,
                          "keyid",
                          {"2FCADF05FFA501BB", "54505A936A4A970E", "326EF111425D14A5"},
                          true);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // sub pub
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "54505A936A4A970E", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(
          rnp_key_export(key, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_ARMORED));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys(
          "GPG", true, buf, buf_len, "keyid", {"2FCADF05FFA501BB", "54505A936A4A970E"}, false);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // sub sec
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "54505A936A4A970E", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(
          rnp_key_export(key, output, RNP_KEY_EXPORT_SECRET | RNP_KEY_EXPORT_ARMORED));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys(
          "GPG", true, buf, buf_len, "keyid", {"2FCADF05FFA501BB", "54505A936A4A970E"}, true);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_dump)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_key_handle_t key = NULL;
    char *           json = NULL;
    json_object *    jso = NULL;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // locate key
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
    assert_non_null(key);

    // dump public key and check results
    assert_rnp_success(rnp_key_packets_to_json(
      key, false, RNP_JSON_DUMP_MPI | RNP_JSON_DUMP_RAW | RNP_JSON_DUMP_GRIP, &json));
    assert_non_null(json);
    jso = json_tokener_parse(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    json_object_put(jso);
    rnp_buffer_destroy(json);

    // dump secret key and check results
    assert_rnp_success(rnp_key_packets_to_json(
      key, true, RNP_JSON_DUMP_MPI | RNP_JSON_DUMP_RAW | RNP_JSON_DUMP_GRIP, &json));
    assert_non_null(json);
    jso = json_tokener_parse(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    json_object_put(jso);
    rnp_buffer_destroy(json);

    // cleanup
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_pkt_dump)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    char *       json = NULL;
    json_object *jso = NULL;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));

    // setup input
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));

    // try with wrong parameters
    assert_rnp_failure(rnp_dump_packets_to_json(input, 0, NULL));
    assert_rnp_failure(rnp_dump_packets_to_json(NULL, 0, &json));
    assert_rnp_failure(rnp_dump_packets_to_json(input, 117, &json));
    // dump
    assert_rnp_success(rnp_dump_packets_to_json(
      input, RNP_JSON_DUMP_MPI | RNP_JSON_DUMP_RAW | RNP_JSON_DUMP_GRIP, &json));
    rnp_input_destroy(input);
    input = NULL;
    assert_non_null(json);

    // check results
    jso = json_tokener_parse(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    json_object_put(jso);
    rnp_buffer_destroy(json);

    // setup input and output
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));

    // try with wrong parameters
    assert_rnp_failure(rnp_dump_packets_to_output(input, NULL, 0));
    assert_rnp_failure(rnp_dump_packets_to_output(NULL, output, 0));
    assert_rnp_failure(rnp_dump_packets_to_output(input, output, 117));
    // dump
    assert_rnp_success(
      rnp_dump_packets_to_output(input, output, RNP_DUMP_MPI | RNP_DUMP_RAW | RNP_DUMP_GRIP));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_rsa_v3_dump)
{
    rnp_input_t input = NULL;
    char *      json = NULL;

    /* dump rsav3 key to json via FFI */
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/4/rsav3-p.asc"));
    assert_rnp_success(rnp_dump_packets_to_json(input, RNP_JSON_DUMP_GRIP, &json));
    rnp_input_destroy(input);
    /* parse dump */
    json_object *jso = json_tokener_parse(json);
    rnp_buffer_destroy(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    json_object *rsapkt = json_object_array_get_idx(jso, 0);
    assert_non_null(rsapkt);
    assert_true(json_object_is_type(rsapkt, json_type_object));
    /* check algorithm string */
    json_object *fld = NULL;
    assert_true(json_object_object_get_ex(rsapkt, "algorithm.str", &fld));
    assert_non_null(fld);
    const char *str = json_object_get_string(fld);
    assert_non_null(str);
    assert_int_equal(strcmp(str, "RSA (Encrypt or Sign)"), 0);
    /* check fingerprint */
    fld = NULL;
    assert_true(json_object_object_get_ex(rsapkt, "fingerprint", &fld));
    assert_non_null(fld);
    str = json_object_get_string(fld);
    assert_non_null(str);
    assert_int_equal(strcmp(str, "06a044022bb5aa7991077466aeba2ce7"), 0);
    json_object_put(jso);
}

TEST_F(rnp_tests, test_ffi_load_userattr)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    // init ffi and load key
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_load/ecc-25519-photo-pub.asc"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    // check userid 0 : ecc-25519
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "cc786278981b0728", &key));
    assert_non_null(key);
    size_t uid_count = 0;
    assert_rnp_success(rnp_key_get_uid_count(key, &uid_count));
    assert_int_equal(uid_count, 2);
    char *uid = NULL;
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_int_equal(strcmp(uid, "ecc-25519"), 0);
    rnp_buffer_destroy(uid);
    // check userattr 1, must be text instead of binary JPEG data
    assert_rnp_success(rnp_key_get_uid_at(key, 1, &uid));
    assert_int_equal(strcmp(uid, "(photo)"), 0);
    rnp_buffer_destroy(uid);
    assert_rnp_success(rnp_key_handle_destroy(key));
    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_revocations)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load key with revoked userid
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_load/ecc-p256-revoked-uid.asc"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    // check userid 0 : ecc-p256
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "ecc-p256", &key));
    assert_non_null(key);
    size_t uid_count = 0;
    assert_rnp_success(rnp_key_get_uid_count(key, &uid_count));
    assert_int_equal(uid_count, 2);
    char *uid = NULL;
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_int_equal(strcmp(uid, "ecc-p256"), 0);
    rnp_buffer_destroy(uid);
    rnp_uid_handle_t uid_handle = NULL;
    assert_rnp_success(rnp_key_get_uid_handle_at(key, 0, &uid_handle));
    assert_non_null(uid_handle);
    bool revoked = true;
    assert_rnp_failure(rnp_uid_is_revoked(NULL, &revoked));
    assert_rnp_failure(rnp_uid_is_revoked(uid_handle, NULL));
    assert_rnp_success(rnp_uid_is_revoked(uid_handle, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_uid_handle_destroy(uid_handle));
    // check userid 1: ecc-p256-revoked
    assert_rnp_success(rnp_key_get_uid_at(key, 1, &uid));
    assert_int_equal(strcmp(uid, "ecc-p256-revoked"), 0);
    rnp_buffer_destroy(uid);
    assert_rnp_success(rnp_key_get_uid_handle_at(key, 1, &uid_handle));
    assert_non_null(uid_handle);
    assert_rnp_success(rnp_uid_is_revoked(uid_handle, &revoked));
    assert_true(revoked);
    assert_rnp_success(rnp_uid_handle_destroy(uid_handle));
    assert_rnp_success(rnp_key_handle_destroy(key));

    // load key with revoked subkey
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_load/ecc-p256-revoked-sub.asc"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    // key is not revoked
    assert_rnp_success(rnp_locate_key(ffi, "userid", "ecc-p256", &key));
    assert_rnp_success(rnp_key_is_revoked(key, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_key_handle_destroy(key));
    // subkey is revoked
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "37E285E9E9851491", &key));
    assert_rnp_success(rnp_key_is_revoked(key, &revoked));
    assert_true(revoked);
    char *reason = NULL;
    assert_rnp_success(rnp_key_get_revocation_reason(key, &reason));
    assert_int_equal(strcmp(reason, "Subkey revocation test."), 0);
    rnp_buffer_destroy(reason);
    assert_rnp_success(rnp_key_is_superseded(key, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_key_is_compromised(key, &revoked));
    assert_true(revoked);
    assert_rnp_success(rnp_key_is_retired(key, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_key_handle_destroy(key));

    // load revoked key
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_load/ecc-p256-revoked-key.asc"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    // key is revoked
    assert_rnp_success(rnp_locate_key(ffi, "userid", "ecc-p256", &key));
    assert_rnp_success(rnp_key_is_revoked(key, &revoked));
    assert_true(revoked);
    reason = NULL;
    assert_rnp_success(rnp_key_get_revocation_reason(key, &reason));
    assert_int_equal(strcmp(reason, "Superseded key test."), 0);
    rnp_buffer_destroy(reason);
    assert_rnp_success(rnp_key_is_superseded(key, &revoked));
    assert_true(revoked);
    assert_rnp_success(rnp_key_is_compromised(key, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_key_is_retired(key, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_key_handle_destroy(key));

    // cleanup
    rnp_ffi_destroy(ffi);
}

#define KEY_OUT_PATH "exported-key.asc"

TEST_F(rnp_tests, test_ffi_file_output)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load two keys
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_load/ecc-p256-pub.asc"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_load/ecc-p521-pub.asc"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);

    rnp_key_handle_t k256 = NULL;
    rnp_key_handle_t k521 = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "ecc-p256", &k256));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "ecc-p521", &k521));

    rnp_output_t output = NULL;
    // test output to path - must overwrite if exists
    assert_rnp_success(rnp_output_to_path(&output, KEY_OUT_PATH));
    assert_rnp_success(rnp_key_export(
      k256, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_ARMORED | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_output_destroy(output));
    assert_true(file_exists(KEY_OUT_PATH));
    off_t sz = file_size(KEY_OUT_PATH);
    assert_rnp_success(rnp_output_to_path(&output, KEY_OUT_PATH));
    assert_rnp_success(rnp_key_export(
      k521, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_ARMORED | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_output_destroy(output));
    assert_true(file_exists(KEY_OUT_PATH));
    assert_true(sz != file_size(KEY_OUT_PATH));
    sz = file_size(KEY_OUT_PATH);
    // test output to file - will fail without overwrite
    assert_rnp_failure(rnp_output_to_file(&output, KEY_OUT_PATH, 0));
    // fail with wrong flags
    assert_rnp_failure(rnp_output_to_file(&output, KEY_OUT_PATH, 0x100));
    // test output to random file - will succeed on creation and export but fail on finish.
    assert_rnp_success(rnp_output_to_file(&output, KEY_OUT_PATH, RNP_OUTPUT_FILE_RANDOM));
    assert_true(file_size(KEY_OUT_PATH) == sz);
    assert_rnp_success(
      rnp_key_export(k256, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_failure(rnp_output_finish(output));
    assert_rnp_success(rnp_output_destroy(output));
    // test output with random + overwrite - will succeed
    assert_rnp_success(rnp_output_to_file(
      &output, KEY_OUT_PATH, RNP_OUTPUT_FILE_RANDOM | RNP_OUTPUT_FILE_OVERWRITE));
    assert_true(file_size(KEY_OUT_PATH) == sz);
    assert_rnp_success(
      rnp_key_export(k256, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_output_finish(output));
    assert_rnp_success(rnp_output_destroy(output));
    assert_true(file_size(KEY_OUT_PATH) != sz);
    sz = file_size(KEY_OUT_PATH);
    // test output with just overwrite - will succeed
    assert_rnp_success(rnp_output_to_file(&output, KEY_OUT_PATH, RNP_OUTPUT_FILE_OVERWRITE));
    assert_true(file_size(KEY_OUT_PATH) == 0);
    assert_rnp_success(
      rnp_key_export(k521, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_output_finish(output));
    assert_rnp_success(rnp_output_destroy(output));
    assert_true(file_size(KEY_OUT_PATH) != sz);
    assert_int_equal(unlink(KEY_OUT_PATH), 0);
    // cleanup
    assert_rnp_success(rnp_key_handle_destroy(k256));
    assert_rnp_success(rnp_key_handle_destroy(k521));
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_signatures)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load key
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_load/ecc-p384-pub.asc"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    // check primary key
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "242A3AA5EA85F44A", &key));
    // some edge cases
    size_t                 sigs = 0;
    rnp_signature_handle_t sig = NULL;
    assert_rnp_failure(rnp_key_get_signature_count(NULL, &sigs));
    assert_rnp_failure(rnp_key_get_signature_count(key, NULL));
    assert_rnp_failure(rnp_key_get_signature_at(key, 0, &sig));
    assert_rnp_failure(rnp_key_get_signature_at(key, 0x10000, &sig));
    assert_rnp_failure(rnp_key_get_signature_at(NULL, 0x10000, &sig));
    assert_rnp_failure(rnp_key_get_signature_at(NULL, 0, NULL));
    // key doesn't have signatures
    assert_rnp_success(rnp_key_get_signature_count(key, &sigs));
    assert_int_equal(sigs, 0);
    // uid must have one signature
    rnp_uid_handle_t uid = NULL;
    assert_rnp_success(rnp_key_get_uid_handle_at(key, 0, &uid));
    assert_rnp_success(rnp_uid_get_signature_count(uid, &sigs));
    assert_int_equal(sigs, 1);
    assert_rnp_failure(rnp_uid_get_signature_at(uid, 1, &sig));
    assert_rnp_success(rnp_uid_get_signature_at(uid, 0, &sig));
    uint32_t creation = 0;
    assert_rnp_success(rnp_signature_get_creation(sig, &creation));
    assert_int_equal(creation, 1549119505);
    char *alg = NULL;
    assert_rnp_failure(rnp_signature_get_alg(NULL, &alg));
    assert_rnp_failure(rnp_signature_get_alg(sig, NULL));
    assert_rnp_success(rnp_signature_get_alg(sig, &alg));
    assert_int_equal(strcmp(alg, "ECDSA"), 0);
    rnp_buffer_destroy(alg);
    assert_rnp_success(rnp_signature_get_hash_alg(sig, &alg));
    assert_int_equal(strcmp(alg, "SHA384"), 0);
    rnp_buffer_destroy(alg);
    char *keyid = NULL;
    assert_rnp_success(rnp_signature_get_keyid(sig, &keyid));
    assert_non_null(keyid);
    assert_int_equal(strcmp(keyid, "242A3AA5EA85F44A"), 0);
    rnp_buffer_destroy(keyid);
    rnp_key_handle_t signer = NULL;
    assert_rnp_success(rnp_signature_get_signer(sig, &signer));
    assert_non_null(signer);
    assert_rnp_success(rnp_key_get_keyid(signer, &keyid));
    assert_non_null(keyid);
    assert_int_equal(strcmp(keyid, "242A3AA5EA85F44A"), 0);
    rnp_buffer_destroy(keyid);
    rnp_key_handle_destroy(signer);
    assert_rnp_success(rnp_signature_handle_destroy(sig));
    // subkey must have one signature
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    assert_rnp_success(rnp_key_get_signature_count(subkey, &sigs));
    assert_int_equal(sigs, 1);
    assert_rnp_success(rnp_key_get_signature_at(subkey, 0, &sig));
    assert_rnp_success(rnp_signature_get_creation(sig, &creation));
    assert_int_equal(creation, 1549119513);
    assert_rnp_success(rnp_signature_get_alg(sig, &alg));
    assert_int_equal(strcmp(alg, "ECDSA"), 0);
    rnp_buffer_destroy(alg);
    assert_rnp_success(rnp_signature_get_hash_alg(sig, &alg));
    assert_int_equal(strcmp(alg, "SHA384"), 0);
    rnp_buffer_destroy(alg);
    assert_rnp_success(rnp_signature_get_keyid(sig, &keyid));
    assert_non_null(keyid);
    assert_int_equal(strcmp(keyid, "242A3AA5EA85F44A"), 0);
    rnp_buffer_destroy(keyid);
    assert_rnp_success(rnp_signature_get_signer(sig, &signer));
    assert_non_null(signer);
    assert_rnp_success(rnp_key_get_keyid(signer, &keyid));
    assert_non_null(keyid);
    assert_int_equal(strcmp(keyid, "242A3AA5EA85F44A"), 0);
    rnp_buffer_destroy(keyid);
    rnp_key_handle_destroy(signer);
    rnp_key_handle_destroy(subkey);
    assert_rnp_success(rnp_signature_handle_destroy(sig));
    assert_rnp_success(rnp_uid_handle_destroy(uid));
    assert_rnp_success(rnp_key_handle_destroy(key));

    // cleanup
    rnp_ffi_destroy(ffi);
}

static bool
check_import_keys(rnp_ffi_t     ffi,
                  json_object **jso,
                  json_object **keyarr,
                  const char *  keypath,
                  size_t        pubcount,
                  size_t        seccount)
{
    rnp_input_t input = NULL;

    if (rnp_input_from_path(&input, keypath)) {
        return false;
    }
    bool   res = false;
    char * keys = NULL;
    size_t keycount = 0;
    *jso = NULL;

    if (rnp_import_keys(
          ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS, &keys)) {
        goto done;
    }
    if (rnp_get_public_key_count(ffi, &keycount) || (keycount != pubcount)) {
        goto done;
    }
    if (rnp_get_secret_key_count(ffi, &keycount) || (keycount != seccount)) {
        goto done;
    }
    if (!keys) {
        goto done;
    }

    *jso = json_tokener_parse(keys);
    if (!jso) {
        goto done;
    }
    if (!json_object_is_type(*jso, json_type_object)) {
        goto done;
    }
    if (!json_object_object_get_ex(*jso, "keys", keyarr)) {
        goto done;
    }
    if (!json_object_is_type(*keyarr, json_type_array)) {
        goto done;
    }
    res = true;
done:
    if (!res) {
        json_object_put(*jso);
        *jso = NULL;
    }
    rnp_input_destroy(input);
    rnp_buffer_destroy(keys);
    return res;
}

static bool
check_key_status(json_object *key, const char *pub, const char *sec, const char *fp)
{
    if (!key) {
        return false;
    }
    if (!json_object_is_type(key, json_type_object)) {
        return false;
    }
    json_object *fld = NULL;
    if (!json_object_object_get_ex(key, "public", &fld)) {
        return false;
    }
    if (strcmp(json_object_get_string(fld), pub) != 0) {
        return false;
    }
    if (!json_object_object_get_ex(key, "secret", &fld)) {
        return false;
    }
    if (strcmp(json_object_get_string(fld), sec) != 0) {
        return false;
    }
    if (!json_object_object_get_ex(key, "fingerprint", &fld)) {
        return false;
    }
    if (strcmp(json_object_get_string(fld), fp) != 0) {
        return false;
    }
    return true;
}

TEST_F(rnp_tests, test_ffi_keys_import)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // some edge cases
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-both.asc"));
    assert_rnp_failure(rnp_import_keys(NULL, input, RNP_LOAD_SAVE_PUBLIC_KEYS, NULL));
    assert_rnp_failure(rnp_import_keys(ffi, NULL, RNP_LOAD_SAVE_PUBLIC_KEYS, NULL));
    assert_rnp_failure(rnp_import_keys(ffi, input, 0, NULL));
    assert_rnp_failure(rnp_import_keys(ffi, input, 0x31, NULL));
    // load just public keys
    assert_rnp_success(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, NULL));
    rnp_input_destroy(input);
    size_t keycount = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 3);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &keycount));
    assert_int_equal(keycount, 0);
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    // load just secret keys from pubkey file
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-pub.asc"));
    assert_rnp_success(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_SECRET_KEYS, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 0);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &keycount));
    assert_int_equal(keycount, 0);
    // load both public and secret keys by specifying just secret (it will create pub part)
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-sec.asc"));
    assert_rnp_success(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_SECRET_KEYS, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 3);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &keycount));
    assert_int_equal(keycount, 3);
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    // import just a public key without subkeys
    json_object *jso = NULL;
    json_object *jsokeys = NULL;
    assert_true(check_import_keys(
      ffi, &jso, &jsokeys, "data/test_stream_key_merge/key-pub-just-key.pgp", 1, 0));
    assert_int_equal(json_object_array_length(jsokeys), 1);
    json_object *jsokey = json_object_array_get_idx(jsokeys, 0);
    assert_true(
      check_key_status(jsokey, "new", "none", "090bd712a1166be572252c3c9747d2a6b3a63124"));
    json_object_put(jso);
    // import just subkey 1
    assert_true(check_import_keys(
      ffi, &jso, &jsokeys, "data/test_stream_key_merge/key-pub-just-subkey-1.pgp", 2, 0));
    assert_int_equal(json_object_array_length(jsokeys), 1);
    jsokey = json_object_array_get_idx(jsokeys, 0);
    assert_true(
      check_key_status(jsokey, "new", "none", "51b45a4c74917272e4e34180af1114a47f5f5b28"));
    json_object_put(jso);
    // import just subkey 2 without sigs
    assert_true(
      check_import_keys(ffi,
                        &jso,
                        &jsokeys,
                        "data/test_stream_key_merge/key-pub-just-subkey-2-no-sigs.pgp",
                        3,
                        0));
    assert_int_equal(json_object_array_length(jsokeys), 1);
    jsokey = json_object_array_get_idx(jsokeys, 0);
    assert_true(
      check_key_status(jsokey, "new", "none", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);
    // import subkey 2 with sigs
    assert_true(check_import_keys(
      ffi, &jso, &jsokeys, "data/test_stream_key_merge/key-pub-just-subkey-2.pgp", 3, 0));
    assert_int_equal(json_object_array_length(jsokeys), 1);
    jsokey = json_object_array_get_idx(jsokeys, 0);
    assert_true(
      check_key_status(jsokey, "updated", "none", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);
    // import first uid
    assert_true(check_import_keys(
      ffi, &jso, &jsokeys, "data/test_stream_key_merge/key-pub-uid-1.pgp", 3, 0));
    assert_int_equal(json_object_array_length(jsokeys), 1);
    jsokey = json_object_array_get_idx(jsokeys, 0);
    assert_true(
      check_key_status(jsokey, "updated", "none", "090bd712a1166be572252c3c9747d2a6b3a63124"));
    json_object_put(jso);
    // import the whole key
    assert_true(
      check_import_keys(ffi, &jso, &jsokeys, "data/test_stream_key_merge/key-pub.pgp", 3, 0));
    assert_int_equal(json_object_array_length(jsokeys), 3);
    jsokey = json_object_array_get_idx(jsokeys, 0);
    assert_true(
      check_key_status(jsokey, "updated", "none", "090bd712a1166be572252c3c9747d2a6b3a63124"));
    jsokey = json_object_array_get_idx(jsokeys, 1);
    assert_true(check_key_status(
      jsokey, "unchanged", "none", "51b45a4c74917272e4e34180af1114a47f5f5b28"));
    jsokey = json_object_array_get_idx(jsokeys, 2);
    assert_true(check_key_status(
      jsokey, "unchanged", "none", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);
    // import the first secret subkey
    assert_true(check_import_keys(
      ffi, &jso, &jsokeys, "data/test_stream_key_merge/key-sec-just-subkey-1.pgp", 3, 1));
    assert_int_equal(json_object_array_length(jsokeys), 1);
    jsokey = json_object_array_get_idx(jsokeys, 0);
    assert_true(check_key_status(
      jsokey, "unchanged", "new", "51b45a4c74917272e4e34180af1114a47f5f5b28"));
    json_object_put(jso);
    // import the second secret subkey
    assert_true(
      check_import_keys(ffi,
                        &jso,
                        &jsokeys,
                        "data/test_stream_key_merge/key-sec-just-subkey-2-no-sigs.pgp",
                        3,
                        2));
    assert_int_equal(json_object_array_length(jsokeys), 1);
    jsokey = json_object_array_get_idx(jsokeys, 0);
    assert_true(check_key_status(
      jsokey, "unchanged", "new", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);
    // import the whole secret key
    assert_true(
      check_import_keys(ffi, &jso, &jsokeys, "data/test_stream_key_merge/key-sec.pgp", 3, 3));
    assert_int_equal(json_object_array_length(jsokeys), 3);
    jsokey = json_object_array_get_idx(jsokeys, 0);
    assert_true(check_key_status(
      jsokey, "unchanged", "new", "090bd712a1166be572252c3c9747d2a6b3a63124"));
    jsokey = json_object_array_get_idx(jsokeys, 1);
    assert_true(check_key_status(
      jsokey, "unchanged", "unchanged", "51b45a4c74917272e4e34180af1114a47f5f5b28"));
    jsokey = json_object_array_get_idx(jsokeys, 2);
    assert_true(check_key_status(
      jsokey, "unchanged", "unchanged", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);
    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_calculate_iterations)
{
    size_t iterations = 0;
    assert_rnp_success(rnp_calculate_iterations("sha256", 500, &iterations));
    assert_true(iterations > 65536);
}

static bool
check_features(const char *type, const char *json, size_t count)
{
    json_object *features = json_tokener_parse(json);
    if (!features) {
        return false;
    }
    bool res = false;
    if (!json_object_is_type(features, json_type_array)) {
        goto done;
    }
    if ((size_t) json_object_array_length(features) != count) {
        RNP_LOG("wrong feature count for %s", type);
        goto done;
    }
    for (size_t i = 0; i < count; i++) {
        json_object *val = json_object_array_get_idx(features, i);
        const char * str = json_object_get_string(val);
        bool         supported = false;
        if (!str || rnp_supports_feature(type, str, &supported) || !supported) {
            goto done;
        }
    }

    res = true;
done:
    json_object_put(features);
    return res;
}

TEST_F(rnp_tests, test_ffi_supported_features)
{
    char *features = NULL;
    /* some edge cases */
    assert_rnp_failure(rnp_supported_features(NULL, &features));
    assert_rnp_failure(rnp_supported_features("something", NULL));
    assert_rnp_failure(rnp_supported_features("symmetric algorithm", NULL));
    assert_rnp_failure(rnp_supported_features("something", &features));
    /* symmetric algorithms */
    assert_rnp_success(rnp_supported_features("Symmetric Algorithm", &features));
    assert_non_null(features);
    assert_true(check_features("symmetric algorithm", features, 12));
    rnp_buffer_destroy(features);
    bool supported = false;
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "idea", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "TRIPLEDES", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "CAST5", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "BLOWFISH", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "AES128", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "AES192", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "AES256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "TWOFISH", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "CAMELLIA128", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "CAMELLIA192", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "CAMELLIA256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "SM4", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("symmetric algorithm", "wrong", &supported));
    assert_false(supported);
    /* aead algorithms */
    assert_rnp_success(rnp_supported_features("aead algorithm", &features));
    assert_non_null(features);
    assert_true(check_features("aead algorithm", features, 2));
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature("aead algorithm", "eax", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("aead algorithm", "ocb", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("aead algorithm", "wrong", &supported));
    assert_false(supported);
    /* protection mode */
    assert_rnp_success(rnp_supported_features("protection mode", &features));
    assert_non_null(features);
    assert_true(check_features("protection mode", features, 1));
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature("protection mode", "cfb", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("protection mode", "wrong", &supported));
    assert_false(supported);
    /* public key algorithm */
    assert_rnp_success(rnp_supported_features("public key algorithm", &features));
    assert_non_null(features);
    assert_true(check_features("public key algorithm", features, 7));
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature("public key algorithm", "rsa", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("public key algorithm", "DSA", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("public key algorithm", "ElGamal", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("public key algorithm", "ECDSA", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("public key algorithm", "ECDH", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("public key algorithm", "EDDSA", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("public key algorithm", "SM2", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("public key algorithm", "wrong", &supported));
    assert_false(supported);
    /* hash algorithm */
    assert_rnp_success(rnp_supported_features("hash algorithm", &features));
    assert_non_null(features);
    assert_true(check_features("hash algorithm", features, 10));
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "md5", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "SHA1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "RIPEMD160", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "SHA256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "SHA384", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "SHA512", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "SHA224", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "SHA3-256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "SHA3-512", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "SM3", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "wrong", &supported));
    assert_false(supported);
    assert_rnp_success(rnp_supports_feature("hash algorithm", "CRC24", &supported));
    assert_false(supported);
    /* compression algorithm */
    assert_rnp_success(rnp_supported_features("compression algorithm", &features));
    assert_non_null(features);
    assert_true(check_features("compression algorithm", features, 4));
    rnp_buffer_destroy(features);
    assert_rnp_success(
      rnp_supports_feature("compression algorithm", "Uncompressed", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("compression algorithm", "Zlib", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("compression algorithm", "ZIP", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("compression algorithm", "BZIP2", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("compression algorithm", "wrong", &supported));
    assert_false(supported);
    /* elliptic curve */
    assert_rnp_success(rnp_supported_features("elliptic curve", &features));
    assert_non_null(features);
    assert_true(check_features("elliptic curve", features, 10));
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature("elliptic curve", "NIST P-256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("elliptic curve", "NIST P-384", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("elliptic curve", "NIST P-521", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("elliptic curve", "ed25519", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("elliptic curve", "curve25519", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("elliptic curve", "brainpoolP256r1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("elliptic curve", "brainpoolP384r1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("elliptic curve", "brainpoolP512r1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("elliptic curve", "secp256k1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("elliptic curve", "SM2 P-256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature("elliptic curve", "wrong", &supported));
    assert_false(supported);
}

TEST_F(rnp_tests, test_ffi_enable_debug)
{
    assert_rnp_success(rnp_enable_debug("dummy.c"));
    assert_rnp_success(rnp_enable_debug("1.c"));
    assert_true(rnp_get_debug("dummy.c"));
    assert_true(rnp_get_debug("1.c"));
    assert_false(rnp_get_debug("dummy"));
    /* NULL enables debug for all sources */
    assert_rnp_success(rnp_enable_debug(NULL));
    assert_true(rnp_get_debug("anything"));
    assert_rnp_success(rnp_disable_debug());
    assert_false(rnp_get_debug("anything"));
    assert_false(rnp_get_debug("dummy.c"));
    assert_false(rnp_get_debug("1.c"));
    assert_rnp_success(rnp_enable_debug("all"));
    assert_true(rnp_get_debug("anything other"));
    /* need to clean it up afterwards - otherwise tests will go crazy */
    assert_rnp_success(rnp_disable_debug());
}

TEST_F(rnp_tests, test_ffi_rnp_key_get_primary_grip)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_key_handle_t key = NULL;
    char *           grip = NULL;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);

    // locate primary key
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7BC6709B15C23A4A", &key));
    assert_non_null(key);

    // some edge cases
    assert_rnp_failure(rnp_key_get_primary_grip(NULL, NULL));
    assert_rnp_failure(rnp_key_get_primary_grip(NULL, &grip));
    assert_rnp_failure(rnp_key_get_primary_grip(key, NULL));
    assert_rnp_failure(rnp_key_get_primary_grip(key, &grip));
    assert_null(grip);
    rnp_key_handle_destroy(key);

    // locate subkey 1
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1ED63EE56FADC34D", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_primary_grip(key, &grip));
    assert_non_null(grip);
    assert_int_equal(strcmp(grip, "66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA"), 0);
    rnp_buffer_destroy(grip);
    grip = NULL;
    rnp_key_handle_destroy(key);

    // locate subkey 2
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1D7E8A5393C997A8", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_primary_grip(key, &grip));
    assert_non_null(grip);
    assert_int_equal(strcmp(grip, "66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA"), 0);
    rnp_buffer_destroy(grip);
    grip = NULL;
    rnp_key_handle_destroy(key);

    // locate subkey 3
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "8A05B89FAD5ADED1", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_primary_grip(key, &grip));
    assert_non_null(grip);
    assert_int_equal(strcmp(grip, "66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA"), 0);
    rnp_buffer_destroy(grip);
    grip = NULL;
    rnp_key_handle_destroy(key);

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_output_to_armor)
{
    rnp_ffi_t    ffi = NULL;
    rnp_output_t memory = NULL;
    rnp_output_t armor = NULL;
    rnp_input_t  input = NULL;

    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);

    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
    assert_non_null(key);

    assert_rnp_success(rnp_output_to_memory(&memory, 0));
    /* some edge cases */
    assert_rnp_failure(rnp_output_to_armor(NULL, &armor, "message"));
    assert_null(armor);
    assert_rnp_failure(rnp_output_to_armor(memory, NULL, "message"));
    assert_null(armor);
    assert_rnp_failure(rnp_output_to_armor(memory, &armor, "wrong"));
    assert_null(armor);
    /* export raw key to armored stream with 'message' header */
    assert_rnp_success(rnp_output_to_armor(memory, &armor, "message"));
    assert_rnp_success(rnp_key_export(key, armor, RNP_KEY_EXPORT_PUBLIC));
    assert_rnp_success(rnp_output_destroy(armor));
    uint8_t *buf = NULL;
    size_t   buf_len = 0;
    /* check contents to make sure it is correct armored stream */
    assert_rnp_success(rnp_output_memory_get_buf(memory, &buf, &buf_len, false));
    assert_non_null(buf);
    const char *hdr = "-----BEGIN PGP MESSAGE-----";
    assert_true(buf_len > strlen(hdr));
    assert_int_equal(strncmp((char *) buf, hdr, strlen(hdr)), 0);
    assert_rnp_success(rnp_input_from_memory(&input, buf, buf_len, false));
    rnp_output_t memory2 = NULL;
    assert_rnp_success(rnp_output_to_memory(&memory2, 0));
    assert_rnp_success(rnp_dearmor(input, memory2));
    rnp_output_destroy(memory2);
    rnp_input_destroy(input);

    rnp_key_handle_destroy(key);
    rnp_output_destroy(memory);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_rnp_guess_contents)
{
    char *      msgt = NULL;
    rnp_input_t input = NULL;
    assert_rnp_failure(rnp_guess_contents(NULL, &msgt));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-pub.pgp"));
    assert_rnp_failure(rnp_guess_contents(input, NULL));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "public key"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_merge/key-pub-just-subkey-1.pgp"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "public key"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-pub.asc"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "public key"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-sec.pgp"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "secret key"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-sec.asc"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "secret key"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_merge/key-sec-just-subkey-1.pgp"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "secret key"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_z/128mb.zip"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "message"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_z/4gb.bzip2.asc"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "message"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_signatures/source.txt.sig"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "signature"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_signatures/source.txt.sig.asc"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "signature"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_signatures/source.txt.asc.asc"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "cleartext"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_signatures/source.txt"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "unknown"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);
}

TEST_F(rnp_tests, test_ffi_literal_filename)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    uint8_t *       signed_buf;
    size_t          signed_len;

    // init ffi
    test_ffi_init(&ffi);
    // init input
    test_ffi_init_sign_memory_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // setup filename and modification time
    assert_rnp_success(rnp_op_sign_set_file_name(op, "checkleak.dat"));
    assert_rnp_success(rnp_op_sign_set_file_name(op, NULL));
    assert_rnp_success(rnp_op_sign_set_file_name(op, "testfile.dat"));
    assert_rnp_success(rnp_op_sign_set_file_mtime(op, 12345678));
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    // make sure the output file was created
    assert_rnp_success(rnp_output_memory_get_buf(output, &signed_buf, &signed_len, true));
    assert_non_null(signed_buf);
    assert_true(signed_len > 0);

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_sign_destroy(op));
    op = NULL;

    // check the resulting stream for correct name/time
    assert_rnp_success(rnp_input_from_memory(&input, signed_buf, signed_len, false));
    char *json = NULL;
    assert_rnp_success(rnp_dump_packets_to_json(input, 0, &json));
    assert_non_null(json);

    std::string jstr = json;
    assert_true(jstr.find("\"filename\":\"testfile.dat\"") != std::string::npos);
    assert_true(jstr.find("\"timestamp\":12345678") != std::string::npos);

    assert_rnp_success(rnp_input_destroy(input));
    rnp_buffer_destroy(signed_buf);
    rnp_buffer_destroy(json);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_op_set_hash)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    uint8_t *       signed_buf;
    size_t          signed_len;

    // init ffi
    test_ffi_init(&ffi);
    // init input
    test_ffi_init_sign_memory_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // make sure it doesn't fail on NULL hash value
    assert_rnp_failure(rnp_op_sign_set_hash(op, NULL));
    assert_rnp_failure(rnp_op_sign_set_hash(op, "Unknown"));
    assert_rnp_success(rnp_op_sign_set_hash(op, "SHA256"));
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    // make sure the output file was created
    assert_rnp_success(rnp_output_memory_get_buf(output, &signed_buf, &signed_len, true));
    assert_non_null(signed_buf);
    assert_true(signed_len > 0);

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_output_destroy(output));
    assert_rnp_success(rnp_op_sign_destroy(op));

    rnp_buffer_destroy(signed_buf);
    rnp_ffi_destroy(ffi);
}

static bool
check_json_pkt_type(json_object *pkt, int tag)
{
    if (!pkt || !json_object_is_type(pkt, json_type_object)) {
      return false;
    }
    json_object *hdr = NULL;
    if (!json_object_object_get_ex(pkt, "header", &hdr)) {
      return false;
    }
    if (!json_object_is_type(hdr, json_type_object)) {
      return false;
    }
    return check_json_field_int(hdr, "tag", tag);
}

TEST_F(rnp_tests, test_ffi_aead_params)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "Some data to encrypt using the AEAD-EAX and AEAD-OCB encryption.";

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // write out some data
    FILE *fp = fopen("plaintext", "w");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));

    // create input+output
    assert_rnp_success(rnp_input_from_path(&input, "plaintext"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    // setup AEAD params
    assert_rnp_success(rnp_op_encrypt_set_aead(op, "OCB"));
    assert_rnp_failure(rnp_op_encrypt_set_aead_bits(op, -1));
    assert_rnp_failure(rnp_op_encrypt_set_aead_bits(op, 60));
    assert_rnp_success(rnp_op_encrypt_set_aead_bits(op, 10));
    // add password (using all defaults)
    assert_rnp_success(rnp_op_encrypt_add_password(op, "pass1", NULL, 0, NULL));
    // execute the operation
    assert_rnp_success(rnp_op_encrypt_execute(op));
    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));
    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_encrypt_destroy(op));
    op = NULL;

    // list packets
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    char *json = NULL;
    assert_rnp_success(rnp_dump_packets_to_json(input, 0, &json));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    json_object *jso = json_tokener_parse(json);
    rnp_buffer_destroy(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    /* check the symmetric-key encrypted session key packet */
    json_object *pkt = json_object_array_get_idx(jso, 0);
    assert_true(check_json_pkt_type(pkt, PGP_PTAG_CT_SK_SESSION_KEY));
    assert_true(check_json_field_int(pkt, "version", 5));
    assert_true(check_json_field_str(pkt, "aead algorithm.str", "OCB"));
    /* check the aead-encrypted packet */
    pkt = json_object_array_get_idx(jso, 1);
    assert_true(check_json_pkt_type(pkt, PGP_PTAG_CT_AEAD_ENCRYPTED));
    assert_true(check_json_field_int(pkt, "version", 1));
    assert_true(check_json_field_str(pkt, "aead algorithm.str", "OCB"));
    assert_true(check_json_field_int(pkt, "chunk size", 10));
    json_object_put(jso);

    /* decrypt */
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "pass1"));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // compare the decrypted file
    assert_true(file_equals("decrypted", plaintext, strlen(plaintext)));
    unlink("decrypted");

    // final cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_detached_verify_input)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;

    // init ffi
    test_ffi_init(&ffi);
    /* verify detached signature via rnp_op_verify_create - should not crash */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_signatures/source.txt.sig"));
    assert_rnp_success(rnp_output_to_null(&output));
    rnp_op_verify_t verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_ffi_destroy(ffi);
}

static bool
check_signature(rnp_op_verify_t op, size_t idx, rnp_result_t status)
{
    rnp_op_verify_signature_t sig = NULL;
    if (rnp_op_verify_get_signature_at(op, idx, &sig)) {
        return false;
    }
    return rnp_op_verify_signature_get_status(sig) == status;
}

TEST_F(rnp_tests, test_ffi_op_verify_sig_count)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;

    // init ffi
    test_ffi_init(&ffi);

    /* signed message */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.signed"));
    assert_rnp_success(rnp_output_to_null(&output));
    rnp_op_verify_t verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    size_t sigcount = 0;
    assert_rnp_failure(rnp_op_verify_get_signature_count(verify, NULL));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed with unknown key */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.signed.unknown"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_ERROR_KEY_NOT_FOUND));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed with malformed signature (bad version) */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.signed.malfsig"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed with invalid signature (modified hash alg) */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.signed.invsig"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_int_equal(rnp_op_verify_execute(verify), RNP_ERROR_SIGNATURE_INVALID);
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_ERROR_SIGNATURE_INVALID));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed without the signature */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.signed.nosig"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* detached signature */
    rnp_input_t source = NULL;
    assert_rnp_success(rnp_input_from_path(&source, "data/test_messages/message.txt"));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.sig"));
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, source, input));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(source);
    rnp_input_destroy(input);

    /* malformed detached signature */
    assert_rnp_success(rnp_input_from_path(&source, "data/test_messages/message.txt"));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.sig.malf"));
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, source, input));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(source);
    rnp_input_destroy(input);

    /* encrypted message */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.encrypted"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* encrypted and signed message */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.signed-encrypted"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* cleartext signed message */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.cleartext-signed"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* cleartext signed with malformed signature (wrong mpi len) */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.cleartext-malf"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_int_equal(rnp_op_verify_execute(verify), RNP_ERROR_SIGNATURE_INVALID);
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_ERROR_SIGNATURE_INVALID));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* cleartext signed without the signature */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.cleartext-nosig"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_ffi_destroy(ffi);
}
