/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#include <rnp/rnp2.h>
#include "rnp_tests.h"
#include "support.h"

void
test_ffi_homedir(void **state)
{
    rnp_test_state_t *rstate = *state;
    rnp_ffi_t         ffi = NULL;
    char *            homedir = NULL;
    size_t            homedir_size = 0;
    char *            path = NULL;
    size_t            path_size = 0;
    char *            pub_format = NULL;
    char *            pub_path = NULL;
    char *            sec_format = NULL;
    char *            sec_path = NULL;
    rnp_keyring_t     pubring, secring;

    // get the default homedir (not a very thorough test)
    homedir = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_get_default_homedir(&homedir));
    assert_non_null(homedir);
    rnp_buffer_free(homedir);
    homedir = NULL;

    // homedir tests/data/keyrings/1
    assert_non_null(
      rnp_compose_path_ex(&homedir, &homedir_size, rstate->data_dir, "keyrings/1", NULL));
    // detect the formats+paths
    assert_int_equal(
      RNP_SUCCESS,
      rnp_detect_homedir_info(homedir, &pub_format, &pub_path, &sec_format, &sec_path));
    // check formats
    assert_int_equal(0, strcmp(pub_format, "GPG"));
    assert_int_equal(0, strcmp(sec_format, "GPG"));
    // check paths
    assert_non_null(rnp_compose_path_ex(
      &path, &path_size, rstate->data_dir, "keyrings/1/pubring.gpg", NULL));
    assert_int_equal(0, strcmp(pub_path, path));
    assert_non_null(rnp_compose_path_ex(
      &path, &path_size, rstate->data_dir, "keyrings/1/secring.gpg", NULL));
    assert_int_equal(0, strcmp(sec_path, path));
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, pub_format, sec_format));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_pubring(ffi, &pubring));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_secring(ffi, &secring));
    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_keyring_load_from_path(pubring, pub_path));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_load_from_path(secring, sec_path));
    // free formats+paths
    rnp_buffer_free(pub_format);
    rnp_buffer_free(pub_path);
    rnp_buffer_free(sec_format);
    rnp_buffer_free(sec_path);
    pub_format = NULL;
    pub_path = NULL;
    sec_format = NULL;
    sec_path = NULL;
    // check key counts
    size_t count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(7, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    // homedir tests/data/keyrings/3
    assert_non_null(
      rnp_compose_path_ex(&homedir, &homedir_size, rstate->data_dir, "keyrings/3", NULL));
    // detect the formats+paths
    assert_int_equal(
      RNP_SUCCESS,
      rnp_detect_homedir_info(homedir, &pub_format, &pub_path, &sec_format, &sec_path));
    // check formats
    assert_int_equal(0, strcmp(pub_format, "KBX"));
    assert_int_equal(0, strcmp(sec_format, "G10"));
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, pub_format, sec_format));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_pubring(ffi, &pubring));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_secring(ffi, &secring));
    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_keyring_load_from_path(pubring, pub_path));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_load_from_path(secring, sec_path));
    // free formats+paths
    rnp_buffer_free(pub_format);
    rnp_buffer_free(pub_path);
    rnp_buffer_free(sec_format);
    rnp_buffer_free(sec_path);
    pub_format = NULL;
    pub_path = NULL;
    sec_format = NULL;
    sec_path = NULL;
    // check key counts
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(2, count);
    // check grip (1)
    rnp_key_handle_t key = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", "63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59", &key));
    assert_non_null(key);
    char *grip = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_key_get_grip(key, &grip));
    assert_non_null(grip);
    assert_true(strcmp(grip, "63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59") == 0);
    rnp_buffer_free(grip);
    rnp_key_handle_free(&key);
    // check grip (2)
    key = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", "7EAB41A2F46257C36F2892696F5A2F0432499AD3", &key));
    assert_non_null(key);
    grip = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_key_get_grip(key, &grip));
    assert_non_null(grip);
    assert_true(strcmp(grip, "7EAB41A2F46257C36F2892696F5A2F0432499AD3") == 0);
    rnp_buffer_free(grip);
    assert_int_equal(RNP_SUCCESS, rnp_key_handle_free(&key));
    key = NULL;
    // cleanup
    rnp_ffi_destroy(ffi);

    // final cleanup
    free(homedir);
    free(path);
}

static void
load_test_data(const char *data_dir, const char *file, char **data, size_t *size)
{
    char *      path = NULL;
    struct stat st = {0};

    assert_non_null(data_dir);
    assert_non_null(file);
    assert_non_null(data);

    path = rnp_compose_path(data_dir, file, NULL);
    assert_non_null(path);

    assert_int_equal(0, stat(path, &st));
    if (size) {
        *size = st.st_size;
    }
    *data = calloc(1, st.st_size + 1);
    assert_non_null(*data);

    FILE *fp = fopen(path, "r");
    assert_non_null(fp);
    assert_int_equal(st.st_size, fread(*data, 1, st.st_size, fp));
    fclose(fp);
    free(path);
}

void
test_ffi_detect_key_format(void **state)
{
    rnp_test_state_t *rstate = *state;
    char *            data = NULL;
    size_t            data_size = 0;
    char *            format = NULL;

    // GPG
    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir, "keyrings/1/pubring.gpg", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);

    // GPG
    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir, "keyrings/1/secring.gpg", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);
    format = NULL;

    // GPG (armored)
    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir, "keyrings/4/rsav3-p.asc", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);

    // KBX
    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir, "keyrings/3/pubring.kbx", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "KBX"));
    free(data);
    free(format);

    // G10
    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir,
                   "keyrings/3/private-keys-v1.d/63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59.key",
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

static int
unused_getkeycb(void *      app_ctx,
                const char *identifier_type,
                const char *identifier,
                bool        secret,
                uint8_t **  buf,
                size_t *    buf_len)
{
    assert_true(false);
    return 0;
}

static int
unused_getpasscb(
  void *app_ctx, rnp_key_handle_t key, const char *pgp_context, char *buf, size_t buf_len)
{
    assert_true(false);
    return 0;
}

static int
getpasscb(void *app_ctx, rnp_key_handle_t key, const char *pgp_context, char *buf, size_t buf_len)
{
    strcpy(buf, (const char *) app_ctx);
    return 0;
}

static int
getpasscb_once(void *app_ctx, rnp_key_handle_t key, const char *pgp_context, char *buf, size_t buf_len)
{
    const char **pass = (const char **)app_ctx;
    if (!*pass) {
        return 1;
    }
    strcpy(buf, *pass);
    *pass = NULL;
    return 0;
}

static void
check_key_properties(rnp_key_handle_t key, bool primary_exptected, bool have_public_expected, bool have_secret_expected)
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

void
test_ffi_keygen_json_pair(void **state)
{
    rnp_test_state_t *rstate = *state;
    rnp_ffi_t         ffi = NULL;
    rnp_keyring_t     pubring = NULL, secring = NULL;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // get keyrings
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_pubring(ffi, &pubring));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_secring(ffi, &secring));

    // load our JSON
    load_test_data(rstate->data_dir, "json/generate-pair.json", &json, NULL);

    // generate the keys
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    free(json);
    json = NULL;

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_free(results);
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
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(primary, true, true, true);
    check_key_properties(sub, false, true, true);

    // cleanup
    rnp_key_handle_free(&primary);
    rnp_key_handle_free(&sub);
    rnp_ffi_destroy(ffi);
}

void
test_ffi_keygen_json_primary(void **state)
{
    rnp_test_state_t *rstate = *state;
    rnp_ffi_t         ffi = NULL;
    rnp_keyring_t     pubring = NULL, secring = NULL;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // get keyrings
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_pubring(ffi, &pubring));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_secring(ffi, &secring));

    // load our JSON
    load_test_data(rstate->data_dir, "json/generate-primary.json", &json, NULL);

    // generate the keys
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    free(json);
    json = NULL;

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_free(results);
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
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(1, count);

    // check some key properties
    check_key_properties(primary, true, true, true);

    // cleanup
    rnp_key_handle_free(&primary);
    rnp_ffi_destroy(ffi);
}

/* This test generates a primary key, and then a subkey (separately).
 */
void
test_ffi_keygen_json_sub(void **state)
{
    rnp_test_state_t *rstate = *state;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;
    rnp_ffi_t         ffi = NULL;
    rnp_keyring_t     pubring = NULL, secring = NULL;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // get keyrings
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_pubring(ffi, &pubring));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_secring(ffi, &secring));

    // generate our primary key
    load_test_data(rstate->data_dir, "json/generate-primary.json", &json, NULL);
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    free(json);
    assert_non_null(results);
    // check key counts
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(1, count);

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_free(results);
    // get a handle+grip for the primary
    rnp_key_handle_t primary = NULL;
    char *primary_grip = NULL;
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
    load_test_data(rstate->data_dir, "json/generate-sub.json", &json, NULL);
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
    rnp_buffer_free(primary_grip);
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
    rnp_buffer_free(results);
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
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(primary, true, true, true);
    check_key_properties(sub, false, true, true);

    // cleanup
    rnp_key_handle_free(&primary);
    rnp_key_handle_free(&sub);
    rnp_ffi_destroy(ffi);
}

// TODO: Hash mismatch in secret key
void
test_ffi_keygen_json_sub_pass_required(void **state)
{
    rnp_test_state_t *rstate = *state;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;
    rnp_ffi_t         ffi = NULL;
    rnp_keyring_t     pubring = NULL, secring = NULL;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS,
                     rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS,
                     rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // get keyrings
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_pubring(ffi, &pubring));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_secring(ffi, &secring));

    // generate our primary key
    load_test_data(rstate->data_dir, "json/generate-primary.json", &json, NULL);
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    free(json);
    assert_non_null(results);
    // check key counts
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(1, count);

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_free(results);
    // get a handle+grip for the primary
    rnp_key_handle_t primary = NULL;
    char *primary_grip = NULL;
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
    assert_int_equal(RNP_SUCCESS, rnp_key_protect(primary, "pass123"));
    assert_int_equal(RNP_SUCCESS, rnp_key_lock(primary));
    rnp_key_handle_free(&primary);
    primary = NULL;

    // load our JSON template
    load_test_data(rstate->data_dir, "json/generate-sub.json", &json, NULL);
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
    rnp_buffer_free(primary_grip);
    primary_grip = NULL;

    // generate the subkey (no getpasscb, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_int_not_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));

    // generate the subkey (wrong pass, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, "wrong"));
    assert_int_not_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));

    // generate the subkey
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, "pass123"));
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    free(json);
    json = NULL;
    assert_non_null(results);

    // parse the results JSON
    parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_free(results);
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
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(sub, false, true, true);

    // cleanup
    rnp_key_handle_free(&primary);
    rnp_key_handle_free(&sub);
    rnp_ffi_destroy(ffi);
}

void
test_ffi_encrypt_pass(void **state)
{
    // rnp_test_state_t *rstate = *state;
    rnp_ffi_t        ffi = NULL;
    rnp_keyring_t    pubring, secring;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *plaintext = "data1";

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_pubring(ffi, &pubring));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_secring(ffi, &secring));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS,
                     rnp_keyring_load_from_path(pubring, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS,
                     rnp_keyring_load_from_path(secring, "data/keyrings/1/secring.gpg"));

    // write out some data
    FILE *fp = fopen("plaintext", "w");
    fwrite(plaintext, strlen(plaintext), 1, fp);
    fclose(fp);

    // create input+output w/ bad paths (should fail)
    assert_int_not_equal(RNP_SUCCESS, rnp_input_from_file(&input, "noexist"));
    assert_null(input);
    assert_int_not_equal(RNP_SUCCESS, rnp_output_to_file(&output, ""));
    assert_null(output);

    // create input+output
    assert_int_equal(RNP_SUCCESS, rnp_input_from_file(&input, "plaintext"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_file(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_create(&op, ffi, input, output));
    // add password (using all defaults)
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_password(op, "pass1", NULL, 0, NULL));
    // add password
    assert_int_equal(
      RNP_SUCCESS,
      rnp_op_encrypt_add_password(
        op, "pass2", "SM3", 12345, "Twofish"));
    // set the data encryption cipher
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_set_cipher(op, "CAST5"));
    // execute the operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_execute(op));

    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));

    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_input_destroy(input));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    input = NULL;
    output = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_destroy(op));
    op = NULL;

    /* decrypt */

    // decrypt (no pass provider, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_file(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_file(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    input = NULL;
    output = NULL;

    // decrypt (wrong pass, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_file(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_file(&output, "decrypted"));
    assert_non_null(output);
    char *pass = "wrong1";
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb_once, &pass));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    input = NULL;
    output = NULL;

    // decrypt (pass1)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_file(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_file(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, "pass1"));
    assert_int_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    // read in the decrypted file
    pgp_memory_t mem = {0};
    assert_true(pgp_mem_readfile(&mem, "decrypted"));
    // compare
    assert_int_equal(mem.length, strlen(plaintext));
    assert_true(memcmp(mem.buf, plaintext, strlen(plaintext)) == 0);
    // cleanup
    pgp_memory_release(&mem);
    unlink("decrypted");

    // decrypt (pass2)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_file(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_file(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, "pass2"));
    assert_int_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    // read in the decrypted file
    mem = (pgp_memory_t){0};
    assert_true(pgp_mem_readfile(&mem, "decrypted"));
    // compare
    assert_int_equal(mem.length, strlen(plaintext));
    assert_true(memcmp(mem.buf, plaintext, strlen(plaintext)) == 0);
    // cleanup
    pgp_memory_release(&mem);

    // final cleanup
    rnp_ffi_destroy(ffi);
}

void
test_ffi_encrypt_pk(void **state)
{
    // rnp_test_state_t *rstate = *state;
    rnp_ffi_t        ffi = NULL;
    rnp_keyring_t    pubring, secring;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *plaintext = "data1";

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_pubring(ffi, &pubring));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_get_secring(ffi, &secring));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS,
                     rnp_keyring_load_from_path(pubring, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS,
                     rnp_keyring_load_from_path(secring, "data/keyrings/1/secring.gpg"));

    // write out some data
    FILE *fp = fopen("plaintext", "w");
    fwrite(plaintext, strlen(plaintext), 1, fp);
    fclose(fp);

    // create input+output
    assert_int_equal(RNP_SUCCESS, rnp_input_from_file(&input, "plaintext"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_file(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_create(&op, ffi, input, output));
    // add recipients
    rnp_key_handle_t key = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "key0-uid2", &key));
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_recipient(op, key));
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "key1-uid1", &key));
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_recipient(op, key));
    // set the data encryption cipher
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_set_cipher(op, "CAST5"));
    // execute the operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_execute(op));

    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));

    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_input_destroy(input));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    input = NULL;
    output = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_destroy(op));
    op = NULL;

    /* decrypt */

    // decrypt (no pass provider, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_file(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_file(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    input = NULL;
    output = NULL;

    // decrypt (wrong pass, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_file(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_file(&output, "decrypted"));
    assert_non_null(output);
    char *pass = "wrong1";
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb_once, &pass));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    input = NULL;
    output = NULL;

    // decrypt
    assert_int_equal(RNP_SUCCESS, rnp_input_from_file(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_file(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, "password"));
    assert_int_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    // read in the decrypted file
    pgp_memory_t mem = {0};
    assert_true(pgp_mem_readfile(&mem, "decrypted"));
    // compare
    assert_int_equal(mem.length, strlen(plaintext));
    assert_true(memcmp(mem.buf, plaintext, strlen(plaintext)) == 0);
    // cleanup
    pgp_memory_release(&mem);

    // final cleanup
    rnp_ffi_destroy(ffi);
}
