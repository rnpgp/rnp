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

const char *test_pub_key =
  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
  "Version: rnp 0.8.0~\n"
  "\n"
  "xo0EWcpWwgEEALrh0ia9CTSLFT1mtASffG6MGWaewji/B4A/7CnNLdn4SM7qBVWtEdBxUIiKw3RO\n"
  "Mcddaewm554hLDn6+MKmOwr+y3zCRKbqwnj0FZpMDjo5Lh6rvXEXmLujnW1cz5iYW6YIdS207W3D\n"
  "rX0drR8vziMht0Z04cu2/dYJBTZsnek9ABEBAAHNC1Rlc3QgdXNlcmlkwrUEEwECACkFAlnKVsIC\n"
  "Gy8CGQEFCwkIBwIGFQgJCgsCBRYCAwEACRC+8H1ZgunpnAAAFEsD/3MOlBh/9ZbLGy7r1B3+wL5u\n"
  "liBwp+3wbnmLtTMySxwHHzVeL66+6PVDWr/ovAcBiIAAdvzg0ofEoo/dw2MvYaavY7mBuQyydRU/\n"
  "MCvFRmdxCMzCm7R3EjqWC1cRQJ2I00jhT1hb8TDQ5lZ3cB8MFjdtQ14AU3hiHOoqFWtX8/vP\n"
  "=iWmK\n"
  "-----END PGP PUBLIC KEY BLOCK-----\n";

void
test_ffi_api(void **state)
{
    rnp_test_state_t *rstate = *state;

    rnp_set_io(stdout, stderr, stdout);

    // FIXME
    const char *test_userid = "Test userid";
    const char *sec_path = "/tmp/secring";
    const char *pub_path = "/tmp/pubring";
    const char *plaintext_message = "Hi there\n";

    rnp_keyring_t secring = NULL, pubring = NULL;
    rnp_result_t  result;

    result = rnp_keyring_create(&pubring, "GPG", pub_path);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    result = rnp_keyring_create(&secring, "GPG", sec_path);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    rnp_key_t pubkey, seckey;

    result = rnp_generate_private_key(
      &pubkey, &seckey, pubring, secring, test_userid, "my secret pass", "SHA1");
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    rnp_key_t restored;
    result = rnp_keyring_find_key(pubring, "userid", test_userid, &restored);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    char * exported_key = NULL;
    size_t exported_key_len = 0;
    result = rnp_export_public_key(restored, 1, &exported_key, &exported_key_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    printf("%s\n", exported_key);

    uint8_t *ciphertext = NULL;
    size_t   ctext_len = 0;

    const char *const recipients[1] = {test_userid};
    result = rnp_encrypt(pubring,
                         recipients,
                         1,
                         "AES-128",
                         "zlib",
                         6,
                         true,
                         (const uint8_t *) plaintext_message,
                         strlen(plaintext_message),
                         &ciphertext,
                         &ctext_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    printf("%s\n", ciphertext);

    uint8_t *decrypted;
    size_t   decrypted_len;
    result = rnp_decrypt(secring, ciphertext, ctext_len, &decrypted, &decrypted_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    printf("Decrypted=");
    for (size_t i = 0; i != decrypted_len; ++i)
        printf("%c", decrypted[i]);
    printf("\n");

    rnp_buffer_free(decrypted);
    rnp_buffer_free(ciphertext);

    uint8_t *sig = NULL;
    size_t   sig_len = 0;
    result = rnp_sign(secring,
                      test_userid,
                      "SHA256",
                      false,
                      true,
                      (const uint8_t *) plaintext_message,
                      strlen(plaintext_message),
                      &sig,
                      &sig_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    printf("%s\n", sig);

    uint8_t *recovered_msg;
    size_t   recovered_msg_len;
    result = rnp_verify(pubring, sig, sig_len, &recovered_msg, &recovered_msg_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    // result = rnp_insert_armored_public_key(keyring, test_pub_key);
    // rnp_assert_int_equal(rstate, result, RNP_SUCCESS);
    // TODO test the key we just loaded (eg verify a signature)

    rnp_keyring_destroy(&pubring);
    rnp_keyring_destroy(&secring);
}

void
test_ffi_homedir(void **state)
{
    rnp_test_state_t *rstate = *state;

    char * homedir = NULL;
    size_t homedir_size = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_default_homedir(&homedir));
    assert_non_null(homedir);
    rnp_buffer_free(homedir);
    homedir = NULL;

    char *        pub_format = NULL;
    char *        sec_format = NULL;
    rnp_keyring_t pubring, secring;
    assert_true(
      rnp_compose_path_ex(&homedir, &homedir_size, rstate->data_dir, "keyrings/1", NULL));

    assert_int_equal(RNP_SUCCESS,
                     rnp_detect_homedir_formats(homedir, &pub_format, &sec_format));
    assert_int_equal(0, strcmp(pub_format, "GPG"));
    assert_int_equal(0, strcmp(sec_format, "GPG"));
    assert_int_equal(
      RNP_SUCCESS,
      rnp_keyring_load_homedir(homedir, pub_format, sec_format, &pubring, &secring));
    rnp_buffer_free(pub_format);
    rnp_buffer_free(sec_format);
    size_t count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(7, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(7, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_destroy(&pubring));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_destroy(&secring));

    assert_true(
      rnp_compose_path_ex(&homedir, &homedir_size, rstate->data_dir, "keyrings/3", NULL));
    assert_int_equal(RNP_SUCCESS,
                     rnp_detect_homedir_formats(homedir, &pub_format, &sec_format));
    assert_int_equal(0, strcmp(pub_format, "KBX"));
    assert_int_equal(0, strcmp(sec_format, "G10"));
    assert_int_equal(
      RNP_SUCCESS,
      rnp_keyring_load_homedir(homedir, pub_format, sec_format, &pubring, &secring));
    rnp_buffer_free(pub_format);
    rnp_buffer_free(sec_format);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(2, count);
    rnp_key_t key = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(secring, 0, &key));
    assert_non_null(key);
    char *grip = NULL;
    rnp_key_get_grip(key, &grip);
    assert_non_null(grip);
    assert_true(strcmp(grip, "63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59") == 0 ||
                strcmp(grip, "7EAB41A2F46257C36F2892696F5A2F0432499AD3") == 0);
    rnp_buffer_free(grip);
    rnp_key_free(&key);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(secring, 1, &key));
    assert_non_null(key);
    grip = NULL;
    rnp_key_get_grip(key, &grip);
    assert_non_null(grip);
    assert_true(strcmp(grip, "63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59") == 0 ||
                strcmp(grip, "7EAB41A2F46257C36F2892696F5A2F0432499AD3") == 0);
    rnp_buffer_free(grip);
    rnp_key_free(&key);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_destroy(&pubring));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_destroy(&secring));

    // cleanup
    free(homedir);
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
test_ffi_keygen_json(void **state)
{
    rnp_test_state_t *rstate = *state;
    rnp_keyring_t     secring = NULL, pubring = NULL;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;

    rnp_set_io(stdout, stderr, stdout);

    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&pubring, "GPG", NULL));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&secring, "GPG", NULL));
    load_test_data(rstate->data_dir, "json/generate-pair.json", &json, NULL);
    assert_int_equal(
      RNP_SUCCESS, rnp_generate_key_json(pubring, secring, NULL, NULL, NULL, json, &results));
    free(json);
    assert_non_null(results);
    printf("%s\n", results);
    rnp_buffer_free(results);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(2, count);
    rnp_keyring_destroy(&pubring);
    rnp_keyring_destroy(&secring);

    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&pubring, "GPG", NULL));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&secring, "GPG", NULL));
    load_test_data(rstate->data_dir, "json/generate-primary.json", &json, NULL);
    assert_int_equal(
      RNP_SUCCESS, rnp_generate_key_json(pubring, secring, NULL, NULL, NULL, json, &results));
    free(json);
    assert_non_null(results);
    printf("%s\n", results);
    rnp_buffer_free(results);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(1, count);
    char *    primary_grip;
    rnp_key_t key;
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(pubring, 0, &key));
    assert_int_equal(RNP_SUCCESS, rnp_key_get_grip(key, &primary_grip));

    load_test_data(rstate->data_dir, "json/generate-sub.json", &json, NULL);
    json_object *jso = json_tokener_parse(json);
    json_object *jsosub;
    json_object *jsoprimary;
    assert_true(json_object_object_get_ex(jso, "subkey", &jsosub));
    assert_true(json_object_object_get_ex(jsosub, "primary", &jsoprimary));
    json_object_object_del(jsoprimary, "grip");
    json_object_object_add(jsoprimary, "grip", json_object_new_string(primary_grip));
    json = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
    json_object_put(jso);
    rnp_key_free(&key);
    rnp_buffer_free(primary_grip);
    //
    assert_int_equal(
      RNP_SUCCESS, rnp_generate_key_json(pubring, secring, NULL, NULL, NULL, json, &results));
    free(json);
    assert_non_null(results);
    printf("%s\n", results);
    rnp_buffer_free(results);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(2, count);

    rnp_keyring_destroy(&pubring);
    rnp_keyring_destroy(&secring);
}
