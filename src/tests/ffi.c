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

    //printf("%s\n", exported_key);

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

    //printf("%s\n", ciphertext);

    uint8_t *decrypted;
    size_t   decrypted_len;
    result = rnp_decrypt(secring, ciphertext, ctext_len, &decrypted, &decrypted_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    rnp_assert_int_equal(rstate, decrypted_len, strlen(plaintext_message));
    for(size_t i = 0; i != decrypted_len; ++i)
       rnp_assert_int_equal(rstate, decrypted[i], plaintext_message[i]);

    rnp_buffer_free(decrypted);
    rnp_buffer_free(ciphertext);

    uint8_t *sig = NULL;
    size_t   sig_len = 0;

    /*
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

    uint8_t *recovered_msg;
    size_t   recovered_msg_len;
    result = rnp_verify(pubring, sig, sig_len, &recovered_msg, &recovered_msg_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    rnp_buffer_free(sig);
    */

    result = rnp_sign_detached(secring, test_userid, "SHA224", true,
                               (const uint8_t *) plaintext_message,
                               strlen(plaintext_message),
                               &sig, &sig_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    printf("%s\n", sig);

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
test_ffi_detect_key_format(void **state)
{
    rnp_test_state_t *rstate = *state;
    char *            data = NULL;
    size_t            data_size = 0;
    char *            format = NULL;

    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir, "keyrings/1/pubring.gpg", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);

    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir, "keyrings/1/secring.gpg", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);
    format = NULL;

    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir, "keyrings/3/pubring.kbx", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "KBX"));
    free(data);
    free(format);

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

    format = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) "ABC", 3, &format));
    assert_null(format);
}

static rnp_key_t
unused_getkeycb(void *      app_ctx,
                const char *identifier_type,
                const char *identifier,
                bool        secret)
{
    assert_true(false);
    return NULL;
}

typedef struct {
    rnp_keyring_t pubring;
    rnp_keyring_t secring;
} getkeycb_data_t;

static rnp_key_t
getkeycb(void *app_ctx, const char *identifier_type, const char *identifier, bool secret)
{
    const getkeycb_data_t *keyrings = app_ctx;
    rnp_key_t              found = NULL;
    rnp_keyring_t          kr = NULL;

    if (secret) {
        kr = keyrings->secring;
    } else {
        kr = keyrings->pubring;
    }
    if (rnp_keyring_find_key(kr, identifier_type, identifier, &found)) {
        assert_true(false);
        return NULL;
    }
    return found;
}

static int
unused_getpasscb(
  void *app_ctx, rnp_key_t key, const char *pgp_context, char *buf, size_t buf_len)
{
    assert_true(false);
    return 0;
}

static int
getpasscb(void *app_ctx, rnp_key_t key, const char *pgp_context, char *buf, size_t buf_len)
{
    strcpy(buf, (const char *) app_ctx);
    return 0;
}

static void
check_key_properties(rnp_key_t key, bool primary, bool secret)
{
    bool isprimary = !primary;
    assert_int_equal(RNP_SUCCESS, rnp_key_is_primary(key, &isprimary));
    assert_true(isprimary == primary);
    bool issub = primary;
    assert_int_equal(RNP_SUCCESS, rnp_key_is_sub(key, &issub));
    assert_true(issub == !primary);
    bool ispublic = secret;
    assert_int_equal(RNP_SUCCESS, rnp_key_is_public(key, &ispublic));
    assert_true(ispublic == !secret);
    bool issecret = !secret;
    assert_int_equal(RNP_SUCCESS, rnp_key_is_secret(key, &issecret));
    assert_true(issecret == secret);
}

void
test_ffi_keygen_json_pair(void **state)
{
    rnp_test_state_t *rstate = *state;
    rnp_keyring_t     pubring = NULL, secring = NULL;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;
    rnp_key_t         key;

    rnp_set_io(stdout, stderr, stdout);

    // create keyrings
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&pubring, "GPG", NULL));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&secring, "GPG", NULL));

    // load our JSON
    load_test_data(rstate->data_dir, "json/generate-pair.json", &json, NULL);

    // generate the keys
    assert_int_equal(
      RNP_SUCCESS,
      rnp_generate_key_json(
        pubring, secring, unused_getkeycb, NULL, unused_getpasscb, NULL, json, &results));
    free(json);
    json = NULL;
    assert_non_null(results);

    // make sure valid JSON was produced
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_free(results);
    json_object_put(parsed_results);

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(2, count);

    // check some key properties
    // primary pub
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(pubring, 0, &key));
    check_key_properties(key, true, false);
    rnp_key_free(&key);
    key = NULL;
    // sub pub
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(pubring, 1, &key));
    check_key_properties(key, false, false);
    rnp_key_free(&key);
    key = NULL;
    // primary sec
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(secring, 0, &key));
    check_key_properties(key, true, true);
    rnp_key_free(&key);
    key = NULL;
    // sub sec
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(secring, 1, &key));
    check_key_properties(key, false, true);
    rnp_key_free(&key);
    key = NULL;

    // cleanup
    rnp_keyring_destroy(&pubring);
    rnp_keyring_destroy(&secring);
}

void
test_ffi_keygen_json_primary(void **state)
{
    rnp_test_state_t *rstate = *state;
    rnp_keyring_t     pubring = NULL, secring = NULL;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;
    rnp_key_t         key;

    rnp_set_io(stdout, stderr, stdout);

    // create keyrings
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&pubring, "GPG", NULL));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&secring, "GPG", NULL));

    // load our JSON
    load_test_data(rstate->data_dir, "json/generate-primary.json", &json, NULL);

    // generate the keys
    assert_int_equal(
      RNP_SUCCESS,
      rnp_generate_key_json(
        pubring, secring, unused_getkeycb, NULL, unused_getpasscb, NULL, json, &results));
    assert_non_null(results);

    // make sure valid JSON was produced
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(1, count);

    // check some key properties
    // primary pub
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(pubring, 0, &key));
    check_key_properties(key, true, false);
    rnp_key_free(&key);
    key = NULL;
    // primary sec
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(secring, 0, &key));
    check_key_properties(key, true, true);
    rnp_key_free(&key);
    key = NULL;

    // cleanup
    json_object_put(parsed_results);
    rnp_buffer_free(results);
    free(json);
    rnp_keyring_destroy(&pubring);
    rnp_keyring_destroy(&secring);
}

// same ring
// diff ring
// req pass

/* This test generates a primary key, and then a subkey (in the same keyring).
 */
void
test_ffi_keygen_json_sub_same_ring(void **state)
{
    rnp_test_state_t *rstate = *state;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;
    rnp_keyring_t     pubring = NULL, secring = NULL;
    rnp_key_t         key = NULL;
    char *            primary_grip = NULL;

    rnp_set_io(stdout, stderr, stdout);

    // create keyrings
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&pubring, "GPG", NULL));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&secring, "GPG", NULL));

    // generate our primary key
    load_test_data(rstate->data_dir, "json/generate-primary.json", &json, NULL);
    assert_int_equal(
      RNP_SUCCESS,
      rnp_generate_key_json(
        pubring, secring, unused_getkeycb, NULL, unused_getpasscb, NULL, json, &results));
    free(json);
    assert_non_null(results);
    rnp_buffer_free(results);
    results = NULL;
    // check key counts
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(1, count);

    // retrieve the grip of the primary key, for later
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(pubring, 0, &key));
    assert_int_equal(RNP_SUCCESS, rnp_key_get_grip(key, &primary_grip));
    rnp_key_free(&key);
    key = NULL;

    // load our JSON
    load_test_data(rstate->data_dir, "json/generate-sub.json", &json, NULL);
    // modify our JSON
    json_object *jso = json_tokener_parse(json);
    free(json);
    json = NULL;
    json_object *jsosub;
    json_object *jsoprimary;
    assert_true(json_object_object_get_ex(jso, "subkey", &jsosub));
    assert_true(json_object_object_get_ex(jsosub, "primary", &jsoprimary));
    json_object_object_del(jsoprimary, "grip");
    json_object_object_add(jsoprimary, "grip", json_object_new_string(primary_grip));
    assert_int_equal(1, json_object_object_length(jsoprimary));
    json = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
    json_object_put(jso);
    rnp_key_free(&key);
    key = NULL;
    rnp_buffer_free(primary_grip);
    primary_grip = NULL;

    // generate the subkey
    assert_int_equal(
      RNP_SUCCESS,
      rnp_generate_key_json(
        pubring, secring, unused_getkeycb, NULL, unused_getpasscb, NULL, json, &results));
    free(json);
    json = NULL;
    assert_non_null(results);
    // make sure valid JSON was produced
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    json_object_put(parsed_results);
    parsed_results = NULL;
    rnp_buffer_free(results);
    results = NULL;

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(2, count);

    // check some key properties
    // primary pub
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(pubring, 0, &key));
    check_key_properties(key, true, false);
    rnp_key_free(&key);
    key = NULL;
    // primary sec
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(secring, 0, &key));
    check_key_properties(key, true, true);
    rnp_key_free(&key);
    key = NULL;
    // sub pub
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(pubring, 1, &key));
    check_key_properties(key, false, false);
    rnp_key_free(&key);
    key = NULL;
    // sub sec
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(secring, 1, &key));
    check_key_properties(key, false, true);
    rnp_key_free(&key);
    key = NULL;

    // cleanup
    rnp_keyring_destroy(&pubring);
    rnp_keyring_destroy(&secring);
}

void
test_ffi_keygen_json_sub_different_ring(void **state)
{
    rnp_test_state_t *rstate = *state;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;
    rnp_keyring_t     primary_pubring = NULL, primary_secring = NULL;
    rnp_keyring_t     pubring = NULL, secring = NULL;
    rnp_key_t         key = NULL;
    char *            primary_grip = NULL;

    rnp_set_io(stdout, stderr, stdout);

    // create keyrings
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&primary_pubring, "GPG", NULL));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&primary_secring, "GPG", NULL));

    // generate our primary key
    load_test_data(rstate->data_dir, "json/generate-primary.json", &json, NULL);
    assert_int_equal(RNP_SUCCESS,
                     rnp_generate_key_json(primary_pubring,
                                           primary_secring,
                                           unused_getkeycb,
                                           NULL,
                                           unused_getpasscb,
                                           NULL,
                                           json,
                                           &results));
    free(json);
    assert_non_null(results);
    rnp_buffer_free(results);
    results = NULL;
    // check key counts
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(primary_pubring, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(primary_secring, &count));
    assert_int_equal(1, count);

    // retrieve the grip of the primary key, for later
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(primary_pubring, 0, &key));
    assert_int_equal(RNP_SUCCESS, rnp_key_get_grip(key, &primary_grip));
    rnp_key_free(&key);
    key = NULL;

    // load our JSON
    load_test_data(rstate->data_dir, "json/generate-sub.json", &json, NULL);
    // modify our JSON
    json_object *jso = json_tokener_parse(json);
    free(json);
    json = NULL;
    json_object *jsosub;
    json_object *jsoprimary;
    assert_true(json_object_object_get_ex(jso, "subkey", &jsosub));
    assert_true(json_object_object_get_ex(jsosub, "primary", &jsoprimary));
    json_object_object_del(jsoprimary, "grip");
    json_object_object_add(jsoprimary, "grip", json_object_new_string(primary_grip));
    assert_int_equal(1, json_object_object_length(jsoprimary));
    json = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
    json_object_put(jso);
    rnp_key_free(&key);
    key = NULL;
    rnp_buffer_free(primary_grip);
    primary_grip = NULL;

    // create keyrings
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&pubring, "GPG", NULL));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&secring, "GPG", NULL));

    // generate the subkey (no getkeycb, should fail)
    assert_int_not_equal(
      RNP_SUCCESS,
      rnp_generate_key_json(
        pubring, secring, NULL, NULL, unused_getpasscb, NULL, json, &results));

    // generate the subkey
    assert_int_equal(RNP_SUCCESS,
                     rnp_generate_key_json(pubring,
                                           secring,
                                           getkeycb,
                                           &(getkeycb_data_t){.pubring = primary_pubring,
                                                              .secring = primary_secring},
                                           unused_getpasscb,
                                           NULL,
                                           json,
                                           &results));
    free(json);
    json = NULL;
    assert_non_null(results);
    // make sure valid JSON was produced
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    json_object_put(parsed_results);
    parsed_results = NULL;
    rnp_buffer_free(results);
    results = NULL;

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(1, count);

    // check some key properties
    // sub pub
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(pubring, 0, &key));
    check_key_properties(key, false, false);
    rnp_key_free(&key);
    key = NULL;
    // sub sec
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(secring, 0, &key));
    check_key_properties(key, false, true);
    rnp_key_free(&key);
    key = NULL;

    // cleanup
    rnp_keyring_destroy(&primary_pubring);
    rnp_keyring_destroy(&primary_secring);
    rnp_keyring_destroy(&pubring);
    rnp_keyring_destroy(&secring);
}

void
test_ffi_keygen_json_sub_pass_required(void **state)
{
    rnp_test_state_t *rstate = *state;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;
    rnp_keyring_t     primary_pubring = NULL, primary_secring = NULL;
    rnp_keyring_t     pubring = NULL, secring = NULL;
    rnp_key_t         key = NULL;
    char *            primary_grip = NULL;

    rnp_set_io(stdout, stderr, stdout);

    // create keyrings
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&primary_pubring, "GPG", NULL));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&primary_secring, "GPG", NULL));

    // generate our primary key
    load_test_data(rstate->data_dir, "json/generate-primary.json", &json, NULL);
    assert_int_equal(RNP_SUCCESS,
                     rnp_generate_key_json(primary_pubring,
                                           primary_secring,
                                           unused_getkeycb,
                                           NULL,
                                           unused_getpasscb,
                                           NULL,
                                           json,
                                           &results));
    free(json);
    assert_non_null(results);
    rnp_buffer_free(results);
    results = NULL;
    // check key counts
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(primary_pubring, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(primary_secring, &count));
    assert_int_equal(1, count);

    // retrieve the grip of the primary key, for later
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(primary_pubring, 0, &key));
    assert_int_equal(RNP_SUCCESS, rnp_key_get_grip(key, &primary_grip));
    rnp_key_free(&key);
    key = NULL;

    // protect+lock the primary key
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(primary_secring, 0, &key));
    assert_int_equal(RNP_SUCCESS, rnp_key_protect(key, "pass123"));
    assert_int_equal(RNP_SUCCESS, rnp_key_lock(key));
    rnp_key_free(&key);
    key = NULL;

    // load our JSON
    load_test_data(rstate->data_dir, "json/generate-sub.json", &json, NULL);
    // modify our JSON
    json_object *jso = json_tokener_parse(json);
    free(json);
    json = NULL;
    json_object *jsosub;
    json_object *jsoprimary;
    assert_true(json_object_object_get_ex(jso, "subkey", &jsosub));
    assert_true(json_object_object_get_ex(jsosub, "primary", &jsoprimary));
    json_object_object_del(jsoprimary, "grip");
    json_object_object_add(jsoprimary, "grip", json_object_new_string(primary_grip));
    assert_int_equal(1, json_object_object_length(jsoprimary));
    json = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
    json_object_put(jso);
    rnp_key_free(&key);
    key = NULL;
    rnp_buffer_free(primary_grip);
    primary_grip = NULL;

    // create keyrings
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&pubring, "GPG", NULL));
    assert_int_equal(RNP_SUCCESS, rnp_keyring_create(&secring, "GPG", NULL));

    // generate the subkey (no getkeycb, should fail)
    assert_int_not_equal(
      RNP_SUCCESS,
      rnp_generate_key_json(
        pubring, secring, NULL, NULL, unused_getpasscb, NULL, json, &results));

    // generate the subkey (no getpasscb, should fail)
    assert_int_not_equal(RNP_SUCCESS,
                         rnp_generate_key_json(pubring,
                                               secring,
                                               getkeycb,
                                               &(getkeycb_data_t){.pubring = primary_pubring,
                                                                  .secring = primary_secring},
                                               NULL,
                                               NULL,
                                               json,
                                               &results));

    // generate the subkey (wrong pass, should fail)
    assert_int_not_equal(RNP_SUCCESS,
                         rnp_generate_key_json(pubring,
                                               secring,
                                               getkeycb,
                                               &(getkeycb_data_t){.pubring = primary_pubring,
                                                                  .secring = primary_secring},
                                               getpasscb,
                                               "wrong",
                                               json,
                                               &results));

    // generate the subkey
    assert_int_equal(RNP_SUCCESS,
                     rnp_generate_key_json(pubring,
                                           secring,
                                           getkeycb,
                                           &(getkeycb_data_t){.pubring = primary_pubring,
                                                              .secring = primary_secring},
                                           getpasscb,
                                           "pass123",
                                           json,
                                           &results));
    free(json);
    json = NULL;
    assert_non_null(results);
    // make sure valid JSON was produced
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    json_object_put(parsed_results);
    parsed_results = NULL;
    rnp_buffer_free(results);
    results = NULL;

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(pubring, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_count(secring, &count));
    assert_int_equal(1, count);

    // check some key properties
    // sub pub
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(pubring, 0, &key));
    check_key_properties(key, false, false);
    rnp_key_free(&key);
    key = NULL;
    // sub sec
    assert_int_equal(RNP_SUCCESS, rnp_keyring_get_key_at(secring, 0, &key));
    check_key_properties(key, false, true);
    rnp_key_free(&key);
    key = NULL;

    // cleanup
    rnp_keyring_destroy(&primary_pubring);
    rnp_keyring_destroy(&primary_secring);
    rnp_keyring_destroy(&pubring);
    rnp_keyring_destroy(&secring);
}
