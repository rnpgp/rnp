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

#include "../librekey/key_store_pgp.h"
#include "pgp-key.h"

#include "rnp_tests.h"
#include "support.h"

/* This test adds some fake keys to a key store and tests some of
 * the search functions.
 */
TEST_F(rnp_tests, test_key_store_search)
{
    // create our store
    rnp_key_store_t *store = rnp_key_store_new("GPG", "");
    assert_non_null(store);
    store->disable_validation = true;

    // some fake key data
    static const struct {
        const char *keyid;
        size_t      count;      // number of keys like this to add to the store
        const char *userids[5]; // NULL terminator required on array and strings
    } testdata[] = {{"000000000000AAAA", 1, {"user1-1", NULL}},
                    {"000000000000BBBB", 2, {"user2", "user1-2", NULL}},
                    {"000000000000CCCC", 1, {"user3", NULL}},
                    {"FFFFFFFFFFFFFFFF", 0, {NULL}}};
    // add our fake test keys
    for (size_t i = 0; i < ARRAY_SIZE(testdata); i++) {
        for (size_t n = 0; n < testdata[i].count; n++) {
            pgp_key_t key = {0};

            key.pkt.tag = PGP_PTAG_CT_PUBLIC_KEY;
            key.pkt.version = PGP_V4;

            // set the keyid
            assert_true(rnp_hex_decode(testdata[i].keyid, key.keyid, sizeof(key.keyid)));
            // keys should have different grips otherwise rnp_key_store_add_key will fail here
            assert_true(rnp_hex_decode(testdata[i].keyid, key.grip, sizeof(key.grip)));
            key.grip[0] = (uint8_t) n;
            // set the userids
            for (size_t uidn = 0; testdata[i].userids[uidn]; uidn++) {
                const char *userid = testdata[i].userids[uidn];
                assert_true(pgp_key_add_userid(&key, (const uint8_t *) userid));
            }
            // add to the store
            assert_true(rnp_key_store_add_key(store, &key));
        }
    }

    // keyid search
    for (size_t i = 0; i < ARRAY_SIZE(testdata); i++) {
        uint8_t keyid[PGP_KEY_ID_SIZE];
        assert_true(rnp_hex_decode(testdata[i].keyid, keyid, sizeof(keyid)));
        list seen_keys = NULL;
        for (pgp_key_t *key = rnp_key_store_get_key_by_id(store, keyid, NULL); key;
             key = rnp_key_store_get_key_by_id(store, keyid, key)) {
            // check that the keyid actually matches
            assert_int_equal(0, memcmp(pgp_key_get_keyid(key), keyid, PGP_KEY_ID_SIZE));
            // check that we have not already encountered this key pointer
            assert_null(list_find(seen_keys, &key, sizeof(key)));
            // keep track of what key pointers we have seen
            assert_non_null(list_append(&seen_keys, &key, sizeof(key)));
        }
        assert_int_equal(list_length(seen_keys), testdata[i].count);
        list_destroy(&seen_keys);
    }
    // keyid search (by_name)
    for (size_t i = 0; i < ARRAY_SIZE(testdata); i++) {
        list       seen_keys = NULL;
        pgp_key_t *key = NULL;
        key = rnp_tests_get_key_by_id(store, testdata[i].keyid, NULL);
        while (key) {
            // check that the keyid actually matches
            uint8_t expected_keyid[PGP_KEY_ID_SIZE];
            assert_true(
              rnp_hex_decode(testdata[i].keyid, expected_keyid, sizeof(expected_keyid)));
            assert_int_equal(0,
                             memcmp(pgp_key_get_keyid(key), expected_keyid, PGP_KEY_ID_SIZE));
            // check that we have not already encountered this key pointer
            assert_null(list_find(seen_keys, &key, sizeof(key)));
            // keep track of what key pointers we have seen
            assert_non_null(list_append(&seen_keys, &key, sizeof(key)));

            // this only returns false on error, regardless of whether it found a match
            key = rnp_tests_get_key_by_id(store, testdata[i].keyid, key);
        }
        // check the count
        assert_int_equal(list_length(seen_keys), testdata[i].count);
        // cleanup
        list_destroy(&seen_keys);
    }

    // userid search (literal)
    for (size_t i = 0; i < ARRAY_SIZE(testdata); i++) {
        for (size_t uidn = 0; testdata[i].userids[uidn]; uidn++) {
            list        seen_keys = NULL;
            pgp_key_t * key = NULL;
            const char *userid = testdata[i].userids[uidn];
            key = rnp_tests_key_search(store, userid, NULL);
            while (key) {
                // check that the userid actually matches
                bool found = false;
                for (unsigned j = 0; j < pgp_key_get_userid_count(key); j++) {
                    if (!strcmp(pgp_key_get_userid(key, j), userid)) {
                        found = true;
                    }
                }
                assert_true(found);
                // check that we have not already encountered this key pointer
                assert_null(list_find(seen_keys, &key, sizeof(key)));
                // keep track of what key pointers we have seen
                assert_non_null(list_append(&seen_keys, &key, sizeof(key)));

                key = rnp_tests_get_key_by_id(store, testdata[i].keyid, key);
            }
            // check the count
            assert_int_equal(list_length(seen_keys), testdata[i].count);
            // cleanup
            list_destroy(&seen_keys);
        }
    }

#ifdef RNP_KEY_STORE_SEARCH_REGEX
    // userid search (regex)
    {
        list        seen_keys = NULL;
        pgp_key_t * key = NULL;
        const char *userid = "user1-.*";
        key = rnp_key_store_get_key_by_name(store, userid, NULL);
        while (key) {
            // check that we have not already encountered this key pointer
            assert_null(list_find(seen_keys, &key, sizeof(key)));
            // keep track of what key pointers we have seen
            assert_non_null(list_append(&seen_keys, &key, sizeof(key)));

            key = rnp_key_store_get_key_by_name(store, userid, key);
        }
        // check the count
        assert_int_equal(list_length(seen_keys), 3);
        // cleanup
        list_destroy(&seen_keys);
    }
#endif //RNP_KEY_STORE_SEARCH_REGEX

    // cleanup
    rnp_key_store_free(store);
}

TEST_F(rnp_tests, test_key_store_search_by_name)
{
    const pgp_key_t *key;
    pgp_key_t *      primsec;
    pgp_key_t *      subsec;
    pgp_key_t *      primpub;
    pgp_key_t *      subpub;

    // load pubring
    rnp_key_store_t *pub_store = rnp_key_store_new("KBX", "data/keyrings/3/pubring.kbx");
    assert_non_null(pub_store);
    assert_true(rnp_key_store_load_from_path(pub_store, NULL));
    // load secring
    rnp_key_store_t *sec_store = rnp_key_store_new("G10", "data/keyrings/3/private-keys-v1.d");
    assert_non_null(sec_store);
    pgp_key_provider_t key_provider = {.callback = rnp_key_provider_store,
                                       .userdata = pub_store};
    assert_true(rnp_key_store_load_from_path(sec_store, &key_provider));

    /* Main key fingerprint and id:
       4F2E62B74E6A4CD333BC19004BE147BB22DF1E60, 4BE147BB22DF1E60
       Subkey fingerprint and id:
       10793E367EE867C32E358F2AA49BAE05C16E8BC8, A49BAE05C16E8BC8
    */

    /* Find keys and subkeys by fingerprint, id and userid */
    primsec = rnp_tests_get_key_by_fpr(
      sec_store, "4F2E62B74E6A4CD333BC19004BE147BB22DF1E60", NULL);
    assert_non_null(primsec);
    key = rnp_tests_get_key_by_id(sec_store, "4BE147BB22DF1E60", NULL);
    assert_true(key == primsec);
    subsec = rnp_tests_get_key_by_fpr(
      sec_store, "10793E367EE867C32E358F2AA49BAE05C16E8BC8", NULL);
    assert_non_null(subsec);
    assert_true(primsec != subsec);
    key = rnp_tests_get_key_by_id(sec_store, "A49BAE05C16E8BC8", NULL);
    assert_true(key == subsec);

    primpub = rnp_tests_get_key_by_fpr(
      pub_store, "4F2E62B74E6A4CD333BC19004BE147BB22DF1E60", NULL);
    assert_non_null(primpub);
    assert_true(primsec != primpub);
    subpub = rnp_tests_get_key_by_fpr(
      pub_store, "10793E367EE867C32E358F2AA49BAE05C16E8BC8", NULL);
    assert_true(primpub != subpub);
    assert_true(subpub != subsec);
    key = rnp_tests_key_search(pub_store, "test1", NULL);
    assert_true(key == primpub);

    /* Try other searches */
    key = rnp_tests_get_key_by_fpr(
      sec_store, "4f2e62b74e6a4cd333bc19004be147bb22df1e60", NULL);
    assert_true(key = primsec);
    key = rnp_tests_get_key_by_fpr(
      sec_store, "0x4f2e62b74e6a4cd333bc19004be147bb22df1e60", NULL);
    assert_true(key = primsec);
    key = rnp_tests_get_key_by_id(pub_store, "4BE147BB22DF1E60", NULL);
    assert_true(key = primsec);
    key = rnp_tests_get_key_by_id(pub_store, "4be147bb22df1e60", NULL);
    assert_true(key = primsec);
    key = rnp_tests_get_key_by_id(pub_store, "0x4be147bb22df1e60", NULL);
    assert_true(key = primsec);
    key = rnp_tests_get_key_by_id(pub_store, "22df1e60", NULL);
    assert_true(key = primsec);
    key = rnp_tests_get_key_by_id(pub_store, "0x22df1e60", NULL);
    assert_true(key = primsec);
    key = rnp_tests_get_key_by_id(pub_store, "4be1 47bb 22df 1e60", NULL);
    assert_true(key = primsec);
    key = rnp_tests_get_key_by_id(pub_store, "4be147bb 22df1e60", NULL);
    assert_true(key = primsec);
    key = rnp_tests_get_key_by_id(pub_store, "    4be147bb\t22df1e60   ", NULL);
    assert_true(key = primsec);
    key = rnp_tests_get_key_by_id(pub_store, "test1", NULL);
    assert_true(key = primsec);
    /* Try negative searches */
    assert_null(rnp_tests_get_key_by_fpr(
      sec_store, "4f2e62b74e6a4cd333bc19004be147bb22df1e", NULL));
    assert_null(rnp_tests_get_key_by_fpr(
      sec_store, "2e62b74e6a4cd333bc19004be147bb22df1e60", NULL));
    assert_null(rnp_tests_get_key_by_id(sec_store, "4be147bb22dfle60", NULL));
    assert_null(rnp_tests_get_key_by_id(sec_store, "", NULL));
    assert_null(rnp_tests_get_key_by_id(sec_store, "test11", NULL));
    assert_null(rnp_tests_get_key_by_id(sec_store, "atest1", NULL));

    // cleanup
    rnp_key_store_free(pub_store);
    rnp_key_store_free(sec_store);
}
