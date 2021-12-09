/*
 * Copyright (c) 2017-2020 [Ribose Inc](https://www.ribose.com).
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

#include <algorithm>
#include <set>
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
    rnp_key_store_t *store = new rnp_key_store_t(PGP_KEY_STORE_GPG, "");
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
            pgp_key_t key;

            key.pkt().tag = PGP_PKT_PUBLIC_KEY;
            key.pkt().version = PGP_V4;
            key.pkt().alg = PGP_PKA_RSA;

            // set the keyid
            assert_true(rnp::hex_decode(
              testdata[i].keyid, (uint8_t *) key.keyid().data(), key.keyid().size()));
            // keys should have different grips otherwise rnp_key_store_add_key will fail here
            pgp_key_grip_t &grip = (pgp_key_grip_t &) key.grip();
            assert_true(rnp::hex_decode(testdata[i].keyid, grip.data(), grip.size()));
            grip[0] = (uint8_t) n;
            // and fingerprint
            pgp_fingerprint_t &fp = (pgp_fingerprint_t &) key.fp();
            assert_true(
              rnp::hex_decode(testdata[i].keyid, fp.fingerprint, PGP_FINGERPRINT_SIZE));
            fp.fingerprint[0] = (uint8_t) n;
            fp.length = PGP_FINGERPRINT_SIZE;
            // set the userids
            for (size_t uidn = 0; testdata[i].userids[uidn]; uidn++) {
                pgp_transferable_userid_t tuid;
                tuid.uid.tag = PGP_PKT_USER_ID;
                tuid.uid.uid_len = strlen(testdata[i].userids[uidn]);
                tuid.uid.uid = (uint8_t *) malloc(tuid.uid.uid_len);
                assert_non_null(tuid.uid.uid);
                memcpy(tuid.uid.uid, testdata[i].userids[uidn], tuid.uid.uid_len);
                key.add_uid(tuid);
            }
            // add to the store
            assert_true(rnp_key_store_add_key(store, &key));
        }
    }

    // keyid search
    for (size_t i = 0; i < ARRAY_SIZE(testdata); i++) {
        pgp_key_id_t keyid = {};
        assert_true(rnp::hex_decode(testdata[i].keyid, keyid.data(), keyid.size()));
        std::set<pgp_key_t *> seen_keys;
        for (pgp_key_t *key = rnp_key_store_get_key_by_id(store, keyid, NULL); key;
             key = rnp_key_store_get_key_by_id(store, keyid, key)) {
            // check that the keyid actually matches
            assert_true(key->keyid() == keyid);
            // check that we have not already encountered this key pointer
            assert_int_equal(seen_keys.count(key), 0);
            // keep track of what key pointers we have seen
            seen_keys.insert(key);
        }
        assert_int_equal(seen_keys.size(), testdata[i].count);
    }
    // keyid search (by_name)
    for (size_t i = 0; i < ARRAY_SIZE(testdata); i++) {
        std::set<pgp_key_t *> seen_keys;
        pgp_key_t *           key = NULL;
        key = rnp_tests_get_key_by_id(store, testdata[i].keyid, NULL);
        while (key) {
            // check that the keyid actually matches
            pgp_key_id_t expected_keyid = {};
            assert_true(rnp::hex_decode(
              testdata[i].keyid, expected_keyid.data(), expected_keyid.size()));
            assert_true(key->keyid() == expected_keyid);
            // check that we have not already encountered this key pointer
            assert_int_equal(seen_keys.count(key), 0);
            // keep track of what key pointers we have seen
            seen_keys.insert(key);
            // this only returns false on error, regardless of whether it found a match
            key = rnp_tests_get_key_by_id(store, testdata[i].keyid, key);
        }
        // check the count
        assert_int_equal(seen_keys.size(), testdata[i].count);
    }

    // userid search (literal)
    for (auto &key : store->keys) {
        for (size_t i = 0; i < key.uid_count(); i++) {
            key.get_uid(i).valid = true;
        }
    }
    for (size_t i = 0; i < ARRAY_SIZE(testdata); i++) {
        for (size_t uidn = 0; testdata[i].userids[uidn]; uidn++) {
            std::set<pgp_key_t *> seen_keys;
            const std::string     userid = testdata[i].userids[uidn];
            pgp_key_t *           key = rnp_tests_key_search(store, userid);
            while (key) {
                // check that the userid actually matches
                bool found = false;
                for (unsigned j = 0; j < key->uid_count(); j++) {
                    if (key->get_uid(j).str == userid) {
                        found = true;
                    }
                }
                assert_true(found);
                // check that we have not already encountered this key pointer
                assert_int_equal(seen_keys.count(key), 0);
                // keep track of what key pointers we have seen
                seen_keys.insert(key);
                key = rnp_tests_get_key_by_id(store, testdata[i].keyid, key);
            }
            // check the count
            assert_int_equal(seen_keys.size(), testdata[i].count);
        }
    }

    // cleanup
    delete store;
}

TEST_F(rnp_tests, test_key_store_search_by_name)
{
    const pgp_key_t *key;
    pgp_key_t *      primsec;
    pgp_key_t *      subsec;
    pgp_key_t *      primpub;
    pgp_key_t *      subpub;

    // load pubring
    rnp_key_store_t *pub_store =
      new rnp_key_store_t(PGP_KEY_STORE_KBX, "data/keyrings/3/pubring.kbx");
    assert_true(rnp_key_store_load_from_path(pub_store, NULL));
    // load secring
    rnp_key_store_t *sec_store =
      new rnp_key_store_t(PGP_KEY_STORE_G10, "data/keyrings/3/private-keys-v1.d");
    pgp_key_provider_t key_provider = {.callback = rnp_key_provider_store,
                                       .userdata = pub_store};
    assert_true(rnp_key_store_load_from_path(sec_store, &key_provider));

    /* Main key fingerprint and id:
       4F2E62B74E6A4CD333BC19004BE147BB22DF1E60, 4BE147BB22DF1E60
       Subkey fingerprint and id:
       10793E367EE867C32E358F2AA49BAE05C16E8BC8, A49BAE05C16E8BC8
    */

    /* Find keys and subkeys by fingerprint, id and userid */
    primsec = rnp_tests_get_key_by_fpr(sec_store, "4F2E62B74E6A4CD333BC19004BE147BB22DF1E60");
    assert_non_null(primsec);
    key = rnp_tests_get_key_by_id(sec_store, "4BE147BB22DF1E60", NULL);
    assert_true(key == primsec);
    subsec = rnp_tests_get_key_by_fpr(sec_store, "10793E367EE867C32E358F2AA49BAE05C16E8BC8");
    assert_non_null(subsec);
    assert_true(primsec != subsec);
    key = rnp_tests_get_key_by_id(sec_store, "A49BAE05C16E8BC8", NULL);
    assert_true(key == subsec);

    primpub = rnp_tests_get_key_by_fpr(pub_store, "4F2E62B74E6A4CD333BC19004BE147BB22DF1E60");
    assert_non_null(primpub);
    assert_true(primsec != primpub);
    subpub = rnp_tests_get_key_by_fpr(pub_store, "10793E367EE867C32E358F2AA49BAE05C16E8BC8");
    assert_true(primpub != subpub);
    assert_true(subpub != subsec);
    key = rnp_tests_key_search(pub_store, "test1");
    assert_true(key == primpub);

    /* Try other searches */
    key = rnp_tests_get_key_by_fpr(sec_store, "4f2e62b74e6a4cd333bc19004be147bb22df1e60");
    assert_true(key == primsec);
    key = rnp_tests_get_key_by_fpr(sec_store, "0x4f2e62b74e6a4cd333bc19004be147bb22df1e60");
    assert_true(key == primsec);
    key = rnp_tests_get_key_by_id(pub_store, "4BE147BB22DF1E60", NULL);
    assert_true(key == primpub);
    key = rnp_tests_get_key_by_id(pub_store, "4be147bb22df1e60", NULL);
    assert_true(key == primpub);
    key = rnp_tests_get_key_by_id(pub_store, "0x4be147bb22df1e60", NULL);
    assert_true(key == primpub);
    key = rnp_tests_get_key_by_id(pub_store, "22df1e60", NULL);
    assert_true(key == primpub);
    key = rnp_tests_get_key_by_id(pub_store, "0x22df1e60", NULL);
    assert_true(key == primpub);
    key = rnp_tests_get_key_by_id(pub_store, "4be1 47bb 22df 1e60", NULL);
    assert_true(key == primpub);
    key = rnp_tests_get_key_by_id(pub_store, "4be147bb 22df1e60", NULL);
    assert_true(key == primpub);
    key = rnp_tests_get_key_by_id(pub_store, "    4be147bb\t22df1e60   ", NULL);
    assert_true(key == primpub);
    key = rnp_tests_get_key_by_id(pub_store, "test1", NULL);
    assert_null(key);
    /* Try negative searches */
    assert_null(rnp_tests_get_key_by_fpr(sec_store, "4f2e62b74e6a4cd333bc19004be147bb22df1e"));
    assert_null(rnp_tests_get_key_by_fpr(sec_store, "2e62b74e6a4cd333bc19004be147bb22df1e60"));
    assert_null(rnp_tests_get_key_by_id(sec_store, "4be147bb22dfle60", NULL));
    assert_null(rnp_tests_get_key_by_id(sec_store, "", NULL));
    assert_null(rnp_tests_get_key_by_id(sec_store, "test11", NULL));
    assert_null(rnp_tests_get_key_by_id(sec_store, "atest1", NULL));

    // cleanup
    delete pub_store;
    delete sec_store;
}
