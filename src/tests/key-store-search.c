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

#include "../librekey/key_store_pgp.h"
#include "pgp-key.h"
#include "utils.h"

#include "rnp_tests.h"
#include "support.h"

/* This test adds some fake keys to a key store and tests some of
 * the search functions.
 */
void
test_key_store_search(void **state)
{
    pgp_io_t io = {.errs = stderr, .res = stdout, .outs = stdout};

    // create our store
    rnp_key_store_t *store = rnp_key_store_new("GPG", "");
    assert_non_null(store);

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

            key.type = PGP_PTAG_CT_PUBLIC_KEY;
            key.key.pubkey.version = 4;

            // set the keyid
            assert_true(rnp_hex_decode(testdata[i].keyid, key.keyid, sizeof(key.keyid)));
            // set the userids
            for (size_t uidn = 0; testdata[i].userids[uidn]; uidn++) {
                const char *userid = testdata[i].userids[uidn];
                assert_true(pgp_add_userid(&key, (const uint8_t *) userid));
            }
            // add to the store
            assert_true(rnp_key_store_add_key(&io, store, &key));
        }
    }

    // keyid search
    for (size_t i = 0; i < ARRAY_SIZE(testdata); i++) {
        uint8_t keyid[PGP_KEY_ID_SIZE];
        assert_true(rnp_hex_decode(testdata[i].keyid, keyid, sizeof(keyid)));
        list seen_keys = NULL;
        for (pgp_key_t *key = rnp_key_store_get_key_by_id(&io, store, keyid, NULL, NULL); key;
             key = rnp_key_store_get_key_by_id(&io, store, keyid, key, NULL)) {
            // check that the keyid actually matches
            assert_int_equal(0, memcmp(key->keyid, keyid, PGP_KEY_ID_SIZE));
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
        key = rnp_key_store_get_key_by_name(&io, store, testdata[i].keyid, NULL);
        while (key) {
            // check that the keyid actually matches
            uint8_t expected_keyid[PGP_KEY_ID_SIZE];
            assert_true(
              rnp_hex_decode(testdata[i].keyid, expected_keyid, sizeof(expected_keyid)));
            assert_int_equal(0, memcmp(key->keyid, expected_keyid, PGP_KEY_ID_SIZE));
            // check that we have not already encountered this key pointer
            assert_null(list_find(seen_keys, &key, sizeof(key)));
            // keep track of what key pointers we have seen
            assert_non_null(list_append(&seen_keys, &key, sizeof(key)));

            // this only returns false on error, regardless of whether it found a match
            key = rnp_key_store_get_key_by_name(&io, store, testdata[i].keyid, key);
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
            key = rnp_key_store_get_key_by_name(&io, store, userid, NULL);
            while (key) {
                // check that the userid actually matches
                bool found = false;
                for (unsigned j = 0; j < key->uidc; j++) {
                    if (!strcmp((char *) key->uids[j], userid)) {
                        found = true;
                    }
                }
                assert_true(found);
                // check that we have not already encountered this key pointer
                assert_null(list_find(seen_keys, &key, sizeof(key)));
                // keep track of what key pointers we have seen
                assert_non_null(list_append(&seen_keys, &key, sizeof(key)));

                key = rnp_key_store_get_key_by_name(&io, store, testdata[i].keyid, key);
            }
            // check the count
            assert_int_equal(list_length(seen_keys), testdata[i].count);
            // cleanup
            list_destroy(&seen_keys);
        }
    }

    // userid search (regex)
    {
        list        seen_keys = NULL;
        pgp_key_t * key = NULL;
        const char *userid = "user1-.*";
        key = rnp_key_store_get_key_by_name(&io, store, userid, NULL);
        while (key) {
            // check that we have not already encountered this key pointer
            assert_null(list_find(seen_keys, &key, sizeof(key)));
            // keep track of what key pointers we have seen
            assert_non_null(list_append(&seen_keys, &key, sizeof(key)));

            key = rnp_key_store_get_key_by_name(&io, store, userid, key);
        }
        // check the count
        assert_int_equal(list_length(seen_keys), 3);
        // cleanup
        list_destroy(&seen_keys);
    }

    // cleanup
    rnp_key_store_free(store);
}
