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

#include <rnp/rnp.h>
#include <rekey/rnp_key_store.h>
#include "rnp_tests.h"
#include "support.h"
#include "utils.h"
#include "pgp-key.h"

static const pgp_subsig_t *
find_subsig(const pgp_key_t *key, const char *userid)
{
    // find the userid index
    int uididx = -1;
    for (unsigned i = 0; i < pgp_get_userid_count(key); i++) {
        if (memcmp(pgp_get_userid(key, i), userid, strlen(userid)) == 0) {
            uididx = i;
            break;
        }
    }
    if (uididx == -1) {
        return NULL;
    }
    int subsigidx = -1;
    // find the subsig index
    for (unsigned i = 0; i < key->subsigc; i++) {
        if ((int) key->subsigs[i].uid == uididx) {
            subsigidx = i;
            break;
        }
    }
    if (subsigidx == -1) {
        return NULL;
    }
    return &key->subsigs[subsigidx];
}

void
test_load_user_prefs(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    rnp_t             rnp;
    int               pipefd[2];
    char              homedir[PATH_MAX];

    paths_concat(homedir, sizeof(homedir), rstate->data_dir, "keyrings/1", NULL);

    rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, homedir, pipefd));
    rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, false));
    rnp_assert_true(rstate, rnp_secret_count(&rnp) == 0 && rnp_public_count(&rnp) == 7);

    {
        const char *userid = "key1-uid0";

        // find the key
        pgp_key_t *key = NULL;
        rnp_assert_non_null(rstate,
                            key = rnp_key_store_get_key_by_name(rnp.pubring, userid, NULL));
        assert_non_null(key);

        const pgp_subsig_t *subsig = find_subsig(key, userid);
        assert_non_null(subsig);

        const pgp_user_prefs_t *prefs = &subsig->prefs;

        // symm algs
        {
            static const uint8_t expected[] = {PGP_SA_AES_192, PGP_SA_CAST5};
            assert_int_equal(prefs->symm_alg_count, ARRAY_SIZE(expected));
            assert_int_equal(0, memcmp(prefs->symm_algs, expected, sizeof(expected)));
        }
        // hash algs
        {
            static const uint8_t expected[] = {PGP_HASH_SHA1, PGP_HASH_SHA224};
            assert_int_equal(prefs->hash_alg_count, ARRAY_SIZE(expected));
            assert_int_equal(0, memcmp(prefs->hash_algs, expected, sizeof(expected)));
        }
        // compression algs
        {
            static const uint8_t expected[] = {PGP_C_ZIP, PGP_C_NONE};
            assert_int_equal(prefs->z_alg_count, ARRAY_SIZE(expected));
            assert_int_equal(0, memcmp(prefs->z_algs, expected, sizeof(expected)));
        }
        // key server prefs
        {
            static const uint8_t expected[] = {PGP_KEY_SERVER_NO_MODIFY};
            assert_int_equal(prefs->ks_pref_count, ARRAY_SIZE(expected));
            assert_int_equal(0, memcmp(prefs->ks_prefs, expected, sizeof(expected)));
        }
        // preferred key server
        {
            static const char *expected = "hkp://pgp.mit.edu";
            assert_non_null(prefs->key_server);
            assert_int_equal(0, memcmp(prefs->key_server, expected, strlen(expected) + 1));
        }
    }

    {
        const char *userid = "key0-uid0";

        // find the key
        pgp_key_t *key = NULL;
        rnp_assert_non_null(rstate,
                            key = rnp_key_store_get_key_by_name(rnp.pubring, userid, NULL));
        assert_non_null(key);

        const pgp_subsig_t *subsig = find_subsig(key, userid);
        assert_non_null(subsig);

        const pgp_user_prefs_t *prefs = &subsig->prefs;

        // symm algs
        {
            static const uint8_t expected[] = {PGP_SA_AES_256,
                                               PGP_SA_AES_192,
                                               PGP_SA_AES_128,
                                               PGP_SA_CAST5,
                                               PGP_SA_TRIPLEDES,
                                               PGP_SA_IDEA};
            assert_int_equal(prefs->symm_alg_count, ARRAY_SIZE(expected));
            assert_int_equal(0, memcmp(prefs->symm_algs, expected, sizeof(expected)));
        }
        // hash algs
        {
            static const uint8_t expected[] = {PGP_HASH_SHA256,
                                               PGP_HASH_SHA1,
                                               PGP_HASH_SHA384,
                                               PGP_HASH_SHA512,
                                               PGP_HASH_SHA224};
            assert_int_equal(prefs->hash_alg_count, ARRAY_SIZE(expected));
            assert_int_equal(0, memcmp(prefs->hash_algs, expected, sizeof(expected)));
        }
        // compression algs
        {
            static const uint8_t expected[] = {PGP_C_ZLIB, PGP_C_BZIP2, PGP_C_ZIP};
            assert_int_equal(prefs->z_alg_count, ARRAY_SIZE(expected));
            assert_int_equal(0, memcmp(prefs->z_algs, expected, sizeof(expected)));
        }
        // key server prefs
        {
            static const uint8_t expected[] = {PGP_KEY_SERVER_NO_MODIFY};
            assert_int_equal(prefs->ks_pref_count, ARRAY_SIZE(expected));
            assert_int_equal(0, memcmp(prefs->ks_prefs, expected, sizeof(expected)));
        }
        // preferred key server
        {
            assert_null(prefs->key_server);
        }
    }

    /* Cleanup */
    close(pipefd[0]);
    rnp_end(&rnp);
}
