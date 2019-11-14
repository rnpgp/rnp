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
#include "../librepgp/stream-packet.h"
#include "../librepgp/stream-sig.h"
#include "pgp-key.h"

#include "rnp_tests.h"
#include "support.h"

/* This test loads a .gpg pubring with a single V3 key,
 * and confirms that appropriate key flags are set.
 */
TEST_F(rnp_tests, test_load_v3_keyring_pgp)
{
    pgp_source_t src = {};

    rnp_key_store_t *key_store = (rnp_key_store_t *) calloc(1, sizeof(*key_store));
    assert_non_null(key_store);

    // load pubring in to the key store
    assert_rnp_success(init_file_src(&src, "data/keyrings/2/pubring.gpg"));
    assert_rnp_success(rnp_key_store_pgp_read_from_src(key_store, &src));
    src_close(&src);
    assert_int_equal(1, rnp_key_store_get_key_count(key_store));

    // find the key by keyid
    static const uint8_t keyid[] = {0xDC, 0x70, 0xC1, 0x24, 0xA5, 0x02, 0x83, 0xF1};
    const pgp_key_t *    key = rnp_key_store_get_key_by_id(key_store, keyid, NULL);
    assert_non_null(key);

    // confirm the key flags are correct
    assert_int_equal(pgp_key_get_flags(key),
                     PGP_KF_ENCRYPT | PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);

    // cleanup
    rnp_key_store_free(key_store);

    // load secret keyring and decrypt the key

    key_store = (rnp_key_store_t *) calloc(1, sizeof(*key_store));
    assert_non_null(key_store);

    assert_rnp_success(init_file_src(&src, "data/keyrings/4/secring.pgp"));
    assert_rnp_success(rnp_key_store_pgp_read_from_src(key_store, &src));
    src_close(&src);
    assert_int_equal(1, rnp_key_store_get_key_count(key_store));

    static const uint8_t keyid2[] = {0x7D, 0x0B, 0xC1, 0x0E, 0x93, 0x34, 0x04, 0xC9};
    key = rnp_key_store_get_key_by_id(key_store, keyid2, NULL);
    assert_non_null(key);

    // confirm the key flags are correct
    assert_int_equal(pgp_key_get_flags(key),
                     PGP_KF_ENCRYPT | PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);

    // check if the key is secret and is locked
    assert_true(pgp_key_is_secret(key));
    assert_true(pgp_key_is_locked(key));

    // decrypt the key
    pgp_rawpacket_t *pkt = pgp_key_get_rawpacket(key, 0);
    pgp_key_pkt_t *  seckey =
      pgp_decrypt_seckey_pgp(pkt->raw, pkt->length, pgp_key_get_pkt(key), "password");
    assert_non_null(seckey);

    // cleanup
    free_key_pkt(seckey);
    free(seckey);
    rnp_key_store_free(key_store);
}

/* This test loads a .gpg pubring with multiple V4 keys,
 * finds a particular key of interest, and confirms that
 * the appropriate key flags are set.
 */
TEST_F(rnp_tests, test_load_v4_keyring_pgp)
{
    pgp_source_t src = {};

    rnp_key_store_t *key_store = (rnp_key_store_t *) calloc(1, sizeof(*key_store));
    assert_non_null(key_store);

    // load it in to the key store
    assert_rnp_success(init_file_src(&src, "data/keyrings/1/pubring.gpg"));
    assert_rnp_success(rnp_key_store_pgp_read_from_src(key_store, &src));
    src_close(&src);
    assert_int_equal(7, rnp_key_store_get_key_count(key_store));

    // find the key by keyid
    static const uint8_t keyid[] = {0x8a, 0x05, 0xb8, 0x9f, 0xad, 0x5a, 0xde, 0xd1};
    const pgp_key_t *    key = rnp_key_store_get_key_by_id(key_store, keyid, NULL);
    assert_non_null(key);

    // confirm the key flags are correct
    assert_int_equal(pgp_key_get_flags(key), PGP_KF_ENCRYPT);

    // cleanup
    rnp_key_store_free(key_store);
}

/* Just a helper for the below test */
static void
check_pgp_keyring_counts(const char *   path,
                         unsigned       primary_count,
                         const unsigned subkey_counts[])
{
    pgp_source_t     src = {};
    rnp_key_store_t *key_store = (rnp_key_store_t *) calloc(1, sizeof(*key_store));

    assert_non_null(key_store);
    // load it in to the key store
    assert_rnp_success(init_file_src(&src, path));
    assert_rnp_success(rnp_key_store_pgp_read_from_src(key_store, &src));
    src_close(&src);

    // count primary keys first
    unsigned total_primary_count = 0;
    for (size_t i = 0; i < rnp_key_store_get_key_count(key_store); i++) {
        if (pgp_key_is_primary_key(rnp_key_store_get_key(key_store, i))) {
            total_primary_count++;
        }
    }
    assert_int_equal(primary_count, total_primary_count);

    // now count subkeys in each primary key
    unsigned total_subkey_count = 0;
    unsigned primary = 0;
    for (size_t i = 0; i < rnp_key_store_get_key_count(key_store); i++) {
        pgp_key_t *key = rnp_key_store_get_key(key_store, i);
        if (pgp_key_is_primary_key(key)) {
            // check the subkey count for this primary key
            assert_int_equal(pgp_key_get_subkey_count(key), subkey_counts[primary++]);
        } else if (pgp_key_is_subkey(key)) {
            total_subkey_count++;
        }
    }

    // check the total (not really needed)
    assert_int_equal(rnp_key_store_get_key_count(key_store),
                     total_primary_count + total_subkey_count);

    // cleanup
    rnp_key_store_free(key_store);
}

/* This test loads a pubring.gpg and secring.gpg and confirms
 * that it contains the expected number of primary keys
 * and the expected number of subkeys for each primary key.
 */
TEST_F(rnp_tests, test_load_keyring_and_count_pgp)
{
    unsigned int primary_count = 2;
    unsigned int subkey_counts[2] = {3, 2};

    // check pubring
    check_pgp_keyring_counts("data/keyrings/1/pubring.gpg", primary_count, subkey_counts);

    // check secring
    check_pgp_keyring_counts("data/keyrings/1/secring.gpg", primary_count, subkey_counts);
}

/* This test loads a V4 keyring and confirms that certain
 * bitfields and time fields are set correctly.
 */
TEST_F(rnp_tests, test_load_check_bitfields_and_times)
{
    uint8_t                keyid[PGP_KEY_ID_SIZE];
    uint8_t                signer_id[PGP_KEY_ID_SIZE] = {0};
    const pgp_key_t *      key;
    const pgp_signature_t *sig = NULL;

    // load keyring
    rnp_key_store_t *key_store = rnp_key_store_new("GPG", "data/keyrings/1/pubring.gpg");
    assert_non_null(key_store);
    assert_true(rnp_key_store_load_from_path(key_store, NULL));

    // find
    key = NULL;
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(pgp_key_get_subsig_count(key), 3);
    // check subsig properties
    for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
        sig = &pgp_key_get_subsig(key, i)->sig;
        static const time_t expected_creation_times[] = {1500569820, 1500569836, 1500569846};
        // check SS_ISSUER_KEY_ID
        assert_true(signature_get_keyid(sig, signer_id));
        assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
        // check SS_CREATION_TIME
        assert_int_equal(signature_get_creation(sig), expected_creation_times[i]);
        // check SS_EXPIRATION_TIME
        assert_int_equal(signature_get_expiration(sig), 0);
    }
    // check SS_KEY_EXPIRY
    assert_int_equal(pgp_key_get_expiration(key), 0);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("1ED63EE56FADC34D", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(pgp_key_get_subsig_count(key), 1);
    sig = &pgp_key_get_subsig(key, 0)->sig;
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(signature_get_creation(sig), 1500569820);
    assert_int_equal(signature_get_creation(sig), pgp_key_get_creation(key));
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(signature_get_expiration(sig), 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(pgp_key_get_expiration(key), 0);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("1D7E8A5393C997A8", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(pgp_key_get_subsig_count(key), 1);
    sig = &pgp_key_get_subsig(key, 0)->sig;
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(signature_get_creation(sig), 1500569851);
    assert_int_equal(signature_get_creation(sig), pgp_key_get_creation(key));
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(signature_get_expiration(sig), 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(pgp_key_get_expiration(key), 123 * 24 * 60 * 60 /* 123 days */);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("8A05B89FAD5ADED1", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(pgp_key_get_subsig_count(key), 1);
    sig = &pgp_key_get_subsig(key, 0)->sig;
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(signature_get_creation(sig), 1500569896);
    assert_int_equal(signature_get_creation(sig), pgp_key_get_creation(key));
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(signature_get_expiration(sig), 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(pgp_key_get_expiration(key), 0);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("2FCADF05FFA501BB", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(pgp_key_get_subsig_count(key), 3);
    // check subsig properties
    for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
        sig = &pgp_key_get_subsig(key, i)->sig;
        static const time_t expected_creation_times[] = {1501372449, 1500570153, 1500570147};

        // check SS_ISSUER_KEY_ID
        assert_true(signature_get_keyid(sig, signer_id));
        assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
        // check SS_CREATION_TIME
        assert_int_equal(signature_get_creation(sig), expected_creation_times[i]);
        // check SS_EXPIRATION_TIME
        assert_int_equal(signature_get_expiration(sig), 0);
    }
    // check SS_KEY_EXPIRY
    assert_int_equal(pgp_key_get_expiration(key), 2076663808);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("54505A936A4A970E", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(pgp_key_get_subsig_count(key), 1);
    sig = &pgp_key_get_subsig(key, 0)->sig;
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("2FCADF05FFA501BB", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(signature_get_creation(sig), 1500569946);
    assert_int_equal(signature_get_creation(sig), pgp_key_get_creation(key));
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(signature_get_expiration(sig), 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(pgp_key_get_expiration(key), 2076663808);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("326EF111425D14A5", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(pgp_key_get_subsig_count(key), 1);
    sig = &pgp_key_get_subsig(key, 0)->sig;
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("2FCADF05FFA501BB", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(signature_get_creation(sig), 1500570165);
    assert_int_equal(signature_get_creation(sig), pgp_key_get_creation(key));
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(signature_get_expiration(sig), 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(pgp_key_get_expiration(key), 0);

    // cleanup
    rnp_key_store_free(key_store);
}

/* This test loads a V3 keyring and confirms that certain
 * bitfields and time fields are set correctly.
 */
TEST_F(rnp_tests, test_load_check_bitfields_and_times_v3)
{
    uint8_t                keyid[PGP_KEY_ID_SIZE];
    uint8_t                signer_id[PGP_KEY_ID_SIZE];
    const pgp_key_t *      key;
    const pgp_signature_t *sig = NULL;

    // load keyring
    rnp_key_store_t *key_store = rnp_key_store_new("GPG", "data/keyrings/2/pubring.gpg");
    assert_non_null(key_store);
    assert_true(rnp_key_store_load_from_path(key_store, NULL));

    // find
    key = NULL;
    assert_true(rnp_hex_decode("DC70C124A50283F1", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(key_store, keyid, NULL);
    assert_non_null(key);
    // check key version
    assert_int_equal(pgp_key_get_version(key), PGP_V3);
    // check subsig count
    assert_int_equal(pgp_key_get_subsig_count(key), 1);
    sig = &pgp_key_get_subsig(key, 0)->sig;
    // check signature version
    assert_int_equal(sig->version, 3);
    // check issuer
    assert_true(rnp_hex_decode("DC70C124A50283F1", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check creation time
    assert_int_equal(signature_get_creation(sig), 1005209227);
    assert_int_equal(signature_get_creation(sig), pgp_key_get_creation(key));
    // check signature expiration time (V3 sigs have none)
    assert_int_equal(signature_get_expiration(sig), 0);
    // check key expiration
    assert_int_equal(pgp_key_get_expiration(key), 0); // only for V4 keys
    assert_int_equal(pgp_key_get_pkt(key)->v3_days, 0);

    // cleanup
    rnp_key_store_free(key_store);
}

#define MERGE_PATH "data/test_stream_key_merge/"

TEST_F(rnp_tests, test_load_armored_pub_sec)
{
    pgp_key_t *      key;
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    rnp_key_store_t *key_store;

    key_store = rnp_key_store_new("GPG", MERGE_PATH "key-both.asc");
    assert_non_null(key_store);
    assert_true(rnp_key_store_load_from_path(key_store, NULL));

    /* we must have 1 main key and 2 subkeys */
    assert_int_equal(rnp_key_store_get_key_count(key_store), 3);

    assert_true(rnp_hex_decode("9747D2A6B3A63124", keyid, sizeof(keyid)));
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_true(key->valid);
    assert_true(pgp_key_is_primary_key(key));
    assert_true(pgp_key_is_secret(key));
    assert_int_equal(pgp_key_get_rawpacket_count(key), 5);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_SECRET_KEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 2)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_rawpacket(key, 3)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 4)->tag, PGP_PTAG_CT_SIGNATURE);

    assert_true(rnp_hex_decode("AF1114A47F5F5B28", keyid, sizeof(keyid)));
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_true(key->valid);
    assert_true(pgp_key_is_subkey(key));
    assert_true(pgp_key_is_secret(key));
    assert_int_equal(pgp_key_get_rawpacket_count(key), 2);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_SIGNATURE);

    assert_true(rnp_hex_decode("16CD16F267CCDD4F", keyid, sizeof(keyid)));
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_true(key->valid);
    assert_true(pgp_key_is_subkey(key));
    assert_true(pgp_key_is_secret(key));
    assert_int_equal(pgp_key_get_rawpacket_count(key), 2);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_SIGNATURE);

    /* both user ids should be present */
    assert_non_null(rnp_tests_key_search(key_store, "key-merge-uid-1"));
    assert_non_null(rnp_tests_key_search(key_store, "key-merge-uid-2"));

    rnp_key_store_free(key_store);
}

static bool
load_transferable_key(pgp_transferable_key_t *key, const char *fname)
{
    pgp_source_t src = {};
    bool         res = !init_file_src(&src, fname) && !process_pgp_key(&src, key);
    src_close(&src);
    return res;
}

static bool
load_transferable_subkey(pgp_transferable_subkey_t *key, const char *fname)
{
    pgp_source_t src = {};
    bool         res = !init_file_src(&src, fname) && !process_pgp_subkey(&src, key);
    src_close(&src);
    return res;
}

static bool
load_keystore(rnp_key_store_t *keystore, const char *fname)
{
    pgp_source_t src = {};
    bool res = !init_file_src(&src, fname) && !rnp_key_store_pgp_read_from_src(keystore, &src);
    src_close(&src);
    return res;
}

static bool
check_subkey_grip(pgp_key_t *key, pgp_key_t *subkey, size_t index)
{
    if (memcmp(
          pgp_key_get_subkey_grip(key, index), pgp_key_get_grip(subkey), PGP_KEY_GRIP_SIZE)) {
        return false;
    }
    return !memcmp(pgp_key_get_grip(key), pgp_key_get_primary_grip(subkey), PGP_KEY_GRIP_SIZE);
}

TEST_F(rnp_tests, test_load_merge)
{
    pgp_key_t *               key, *skey1, *skey2;
    uint8_t                   keyid[PGP_KEY_ID_SIZE];
    uint8_t                   sub1id[PGP_KEY_ID_SIZE];
    uint8_t                   sub2id[PGP_KEY_ID_SIZE];
    rnp_key_store_t *         key_store;
    pgp_transferable_key_t    tkey = {};
    pgp_transferable_subkey_t tskey = {};
    pgp_password_provider_t   provider = (pgp_password_provider_t){
      .callback = string_copy_password_callback, .userdata = (void *) "password"};

    key_store = rnp_key_store_new("GPG", "");
    assert_non_null(key_store);
    assert_true(rnp_hex_decode("9747D2A6B3A63124", keyid, sizeof(keyid)));
    assert_true(rnp_hex_decode("AF1114A47F5F5B28", sub1id, sizeof(sub1id)));
    assert_true(rnp_hex_decode("16CD16F267CCDD4F", sub2id, sizeof(sub2id)));

    /* load just key packet */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-just-key.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(rnp_key_store_get_key_count(key_store), 1);
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_false(key->valid);
    assert_int_equal(pgp_key_get_rawpacket_count(key), 1);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_PUBLIC_KEY);

    /* load key + user id 1 without sigs */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-uid-1-no-sigs.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(rnp_key_store_get_key_count(key_store), 1);
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_false(key->valid);
    assert_int_equal(pgp_key_get_userid_count(key), 1);
    assert_int_equal(pgp_key_get_rawpacket_count(key), 2);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_USER_ID);
    assert_true(key == rnp_tests_key_search(key_store, "key-merge-uid-1"));

    /* load key + user id 1 with sigs */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-uid-1.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(rnp_key_store_get_key_count(key_store), 1);
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_true(key->valid);
    assert_int_equal(pgp_key_get_userid_count(key), 1);
    assert_int_equal(pgp_key_get_rawpacket_count(key), 3);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 2)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_true(key == rnp_tests_key_search(key_store, "key-merge-uid-1"));

    /* load key + user id 2 with sigs */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-uid-2.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    /* try to add it twice */
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(rnp_key_store_get_key_count(key_store), 1);
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_true(key->valid);
    assert_int_equal(pgp_key_get_userid_count(key), 2);
    assert_int_equal(pgp_key_get_rawpacket_count(key), 5);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 2)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_rawpacket(key, 3)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 4)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_true(key == rnp_tests_key_search(key_store, "key-merge-uid-1"));
    assert_true(key == rnp_tests_key_search(key_store, "key-merge-uid-2"));

    /* load key + subkey 1 without sigs */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-subkey-1-no-sigs.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(rnp_key_store_get_key_count(key_store), 2);
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(key_store, sub1id, NULL));
    assert_true(key->valid);
    assert_false(skey1->valid);
    assert_int_equal(pgp_key_get_userid_count(key), 2);
    assert_int_equal(pgp_key_get_subkey_count(key), 1);
    assert_true(check_subkey_grip(key, skey1, 0));
    assert_int_equal(pgp_key_get_rawpacket_count(key), 5);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 2)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_rawpacket(key, 3)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 4)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_userid_count(skey1), 0);
    assert_int_equal(pgp_key_get_rawpacket_count(skey1), 1);
    assert_int_equal(pgp_key_get_rawpacket(skey1, 0)->tag, PGP_PTAG_CT_PUBLIC_SUBKEY);

    /* load just subkey 1 but with signature */
    assert_true(load_transferable_subkey(&tskey, MERGE_PATH "key-pub-no-key-subkey-1.pgp"));
    assert_true(rnp_key_store_add_transferable_subkey(key_store, &tskey, key));
    /* try to add it twice */
    assert_true(rnp_key_store_add_transferable_subkey(key_store, &tskey, key));
    transferable_subkey_destroy(&tskey);
    assert_int_equal(rnp_key_store_get_key_count(key_store), 2);
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(key_store, sub1id, NULL));
    assert_true(key->valid);
    assert_true(skey1->valid);
    assert_int_equal(pgp_key_get_userid_count(key), 2);
    assert_int_equal(pgp_key_get_subkey_count(key), 1);
    assert_true(check_subkey_grip(key, skey1, 0));
    assert_int_equal(pgp_key_get_rawpacket_count(key), 5);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 2)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_rawpacket(key, 3)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 4)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_userid_count(skey1), 0);
    assert_int_equal(pgp_key_get_rawpacket_count(skey1), 2);
    assert_int_equal(pgp_key_get_rawpacket(skey1, 0)->tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_int_equal(pgp_key_get_rawpacket(skey1, 1)->tag, PGP_PTAG_CT_SIGNATURE);

    /* load key + subkey 2 with signature */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-subkey-2.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    /* try to add it twice */
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(rnp_key_store_get_key_count(key_store), 3);
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(key_store, sub1id, NULL));
    assert_non_null(skey2 = rnp_key_store_get_key_by_id(key_store, sub2id, NULL));
    assert_true(key->valid);
    assert_true(skey1->valid);
    assert_true(skey2->valid);
    assert_int_equal(pgp_key_get_userid_count(key), 2);
    assert_int_equal(pgp_key_get_subkey_count(key), 2);
    assert_true(check_subkey_grip(key, skey1, 0));
    assert_true(check_subkey_grip(key, skey2, 1));
    assert_int_equal(pgp_key_get_rawpacket_count(key), 5);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 2)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_rawpacket(key, 3)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 4)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_userid_count(skey1), 0);
    assert_int_equal(pgp_key_get_rawpacket_count(skey1), 2);
    assert_int_equal(pgp_key_get_rawpacket(skey1, 0)->tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_int_equal(pgp_key_get_rawpacket(skey1, 1)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_userid_count(skey2), 0);
    assert_int_equal(pgp_key_get_rawpacket_count(skey2), 2);
    assert_int_equal(pgp_key_get_rawpacket(skey2, 0)->tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_int_equal(pgp_key_get_rawpacket(skey2, 1)->tag, PGP_PTAG_CT_SIGNATURE);

    /* load secret key & subkeys */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-sec-no-uid-no-sigs.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    /* try to add it twice */
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(rnp_key_store_get_key_count(key_store), 3);
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(key_store, sub1id, NULL));
    assert_non_null(skey2 = rnp_key_store_get_key_by_id(key_store, sub2id, NULL));
    assert_true(key->valid);
    assert_true(skey1->valid);
    assert_true(skey2->valid);
    assert_int_equal(pgp_key_get_userid_count(key), 2);
    assert_int_equal(pgp_key_get_subkey_count(key), 2);
    assert_true(check_subkey_grip(key, skey1, 0));
    assert_true(check_subkey_grip(key, skey2, 1));
    assert_int_equal(pgp_key_get_rawpacket_count(key), 5);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_SECRET_KEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 2)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_rawpacket(key, 3)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 4)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_userid_count(skey1), 0);
    assert_int_equal(pgp_key_get_rawpacket_count(skey1), 2);
    assert_int_equal(pgp_key_get_rawpacket(skey1, 0)->tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(pgp_key_get_rawpacket(skey1, 1)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_userid_count(skey2), 0);
    assert_int_equal(pgp_key_get_rawpacket_count(skey2), 2);
    assert_int_equal(pgp_key_get_rawpacket(skey2, 0)->tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(pgp_key_get_rawpacket(skey2, 1)->tag, PGP_PTAG_CT_SIGNATURE);

    assert_true(pgp_key_unlock(key, &provider));
    assert_true(pgp_key_unlock(skey1, &provider));
    assert_true(pgp_key_unlock(skey2, &provider));

    /* load the whole public + secret key */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub.asc"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-sec.asc"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(rnp_key_store_get_key_count(key_store), 3);
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(key_store, sub1id, NULL));
    assert_non_null(skey2 = rnp_key_store_get_key_by_id(key_store, sub2id, NULL));
    assert_true(key->valid);
    assert_true(skey1->valid);
    assert_true(skey2->valid);
    assert_int_equal(pgp_key_get_userid_count(key), 2);
    assert_int_equal(pgp_key_get_subkey_count(key), 2);
    assert_true(check_subkey_grip(key, skey1, 0));
    assert_true(check_subkey_grip(key, skey2, 1));
    assert_int_equal(pgp_key_get_rawpacket_count(key), 5);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_SECRET_KEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 2)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_rawpacket(key, 3)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 4)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_userid_count(skey1), 0);
    assert_int_equal(pgp_key_get_rawpacket_count(skey1), 2);
    assert_int_equal(pgp_key_get_rawpacket(skey1, 0)->tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(pgp_key_get_rawpacket(skey1, 1)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(pgp_key_get_userid_count(skey2), 0);
    assert_int_equal(pgp_key_get_rawpacket_count(skey2), 2);
    assert_int_equal(pgp_key_get_rawpacket(skey2, 0)->tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(pgp_key_get_rawpacket(skey2, 1)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_true(key == rnp_tests_key_search(key_store, "key-merge-uid-1"));
    assert_true(key == rnp_tests_key_search(key_store, "key-merge-uid-2"));

    rnp_key_store_free(key_store);
}

TEST_F(rnp_tests, test_load_public_from_secret)
{
    pgp_key_t *      key, *skey1, *skey2, keycp;
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    uint8_t          sub1id[PGP_KEY_ID_SIZE];
    uint8_t          sub2id[PGP_KEY_ID_SIZE];
    rnp_key_store_t *secstore, *pubstore;

    assert_non_null(secstore = rnp_key_store_new("GPG", MERGE_PATH "key-sec.asc"));
    assert_true(rnp_key_store_load_from_path(secstore, NULL));
    assert_non_null(pubstore = rnp_key_store_new("GPG", "pubring.gpg"));

    assert_true(rnp_hex_decode("9747D2A6B3A63124", keyid, sizeof(keyid)));
    assert_true(rnp_hex_decode("AF1114A47F5F5B28", sub1id, sizeof(sub1id)));
    assert_true(rnp_hex_decode("16CD16F267CCDD4F", sub2id, sizeof(sub2id)));

    assert_non_null(key = rnp_key_store_get_key_by_id(secstore, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(secstore, sub1id, NULL));
    assert_non_null(skey2 = rnp_key_store_get_key_by_id(secstore, sub2id, NULL));

    /* copy the secret key */
    assert_rnp_success(pgp_key_copy(&keycp, key, false));
    assert_true(pgp_key_is_secret(&keycp));
    assert_int_equal(pgp_key_get_subkey_count(&keycp), 2);
    assert_false(
      memcmp(pgp_key_get_subkey_grip(&keycp, 0), pgp_key_get_grip(skey1), PGP_KEY_GRIP_SIZE));
    assert_false(
      memcmp(pgp_key_get_subkey_grip(&keycp, 1), pgp_key_get_grip(skey2), PGP_KEY_GRIP_SIZE));
    assert_false(memcmp(pgp_key_get_grip(&keycp), pgp_key_get_grip(key), PGP_KEY_GRIP_SIZE));
    assert_int_equal(pgp_key_get_rawpacket(&keycp, 0)->tag, PGP_PTAG_CT_SECRET_KEY);
    pgp_key_free_data(&keycp);

    /* copy the public part */
    assert_rnp_success(pgp_key_copy(&keycp, key, true));
    assert_false(pgp_key_is_secret(&keycp));
    assert_int_equal(pgp_key_get_subkey_count(&keycp), 2);
    assert_true(check_subkey_grip(&keycp, skey1, 0));
    assert_true(check_subkey_grip(&keycp, skey2, 1));
    assert_false(memcmp(pgp_key_get_grip(&keycp), pgp_key_get_grip(key), PGP_KEY_GRIP_SIZE));
    assert_int_equal(pgp_key_get_rawpacket(&keycp, 0)->tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_null(pgp_key_get_pkt(&keycp)->sec_data);
    assert_int_equal(pgp_key_get_pkt(&keycp)->sec_len, 0);
    assert_false(pgp_key_get_pkt(&keycp)->material.secret);
    rnp_key_store_add_key(pubstore, &keycp);
    /* subkey 1 */
    assert_rnp_success(pgp_key_copy(&keycp, skey1, true));
    assert_false(pgp_key_is_secret(&keycp));
    assert_int_equal(pgp_key_get_subkey_count(&keycp), 0);
    assert_true(check_subkey_grip(key, &keycp, 0));
    assert_false(memcmp(pgp_key_get_grip(&keycp), pgp_key_get_grip(skey1), PGP_KEY_GRIP_SIZE));
    assert_false(memcmp(pgp_key_get_keyid(&keycp), sub1id, PGP_KEY_ID_SIZE));
    assert_int_equal(pgp_key_get_rawpacket(&keycp, 0)->tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_null(pgp_key_get_pkt(&keycp)->sec_data);
    assert_int_equal(pgp_key_get_pkt(&keycp)->sec_len, 0);
    assert_false(pgp_key_get_pkt(&keycp)->material.secret);
    rnp_key_store_add_key(pubstore, &keycp);
    /* subkey 2 */
    assert_rnp_success(pgp_key_copy(&keycp, skey2, true));
    assert_false(pgp_key_is_secret(&keycp));
    assert_int_equal(pgp_key_get_subkey_count(&keycp), 0);
    assert_true(check_subkey_grip(key, &keycp, 1));
    assert_false(memcmp(pgp_key_get_grip(&keycp), pgp_key_get_grip(skey2), PGP_KEY_GRIP_SIZE));
    assert_false(memcmp(pgp_key_get_keyid(&keycp), sub2id, PGP_KEY_ID_SIZE));
    assert_int_equal(pgp_key_get_rawpacket(&keycp, 0)->tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_null(pgp_key_get_pkt(&keycp)->sec_data);
    assert_int_equal(pgp_key_get_pkt(&keycp)->sec_len, 0);
    assert_false(pgp_key_get_pkt(&keycp)->material.secret);
    rnp_key_store_add_key(pubstore, &keycp);
    /* save pubring */
    assert_true(rnp_key_store_write_to_path(pubstore));
    rnp_key_store_free(pubstore);
    /* reload */
    assert_non_null(pubstore = rnp_key_store_new("GPG", "pubring.gpg"));
    assert_true(rnp_key_store_load_from_path(pubstore, NULL));
    assert_non_null(key = rnp_key_store_get_key_by_id(pubstore, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(pubstore, sub1id, NULL));
    assert_non_null(skey2 = rnp_key_store_get_key_by_id(pubstore, sub2id, NULL));

    rnp_key_store_free(pubstore);
    rnp_key_store_free(secstore);
}

TEST_F(rnp_tests, test_key_import)
{
    cli_rnp_t                      rnp = {};
    pgp_transferable_key_t     tkey = {};
    pgp_transferable_subkey_t *tskey = NULL;
    pgp_transferable_userid_t *tuid = NULL;

    assert_int_equal(mkdir(".rnp", S_IRWXU), 0);
    assert_true(setup_cli_rnp_common(&rnp, RNP_KEYSTORE_GPG, ".rnp", NULL));

    /* import just the public key */
    rnp_cfg_t cfg = {};
    rnp_cfg_init(&cfg);
    rnp_cfg_setstr(&cfg, CFG_KEYFILE, MERGE_PATH "key-pub-just-key.pgp");
    assert_true(cli_rnp_add_key(&cfg, &rnp));
    assert_true(cli_rnp_save_keyrings(&rnp));
    size_t keycount = 0;
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 1);
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 0);

    assert_true(load_transferable_key(&tkey, ".rnp/pubring.gpg"));
    assert_int_equal(list_length(tkey.subkeys), 0);
    assert_int_equal(list_length(tkey.signatures), 0);
    assert_int_equal(list_length(tkey.userids), 0);
    assert_int_equal(tkey.key.tag, PGP_PTAG_CT_PUBLIC_KEY);
    transferable_key_destroy(&tkey);

    /* import public key + 1 userid */
    rnp_cfg_setstr(&cfg, CFG_KEYFILE, MERGE_PATH "key-pub-uid-1-no-sigs.pgp");
    assert_true(cli_rnp_add_key(&cfg, &rnp));
    assert_true(cli_rnp_save_keyrings(&rnp));
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 1);
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 0);

    assert_true(load_transferable_key(&tkey, ".rnp/pubring.gpg"));
    assert_int_equal(list_length(tkey.subkeys), 0);
    assert_int_equal(list_length(tkey.signatures), 0);
    assert_int_equal(list_length(tkey.userids), 1);
    assert_non_null(tuid = (pgp_transferable_userid_t *) list_front(tkey.userids));
    assert_int_equal(list_length(tuid->signatures), 0);
    assert_false(memcmp(tuid->uid.uid, "key-merge-uid-1", 15));
    assert_int_equal(tkey.key.tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(tuid->uid.tag, PGP_PTAG_CT_USER_ID);
    transferable_key_destroy(&tkey);

    /* import public key + 1 userid + signature */
    rnp_cfg_setstr(&cfg, CFG_KEYFILE, MERGE_PATH "key-pub-uid-1.pgp");
    assert_true(cli_rnp_add_key(&cfg, &rnp));
    assert_true(cli_rnp_save_keyrings(&rnp));
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 1);
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 0);

    assert_true(load_transferable_key(&tkey, ".rnp/pubring.gpg"));
    assert_int_equal(list_length(tkey.subkeys), 0);
    assert_int_equal(list_length(tkey.signatures), 0);
    assert_int_equal(list_length(tkey.userids), 1);
    assert_int_equal(tkey.key.tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_non_null(tuid = (pgp_transferable_userid_t *) list_front(tkey.userids));
    assert_int_equal(list_length(tuid->signatures), 1);
    assert_false(memcmp(tuid->uid.uid, "key-merge-uid-1", 15));
    assert_int_equal(tuid->uid.tag, PGP_PTAG_CT_USER_ID);
    transferable_key_destroy(&tkey);

    /* import public key + 1 subkey */
    rnp_cfg_setstr(&cfg, CFG_KEYFILE, MERGE_PATH "key-pub-subkey-1.pgp");
    assert_true(cli_rnp_add_key(&cfg, &rnp));
    assert_true(cli_rnp_save_keyrings(&rnp));
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 0);

    assert_true(load_transferable_key(&tkey, ".rnp/pubring.gpg"));
    assert_int_equal(list_length(tkey.subkeys), 1);
    assert_int_equal(list_length(tkey.signatures), 0);
    assert_int_equal(list_length(tkey.userids), 1);
    assert_int_equal(tkey.key.tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_non_null(tuid = (pgp_transferable_userid_t *) list_front(tkey.userids));
    assert_int_equal(list_length(tuid->signatures), 1);
    assert_false(memcmp(tuid->uid.uid, "key-merge-uid-1", 15));
    assert_int_equal(tuid->uid.tag, PGP_PTAG_CT_USER_ID);
    assert_non_null(tskey = (pgp_transferable_subkey_t *) list_front(tkey.subkeys));
    assert_int_equal(list_length(tskey->signatures), 1);
    assert_int_equal(tskey->subkey.tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    transferable_key_destroy(&tkey);

    /* import secret key with 1 uid and 1 subkey */
    rnp_cfg_setstr(&cfg, CFG_KEYFILE, MERGE_PATH "key-sec-uid-1-subkey-1.pgp");
    assert_true(cli_rnp_add_key(&cfg, &rnp));
    assert_true(cli_rnp_save_keyrings(&rnp));
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);

    assert_true(load_transferable_key(&tkey, ".rnp/pubring.gpg"));
    assert_int_equal(list_length(tkey.subkeys), 1);
    assert_int_equal(list_length(tkey.signatures), 0);
    assert_int_equal(list_length(tkey.userids), 1);
    assert_int_equal(tkey.key.tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_non_null(tuid = (pgp_transferable_userid_t *) list_front(tkey.userids));
    assert_int_equal(list_length(tuid->signatures), 1);
    assert_false(memcmp(tuid->uid.uid, "key-merge-uid-1", 15));
    assert_int_equal(tuid->uid.tag, PGP_PTAG_CT_USER_ID);
    assert_non_null(tskey = (pgp_transferable_subkey_t *) list_front(tkey.subkeys));
    assert_int_equal(list_length(tskey->signatures), 1);
    assert_int_equal(tskey->subkey.tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    transferable_key_destroy(&tkey);

    assert_true(load_transferable_key(&tkey, ".rnp/secring.gpg"));
    assert_int_equal(list_length(tkey.subkeys), 1);
    assert_int_equal(list_length(tkey.signatures), 0);
    assert_int_equal(list_length(tkey.userids), 1);
    assert_int_equal(tkey.key.tag, PGP_PTAG_CT_SECRET_KEY);
    assert_rnp_success(decrypt_secret_key(&tkey.key, "password"));
    assert_non_null(tuid = (pgp_transferable_userid_t *) list_front(tkey.userids));
    assert_int_equal(list_length(tuid->signatures), 1);
    assert_false(memcmp(tuid->uid.uid, "key-merge-uid-1", 15));
    assert_int_equal(tuid->uid.tag, PGP_PTAG_CT_USER_ID);
    assert_non_null(tskey = (pgp_transferable_subkey_t *) list_front(tkey.subkeys));
    assert_int_equal(list_length(tskey->signatures), 1);
    assert_int_equal(tskey->subkey.tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_rnp_success(decrypt_secret_key(&tskey->subkey, "password"));
    transferable_key_destroy(&tkey);

    /* import secret key with 2 uids and 2 subkeys */
    rnp_cfg_setstr(&cfg, CFG_KEYFILE, MERGE_PATH "key-sec.pgp");
    assert_true(cli_rnp_add_key(&cfg, &rnp));
    assert_true(cli_rnp_save_keyrings(&rnp));
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 3);
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 3);

    assert_true(load_transferable_key(&tkey, ".rnp/pubring.gpg"));
    assert_int_equal(list_length(tkey.subkeys), 2);
    assert_int_equal(list_length(tkey.signatures), 0);
    assert_int_equal(list_length(tkey.userids), 2);
    assert_int_equal(tkey.key.tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_non_null(tuid = (pgp_transferable_userid_t *) list_front(tkey.userids));
    assert_int_equal(list_length(tuid->signatures), 1);
    assert_false(memcmp(tuid->uid.uid, "key-merge-uid-1", 15));
    assert_int_equal(tuid->uid.tag, PGP_PTAG_CT_USER_ID);
    assert_non_null(tuid = (pgp_transferable_userid_t *) list_next((list_item *) tuid));
    assert_int_equal(list_length(tuid->signatures), 1);
    assert_false(memcmp(tuid->uid.uid, "key-merge-uid-2", 15));
    assert_int_equal(tuid->uid.tag, PGP_PTAG_CT_USER_ID);
    assert_non_null(tskey = (pgp_transferable_subkey_t *) list_front(tkey.subkeys));
    assert_int_equal(list_length(tskey->signatures), 1);
    assert_int_equal(tskey->subkey.tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_non_null(tskey = (pgp_transferable_subkey_t *) list_next((list_item *) tskey));
    assert_int_equal(list_length(tskey->signatures), 1);
    assert_int_equal(tskey->subkey.tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    transferable_key_destroy(&tkey);

    assert_true(load_transferable_key(&tkey, ".rnp/secring.gpg"));
    assert_int_equal(list_length(tkey.subkeys), 2);
    assert_int_equal(list_length(tkey.signatures), 0);
    assert_int_equal(list_length(tkey.userids), 2);
    assert_int_equal(tkey.key.tag, PGP_PTAG_CT_SECRET_KEY);
    assert_rnp_success(decrypt_secret_key(&tkey.key, "password"));
    assert_non_null(tuid = (pgp_transferable_userid_t *) list_front(tkey.userids));
    assert_int_equal(list_length(tuid->signatures), 1);
    assert_false(memcmp(tuid->uid.uid, "key-merge-uid-1", 15));
    assert_int_equal(tuid->uid.tag, PGP_PTAG_CT_USER_ID);
    assert_non_null(tuid = (pgp_transferable_userid_t *) list_next((list_item *) tuid));
    assert_int_equal(list_length(tuid->signatures), 1);
    assert_false(memcmp(tuid->uid.uid, "key-merge-uid-2", 15));
    assert_int_equal(tuid->uid.tag, PGP_PTAG_CT_USER_ID);
    assert_non_null(tskey = (pgp_transferable_subkey_t *) list_front(tkey.subkeys));
    assert_int_equal(list_length(tskey->signatures), 1);
    assert_int_equal(tskey->subkey.tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_rnp_success(decrypt_secret_key(&tskey->subkey, "password"));
    assert_non_null(tskey = (pgp_transferable_subkey_t *) list_next((list_item *) tskey));
    assert_int_equal(list_length(tskey->signatures), 1);
    assert_int_equal(tskey->subkey.tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_rnp_success(decrypt_secret_key(&tskey->subkey, "password"));
    transferable_key_destroy(&tkey);

    rnp_cfg_free(&cfg);
    cli_rnp_end(&rnp);
}

TEST_F(rnp_tests, test_load_subkey)
{
    pgp_key_t *      key, *skey1, *skey2;
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    uint8_t          sub1id[PGP_KEY_ID_SIZE];
    uint8_t          sub2id[PGP_KEY_ID_SIZE];
    rnp_key_store_t *key_store;

    key_store = rnp_key_store_new("GPG", "");
    assert_non_null(key_store);
    assert_true(rnp_hex_decode("9747D2A6B3A63124", keyid, sizeof(keyid)));
    assert_true(rnp_hex_decode("AF1114A47F5F5B28", sub1id, sizeof(sub1id)));
    assert_true(rnp_hex_decode("16CD16F267CCDD4F", sub2id, sizeof(sub2id)));

    /* load first subkey with signature */
    assert_true(load_keystore(key_store, MERGE_PATH "key-pub-just-subkey-1.pgp"));
    assert_int_equal(rnp_key_store_get_key_count(key_store), 1);
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(key_store, sub1id, NULL));
    assert_false(skey1->valid);
    assert_int_equal(pgp_key_get_rawpacket_count(skey1), 2);
    assert_int_equal(pgp_key_get_rawpacket(skey1, 0)->tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_int_equal(pgp_key_get_rawpacket(skey1, 1)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_null(pgp_key_get_primary_grip(skey1));

    /* load second subkey, without signature */
    assert_true(load_keystore(key_store, MERGE_PATH "key-pub-just-subkey-2-no-sigs.pgp"));
    assert_int_equal(rnp_key_store_get_key_count(key_store), 2);
    assert_non_null(skey2 = rnp_key_store_get_key_by_id(key_store, sub2id, NULL));
    assert_false(skey2->valid);
    assert_int_equal(pgp_key_get_rawpacket_count(skey2), 1);
    assert_int_equal(pgp_key_get_rawpacket(skey2, 0)->tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_null(pgp_key_get_primary_grip(skey2));
    assert_false(skey1 == skey2);

    /* load primary key without subkey signatures */
    assert_true(load_keystore(key_store, MERGE_PATH "key-pub-uid-1.pgp"));
    assert_int_equal(rnp_key_store_get_key_count(key_store), 3);
    assert_non_null(key = rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_true(key->valid);
    assert_int_equal(pgp_key_get_rawpacket_count(key), 3);
    assert_int_equal(pgp_key_get_rawpacket(key, 0)->tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(pgp_key_get_rawpacket(key, 1)->tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(pgp_key_get_rawpacket(key, 2)->tag, PGP_PTAG_CT_SIGNATURE);
    assert_true(skey1 == rnp_key_store_get_key_by_id(key_store, sub1id, NULL));
    assert_true(skey2 == rnp_key_store_get_key_by_id(key_store, sub2id, NULL));
    assert_non_null(pgp_key_get_primary_grip(skey1));
    assert_true(check_subkey_grip(key, skey1, 0));
    assert_int_equal(pgp_key_get_subkey_count(key), 1);
    assert_true(skey1->valid);
    assert_false(skey2->valid);

    /* load second subkey with signature */
    assert_true(load_keystore(key_store, MERGE_PATH "key-pub-just-subkey-2.pgp"));
    assert_int_equal(rnp_key_store_get_key_count(key_store), 3);
    assert_true(key == rnp_key_store_get_key_by_id(key_store, keyid, NULL));
    assert_true(skey1 == rnp_key_store_get_key_by_id(key_store, sub1id, NULL));
    assert_true(skey2 == rnp_key_store_get_key_by_id(key_store, sub2id, NULL));
    assert_non_null(pgp_key_get_primary_grip(skey2));
    assert_true(check_subkey_grip(key, skey2, 1));
    assert_int_equal(pgp_key_get_subkey_count(key), 2);
    assert_true(skey2->valid);

    rnp_key_store_free(key_store);
}
