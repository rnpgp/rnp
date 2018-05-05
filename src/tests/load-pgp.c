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

#include "rnp_tests.h"
#include "support.h"

/* This test loads a .gpg pubring with a single V3 key,
 * and confirms that appropriate key flags are set.
 */
void
test_load_v3_keyring_pgp(void **state)
{
    rnp_test_state_t *rstate = *state;
    char              path[PATH_MAX];
    pgp_io_t          io = {.errs = stderr, .res = stdout, .outs = stdout};
    pgp_memory_t      mem = {0};

    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/2/pubring.gpg", NULL);
    // read the pubring into memory
    assert_true(pgp_mem_readfile(&mem, path));

    rnp_key_store_t *key_store = calloc(1, sizeof(*key_store));
    assert_non_null(key_store);

    // load it in to the key store
    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, 0, &mem, NULL));
    assert_int_equal(1, list_length(key_store->keys));

    // find the key by keyid
    static const uint8_t keyid[] = {0xDC, 0x70, 0xC1, 0x24, 0xA5, 0x02, 0x83, 0xF1};
    const pgp_key_t *    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL, NULL);
    assert_non_null(key);

    // confirm the key flags are correct
    assert_int_equal(key->key_flags,
                     PGP_KF_ENCRYPT | PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);

    // cleanup
    rnp_key_store_free(key_store);
    pgp_memory_release(&mem);

    // load secret keyring and decrypt the key
    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/4/secring.pgp", NULL);
    assert_true(pgp_mem_readfile(&mem, path));

    key_store = calloc(1, sizeof(*key_store));
    assert_non_null(key_store);

    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, 0, &mem, NULL));
    assert_int_equal(1, list_length(key_store->keys));

    static const uint8_t keyid2[] = {0x7D, 0x0B, 0xC1, 0x0E, 0x93, 0x34, 0x04, 0xC9};
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid2, NULL, NULL);
    assert_non_null(key);

    // confirm the key flags are correct
    assert_int_equal(key->key_flags,
                     PGP_KF_ENCRYPT | PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);

    // check if the key is secret and is locked
    assert_true(pgp_is_key_secret(key));
    assert_true(pgp_key_is_locked(key));

    // decrypt the key
    pgp_seckey_t *seckey = pgp_decrypt_seckey_pgp(
      key->packets[0].raw, key->packets[0].length, pgp_get_pubkey(key), "password");
    assert_non_null(seckey);

    // cleanup
    pgp_seckey_free(seckey);
    free(seckey);
    rnp_key_store_free(key_store);
    pgp_memory_release(&mem);
}

/* This test loads a .gpg pubring with multiple V4 keys,
 * finds a particular key of interest, and confirms that
 * the appropriate key flags are set.
 */
void
test_load_v4_keyring_pgp(void **state)
{
    rnp_test_state_t *rstate = *state;
    char              path[PATH_MAX];
    pgp_io_t          io = {.errs = stderr, .res = stdout, .outs = stdout};
    pgp_memory_t      mem = {0};

    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/1/pubring.gpg", NULL);
    // read the pubring into memory
    assert_true(pgp_mem_readfile(&mem, path));

    rnp_key_store_t *key_store = calloc(1, sizeof(*key_store));
    assert_non_null(key_store);

    // load it in to the key store
    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, 0, &mem, NULL));
    assert_int_equal(7, list_length(key_store->keys));

    // find the key by keyid
    static const uint8_t keyid[] = {0x8a, 0x05, 0xb8, 0x9f, 0xad, 0x5a, 0xde, 0xd1};
    const pgp_key_t *    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL, NULL);
    assert_non_null(key);

    // confirm the key flags are correct
    assert_int_equal(key->key_flags, PGP_KF_ENCRYPT);

    // cleanup
    rnp_key_store_free(key_store);
    pgp_memory_release(&mem);
}

/* Just a helper for the below test */
static void
check_pgp_keyring_counts(const char *   path,
                         unsigned       primary_count,
                         const unsigned subkey_counts[])
{
    pgp_io_t     io = {.errs = stderr, .res = stdout, .outs = stdout};
    pgp_memory_t mem = {0};

    // read the keyring into memory
    assert_true(pgp_mem_readfile(&mem, path));

    rnp_key_store_t *key_store = calloc(1, sizeof(*key_store));
    assert_non_null(key_store);

    // load it in to the key store
    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, 0, &mem, NULL));

    // count primary keys first
    unsigned total_primary_count = 0;
    for (list_item *key_item = list_front(key_store->keys); key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        if (pgp_key_is_primary_key(key)) {
            total_primary_count++;
        }
    }
    assert_int_equal(primary_count, total_primary_count);

    // now count subkeys in each primary key
    unsigned total_subkey_count = 0;
    unsigned primary = 0;
    for (list_item *key_item = list_front(key_store->keys); key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        if (pgp_key_is_primary_key(key)) {
            // check the subkey count for this primary key
            assert_int_equal(list_length(key->subkey_grips), subkey_counts[primary++]);
        } else if (pgp_key_is_subkey(key)) {
            total_subkey_count++;
        }
    }

    // check the total (not really needed)
    assert_int_equal(list_length(key_store->keys), total_primary_count + total_subkey_count);

    // cleanup
    rnp_key_store_free(key_store);
    pgp_memory_release(&mem);
}

/* This test loads a pubring.gpg and secring.gpg and confirms
 * that it contains the expected number of primary keys
 * and the expected number of subkeys for each primary key.
 */
void
test_load_keyring_and_count_pgp(void **state)
{
    rnp_test_state_t *rstate = *state;
    char              path[PATH_MAX];
    static const struct {
        unsigned primary_count;
        unsigned subkey_counts[];
    } expected = {2, {3, 2}};

    // check pubring
    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/1/pubring.gpg", NULL);
    check_pgp_keyring_counts(path, expected.primary_count, expected.subkey_counts);

    // check secring
    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/1/secring.gpg", NULL);
    check_pgp_keyring_counts(path, expected.primary_count, expected.subkey_counts);
}

/* This test loads a V4 keyring and confirms that certain
 * bitfields and time fields are set correctly.
 */
void
test_load_check_bitfields_and_times(void **state)
{
    pgp_io_t         io = {.errs = stderr, .res = stdout, .outs = stdout};
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    const pgp_key_t *key;

    // load keyring
    rnp_key_store_t *key_store = rnp_key_store_new("GPG", "data/keyrings/1/pubring.gpg");
    assert_non_null(key_store);
    assert_true(rnp_key_store_load_from_file(&io, key_store, 0, NULL));

    // find
    key = NULL;
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 3);
    // check subsig properties
    for (unsigned i = 0; i < key->subsigc; i++) {
        const pgp_subsig_t *ss = &key->subsigs[i];
        static const time_t expected_creation_times[] = {1500569820, 1500569836, 1500569846};

        // check SS_ISSUER_KEY_ID
        assert_int_equal(ss->sig.info.signer_id_set, 1);
        assert_int_equal(memcmp(keyid, ss->sig.info.signer_id, PGP_KEY_ID_SIZE), 0);
        // check SS_CREATION_TIME
        assert_int_equal(ss->sig.info.creation_set, 1);
        assert_int_equal(ss->sig.info.creation, expected_creation_times[i]);
        // check SS_EXPIRATION_TIME
        assert_int_equal(ss->sig.info.expiration_set, 0);
        assert_int_equal(ss->sig.info.expiration, 0);
    }
    // check SS_KEY_EXPIRY
    assert_int_equal(key->key.pubkey.expiration, 0);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("1ED63EE56FADC34D", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    assert_int_equal(key->subsigs[0].sig.info.signer_id_set, 1);
    assert_int_equal(memcmp(keyid, key->subsigs[0].sig.info.signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(key->subsigs[0].sig.info.creation_set, 1);
    assert_int_equal(key->subsigs[0].sig.info.creation, 1500569820);
    assert_int_equal(key->subsigs[0].sig.info.creation, key->key.pubkey.pkt.creation_time);
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(key->subsigs[0].sig.info.expiration_set, 0);
    assert_int_equal(key->subsigs[0].sig.info.expiration, 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(key->key.pubkey.expiration, 0);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("1D7E8A5393C997A8", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    assert_int_equal(key->subsigs[0].sig.info.signer_id_set, 1);
    assert_int_equal(memcmp(keyid, key->subsigs[0].sig.info.signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(key->subsigs[0].sig.info.creation_set, 1);
    assert_int_equal(key->subsigs[0].sig.info.creation, 1500569851);
    assert_int_equal(key->subsigs[0].sig.info.creation, key->key.pubkey.pkt.creation_time);
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(key->subsigs[0].sig.info.expiration_set, 0);
    assert_int_equal(key->subsigs[0].sig.info.expiration, 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(key->key.pubkey.expiration, 123 * 24 * 60 * 60 /* 123 days */);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("8A05B89FAD5ADED1", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    assert_int_equal(key->subsigs[0].sig.info.signer_id_set, 1);
    assert_int_equal(memcmp(keyid, key->subsigs[0].sig.info.signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(key->subsigs[0].sig.info.creation_set, 1);
    assert_int_equal(key->subsigs[0].sig.info.creation, 1500569896);
    assert_int_equal(key->subsigs[0].sig.info.creation, key->key.pubkey.pkt.creation_time);
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(key->subsigs[0].sig.info.expiration_set, 0);
    assert_int_equal(key->subsigs[0].sig.info.expiration, 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(key->key.pubkey.expiration, 0);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("2FCADF05FFA501BB", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 3);
    // check subsig properties
    for (unsigned i = 0; i < key->subsigc; i++) {
        const pgp_subsig_t *ss = &key->subsigs[i];
        static const time_t expected_creation_times[] = {1501372449, 1500570153, 1500570147};

        // check SS_ISSUER_KEY_ID
        assert_int_equal(ss->sig.info.signer_id_set, 1);
        assert_int_equal(memcmp(keyid, ss->sig.info.signer_id, PGP_KEY_ID_SIZE), 0);
        // check SS_CREATION_TIME
        assert_int_equal(ss->sig.info.creation_set, 1);
        assert_int_equal(ss->sig.info.creation, expected_creation_times[i]);
        // check SS_EXPIRATION_TIME
        assert_int_equal(ss->sig.info.expiration_set, 0);
        assert_int_equal(ss->sig.info.expiration, 0);
    }
    // check SS_KEY_EXPIRY
    assert_int_equal(key->key.pubkey.expiration, 2076663808);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("54505A936A4A970E", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("2FCADF05FFA501BB", keyid, sizeof(keyid)));
    assert_int_equal(key->subsigs[0].sig.info.signer_id_set, 1);
    assert_int_equal(memcmp(keyid, key->subsigs[0].sig.info.signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(key->subsigs[0].sig.info.creation_set, 1);
    assert_int_equal(key->subsigs[0].sig.info.creation, 1500569946);
    assert_int_equal(key->subsigs[0].sig.info.creation, key->key.pubkey.pkt.creation_time);
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(key->subsigs[0].sig.info.expiration_set, 0);
    assert_int_equal(key->subsigs[0].sig.info.expiration, 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(key->key.pubkey.expiration, 2076663808);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("326EF111425D14A5", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("2FCADF05FFA501BB", keyid, sizeof(keyid)));
    assert_int_equal(key->subsigs[0].sig.info.signer_id_set, 1);
    assert_int_equal(memcmp(keyid, key->subsigs[0].sig.info.signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(key->subsigs[0].sig.info.creation_set, 1);
    assert_int_equal(key->subsigs[0].sig.info.creation, 1500570165);
    assert_int_equal(key->subsigs[0].sig.info.creation, key->key.pubkey.pkt.creation_time);
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(key->subsigs[0].sig.info.expiration_set, 0);
    assert_int_equal(key->subsigs[0].sig.info.expiration, 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(key->key.pubkey.expiration, 0);

    // cleanup
    rnp_key_store_free(key_store);
}

/* This test loads a V3 keyring and confirms that certain
 * bitfields and time fields are set correctly.
 */
void
test_load_check_bitfields_and_times_v3(void **state)
{
    pgp_io_t         io = {.errs = stderr, .res = stdout, .outs = stdout};
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    const pgp_key_t *key;

    // load keyring
    rnp_key_store_t *key_store = rnp_key_store_new("GPG", "data/keyrings/2/pubring.gpg");
    assert_non_null(key_store);
    assert_true(rnp_key_store_load_from_file(&io, key_store, 0, NULL));

    // find
    key = NULL;
    assert_true(rnp_hex_decode("DC70C124A50283F1", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL, NULL);
    assert_non_null(key);
    // check key version
    assert_int_equal(key->key.pubkey.pkt.version, PGP_V3);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check signature version
    assert_int_equal(key->subsigs[0].sig.info.version, 3);
    // check issuer
    assert_true(rnp_hex_decode("DC70C124A50283F1", keyid, sizeof(keyid)));
    assert_int_equal(key->subsigs[0].sig.info.signer_id_set, 1);
    assert_int_equal(memcmp(keyid, key->subsigs[0].sig.info.signer_id, PGP_KEY_ID_SIZE), 0);
    // check creation time
    assert_int_equal(key->subsigs[0].sig.info.creation_set, 1);
    assert_int_equal(key->subsigs[0].sig.info.creation, 1005209227);
    assert_int_equal(key->subsigs[0].sig.info.creation, key->key.pubkey.pkt.creation_time);
    // check signature expiration time (V3 sigs have none)
    assert_int_equal(key->subsigs[0].sig.info.expiration_set, 0);
    assert_int_equal(key->subsigs[0].sig.info.expiration, 0);
    // check key expiration
    assert_int_equal(key->key.pubkey.expiration, 0); // only for V4 keys
    assert_int_equal(key->key.pubkey.pkt.v3_days, 0);

    // cleanup
    rnp_key_store_free(key_store);
}
