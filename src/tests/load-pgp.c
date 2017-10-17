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
    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, 0, &mem));
    assert_int_equal(1, key_store->keyc);

    // find the key by keyid
    static const uint8_t keyid[] = {0xDC, 0x70, 0xC1, 0x24, 0xA5, 0x02, 0x83, 0xF1};
    unsigned             from = 0;
    const pgp_key_t *    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, &from, NULL);
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

    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, 0, &mem));
    assert_int_equal(1, key_store->keyc);

    static const uint8_t keyid2[] = {0x7D, 0x0B, 0xC1, 0x0E, 0x93, 0x34, 0x04, 0xC9};
    from = 0;
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid2, &from, NULL);
    assert_non_null(key);

    // confirm the key flags are correct
    assert_int_equal(key->key_flags,
        PGP_KF_ENCRYPT | PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);

    // check if the key is secret and is locked
    assert_true(pgp_is_key_secret(key));
    assert_true(pgp_key_is_locked(key));

    // decrypt the key
    pgp_seckey_t *seckey = pgp_decrypt_seckey_pgp(key->packets[0].raw, key->packets[0].length, pgp_get_pubkey(key), "password");
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
    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, 0, &mem));
    assert_int_equal(7, key_store->keyc);

    // find the key by keyid
    static const uint8_t keyid[] = {0x8a, 0x05, 0xb8, 0x9f, 0xad, 0x5a, 0xde, 0xd1};
    unsigned             from = 0;
    const pgp_key_t *    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, &from, NULL);
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
    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, 0, &mem));

    // count primary keys first
    unsigned total_primary_count = 0;
    for (unsigned i = 0; i < key_store->keyc; i++) {
        pgp_key_t *key = &key_store->keys[i];
        if (pgp_key_is_primary_key(key)) {
            total_primary_count++;
        }
    }
    assert_int_equal(primary_count, total_primary_count);

    // now count subkeys in each primary key
    unsigned total_subkey_count = 0;
    unsigned primary = 0;
    for (unsigned i = 0; i < key_store->keyc; i++) {
        pgp_key_t *key = &key_store->keys[i];
        if (pgp_key_is_primary_key(key)) {
            // check the subkey count for this primary key
            assert_int_equal(key->subkeyc, subkey_counts[primary++]);
        } else if (pgp_key_is_subkey(key)) {
            total_subkey_count++;
        }
    }

    // check the total (not really needed)
    assert_int_equal(key_store->keyc, total_primary_count + total_subkey_count);

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
