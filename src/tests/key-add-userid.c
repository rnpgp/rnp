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
#include "utils.h"
#include "crypto/hash.h"

/* This test loads a pgp keyring and adds a few userids to the key.
 */
void
test_key_add_userid(void **state)
{
    rnp_test_state_t * rstate = *state;
    char               path[PATH_MAX];
    pgp_io_t           io = {.errs = stderr, .res = stdout, .outs = stdout};
    pgp_key_t *        key = NULL;
    static const char *keyids[] = {"7bc6709b15c23a4a", // primary
                                   "1ed63ee56fadc34d",
                                   "1d7e8a5393c997a8",
                                   "8a05b89fad5aded1",
                                   "2fcadf05ffa501bb", // primary
                                   "54505a936a4a970e",
                                   "326ef111425d14a5"};

    rnp_key_store_t *ks = calloc(1, sizeof(*ks));
    assert_non_null(ks);

    pgp_memory_t mem = {0};
    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/1/secring.gpg", NULL);
    assert_true(pgp_mem_readfile(&mem, path));
    assert_true(rnp_key_store_pgp_read_from_mem(&io, ks, &mem, NULL));
    pgp_memory_release(&mem);

    // locate our key
    assert_non_null(key = rnp_key_store_get_key_by_name(&io, ks, keyids[0], NULL));
    assert_non_null(key);

    // unlock the key
    assert_true(
      pgp_key_unlock(key,
                     &(pgp_password_provider_t){.callback = string_copy_password_callback,
                                                .userdata = "password"}));

    // save the counts for a few items
    unsigned uidc = key->uidc;
    unsigned subsigc = key->subsigc;

    // add a userid
    assert_true(pgp_key_add_userid(
      key,
      pgp_get_key_pkt(key),
      PGP_HASH_SHA1,
      &(rnp_selfsig_cert_info){
        .userid = "added1", .key_flags = 0xAB, .key_expiration = 123456789, .primary = 1}));

    // make sure this userid has been marked as primary
    assert_int_equal(key->uidc - 1, key->uid0);

    // try to add the same userid (should fail)
    assert_false(pgp_key_add_userid(
      key, pgp_get_key_pkt(key), PGP_HASH_SHA1, &(rnp_selfsig_cert_info){.userid = "added1"}));

    // try to add another primary userid (should fail)
    assert_false(
      pgp_key_add_userid(key,
                         pgp_get_key_pkt(key),
                         PGP_HASH_SHA1,
                         &(rnp_selfsig_cert_info){.userid = "added2", .primary = 1}));

    // actually add another userid
    assert_true(
      pgp_key_add_userid(key,
                         pgp_get_key_pkt(key),
                         PGP_HASH_SHA1,
                         &(rnp_selfsig_cert_info){.userid = "added2", .key_flags = 0xCD}));

    // confirm that the counts have increased as expected
    assert_int_equal(key->uidc, uidc + 2);
    assert_int_equal(key->subsigc, subsigc + 2);

    // check the userids array
    // added1
    assert_int_equal(0, strcmp((char *) key->uids[key->uidc - 2], "added1"));
    assert_int_equal(key->uidc - 2, key->subsigs[key->subsigc - 2].uid);
    assert_int_equal(0xAB, key->subsigs[key->subsigc - 2].key_flags);
    assert_int_equal(123456789, key->expiration);
    // added2
    assert_int_equal(0, strcmp((char *) key->uids[key->uidc - 1], "added2"));
    assert_int_equal(key->uidc - 1, key->subsigs[key->subsigc - 1].uid);
    assert_int_equal(0xCD, key->subsigs[key->subsigc - 1].key_flags);

    // save the raw packets for the key (to reload later)
    mem = (pgp_memory_t){0};
    for (unsigned i = 0; i < key->packetc; i++) {
        pgp_memory_add(&mem, key->packets[i].raw, key->packets[i].length);
    }
    // cleanup
    rnp_key_store_free(ks);
    key = NULL;

    // start over
    ks = calloc(1, sizeof(*ks));
    assert_non_null(ks);
    // read from the saved packets
    assert_true(rnp_key_store_pgp_read_from_mem(&io, ks, &mem, NULL));
    pgp_memory_release(&mem);
    assert_non_null(key = rnp_key_store_get_key_by_name(&io, ks, keyids[0], NULL));

    // confirm that the counts have increased as expected
    assert_int_equal(key->uidc, uidc + 2);
    assert_int_equal(key->subsigc, subsigc + 2);

    // check the userids array
    // added1
    assert_int_equal(0, strcmp((char *) key->uids[key->uidc - 2], "added1"));
    assert_int_equal(key->uidc - 2, key->subsigs[key->subsigc - 2].uid);
    assert_int_equal(0xAB, key->subsigs[key->subsigc - 2].key_flags);
    assert_int_equal(123456789, key->expiration);
    // added2
    assert_int_equal(0, strcmp((char *) key->uids[key->uidc - 1], "added2"));
    assert_int_equal(key->uidc - 1, key->subsigs[key->subsigc - 1].uid);
    assert_int_equal(0xCD, key->subsigs[key->subsigc - 1].key_flags);

    // cleanup
    rnp_key_store_free(ks);
}
