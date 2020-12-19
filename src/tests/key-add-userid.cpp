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
#include "crypto/hash.h"

/* This test loads a pgp keyring and adds a few userids to the key.
 */
TEST_F(rnp_tests, test_key_add_userid)
{
    pgp_key_t *        key = NULL;
    pgp_source_t       src = {};
    pgp_dest_t         dst = {};
    static const char *keyids[] = {"7bc6709b15c23a4a", // primary
                                   "1ed63ee56fadc34d",
                                   "1d7e8a5393c997a8",
                                   "8a05b89fad5aded1",
                                   "2fcadf05ffa501bb", // primary
                                   "54505a936a4a970e",
                                   "326ef111425d14a5"};

    rnp_key_store_t *ks = new rnp_key_store_t();

    assert_rnp_success(init_file_src(&src, "data/keyrings/1/secring.gpg"));
    assert_rnp_success(rnp_key_store_pgp_read_from_src(ks, &src));
    src_close(&src);

    // locate our key
    assert_non_null(key = rnp_tests_get_key_by_id(ks, keyids[0], NULL));
    assert_non_null(key);

    // unlock the key
    pgp_password_provider_t pprov = {.callback = string_copy_password_callback,
                                     .userdata = (void *) "password"};
    assert_true(key->unlock(pprov));

    // save the counts for a few items
    unsigned uidc = key->uid_count();
    unsigned subsigc = key->sig_count();

    // add a userid

    rnp_selfsig_cert_info_t selfsig = {};
    memcpy(selfsig.userid, "added1", 7);
    selfsig.key_flags = 0xAB;
    selfsig.key_expiration = 123456789;
    selfsig.primary = 1;
    assert_true(pgp_key_add_userid_certified(key, &key->pkt(), PGP_HASH_SHA1, &selfsig));

    // make sure this userid has been marked as primary
    assert_int_equal(key->uid_count() - 1, key->uid0);
    // make sure key expiration and flags are set
    assert_int_equal(123456789, key->expiration());
    assert_int_equal(0xAB, key->flags());

    // try to add the same userid (should fail)
    rnp_selfsig_cert_info_t dup_selfsig = {};
    memcpy(dup_selfsig.userid, "added1", 7);
    assert_false(pgp_key_add_userid_certified(key, &key->pkt(), PGP_HASH_SHA1, &dup_selfsig));

    // try to add another primary userid (should fail)
    rnp_selfsig_cert_info_t selfsig2 = {};
    memcpy(selfsig2.userid, "added2", 7);
    selfsig2.primary = 1;
    assert_false(pgp_key_add_userid_certified(key, &key->pkt(), PGP_HASH_SHA1, &selfsig2));

    memcpy(selfsig2.userid, "added2", 7);
    selfsig2.key_flags = 0xCD;
    selfsig2.primary = 0;

    // actually add another userid
    assert_true(pgp_key_add_userid_certified(key, &key->pkt(), PGP_HASH_SHA1, &selfsig2));

    // confirm that the counts have increased as expected
    assert_int_equal(key->uid_count(), uidc + 2);
    assert_int_equal(key->sig_count(), subsigc + 2);

    // make sure key expiration and flags are now updated
    assert_int_equal(0, key->expiration());
    assert_int_equal(0xCD, key->flags());
    // check the userids array
    // added1
    assert_true(key->get_uid(uidc).str == "added1");
    assert_int_equal(uidc, key->get_sig(subsigc).uid);
    assert_int_equal(0xAB, key->get_sig(subsigc).key_flags);
    // added2
    assert_true(key->get_uid(uidc + 1).str == "added2");
    assert_int_equal(uidc + 1, key->get_sig(subsigc + 1).uid);
    assert_int_equal(0xCD, key->get_sig(subsigc + 1).key_flags);

    // save the raw packets for the key (to reload later)
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    key->write(dst);
    // cleanup
    delete ks;
    key = NULL;

    // start over
    ks = new rnp_key_store_t();
    assert_non_null(ks);
    // read from the saved packets
    assert_rnp_success(init_mem_src(&src, mem_dest_get_memory(&dst), dst.writeb, false));
    assert_rnp_success(rnp_key_store_pgp_read_from_src(ks, &src));
    src_close(&src);
    dst_close(&dst, true);
    assert_non_null(key = rnp_tests_get_key_by_id(ks, keyids[0], NULL));

    // confirm that the counts have increased as expected
    assert_int_equal(key->uid_count(), uidc + 2);
    assert_int_equal(key->sig_count(), subsigc + 2);

    // make sure correct key expiration and flags are set
    assert_int_equal(0, key->expiration());
    assert_int_equal(0xCD, key->flags());

    // check the userids array
    // added1
    assert_true(key->get_uid(uidc).str == "added1");
    assert_int_equal(uidc, key->get_sig(subsigc).uid);
    assert_int_equal(0xAB, key->get_sig(subsigc).key_flags);
    // added2
    assert_true(key->get_uid(uidc + 1).str == "added2");
    assert_int_equal(uidc + 1, key->get_sig(subsigc + 1).uid);
    assert_int_equal(0xCD, key->get_sig(subsigc + 1).key_flags);

    // cleanup
    delete ks;
}
