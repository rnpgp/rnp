/*
 * Copyright (c) 2021 [Ribose Inc](https://www.ribose.com).
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

#include <sstream>
#include <rnp/rnp.h>
#include "rnp_tests.h"
#include "support.h"

TEST_F(rnp_tests, test_ffi_key_set_expiry_multiple_uids)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));

    /* load key with 3 uids with zero key expiration */
    assert_true(import_all_keys(ffi, "data/test_key_edge_cases/alice-3-uids.pgp"));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    size_t count = 0;
    assert_rnp_success(rnp_key_get_uid_count(key, &count));
    assert_int_equal(count, 3);
    uint32_t expiry = 10;
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    assert_true(check_uid_primary(key, 0, false));
    assert_true(check_uid_primary(key, 1, false));
    assert_true(check_uid_primary(key, 2, false));
    /* set expiration time to minimum value so key is expired now, but uids are still valid */
    assert_rnp_success(rnp_key_set_expiration(key, 1));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 1);
    bool valid = true;
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_false(valid);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    /* reload */
    rnp_key_handle_destroy(key);
    reload_keyrings(&ffi);
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 1);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    /* set expiration to maximum value */
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_key_set_expiration(key, 0xFFFFFFFF));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0xFFFFFFFF);
    valid = false;
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_true(valid);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    rnp_key_handle_destroy(key);
    /* reload and make sure changes are saved */
    reload_keyrings(&ffi);
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Caesar <caesar@rnp>", &key));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0xFFFFFFFF);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    rnp_key_handle_destroy(key);

    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    /* load key with 3 uids, including primary, with key expiration */
    assert_true(
      import_all_keys(ffi, "data/test_key_edge_cases/alice-3-uids-primary-expiring.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    expiry = 0;
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 674700647);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    assert_true(check_uid_primary(key, 0, true));
    assert_true(check_uid_primary(key, 1, false));
    assert_true(check_uid_primary(key, 2, false));
    assert_rnp_success(rnp_key_unlock(key, "password"));
    assert_rnp_success(rnp_key_set_expiration(key, 0));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    valid = false;
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_true(valid);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    rnp_key_handle_destroy(key);
    /* reload and make sure it is saved */
    reload_keyrings(&ffi);
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Caesar <caesar@rnp>", &key));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    assert_true(check_uid_primary(key, 0, true));
    rnp_key_handle_destroy(key);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_primary_uid_conflict)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));

    /* load key with 1 uid and two certifications: first marks uid primary, but expires key
     * second marks uid as non-primary, but has zero key expiration */
    assert_true(
      import_all_keys(ffi, "data/test_key_edge_cases/key-primary-uid-conflict-pub.pgp"));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "userid_2_sigs", &key));
    assert_int_equal(get_key_uids(key), 1);
    assert_int_equal(get_key_expiry(key), 0);
    assert_true(check_key_valid(key, true));
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_primary(key, 0, false));
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_expired_certification_and_direct_sig)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));

    /* load key with 2 uids and direct-key signature:
     * - direct-key sig has 0 key expiration time but expires in 30 seconds
     * - first uid is not primary, but key expiration is 60 seconds
     * - second uid is marked as primary, doesn't expire key, but certification expires in 60
     *   seconds */
    assert_true(import_all_keys(ffi, "data/test_key_edge_cases/key-expired-cert-direct.pgp"));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "primary-uid-expired-cert", &key));
    assert_null(key);
    assert_rnp_success(rnp_locate_key(ffi, "userid", "expired-certifications", &key));
    assert_non_null(key);
    assert_int_equal(get_key_uids(key), 2);
    assert_int_equal(get_key_expiry(key), 60);
    rnp_signature_handle_t sig = NULL;
    assert_rnp_success(rnp_key_get_signature_at(key, 0, &sig));
    assert_non_null(sig);
    assert_int_equal(rnp_signature_is_valid(sig, 0), RNP_ERROR_SIGNATURE_EXPIRED);
    rnp_signature_handle_destroy(sig);
    assert_true(check_key_valid(key, false));
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_primary(key, 0, false));
    assert_true(check_uid_valid(key, 1, false));
    assert_true(check_uid_primary(key, 1, false));
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_25519_tweaked_bits)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    /* try public key */
    assert_true(import_all_keys(ffi, "data/test_key_edge_cases/key-25519-non-tweaked.asc"));
    rnp_key_handle_t sub = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "950EE0CD34613DBA", &sub));
    bool tweaked = true;
    assert_rnp_failure(rnp_key_25519_bits_tweaked(NULL, &tweaked));
    assert_rnp_failure(rnp_key_25519_bits_tweaked(sub, NULL));
    assert_rnp_failure(rnp_key_25519_bits_tweaked(sub, &tweaked));
    assert_rnp_failure(rnp_key_25519_bits_tweak(NULL));
    assert_rnp_failure(rnp_key_25519_bits_tweak(sub));
    rnp_key_handle_destroy(sub);
    /* load secret key */
    assert_true(
      import_all_keys(ffi, "data/test_key_edge_cases/key-25519-non-tweaked-sec.asc"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "950EE0CD34613DBA", &sub));
    assert_rnp_failure(rnp_key_25519_bits_tweaked(NULL, &tweaked));
    assert_rnp_failure(rnp_key_25519_bits_tweaked(sub, NULL));
    assert_rnp_success(rnp_key_25519_bits_tweaked(sub, &tweaked));
    assert_false(tweaked);
    /* protect key and try again */
    assert_rnp_success(rnp_key_protect(sub, "password", NULL, NULL, NULL, 100000));
    assert_rnp_failure(rnp_key_25519_bits_tweaked(sub, &tweaked));
    assert_rnp_success(rnp_key_unlock(sub, "password"));
    tweaked = true;
    assert_rnp_success(rnp_key_25519_bits_tweaked(sub, &tweaked));
    assert_false(tweaked);
    assert_rnp_success(rnp_key_lock(sub));
    assert_rnp_failure(rnp_key_25519_bits_tweaked(sub, &tweaked));
    /* now let's tweak it */
    assert_rnp_failure(rnp_key_25519_bits_tweak(NULL));
    assert_rnp_failure(rnp_key_25519_bits_tweak(sub));
    assert_rnp_success(rnp_key_unlock(sub, "password"));
    assert_rnp_failure(rnp_key_25519_bits_tweak(sub));
    assert_rnp_success(rnp_key_unprotect(sub, "password"));
    assert_rnp_success(rnp_key_25519_bits_tweak(sub));
    assert_rnp_success(rnp_key_25519_bits_tweaked(sub, &tweaked));
    assert_true(tweaked);
    /* export unprotected key */
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "3176FC1486AA2528", &key));
    auto clearsecdata = export_key(key, true, true);
    rnp_key_handle_destroy(key);
    assert_rnp_success(rnp_key_protect(sub, "password", NULL, NULL, NULL, 100000));
    rnp_key_handle_destroy(sub);
    /* make sure it is exported and saved tweaked and protected */
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "3176FC1486AA2528", &key));
    auto secdata = export_key(key, true, true);
    rnp_key_handle_destroy(key);
    reload_keyrings(&ffi);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "950EE0CD34613DBA", &sub));
    bool prot = false;
    assert_rnp_success(rnp_key_is_protected(sub, &prot));
    assert_true(prot);
    assert_rnp_success(rnp_key_unlock(sub, "password"));
    tweaked = false;
    assert_rnp_success(rnp_key_25519_bits_tweaked(sub, &tweaked));
    assert_true(tweaked);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
    /* import cleartext exported key */
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_true(import_all_keys(ffi, clearsecdata.data(), clearsecdata.size()));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "950EE0CD34613DBA", &sub));
    prot = true;
    assert_rnp_success(rnp_key_is_protected(sub, &prot));
    assert_false(prot);
    tweaked = false;
    assert_rnp_success(rnp_key_25519_bits_tweaked(sub, &tweaked));
    assert_true(tweaked);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
    /* import exported key */
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_true(import_all_keys(ffi, secdata.data(), secdata.size()));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "950EE0CD34613DBA", &sub));
    prot = false;
    assert_rnp_success(rnp_key_is_protected(sub, &prot));
    assert_true(prot);
    assert_rnp_success(rnp_key_unlock(sub, "password"));
    tweaked = false;
    assert_rnp_success(rnp_key_25519_bits_tweaked(sub, &tweaked));
    assert_true(tweaked);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
}
