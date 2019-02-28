/*
 * Copyright (c) 2019, [Ribose Inc](https://www.ribose.com).
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

#include "pgp-key.h"

#include "rnp_tests.h"
#include "support.h"

void
test_key_prefs(void **state)
{
    pgp_user_prefs_t pref1 = {};
    pgp_user_prefs_t pref2 = {};

    /* symm algs */
    assert_true(pgp_user_prefs_add_symm_alg(&pref1, PGP_SA_AES_256));
    assert_true(pgp_user_prefs_add_symm_alg(&pref1, PGP_SA_AES_256));
    assert_true(pgp_user_prefs_add_symm_alg(&pref1, PGP_SA_AES_192));
    assert_true(pgp_user_prefs_add_symm_alg(&pref1, PGP_SA_AES_192));
    assert_true(pgp_user_prefs_add_symm_alg(&pref1, PGP_SA_AES_128));
    assert_true(pgp_user_prefs_add_symm_alg(&pref1, PGP_SA_AES_128));
    assert_int_equal(pref1.symm_alg_count, 3);
    assert_int_equal(pref1.symm_algs[0], PGP_SA_AES_256);
    assert_int_equal(pref1.symm_algs[1], PGP_SA_AES_192);
    assert_int_equal(pref1.symm_algs[2], PGP_SA_AES_128);
    assert_true(pgp_user_prefs_add_symm_alg(&pref2, PGP_SA_CAMELLIA_128));
    assert_true(pgp_user_prefs_add_symm_alg(&pref2, PGP_SA_CAMELLIA_192));
    assert_true(pgp_user_prefs_add_symm_alg(&pref2, PGP_SA_CAMELLIA_256));
    assert_true(pgp_user_prefs_set_symm_algs(&pref1, pref2.symm_algs, pref2.symm_alg_count));
    assert_int_equal(pref1.symm_alg_count, 3);
    assert_int_equal(pref1.symm_algs[0], PGP_SA_CAMELLIA_128);
    assert_int_equal(pref1.symm_algs[1], PGP_SA_CAMELLIA_192);
    assert_int_equal(pref1.symm_algs[2], PGP_SA_CAMELLIA_256);
    /* hash algs */
    assert_true(pgp_user_prefs_add_hash_alg(&pref1, PGP_HASH_SHA512));
    assert_true(pgp_user_prefs_add_hash_alg(&pref1, PGP_HASH_SHA384));
    assert_true(pgp_user_prefs_add_hash_alg(&pref1, PGP_HASH_SHA512));
    assert_true(pgp_user_prefs_add_hash_alg(&pref1, PGP_HASH_SHA384));
    assert_true(pgp_user_prefs_add_hash_alg(&pref1, PGP_HASH_SHA256));
    assert_true(pgp_user_prefs_add_hash_alg(&pref1, PGP_HASH_SHA256));
    assert_int_equal(pref1.hash_alg_count, 3);
    assert_int_equal(pref1.hash_algs[0], PGP_HASH_SHA512);
    assert_int_equal(pref1.hash_algs[1], PGP_HASH_SHA384);
    assert_int_equal(pref1.hash_algs[2], PGP_HASH_SHA256);
    assert_true(pgp_user_prefs_add_hash_alg(&pref2, PGP_HASH_SHA3_512));
    assert_true(pgp_user_prefs_add_hash_alg(&pref2, PGP_HASH_SHA3_256));
    assert_true(pgp_user_prefs_add_hash_alg(&pref2, PGP_HASH_SHA1));
    assert_true(pgp_user_prefs_set_hash_algs(&pref1, pref2.hash_algs, pref2.hash_alg_count));
    assert_int_equal(pref1.hash_alg_count, 3);
    assert_int_equal(pref1.hash_algs[0], PGP_HASH_SHA3_512);
    assert_int_equal(pref1.hash_algs[1], PGP_HASH_SHA3_256);
    assert_int_equal(pref1.hash_algs[2], PGP_HASH_SHA1);
    /* z algs */
    assert_true(pgp_user_prefs_add_z_alg(&pref1, PGP_C_ZIP));
    assert_true(pgp_user_prefs_add_z_alg(&pref1, PGP_C_ZLIB));
    assert_true(pgp_user_prefs_add_z_alg(&pref1, PGP_C_BZIP2));
    assert_true(pgp_user_prefs_add_z_alg(&pref1, PGP_C_ZIP));
    assert_true(pgp_user_prefs_add_z_alg(&pref1, PGP_C_ZLIB));
    assert_true(pgp_user_prefs_add_z_alg(&pref1, PGP_C_BZIP2));
    assert_int_equal(pref1.z_alg_count, 3);
    assert_int_equal(pref1.z_algs[0], PGP_C_ZIP);
    assert_int_equal(pref1.z_algs[1], PGP_C_ZLIB);
    assert_int_equal(pref1.z_algs[2], PGP_C_BZIP2);
    assert_true(pgp_user_prefs_add_z_alg(&pref2, PGP_C_BZIP2));
    assert_true(pgp_user_prefs_set_z_algs(&pref1, pref2.z_algs, pref2.z_alg_count));
    assert_int_equal(pref1.z_alg_count, 1);
    assert_int_equal(pref1.z_algs[0], PGP_C_BZIP2);
    /* ks prefs */
    assert_true(pgp_user_prefs_add_ks_pref(&pref1, PGP_KEY_SERVER_NO_MODIFY));
    assert_int_equal(pref1.ks_pref_count, 1);
    assert_int_equal(pref1.ks_prefs[0], PGP_KEY_SERVER_NO_MODIFY);
    assert_true(pgp_user_prefs_add_ks_pref(&pref2, (pgp_key_server_prefs_t) 0x20));
    assert_true(pgp_user_prefs_add_ks_pref(&pref2, (pgp_key_server_prefs_t) 0x40));
    assert_true(pgp_user_prefs_set_ks_prefs(&pref1, pref2.ks_prefs, pref2.ks_pref_count));
    assert_int_equal(pref1.ks_pref_count, 2);
    assert_int_equal(pref1.ks_prefs[0], 0x20);
    assert_int_equal(pref1.ks_prefs[1], 0x40);
    /* ks url */
    pref1.key_server = (uint8_t*) strdup("hkp://something/");
    /* now free prefs */
    pgp_free_user_prefs(&pref1);
    pgp_free_user_prefs(&pref2);
}
