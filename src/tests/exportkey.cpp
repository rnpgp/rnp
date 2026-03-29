/*
 * Copyright (c) 2017-2020 [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "rnp.h"
#include <rekey/rnp_key_store.h>
#include "rnp_tests.h"
#include "support.h"
#include "../rnp/fficli.h"

TEST_F(rnp_tests, rnpkeys_exportkey_verifyUserId)
{
    /* Generate the key and export it */
    cli_rnp_t rnp = {};
    int       pipefd[2] = {-1, -1};

    /* Initialize the rnp structure. */
    assert_true(setup_cli_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));
    /* Generate the key */
    cli_set_default_rsa_key_desc(rnp.cfg(), "SHA256");
    assert_true(cli_rnp_generate_key(&rnp, NULL));

    /* Loading keyrings and checking whether they have correct key */
    assert_true(rnp.load_keyrings(true));
    size_t keycount = 0;
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);

    std::vector<rnp_key_handle_t> keys;
    assert_true(rnp.keys_matching(keys, getenv_logname(), CLI_SEARCH_SUBKEYS_AFTER));
    assert_int_equal(keys.size(), 2);
    clear_key_handles(keys);

    /* Try to export the key with specified userid parameter from the env */
    assert_true(cli_rnp_export_keys(&rnp, getenv_logname()));

    /* try to export the key with specified userid parameter (which is wrong) */
    assert_false(cli_rnp_export_keys(&rnp, "LOGNAME"));

    if (pipefd[0] != -1) {
        close(pipefd[0]);
    }
    rnp.end(); // Free memory and other allocated resources.
}

TEST_F(rnp_tests, rnpkeys_exportkey_autocrypt)
{
    /* Set up CLI rnp pointing at keyring 1 (has key 7bc6709b15c23a4a with multiple UIDs
     * and an encryption subkey 8a05b89fad5aded1). */
    cli_rnp_t rnp = {};
    int       pipefd[2] = {-1, -1};
    assert_true(
      setup_cli_rnp_common(&rnp, RNP_KEYSTORE_GPG, "data/keyrings/1", pipefd));
    assert_true(rnp.load_keyrings(false));

    /* Export with explicit keyid filter and userid, verify output is valid. */
    rnp.cfg().set_str(CFG_OUTFILE, "ac-out.pgp");
    rnp.cfg().add_str(CFG_USERID, "key0-uid0");
    assert_true(cli_rnp_export_autocrypt_key(&rnp, "7bc6709b15c23a4a"));

    /* Re-import the exported data into a fresh FFI and verify structure. */
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_true(import_all_keys(ffi, "ac-out.pgp"));
    size_t count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 2);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(count, 0);
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_non_null(key);
    rnp_key_handle_t sub = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "8a05b89fad5aded1", &sub));
    assert_non_null(sub);
    /* Only one UID should be present in the autocrypt export. */
    assert_rnp_success(rnp_key_get_uid_count(key, &count));
    assert_int_equal(count, 1);
    char *uid_str = NULL;
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid_str));
    assert_string_equal(uid_str, "key0-uid0");
    rnp_buffer_destroy(uid_str);
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);

    /* A non-matching filter should return false. */
    rnp.cfg().set_str(CFG_OUTFILE, "ac-out2.pgp");
    assert_false(cli_rnp_export_autocrypt_key(&rnp, "nosuchkey"));

    if (pipefd[0] != -1) {
        close(pipefd[0]);
    }
    rnp.end();
}
