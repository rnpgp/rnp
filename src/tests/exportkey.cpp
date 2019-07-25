/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

void
rnpkeys_exportkey_verifyUserId(void **state)
{
    /* Generate the key and export it */
    cli_rnp_t rnp = {};
    rnp_cfg_t cfg = {};
    int       pipefd[2];

    /* Initialize the rnp structure. */
    assert_true(setup_cli_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));
    rnp_cfg_init(&cfg);

    /* Generate the key */
    cli_set_default_rsa_key_desc(&cfg, "SHA256");

    assert_true(cli_rnp_generate_key(&cfg, &rnp, NULL));

    /* Loading keyrings and checking whether they have correct key */
    assert_true(cli_rnp_load_keyrings(&rnp, true));
    size_t keycount = 0;
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);

    list keys = cli_rnp_get_keylist(&rnp, getenv("LOGNAME"), false);
    assert_int_equal(list_length(keys), 2);
    cli_rnp_keylist_destroy(&keys);

    /* Try to export the key with specified userid parameter from the env */
    assert_true(cli_rnp_export_keys(&cfg, &rnp, getenv("LOGNAME")));

    /* try to export the key with specified userid parameter (which is wrong) */
    assert_false(cli_rnp_export_keys(&cfg, &rnp, "LOGNAME"));

    close(pipefd[0]);
    cli_rnp_end(&rnp); // Free memory and other allocated resources.
    rnp_cfg_free(&cfg);
}
