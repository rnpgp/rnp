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

#include <rnp/rnp.h>
#include <rekey/rnp_key_store.h>
#include "rnp_tests.h"
#include "support.h"

void
rnpkeys_exportkey_verifyUserId(void **state)
{
    /* Generate the key and export it */
    rnp_test_state_t *rstate = *state;
    rnp_t             rnp;
    int               pipefd[2];
    char *            exportedkey = NULL;

    /* Initialize the rnp structure. */
    rnp_assert_ok(
      rstate,
      setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd, "passwordforkeygeneration\n"));

    /* Generate the key */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
    rnp_assert_ok(rstate, rnp_generate_key(&rnp));

    /* Loading keyrings and checking whether they have correct key */
    rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, 1));
    rnp_assert_int_not_equal(rstate, 0, rnp_secret_count(&rnp));
    rnp_assert_int_not_equal(rstate, 0, rnp_public_count(&rnp));
    rnp_assert_true(rstate, rnp_find_key(&rnp, getenv("LOGNAME")));

    /* Try to export the key without passing userid from the interface : this should fail*/
    exportedkey = rnp_export_key(&rnp, NULL);
    rnp_assert_null(rstate, exportedkey);
    free(exportedkey);

    /* Try to export the key with specified userid parameter from the env */
    exportedkey = rnp_export_key(&rnp, getenv("LOGNAME"));
    rnp_assert_non_null(rstate, exportedkey);
    free(exportedkey);

    /* try to export the key with specified userid parameter (which is wrong) */
    exportedkey = rnp_export_key(&rnp, "LOGNAME");
    rnp_assert_null(rstate, exportedkey);
    free(exportedkey);
    rnp_end(&rnp); // Free memory and other allocated resources.
}
