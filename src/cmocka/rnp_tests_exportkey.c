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

#include <rnp.h>

#include "rnp_tests.h"
#include "rnp_tests_support.h"

void
rnpkeys_exportkey_verifyUserId(void **state)
{
    rnp_test_state_t *rstate = *state;
    /* * Execute the Generate-key command to generate a new pair of private/public
     * key
     * Verify the key was generated with the correct UserId.
     */
    rnp_t rnp;
    char  passfd[4] = {0};
    int   pipefd[2];
    char *fdptr;
    char *exportedkey = NULL;

    /* Setup the pass phrase fd to avoid user-input*/
    rnp_assert_int_equal(rstate, setupPassphrasefd(pipefd), 1);
    /*Initialize the basic RNP structure. */
    fdptr = uint_to_string(passfd, 4, pipefd[0], 10);
    rnp_assert_int_equal(
      rstate,
      1,
      setup_rnp_common(&rnp,
                       fdptr)); // Ensure the rnp core structure is correctly initialized.
    rnp_assert_int_equal(rstate, 1, rnp_setvar(&rnp, "hash", "SHA256"));

    rnp.action.generate_key_ctx.key_alg = PGP_PKA_RSA;
    rnp.action.generate_key_ctx.sym_alg = PGP_SA_DEFAULT_CIPHER;
    rnp.action.generate_key_ctx.rsa.modulus_bit_len = 1024;
    rnp_assert_int_equal(
      rstate, 1, rnp_generate_key(&rnp, NULL)); // Ensure the key was generated.

    /*Load the newly generated rnp key*/
    rnp_assert_int_equal(rstate, 1, rnp_load_keys(&rnp)); // Ensure the keyring is loaded.

    /*try to export the key without passing userid from the interface;
     * stack MUST query the set userid option to find the key*/
    exportedkey = rnp_export_key(&rnp, NULL);
    rnp_assert_non_null(rstate, exportedkey);
    free(exportedkey);

    /*try to export the key with specified userid parameter from the interface;
     * stack MUST NOT query the set userid option to find the key*/
    exportedkey = rnp_export_key(&rnp, getenv("LOGNAME"));
    rnp_assert_non_null(rstate, exportedkey);
    free(exportedkey);

    /* try to export the key with specified userid parameter (which is wrong) from
     * the
     * interface;
     * stack MUST NOT be able to find the key*/
    exportedkey = rnp_export_key(&rnp, "LOGNAME");
    rnp_assert_null(rstate, exportedkey);
    free(exportedkey);

    rnp_end(&rnp); // Free memory and other allocated resources.
}
