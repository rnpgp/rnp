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

#include <key_store_pgp.h>
#include <rnp.h>
#include <rnp_tests_support.h>

void
rnpkeys_exportkey_verifyUserId(void **state)
{
    /* * Execute the Generate-key command to generate a new pair of private/public
     * key
     * Verify the key was generated with the correct UserId.
     */
    rnp_t     rnp;
    const int numbits = 1024;
    char      passfd[4] = {0};
    int       pipefd[2];
    char *    exportedkey = NULL;

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);
    /*Initialize the basic RNP structure. */
    memset(&rnp, '\0', sizeof(rnp));

    /*Set the default parameters*/
    rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
    rnp_setvar(&rnp, "res", "<stdout>");
    rnp_setvar(&rnp, "format", "human");
    rnp_setvar(&rnp, "userid", getenv("LOGNAME"));
    rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
    assert_int_equal(rnp_setvar(&rnp, "hash", "SHA256"), 1);

    int retVal = rnp_init(&rnp);
    assert_int_equal(retVal, 1); // Ensure the rnp core structure is correctly initialized.

    retVal = rnp_generate_key(&rnp, NULL, numbits);
    assert_int_equal(retVal, 1); // Ensure the key was generated.

    /*Load the newly generated rnp key*/
    retVal = rnp_load_keys(&rnp);
    assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

    /*try to export the key without passing userid from the interface;
     * stack MUST query the set userid option to find the key*/
    exportedkey = rnp_export_key(&rnp, NULL);
    assert_non_null(exportedkey);
    free(exportedkey);
    exportedkey = NULL;

    /*try to export the key with specified userid parameter from the interface;
     * stack MUST NOT query the set userid option to find the key*/
    exportedkey = rnp_export_key(&rnp, getenv("LOGNAME"));
    assert_non_null(exportedkey);
    free(exportedkey);
    exportedkey = NULL;

    /* try to export the key with specified userid parameter (which is wrong) from
     * the
     * interface;
     * stack MUST NOT be able to find the key*/
    exportedkey = rnp_export_key(&rnp, "LOGNAME");
    assert_null(exportedkey);
    free(exportedkey);

    rnp_end(&rnp); // Free memory and other allocated resources.
}
