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

#include <rnp.h>
#include <rnp_tests_support.h>
#include "symmetric.h"

static void
set_default_rsa_key_desc(rnp_keygen_desc_t *key_desc)
{
    key_desc->key_alg = PGP_PKA_RSA;
    key_desc->sym_alg = PGP_SA_DEFAULT_CIPHER;
    key_desc->rsa.modulus_bit_len = 1024;
}

void
rnpkeys_generatekey_testSignature(void **state)
{
    const char *hashAlg[] = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SM3", NULL};

    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new pair of private/public
     * key
     * Sign a message, then verify it
     */
    rnp_t     rnp;
    char      passfd[4] = {0};
    char *    fdptr;
    int       pipefd[2];
    int       retVal;

    char memToSign[] = "A simple test message";
    char signatureBuf[4096] = {0};
    char recoveredSig[4096] = {0};
    char userId[128];

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);

    for (int i = 0; hashAlg[i] != NULL; i++) {
        /* Setup passphrase input and rnp structure */
        assert_int_equal(setupPassphrasefd(pipefd), 1);
        fdptr = uint_to_string(passfd, 4, pipefd[0], 16);
        setup_rnp_common(&rnp, fdptr);

        memset(userId, 0, sizeof(userId));
        strcpy(userId, "sigtest_");
        strcat(userId, hashAlg[i]);

        set_default_rsa_key_desc(&rnp.action.generate_key_ctx);
        retVal = rnp_generate_key(&rnp, userId);
        assert_int_equal(retVal, 1); // Ensure the key was generated

        /*Load the newly generated rnp key*/
        retVal = rnp_load_keys(&rnp);
        assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

        retVal = rnp_find_key(&rnp, userId);
        assert_int_equal(retVal, 1); // Ensure the key can be found with the userId

        close(pipefd[0]);
        rnp_end(&rnp);

        for (unsigned int cleartext = 0; cleartext <= 1; ++cleartext) {
            for (unsigned int armored = 0; armored <= 1; ++armored) {
                const int skip_null = (cleartext == 1) ? 1 : 0;

                if (cleartext == 1 && armored == 0) {
                    // This combination doesn't work...
                    continue;
                }

                /* Setup passphrase input and rnp structure */
                assert_int_equal(setupPassphrasefd(pipefd), 1);
                fdptr = uint_to_string(passfd, 4, pipefd[0], 16);
                setup_rnp_common(&rnp, fdptr);
                retVal = rnp_load_keys(&rnp);
                assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

                rnp.ctx.armour = armored;
                assert_int_equal(rnp_setvar(&rnp, "hash", hashAlg[i]), 1);

                /* Signing the memory */
                retVal = rnp_sign_memory(&rnp,
                                         userId,
                                         memToSign,
                                         strlen(memToSign) - skip_null,
                                         signatureBuf,
                                         sizeof(signatureBuf),
                                         cleartext);

                assert_int_not_equal(retVal, 0); // Ensure signature operation succeeded
                const int sigLen = retVal;
                close(pipefd[0]);
                rnp_end(&rnp);

                /* Setup rnp again and load keyring. Passphrase is not needed */
                setup_rnp_common(&rnp, NULL);
                retVal = rnp_load_keys(&rnp);
                assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

                /* Verify the memory */
                retVal = rnp_verify_memory(
                  &rnp, signatureBuf, sigLen, recoveredSig, sizeof(recoveredSig), armored);
                /* Ensure signature verification passed */
                assert_int_equal(retVal, strlen(memToSign) - (skip_null ? 1 : 0));
                assert_string_equal(recoveredSig, memToSign);

                /* Corrupt te signature */
                /* TODO be smarter about this */
                signatureBuf[50] ^= 0x0C;

                retVal = rnp_verify_memory(
                  &rnp, signatureBuf, sigLen, recoveredSig, sizeof(recoveredSig), armored);
                /* Ensure that signature verification fails */
                assert_int_equal(retVal, 0);
                rnp_end(&rnp);
            }
        }
    }
}

void
rnpkeys_generatekey_testEncryption(void **state)
{
    const char *cipherAlg[] = {"Blowfish",
                               "Twofish",
                               "CAST5",
                               "TripleDES",
                               "AES128",
                               "AES192",
                               "AES256",
                               "Camellia128",
                               "Camellia192",
                               "Camellia256",
                               NULL};

    rnp_t     rnp;
    char      passfd[4] = {0};
    char *    fdptr;
    int       pipefd[2];
    int       retVal;

    char memToEncrypt[] = "A simple test message";
    char ciphertextBuf[4096] = {0};
    char plaintextBuf[4096] = {0};
    char userId[128] = {0};

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);
    fdptr = uint_to_string(passfd, 4, pipefd[0], 16);
    setup_rnp_common(&rnp, fdptr);

    strcpy(userId, "ciphertest");

    set_default_rsa_key_desc(&rnp.action.generate_key_ctx);
    retVal = rnp_generate_key(&rnp, userId);
    assert_int_equal(retVal, 1); // Ensure the key was generated

    /*Load the newly generated rnp key*/
    retVal = rnp_load_keys(&rnp);
    assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

    retVal = rnp_find_key(&rnp, userId);
    assert_int_equal(retVal, 1); // Ensure the key can be found with the userId

    rnp_end(&rnp);

    for (int i = 0; cipherAlg[i] != NULL; i++) {
        for (unsigned int armored = 0; armored <= 1; ++armored) {
            /* setting up rnp and encrypting memory */
            setup_rnp_common(&rnp, NULL);
            retVal = rnp_load_keys(&rnp);
            assert_int_equal(retVal, 1); // Ensure the keyring is loaded.
            /* setting the cipher and armored flags */
            assert_int_equal(rnp_setvar(&rnp, "cipher", cipherAlg[i]), 1);
            rnp.ctx.armour = armored;
            rnp.ctx.ealg = pgp_str_to_cipher(cipherAlg[i]);

            retVal = rnp_encrypt_memory(&rnp,
                                        userId,
                                        memToEncrypt,
                                        strlen(memToEncrypt),
                                        ciphertextBuf,
                                        sizeof(ciphertextBuf));
            assert_int_not_equal(retVal, 0); // Ensure encryption operation succeeded
            const int ctextLen = retVal;
            rnp_end(&rnp);

            /* setting up rnp again and decrypting memory */
            assert_int_equal(setupPassphrasefd(pipefd), 1);
            fdptr = uint_to_string(passfd, 4, pipefd[0], 16);
            setup_rnp_common(&rnp, fdptr);
            retVal = rnp_load_keys(&rnp);
            assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

            retVal = rnp_decrypt_memory(
              &rnp, ciphertextBuf, ctextLen, plaintextBuf, sizeof(plaintextBuf), armored);

            /* Ensure plaintext recovered */
            assert_int_equal(retVal, strlen(memToEncrypt));
            assert_string_equal(memToEncrypt, plaintextBuf);
            close(pipefd[0]);
            rnp_end(&rnp);
        }
    }
}

void
rnpkeys_generatekey_verifySupportedHashAlg(void **state)
{
    const char *hashAlg[] = {"MD5",
                             "SHA1",
                             //"RIPEMD160",
                             "SHA256",
                             "SHA384",
                             "SHA512",
                             "SHA224",
                             "SM3"};

    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new pair of private/public
     * key
     * Verify the key was generated with the correct UserId.*/
    rnp_t rnp;
    char  passfd[4] = {0};
    int   pipefd[2];

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);

    for (int i = 0; i < sizeof(hashAlg) / sizeof(hashAlg[0]); i++) {
        /*Initialize the basic RNP structure. */
        memset(&rnp, '\0', sizeof(rnp));

        /*Set the default parameters*/
        rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
        rnp_setvar(&rnp, "res", "<stdout>");
        rnp_setvar(&rnp, "format", "human");
        rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
        assert_int_equal(rnp_setvar(&rnp, "hash", hashAlg[i]), 1);

        int retVal = rnp_init(&rnp);
        assert_int_equal(retVal, 1); // Ensure the rnp core structure is correctly initialized.

        set_default_rsa_key_desc(&rnp.action.generate_key_ctx);
        retVal = rnp_generate_key(&rnp, NULL);
        assert_int_equal(retVal, 1); // Ensure the key was generated

        /*Load the newly generated rnp key*/
        retVal = rnp_load_keys(&rnp);
        assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

        retVal = rnp_find_key(&rnp, getenv("LOGNAME"));
        assert_int_equal(retVal, 1); // Ensure the key can be found with the userId

        rnp_end(&rnp); // Free memory and other allocated resources.
    }
}

void
rnpkeys_generatekey_verifyUserIdOption(void **state)
{
    char        userId[1024] = {0};
    const char *UserId[] = {"rnpkeys_generatekey_verifyUserIdOption_MD5",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA-1",
                            "rnpkeys_generatekey_verifyUserIdOption_RIPEMD160",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA256",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA384",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA512",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA224"};

    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new pair of private/public
     * key
     * Verify the key was generated with the correct UserId.*/
    rnp_t rnp;
    char  passfd[4] = {0};
    int   pipefd[2];

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);

    for (int i = 0; i < sizeof(UserId) / sizeof(UserId[0]); i++) {
        /* Set the user id to be used*/
        snprintf(userId, sizeof(userId), "%s", UserId[i]);

        /*Initialize the basic RNP structure. */
        memset(&rnp, '\0', sizeof(rnp));

        /*Set the default parameters*/
        rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
        rnp_setvar(&rnp, "res", "<stdout>");
        rnp_setvar(&rnp, "format", "human");
        rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
        assert_int_equal(rnp_setvar(&rnp, "hash", "SHA256"), 1);

        int retVal = rnp_init(&rnp);
        assert_int_equal(retVal, 1); // Ensure the rnp core structure is correctly initialized.

        set_default_rsa_key_desc(&rnp.action.generate_key_ctx);
        retVal = rnp_generate_key(&rnp, userId);
        assert_int_equal(retVal, 1); // Ensure the key was generated

        /*Load the newly generated rnp key*/
        retVal = rnp_load_keys(&rnp);
        assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

        retVal = rnp_find_key(&rnp, userId);
        assert_int_equal(retVal, 1); // Ensure the key can be found with the userId

        rnp_end(&rnp); // Free memory and other allocated resources.
    }
}

void
rnpkeys_generatekey_verifykeyHomeDirOption(void **state)
{
    const char *ourdir = (char *) *state;
    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new pair of private/public
     * key
     * Verify the key was generated with the correct UserId.*/
    rnp_t rnp;
    char  passfd[4] = {0};
    int   pipefd[2];

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);

    /*Initialize the basic RNP structure. */
    memset(&rnp, '\0', sizeof(rnp));

    /*Set the default parameters*/
    rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
    rnp_setvar(&rnp, "res", "<stdout>");
    rnp_setvar(&rnp, "format", "human");
    rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
    assert_int_equal(rnp_setvar(&rnp, "hash", "SHA256"), 1);

    assert_int_equal(1, rnp_init(&rnp));

    // pubring and secring should not exist yet
    assert_false(path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    assert_false(path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    // Ensure the key was generated.
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx);
    assert_int_equal(1, rnp_generate_key(&rnp, NULL));

    // pubring and secring should now exist
    assert_true(path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    assert_true(path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    assert_int_equal(1, rnp_load_keys(&rnp));
    assert_int_equal(1, rnp_find_key(&rnp, getenv("LOGNAME")));
    rnp_end(&rnp);

    // Now we start over with a new home.
    memset(&rnp, 0, sizeof(rnp));
    // Create a directory "newhome" within this tests temporary directory.
    char newhome[256];
    paths_concat(newhome, sizeof(newhome), ourdir, "newhome", NULL);
    path_mkdir(0700, newhome, NULL);

    // Set the homedir to our newhome path.
    assert_int_equal(1, rnp_setvar(&rnp, "homedir", newhome));

    /*Set the default parameters*/
    rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
    rnp_setvar(&rnp, "res", "<stdout>");
    rnp_setvar(&rnp, "format", "human");
    rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));

    assert_int_equal(rnp_setvar(&rnp, "hash", "SHA256"), 1);

    assert_int_equal(1, rnp_init(&rnp));

    // pubring and secring should not exist yet
    assert_false(path_file_exists(newhome, ".rnp/pubring.gpg", NULL));
    assert_false(path_file_exists(newhome, ".rnp/secring.gpg", NULL));

    // Ensure the key was generated.
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx);
    assert_int_equal(1, rnp_generate_key(&rnp, "newhomekey"));

    // pubring and secring should now exist
    assert_true(path_file_exists(newhome, ".rnp/pubring.gpg", NULL));
    assert_true(path_file_exists(newhome, ".rnp/secring.gpg", NULL));

    // Load the keys in our newhome directory
    assert_int_equal(1, rnp_load_keys(&rnp));

    // We should NOT find this key.
    assert_int_equal(0, rnp_find_key(&rnp, getenv("LOGNAME")));

    // We should find this key, instead.
    assert_int_equal(1, rnp_find_key(&rnp, "newhomekey"));

    rnp_end(&rnp); // Free memory and other allocated resources.
}

void
rnpkeys_generatekey_verifykeyNonexistingHomeDir(void **state)
{
    const char *ourdir = (char *) *state;
    char        passfd[4] = {0};
    int         pipefd[2];
    rnp_t       rnp;
    char        fakedir[256];

    // fakedir is a directory that does not exist
    paths_concat(fakedir, sizeof(fakedir), ourdir, "fake", NULL);

    /****************************************************************/
    // First, make sure init succeeds with the default (using $HOME)
    memset(&rnp, '\0', sizeof(rnp));
    assert_int_equal(1, rnp_init(&rnp));
    rnp_end(&rnp);

    /****************************************************************/
    // Ensure it fails when we set an invalid "homedir"
    memset(&rnp, '\0', sizeof(rnp));
    rnp_setvar(&rnp, "homedir", fakedir);
    assert_int_equal(0, rnp_init(&rnp));
    rnp_end(&rnp);

    /****************************************************************/
    // Ensure it fails when we do not explicitly set "homedir" and
    // $HOME is invalid.
    memset(&rnp, '\0', sizeof(rnp));
    assert_int_equal(0, setenv("HOME", fakedir, 1));
    assert_int_equal(0, rnp_init(&rnp));
    // Restore our original $HOME.
    assert_int_equal(0, setenv("HOME", ourdir, 1));
    rnp_end(&rnp);

    /****************************************************************/
    // Ensure key generation fails when we set an invalid "homedir"
    // after rnp_init.
    memset(&rnp, '\0', sizeof(rnp));
    assert_int_equal(setupPassphrasefd(pipefd), 1);
    rnp_setvar(&rnp, "res", "<stdout>");
    rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
    assert_int_equal(1, rnp_init(&rnp));
    rnp_setvar(&rnp, "homedir", fakedir);
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx);
    assert_int_equal(0, rnp_generate_key(&rnp, NULL));
    rnp_end(&rnp);
}

void
rnpkeys_generatekey_verifykeyHomeDirNoPermission(void **state)
{
    const char *ourdir = (char *) *state;

    char nopermsdir[256];
    paths_concat(nopermsdir, sizeof(nopermsdir), ourdir, "noperms", NULL);
    path_mkdir(0000, nopermsdir, NULL);

    rnp_t rnp;
    char  passfd[4] = {0};
    int   pipefd[2];

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);

    /* Set the home directory to a non-default value and ensure the read/write
     * permission
     * for the specified directory*/
    int retVal = setenv("HOME", nopermsdir, 1);
    assert_int_equal(retVal, 0); // Ensure the enviornment variable was set

    /*Initialize the basic RNP structure. */
    memset(&rnp, '\0', sizeof(rnp));

    /*Set the default parameters*/
    rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
    rnp_setvar(&rnp, "res", "<stdout>");
    rnp_setvar(&rnp, "format", "human");
    rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
    assert_int_equal(rnp_setvar(&rnp, "hash", "SHA256"), 1);

    retVal = rnp_init(&rnp);
    assert_int_equal(retVal, 1); // Ensure the rnp core structure is correctly initialized.

    set_default_rsa_key_desc(&rnp.action.generate_key_ctx);
    retVal = rnp_generate_key(&rnp, NULL);
    assert_int_equal(retVal, 0); // Ensure the key was NOT generated as the
                                 // directory has only list read permissions.

    rnp_end(&rnp); // Free memory and other allocated resources.
}
