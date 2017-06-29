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
#include <key_store.h>
#include <rnp_tests_support.h>
#include "symmetric.h"

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
    rnp_ctx_t ctx;
    int       pipefd[2];
    int       retVal;
    char      memToSign[] = "A simple test message";
    char      signatureBuf[4096] = {0};
    char      recoveredSig[4096] = {0};
    char      userId[128];

    for (int i = 0; hashAlg[i] != NULL; i++) {
        /* Setup passphrase input and rnp structure */
        setup_rnp_common(&rnp, GPG_KEY_STORE, NULL, pipefd);

        memset(userId, 0, sizeof(userId));
        strcpy(userId, "sigtest_");
        strcat(userId, hashAlg[i]);
        
        /* Generate the RSA key and make sure it was generated */
        set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_DEFAULT_HASH_ALGORITHM);
        assert_int_equal(rnp_generate_key(&rnp, userId), 1);

        /* Load the newly generated rnp key */
        assert_int_equal(rnp_key_store_load_keys(&rnp, 1), 1);
        assert_true(rnp_secret_count(&rnp) > 0 && rnp_public_count(&rnp) > 0);

        /* Make sure just generated key is present in the keyring */
        assert_int_equal(rnp_find_key(&rnp, userId), 1); 

        /* Cleanup */
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
                setup_rnp_common(&rnp, GPG_KEY_STORE, NULL, pipefd);

                /* Load keyring */
                assert_int_equal(rnp_key_store_load_keys(&rnp, 1), 1);
                assert_true(rnp_secret_count(&rnp) > 0);

                /* Setup signing context */
                rnp_ctx_init(&ctx, &rnp);
                ctx.armour = armored;
                ctx.halg = pgp_str_to_hash_alg(hashAlg[i]);
                ctx.filename = strdup("dummyfile.dat");
                assert_int_not_equal(ctx.halg, PGP_HASH_UNKNOWN);

                /* Signing the memory */
                retVal = rnp_sign_memory(&ctx,
                                         userId,
                                         memToSign,
                                         strlen(memToSign) - skip_null,
                                         signatureBuf,
                                         sizeof(signatureBuf),
                                         cleartext);

                /* Make sure operation succeeded, and cleanup */
                assert_int_not_equal(retVal, 0);
                const int sigLen = retVal;
                close(pipefd[0]);
                rnp_ctx_free(&ctx);

                /* Verify the memory */
                rnp_ctx_init(&ctx, &rnp);
                retVal = rnp_verify_memory(
                  &ctx, signatureBuf, sigLen, recoveredSig, sizeof(recoveredSig), armored);
                /* Ensure signature verification passed */
                assert_int_equal(retVal, strlen(memToSign) - (skip_null ? 1 : 0));
                assert_string_equal(recoveredSig, memToSign);

                /* Corrupt the signature */
                /* TODO be smarter about this */
                signatureBuf[50] ^= 0x0C;

                retVal = rnp_verify_memory(
                  &ctx, signatureBuf, sigLen, recoveredSig, sizeof(recoveredSig), armored);
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
    rnp_ctx_t ctx;
    int       pipefd[2];
    int       retVal;
    char      memToEncrypt[] = "A simple test message";
    char      ciphertextBuf[4096] = {0};
    char      plaintextBuf[4096] = {0};
    char      userId[128] = {0};

    /* Setup passphrase input and rnp structure */
    setup_rnp_common(&rnp, GPG_KEY_STORE, NULL, pipefd);

    strcpy(userId, "ciphertest");
    /* Generate the RSA key and make sure it was generated */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_DEFAULT_HASH_ALGORITHM);
    assert_int_equal(rnp_generate_key(&rnp, userId), 1);

    /* Load keyring */
    assert_int_equal(rnp_key_store_load_keys(&rnp, 1), 1);
    assert_true(rnp_secret_count(&rnp) > 0 && rnp_public_count(&rnp) > 0);

    /* Make sure just generated key is present in the keyring */
    assert_int_equal(rnp_find_key(&rnp, userId), 1);

    /* Cleanup */
    close(pipefd[0]);
    rnp_end(&rnp);

    for (int i = 0; cipherAlg[i] != NULL; i++) {
        for (unsigned int armored = 0; armored <= 1; ++armored) {
            /* setting up rnp and encrypting memory */
            setup_rnp_common(&rnp, GPG_KEY_STORE, NULL, NULL);

            /* Load keyring */
            assert_int_equal(rnp_key_store_load_keys(&rnp, 0), 1);
            assert_int_equal(rnp_secret_count(&rnp), 0);

            /* setting the cipher and armored flags */
            rnp_ctx_init(&ctx, &rnp);
            ctx.armour = armored;
            ctx.filename = strdup("dummyfile.dat");
            ctx.ealg = pgp_str_to_cipher(cipherAlg[i]);
            /* checking whether we have correct cipher constant */
            assert_true((ctx.ealg != PGP_SA_DEFAULT_CIPHER) || (strcmp(cipherAlg[i], "CAST5") == 0));

            /* Encrypting the memory */
            retVal = rnp_encrypt_memory(&ctx,
                                        userId,
                                        memToEncrypt,
                                        strlen(memToEncrypt),
                                        ciphertextBuf,
                                        sizeof(ciphertextBuf));
            assert_int_not_equal(retVal, 0);
            const int ctextLen = retVal;
            rnp_ctx_free(&ctx);
            rnp_end(&rnp);

            /* Setting up rnp again and decrypting memory */
            setup_rnp_common(&rnp, GPG_KEY_STORE, NULL, pipefd);

            /* Loading the keyrings */
            assert_int_equal(rnp_key_store_load_keys(&rnp, 1), 1);
            assert_true(rnp_secret_count(&rnp) > 0);
            
            /* Setting the decryption context */
            rnp_ctx_init(&ctx, &rnp);
            ctx.armour = armored;

            /* Decrypting the memory */
            retVal = rnp_decrypt_memory(&ctx, ciphertextBuf, ctextLen, plaintextBuf, sizeof(plaintextBuf));

            /* Ensure plaintext recovered */
            assert_int_equal(retVal, strlen(memToEncrypt));
            assert_string_equal(memToEncrypt, plaintextBuf);
            close(pipefd[0]);
            rnp_ctx_free(&ctx);
            rnp_end(&rnp);
        }
    }
}

void
rnpkeys_generatekey_verifySupportedHashAlg(void **state)
{
    /* Generate key for each of the hash algorithms. Check whether key was generated successfully */
    
    const char *hashAlg[] = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA224", "SM3"};
    enum key_store_format_t keystores[] = {GPG_KEY_STORE, KBX_KEY_STORE};
    rnp_t rnp;
    int   pipefd[2];

    for (int i = 0; i < sizeof(hashAlg) / sizeof(hashAlg[0]); i++) {
        for (int j = 0; j < sizeof(keystores) / sizeof(keystores[0]); j++) {
            /* Setting up rnp again and decrypting memory */
            setup_rnp_common(&rnp, keystores[j], NULL, pipefd);
            assert_true(rnp.key_store_format == keystores[j]);

            set_default_rsa_key_desc(&rnp.action.generate_key_ctx, pgp_str_to_hash_alg(hashAlg[i]));
            assert_int_not_equal(rnp.action.generate_key_ctx.hash_alg, PGP_HASH_UNKNOWN);

            /* Generate key with specified parameters */
            assert_int_equal(rnp_generate_key(&rnp, NULL), 1);

            /* Load the newly generated rnp key */
            assert_int_equal(rnp_key_store_load_keys(&rnp, 1), 1);
            assert_true(rnp_secret_count(&rnp) > 0 && rnp_public_count(&rnp) > 0);

            assert_int_equal(rnp_find_key(&rnp, getenv("LOGNAME")), 1);

            /* Close pipe and free allocated memory */
            close(pipefd[0]);
            rnp_end(&rnp);
        }
    }
}

void
rnpkeys_generatekey_verifyUserIdOption(void **state)
{
    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new keypair
     * Verify the key was generated with the correct UserId. */
    
    char        userId[1024] = {0};
    const char *userIds[] = {"rnpkeys_generatekey_verifyUserIdOption_MD5",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA-1",
                            "rnpkeys_generatekey_verifyUserIdOption_RIPEMD160",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA256",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA384",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA512",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA224"};

    enum key_store_format_t keystores[] = {GPG_KEY_STORE, KBX_KEY_STORE};
    rnp_t rnp;
    int   pipefd[2];

    for (int i = 0; i < sizeof(userIds) / sizeof(userIds[0]); i++) {
        for (int j = 0; j < sizeof(keystores) / sizeof(keystores[0]); j++) {
            /* Set the user id to be used*/
            snprintf(userId, sizeof(userId), "%s", userIds[i]);

            /*Initialize the basic RNP structure. */
            setup_rnp_common(&rnp, keystores[j], NULL, pipefd);
            assert_true(rnp.key_store_format == keystores[j]);

            set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
            /* Generate the key with corresponding userId */
            assert_int_equal(rnp_generate_key(&rnp, userId), 1);

            /*Load the newly generated rnp key*/
            assert_int_equal(rnp_key_store_load_keys(&rnp, 1), 1);
            assert_true(rnp_secret_count(&rnp) > 0 && rnp_public_count(&rnp) > 0);
            assert_int_equal(rnp_find_key(&rnp, userId), 1);

            /* Close pipe and free allocated memory */
            close(pipefd[0]);
            rnp_end(&rnp);
        }
    }
}

void
rnpkeys_generatekey_verifykeyHomeDirOption(void **state)
{
    /* Try to generate keypair in different home directories */

    const char *ourdir = getenv("HOME");
    char        newhome[256];
    rnp_t       rnp;
    int         pipefd[2];

    /* Initialize the rnp structure. */
    setup_rnp_common(&rnp, GPG_KEY_STORE, NULL, pipefd);

    /* Pubring and secring should not exist yet */
    assert_false(path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    assert_false(path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    /* Ensure the key was generated. */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
    assert_int_equal(1, rnp_generate_key(&rnp, NULL));

    /* Pubring and secring should now exist */
    assert_true(path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    assert_true(path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    assert_int_equal(rnp_key_store_load_keys(&rnp, 1), 1);
    assert_int_equal(rnp_secret_count(&rnp), 1);
    assert_int_equal(rnp_public_count(&rnp), 1);
    assert_int_equal(rnp_find_key(&rnp, getenv("LOGNAME")), 1);

    close(pipefd[0]);
    rnp_end(&rnp);

    /* Now we start over with a new home. When home is specified explicitly then it should include .rnp as well */
    paths_concat(newhome, sizeof(newhome), ourdir, "newhome", NULL);
    path_mkdir(0700, newhome, NULL);
    paths_concat(newhome, sizeof(newhome), ourdir, "newhome", ".rnp", NULL);
    path_mkdir(0700, newhome, NULL);    

    /* Initialize the rnp structure. */
    setup_rnp_common(&rnp, GPG_KEY_STORE, newhome, pipefd);

    /* Pubring and secring should not exist yet */
    assert_false(path_file_exists(newhome, "pubring.gpg", NULL));
    assert_false(path_file_exists(newhome, "secring.gpg", NULL));

    /* Ensure the key was generated. */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
    assert_int_equal(1, rnp_generate_key(&rnp, "newhomekey"));

    /* Pubring and secring should now exist */
    assert_true(path_file_exists(newhome, "pubring.gpg", NULL));
    assert_true(path_file_exists(newhome, "secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    assert_int_equal(rnp_key_store_load_keys(&rnp, 1), 1);
    assert_int_equal(rnp_secret_count(&rnp), 1);
    assert_int_equal(rnp_public_count(&rnp), 1);
    /* We should not find this key */
    assert_int_equal(rnp_find_key(&rnp, getenv("LOGNAME")), 0);

    close(pipefd[0]);
    rnp_end(&rnp);
}

void
rnpkeys_generatekey_verifykeyKBXHomeDirOption(void **state)
{
    /* Try to generate keypair in different home directories for KBX keystorage */
    
    const char *ourdir = (char *) *state;
    char        newhome[256];
    rnp_t       rnp;
    int         pipefd[2];

    /* Initialize the rnp structure. */
    setup_rnp_common(&rnp, KBX_KEY_STORE, NULL, pipefd);

    /* Pubring and secring should not exist yet */
    assert_false(path_file_exists(ourdir, ".rnp/pubring.kbx", NULL));
    assert_false(path_file_exists(ourdir, ".rnp/secring.kbx", NULL));
    assert_false(path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    assert_false(path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    /* Ensure the key was generated. */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
    assert_int_equal(1, rnp_generate_key(&rnp, NULL));

    /* Pubring and secring should now exist, but only for the KBX */
    assert_true(path_file_exists(ourdir, ".rnp/pubring.kbx", NULL));
    assert_true(path_file_exists(ourdir, ".rnp/secring.kbx", NULL));
    assert_false(path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    assert_false(path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    assert_int_equal(rnp_key_store_load_keys(&rnp, 1), 1);
    assert_int_equal(rnp_secret_count(&rnp), 1);
    assert_int_equal(rnp_public_count(&rnp), 1);
    assert_int_equal(rnp_find_key(&rnp, getenv("LOGNAME")), 1);

    close(pipefd[0]);
    rnp_end(&rnp);

    /* Now we start over with a new home. */
    paths_concat(newhome, sizeof(newhome), ourdir, "newhome", NULL);
    path_mkdir(0700, newhome, NULL);

    /* Initialize the rnp structure. */
    setup_rnp_common(&rnp, KBX_KEY_STORE, newhome, pipefd);

    /* Pubring and secring should not exist yet */
    assert_false(path_file_exists(newhome, "pubring.kbx", NULL));
    assert_false(path_file_exists(newhome, "secring.kbx", NULL));
    assert_false(path_file_exists(newhome, "pubring.gpg", NULL));
    assert_false(path_file_exists(newhome, "secring.gpg", NULL));

    /* Ensure the key was generated. */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
    assert_int_equal(1, rnp_generate_key(&rnp, "newhomekey"));

    /* Pubring and secring should now exist, but only for the KBX */
    assert_true(path_file_exists(newhome, "pubring.kbx", NULL));
    assert_true(path_file_exists(newhome, "secring.kbx", NULL));
    assert_false(path_file_exists(newhome, "pubring.gpg", NULL));
    assert_false(path_file_exists(newhome, "secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    assert_int_equal(rnp_key_store_load_keys(&rnp, 1), 1);
    assert_int_equal(rnp_secret_count(&rnp), 1);
    assert_int_equal(rnp_public_count(&rnp), 1);
    /* We should not find this key */
    assert_int_equal(rnp_find_key(&rnp, getenv("LOGNAME")), 0);

    close(pipefd[0]);
    rnp_end(&rnp);
}

void
rnpkeys_generatekey_verifykeyNonexistingHomeDir(void **state)
{
    /* This test is empty now since meaning of homedir was changed */
}

void
rnpkeys_generatekey_verifykeyHomeDirNoPermission(void **state)
{
    const char *ourdir = (char *) *state;
    char        nopermsdir[256];
    rnp_t       rnp;
    int         pipefd[2];

    paths_concat(nopermsdir, sizeof(nopermsdir), ourdir, "noperms", NULL);
    path_mkdir(0000, nopermsdir, NULL);

    /* Initialize the rnp structure. */
    setup_rnp_common(&rnp, GPG_KEY_STORE, nopermsdir, pipefd);

    /* Try to generate key in the directory and make sure generation fails */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
    assert_int_equal(0, rnp_generate_key(&rnp, NULL));

    close(pipefd[0]);
    rnp_end(&rnp);
}
