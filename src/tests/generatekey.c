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

#include <rnp/rnp.h>
#include <rekey/rnp_key_store.h>
#include <rnp/rnpcfg.h>
#include <rnpkeys/rnpkeys.h>

#include "rnp_tests.h"
#include "support.h"
#include "symmetric.h"
#include "hash.h"

void
rnpkeys_generatekey_testSignature(void **state)
{
    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new pair of private/public
     * key
     * Sign a message, then verify it
     */

    rnp_test_state_t *rstate = *state;
    const char *hashAlg[] = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SM3", NULL};
    rnp_t       rnp;
    rnp_ctx_t   ctx;
    int         pipefd[2];
    int         retVal;
    char        memToSign[] = "A simple test message";
    char        signatureBuf[4096] = {0};
    char        recoveredSig[4096] = {0};
    char        userId[128];

    for (int i = 0; hashAlg[i] != NULL; i++) {
        /* Setup passphrase input and rnp structure */
        rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));

        memset(userId, 0, sizeof(userId));
        strcpy(userId, "sigtest_");
        strcat(userId, hashAlg[i]);

        /* Generate the RSA key and make sure it was generated */
        set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_DEFAULT_HASH_ALGORITHM);
        strncpy((char *) rnp.action.generate_key_ctx.primary.cert.userid,
                userId,
                sizeof(rnp.action.generate_key_ctx.primary.cert.userid));
        rnp_assert_ok(rstate, rnp_generate_key(&rnp));

        /* Load the newly generated rnp key */
        rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, true));
        rnp_assert_true(rstate, rnp_secret_count(&rnp) > 0 && rnp_public_count(&rnp) > 0);

        /* Make sure just generated key is present in the keyring */
        rnp_assert_true(rstate, rnp_find_key(&rnp, userId));

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
                rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));

                /* Load keyring */
                rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, true));
                rnp_assert_true(rstate, rnp_secret_count(&rnp) > 0);

                /* Setup signing context */
                rnp_ctx_init(&ctx, &rnp);
                ctx.armour = armored;
                ctx.halg = pgp_str_to_hash_alg(hashAlg[i]);
                ctx.filename = strdup("dummyfile.dat");
                rnp_assert_int_not_equal(rstate, ctx.halg, PGP_HASH_UNKNOWN);

                /* Signing the memory */
                retVal = rnp_sign_memory(&ctx,
                                         userId,
                                         memToSign,
                                         strlen(memToSign) - skip_null,
                                         signatureBuf,
                                         sizeof(signatureBuf),
                                         cleartext);

                /* Make sure operation succeeded, and cleanup */
                rnp_assert_int_not_equal(rstate, retVal, 0);
                const int sigLen = retVal;
                close(pipefd[0]);
                rnp_ctx_free(&ctx);

                /* Verify the memory */
                rnp_ctx_init(&ctx, &rnp);
                ctx.armour = armored;
                retVal = rnp_verify_memory(
                  &ctx, signatureBuf, sigLen, recoveredSig, sizeof(recoveredSig));
                /* Ensure signature verification passed */
                rnp_assert_int_equal(rstate, retVal, strlen(memToSign) - (skip_null ? 1 : 0));
                assert_string_equal(recoveredSig, memToSign);

                /* Corrupt the signature */
                /* TODO be smarter about this */
                signatureBuf[50] ^= 0x0C;

                retVal = rnp_verify_memory(
                  &ctx, signatureBuf, sigLen, recoveredSig, sizeof(recoveredSig));
                /* Ensure that signature verification fails */
                rnp_assert_int_equal(rstate, retVal, 0);
                rnp_end(&rnp);
            }
        }
    }
}

void
rnpkeys_generatekey_testEncryption(void **state)
{
    rnp_test_state_t *rstate = *state;
    const char *      cipherAlg[] = {"Blowfish",
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
    rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));

    strcpy(userId, "ciphertest");
    /* Generate the RSA key and make sure it was generated */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_DEFAULT_HASH_ALGORITHM);
    strncpy((char *) rnp.action.generate_key_ctx.primary.cert.userid,
            userId,
            sizeof(rnp.action.generate_key_ctx.primary.cert.userid));
    rnp_assert_ok(rstate, rnp_generate_key(&rnp));

    /* Load keyring */
    rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, true));
    rnp_assert_true(rstate, rnp_secret_count(&rnp) > 0 && rnp_public_count(&rnp) > 0);

    /* Make sure just generated key is present in the keyring */
    rnp_assert_true(rstate, rnp_find_key(&rnp, userId));

    /* Cleanup */
    close(pipefd[0]);
    rnp_end(&rnp);

    for (int i = 0; cipherAlg[i] != NULL; i++) {
        for (unsigned int armored = 0; armored <= 1; ++armored) {
            /* setting up rnp and encrypting memory */
            rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, NULL));

            /* Load keyring */
            rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, false));
            rnp_assert_int_equal(rstate, 0, rnp_secret_count(&rnp));

            /* setting the cipher and armored flags */
            rnp_ctx_init(&ctx, &rnp);
            ctx.armour = armored;
            ctx.filename = strdup("dummyfile.dat");
            ctx.ealg = pgp_str_to_cipher(cipherAlg[i]);
            /* checking whether we have correct cipher constant */
            rnp_assert_true(rstate,
                            (ctx.ealg != PGP_SA_DEFAULT_CIPHER) ||
                              (strcmp(cipherAlg[i], "AES256") == 0));

            /* Encrypting the memory */
            retVal = rnp_encrypt_memory(&ctx,
                                        userId,
                                        memToEncrypt,
                                        strlen(memToEncrypt),
                                        ciphertextBuf,
                                        sizeof(ciphertextBuf));
            rnp_assert_int_not_equal(rstate, retVal, 0);
            const int ctextLen = retVal;
            rnp_ctx_free(&ctx);
            rnp_end(&rnp);

            /* Setting up rnp again and decrypting memory */
            rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));

            /* Loading the keyrings */
            rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, true));
            rnp_assert_true(rstate, rnp_secret_count(&rnp) > 0);

            /* Setting the decryption context */
            rnp_ctx_init(&ctx, &rnp);
            ctx.armour = armored;

            /* Decrypting the memory */
            retVal = rnp_decrypt_memory(
              &ctx, ciphertextBuf, ctextLen, plaintextBuf, sizeof(plaintextBuf));

            /* Ensure plaintext recovered */
            rnp_assert_int_equal(rstate, retVal, strlen(memToEncrypt));
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
    /* Generate key for each of the hash algorithms. Check whether key was generated
     * successfully */

    rnp_test_state_t *rstate = *state;
    const char *hashAlg[] = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA224", "SM3"};
    const char *keystores[] = {RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG21, RNP_KEYSTORE_KBX};
    rnp_t rnp;
    int   pipefd[2];

    for (int i = 0; i < sizeof(hashAlg) / sizeof(hashAlg[0]); i++) {
        for (int j = 0; j < sizeof(keystores) / sizeof(keystores[0]); j++) {
            /* Setting up rnp again and decrypting memory */
            printf("keystore: %s\n", keystores[j]);
            rnp_assert_ok(rstate, setup_rnp_common(&rnp, keystores[j], NULL, pipefd));

            set_default_rsa_key_desc(&rnp.action.generate_key_ctx,
                                     pgp_str_to_hash_alg(hashAlg[i]));
            rnp_assert_int_not_equal(
              rstate, rnp.action.generate_key_ctx.primary.crypto.hash_alg, PGP_HASH_UNKNOWN);
            rnp_assert_int_not_equal(
              rstate, rnp.action.generate_key_ctx.subkey.crypto.hash_alg, PGP_HASH_UNKNOWN);

            /* Generate key with specified parameters */
            rnp_assert_ok(rstate, rnp_generate_key(&rnp));

            /* Load the newly generated rnp key */
            rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, true));
            rnp_assert_true(rstate, rnp_secret_count(&rnp) > 0 && rnp_public_count(&rnp) > 0);

            // G10 doesn't support metadata
            if (strcmp(keystores[j], RNP_KEYSTORE_G10) != 0) {
                rnp_assert_true(rstate, rnp_find_key(&rnp, getenv("LOGNAME")));
            }

            /* Close pipe and free allocated memory */
            close(pipefd[0]);
            rnp_end(&rnp); // Free memory and other allocated resources.
        }
    }
}

void
rnpkeys_generatekey_verifyUserIdOption(void **state)
{
    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new keypair
     * Verify the key was generated with the correct UserId. */

    rnp_test_state_t *rstate = *state;
    char              userId[1024] = {0};
    const char *      userIds[] = {"rnpkeys_generatekey_verifyUserIdOption_MD5",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA-1",
                             "rnpkeys_generatekey_verifyUserIdOption_RIPEMD160",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA256",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA384",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA512",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA224"};

    const char *keystores[] = {RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG21, RNP_KEYSTORE_KBX};
    rnp_t rnp;
    int   pipefd[2];

    for (int i = 0; i < sizeof(userIds) / sizeof(userIds[0]); i++) {
        for (int j = 0; j < sizeof(keystores) / sizeof(keystores[0]); j++) {
            /* Set the user id to be used*/
            snprintf(userId, sizeof(userId), "%s", userIds[i]);

            /*Initialize the basic RNP structure. */
            rnp_assert_ok(rstate, setup_rnp_common(&rnp, keystores[j], NULL, pipefd));

            set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
            strncpy((char *) rnp.action.generate_key_ctx.primary.cert.userid,
                    userId,
                    sizeof(rnp.action.generate_key_ctx.primary.cert.userid));
            /* Generate the key with corresponding userId */
            rnp_assert_ok(rstate, rnp_generate_key(&rnp));

            /*Load the newly generated rnp key*/
            rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, true));
            rnp_assert_true(rstate, rnp_secret_count(&rnp) > 0 && rnp_public_count(&rnp) > 0);

            // G10 doesn't support metadata
            if (strcmp(keystores[j], RNP_KEYSTORE_G10) != 0) {
                rnp_assert_true(rstate, rnp_find_key(&rnp, userId));
            }

            /* Close pipe and free allocated memory */
            close(pipefd[0]);
            rnp_end(&rnp); // Free memory and other allocated resources.
        }
    }
}

void
rnpkeys_generatekey_verifykeyHomeDirOption(void **state)
{
    /* Try to generate keypair in different home directories */

    rnp_test_state_t *rstate = *state;
    const char *      ourdir = rstate->home;
    char              newhome[256];
    rnp_t             rnp;
    int               pipefd[2];

    /* Initialize the rnp structure. */
    rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));

    /* Pubring and secring should not exist yet */
    rnp_assert_false(rstate, path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    rnp_assert_false(rstate, path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    /* Ensure the key was generated. */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
    rnp_assert_ok(rstate, rnp_generate_key(&rnp));

    /* Pubring and secring should now exist */
    rnp_assert_true(rstate, path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    rnp_assert_true(rstate, path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, true));
    rnp_assert_int_equal(rstate, 2, rnp_secret_count(&rnp));
    rnp_assert_int_equal(rstate, 2, rnp_public_count(&rnp));
    rnp_assert_true(rstate, rnp_find_key(&rnp, getenv("LOGNAME")));

    close(pipefd[0]);
    rnp_end(&rnp);

    /* Now we start over with a new home. When home is specified explicitly then it should
     * include .rnp as well */
    paths_concat(newhome, sizeof(newhome), ourdir, "newhome", NULL);
    path_mkdir(0700, newhome, NULL);
    paths_concat(newhome, sizeof(newhome), ourdir, "newhome", ".rnp", NULL);
    path_mkdir(0700, newhome, NULL);

    /* Initialize the rnp structure. */
    rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, newhome, pipefd));

    /* Pubring and secring should not exist yet */
    rnp_assert_false(rstate, path_file_exists(newhome, "pubring.gpg", NULL));
    rnp_assert_false(rstate, path_file_exists(newhome, "secring.gpg", NULL));

    /* Ensure the key was generated. */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
    strncpy((char *) rnp.action.generate_key_ctx.primary.cert.userid,
            "newhomekey",
            sizeof(rnp.action.generate_key_ctx.primary.cert.userid));
    rnp_assert_ok(rstate, rnp_generate_key(&rnp));

    /* Pubring and secring should now exist */
    rnp_assert_true(rstate, path_file_exists(newhome, "pubring.gpg", NULL));
    rnp_assert_true(rstate, path_file_exists(newhome, "secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, true));
    rnp_assert_int_equal(rstate, 2, rnp_secret_count(&rnp));
    rnp_assert_int_equal(rstate, 2, rnp_public_count(&rnp));
    /* We should not find this key */
    rnp_assert_false(rstate, rnp_find_key(&rnp, getenv("LOGNAME")));

    close(pipefd[0]);
    rnp_end(&rnp); // Free memory and other allocated resources.
}

void
rnpkeys_generatekey_verifykeyKBXHomeDirOption(void **state)
{
    /* Try to generate keypair in different home directories for KBX keystorage */

    rnp_test_state_t *rstate = *state;
    const char *      ourdir = rstate->home;
    char              newhome[256];
    rnp_t             rnp;
    int               pipefd[2];

    /* Initialize the rnp structure. */
    rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_KBX, NULL, pipefd));

    /* Pubring and secring should not exist yet */
    rnp_assert_false(rstate, path_file_exists(ourdir, ".rnp/pubring.kbx", NULL));
    rnp_assert_false(rstate, path_file_exists(ourdir, ".rnp/secring.kbx", NULL));
    rnp_assert_false(rstate, path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    rnp_assert_false(rstate, path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    /* Ensure the key was generated. */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
    rnp_assert_ok(rstate, rnp_generate_key(&rnp));

    /* Pubring and secring should now exist, but only for the KBX */
    rnp_assert_true(rstate, path_file_exists(ourdir, ".rnp/pubring.kbx", NULL));
    rnp_assert_true(rstate, path_file_exists(ourdir, ".rnp/secring.kbx", NULL));
    rnp_assert_false(rstate, path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    rnp_assert_false(rstate, path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, true));
    rnp_assert_int_equal(rstate, 2, rnp_secret_count(&rnp));
    rnp_assert_int_equal(rstate, 2, rnp_public_count(&rnp));
    rnp_assert_true(rstate, rnp_find_key(&rnp, getenv("LOGNAME")));

    close(pipefd[0]);
    rnp_end(&rnp);

    /* Now we start over with a new home. */
    paths_concat(newhome, sizeof(newhome), ourdir, "newhome", NULL);
    path_mkdir(0700, newhome, NULL);

    /* Initialize the rnp structure. */
    rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_KBX, newhome, pipefd));

    /* Pubring and secring should not exist yet */
    rnp_assert_false(rstate, path_file_exists(newhome, "pubring.kbx", NULL));
    rnp_assert_false(rstate, path_file_exists(newhome, "secring.kbx", NULL));
    rnp_assert_false(rstate, path_file_exists(newhome, "pubring.gpg", NULL));
    rnp_assert_false(rstate, path_file_exists(newhome, "secring.gpg", NULL));

    /* Ensure the key was generated. */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
    strncpy((char *) rnp.action.generate_key_ctx.primary.cert.userid,
            "newhomekey",
            sizeof(rnp.action.generate_key_ctx.primary.cert.userid));
    rnp_assert_ok(rstate, rnp_generate_key(&rnp));

    /* Pubring and secring should now exist, but only for the KBX */
    rnp_assert_true(rstate, path_file_exists(newhome, "pubring.kbx", NULL));
    rnp_assert_true(rstate, path_file_exists(newhome, "secring.kbx", NULL));
    rnp_assert_false(rstate, path_file_exists(newhome, "pubring.gpg", NULL));
    rnp_assert_false(rstate, path_file_exists(newhome, "secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, true));
    rnp_assert_int_equal(rstate, 2, rnp_secret_count(&rnp));
    rnp_assert_int_equal(rstate, 2, rnp_public_count(&rnp));
    /* We should not find this key */
    rnp_assert_false(rstate, rnp_find_key(&rnp, getenv("LOGNAME")));

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
    rnp_test_state_t *rstate = *state;
    const char *      ourdir = rstate->home;
    char              nopermsdir[256];
    rnp_t             rnp;
    int               pipefd[2];

    paths_concat(nopermsdir, sizeof(nopermsdir), ourdir, "noperms", NULL);
    path_mkdir(0000, nopermsdir, NULL);

    /* Initialize the rnp structure. */
    rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, nopermsdir, pipefd));

    /* Try to generate key in the directory and make sure generation fails */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
    rnp_assert_fail(rstate, rnp_generate_key(&rnp));

    close(pipefd[0]);
    rnp_end(&rnp);
}

static bool
ask_expert_details(rnp_t *ctx, rnp_cfg_t *ops, const char *rsp, size_t rsp_len)
{
    /* Run tests*/
    bool      ret = true;
    rnp_cfg_t cfg = {0};
    int       pipefd[2] = {0};
    if (setup_rnp_common(ctx, RNP_KEYSTORE_GPG, NULL, NULL) != true) {
        return false;
    }
    if (pipe(pipefd) == -1) {
        ret = false;
        goto end;
    }
    rnp_cfg_setint(ops, CFG_PASSFD, pipefd[0]);
    write_pass_to_pipe(pipefd[1], 2);
    if (!rnpkeys_init(&cfg, ctx, ops, true)) {
        return false;
    }

    int user_input_pipefd[2] = {0};

    /* Write response to fd */
    if (pipe(user_input_pipefd) == -1) {
        ret = false;
        goto end;
    }
    for (int i = 0; i < rsp_len;) {
        i += write(user_input_pipefd[1], rsp + i, rsp_len - i);
    }
    close(user_input_pipefd[1]);

    /* Mock user-input*/
    ctx->user_input_fp = fdopen(user_input_pipefd[0], "r");

    if (!rnp_cmd(&cfg, ctx, CMD_GENERATE_KEY, NULL)) {
        ret = false;
        goto end;
    }

end:
    /* Close & clean fd*/
    if (ctx->user_input_fp) {
        fclose(ctx->user_input_fp);
        ctx->user_input_fp = NULL;
    }
    if (user_input_pipefd[0]) {
        close(user_input_pipefd[0]);
    }
    rnp_cfg_free(&cfg);
    return ret;
}

void
rnpkeys_generatekey_testExpertMode(void **state)
{
    rnp_test_state_t *rstate = *state;
    rnp_t             rnp;
    rnp_cfg_t         ops = {0};

    // Setup directories and cleanup context
    static const char test_ecdh_256[] = "18\n1\n";
    static const char test_ecdh_384[] = "18\n2\n";
    static const char test_ecdh_521[] = "18\n3\n";
    static const char test_ecdsa_256[] = "19\n1\n";
    static const char test_ecdsa_384[] = "19\n2\n";
    static const char test_ecdsa_521[] = "19\n3\n";
    static const char test_eddsa[] = "22\n";
    static const char test_sm2[] = "99\n";
    static const char test_rsa_1024[] = "1\n1024\n";
    static const char test_rsa_ask_twice_4096[] = "1\n1023\n4096\n";

    rnp_assert_true(rstate, rnp_cfg_setbool(&ops, CFG_EXPERT, true));

    rnp_assert_true(rstate,
                    ask_expert_details(&rnp, &ops, test_ecdh_256, strlen(test_ecdh_256)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.key_alg, PGP_PKA_ECDH);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.ecc.curve, PGP_CURVE_NIST_P_256);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.hash_alg, PGP_HASH_SHA256);
    rnp_end(&rnp);

    rnp_assert_true(rstate,
                    ask_expert_details(&rnp, &ops, test_ecdh_384, strlen(test_ecdh_384)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.key_alg, PGP_PKA_ECDH);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.ecc.curve, PGP_CURVE_NIST_P_384);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.hash_alg, PGP_HASH_SHA384);
    rnp_end(&rnp);

    rnp_assert_true(rstate,
                    ask_expert_details(&rnp, &ops, test_ecdh_521, strlen(test_ecdh_521)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.key_alg, PGP_PKA_ECDH);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.ecc.curve, PGP_CURVE_NIST_P_521);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.hash_alg, PGP_HASH_SHA512);
    rnp_end(&rnp);

    rnp_assert_true(rstate,
                    ask_expert_details(&rnp, &ops, test_ecdsa_256, strlen(test_ecdsa_256)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.key_alg, PGP_PKA_ECDSA);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.ecc.curve, PGP_CURVE_NIST_P_256);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.hash_alg, PGP_HASH_SHA256);
    rnp_end(&rnp);

    rnp_assert_true(rstate,
                    ask_expert_details(&rnp, &ops, test_ecdsa_384, strlen(test_ecdsa_384)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.key_alg, PGP_PKA_ECDSA);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.ecc.curve, PGP_CURVE_NIST_P_384);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.hash_alg, PGP_HASH_SHA384);
    rnp_end(&rnp);

    rnp_assert_true(rstate,
                    ask_expert_details(&rnp, &ops, test_ecdsa_521, strlen(test_ecdsa_521)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.key_alg, PGP_PKA_ECDSA);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.ecc.curve, PGP_CURVE_NIST_P_521);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.hash_alg, PGP_HASH_SHA512);
    rnp_end(&rnp);

    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, test_eddsa, strlen(test_eddsa)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.key_alg, PGP_PKA_EDDSA);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.ecc.curve, PGP_CURVE_ED25519);
    rnp_end(&rnp);

    rnp_assert_true(rstate,
                    ask_expert_details(&rnp, &ops, test_rsa_1024, strlen(test_rsa_1024)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.key_alg, PGP_PKA_RSA);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.rsa.modulus_bit_len, 1024);
    rnp_end(&rnp);

    rnp_assert_true(rstate,
                    ask_expert_details(
                      &rnp, &ops, test_rsa_ask_twice_4096, strlen(test_rsa_ask_twice_4096)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.key_alg, PGP_PKA_RSA);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.rsa.modulus_bit_len, 4096);
    rnp_end(&rnp);

    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, test_sm2, strlen(test_sm2)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.key_alg, PGP_PKA_SM2);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.ecc.curve, PGP_CURVE_SM2_P_256);
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.hash_alg, PGP_HASH_SM3);
    rnp_end(&rnp);

    rnp_cfg_free(&ops);
}

void
generatekeyECDSA_explicitlySetSmallOutputDigest_DigestAlgAdjusted(void **state)
{
    rnp_test_state_t *rstate = *state;
    rnp_t             rnp;
    rnp_cfg_t         ops = {0};

    static const char test_ecdsa_384[] = "19\n2\n";

    rnp_assert_true(rstate, rnp_cfg_setbool(&ops, CFG_EXPERT, true));
    rnp_assert_true(rstate, rnp_cfg_set(&ops, CFG_HASH, "SHA1"));

    rnp_assert_true(rstate,
                    ask_expert_details(&rnp, &ops, test_ecdsa_384, strlen(test_ecdsa_384)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.hash_alg, PGP_HASH_SHA384);

    rnp_cfg_free(&ops);
}

void
generatekeyECDSA_explicitlySetBiggerThanNeededDigest_ShouldSuceed(void **state)
{
    rnp_test_state_t *rstate = *state;
    rnp_t             rnp;
    rnp_cfg_t         ops = {0};

    static const char test_ecdsa_384[] = "19\n2\n";

    rnp_assert_true(rstate, rnp_cfg_setbool(&ops, CFG_EXPERT, true));
    rnp_assert_true(rstate, rnp_cfg_set(&ops, CFG_HASH, "SHA512"));

    rnp_assert_true(rstate,
                    ask_expert_details(&rnp, &ops, test_ecdsa_384, strlen(test_ecdsa_384)));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.crypto.hash_alg, PGP_HASH_SHA512);

    rnp_cfg_free(&ops);
}

void
generatekeyECDSA_explicitlySetWrongDigest_ShouldFail(void **state)
{
    rnp_test_state_t *rstate = *state;
    rnp_t             rnp;
    rnp_cfg_t         ops = {0};

    static const char test_ecdsa_384[] = "19\n2\n";

    rnp_assert_true(rstate, rnp_cfg_setbool(&ops, CFG_EXPERT, true));
    rnp_assert_true(rstate, rnp_cfg_set(&ops, CFG_HASH, "WRONG_DIGEST_ALGORITHM"));

    rnp_assert_false(rstate,
                     ask_expert_details(&rnp, &ops, test_ecdsa_384, strlen(test_ecdsa_384)));
    rnp_cfg_free(&ops);
}
