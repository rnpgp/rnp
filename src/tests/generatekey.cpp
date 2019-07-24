/*
 * Copyright (c) 2017-2018 [Ribose Inc](https://www.ribose.com).
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

#include "rnp.h"
#include <rekey/rnp_key_store.h>
#include <rnp/rnpcfg.h>
#include <rnpkeys/rnpkeys.h>

#include "rnp_tests.h"
#include "support.h"
#include "crypto/common.h"
#include "crypto.h"
#include "pgp-key.h"
#include "librepgp/stream-ctx.h"
#include "librepgp/stream-sig.h"
#include "librepgp/stream-key.h"
#include "defaults.h"

extern rng_t global_rng;

void
rnpkeys_generatekey_testSignature(void **state)
{
    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new pair of private/public
     * key
     * Sign a message, then verify it
     */

    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    const char * hashAlg[] = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SM3", NULL};
    rnp_t        rnp;
    rnp_ctx_t    ctx;
    rnp_result_t ret;
    size_t       reslen;
    size_t       siglen;
    int          pipefd[2];
    char         memToSign[] = "A simple test message";
    char         signatureBuf[4096] = {0};
    char         recoveredSig[4096] = {0};
    char         userId[128];

    for (int i = 0; hashAlg[i] != NULL; i++) {
        /* Setup password input and rnp structure */
        rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));

        memset(userId, 0, sizeof(userId));
        strcpy(userId, "sigtest_");
        strcat(userId, hashAlg[i]);

        /* Generate the RSA key and make sure it was generated */
        set_default_rsa_key_desc(&rnp.action.generate_key_ctx, DEFAULT_PGP_HASH_ALG);
        strncpy((char *) rnp.action.generate_key_ctx.primary.keygen.cert.userid,
                userId,
                sizeof(rnp.action.generate_key_ctx.primary.keygen.cert.userid));
        rnp.action.generate_key_ctx.primary.protection.iterations = 1;
        rnp_assert_non_null(rstate, rnp_generate_key(&rnp));

        /* Load the newly generated rnp key */
        rnp_assert_ok(rstate, rnp_load_keyrings(&rnp, true));
        rnp_assert_true(rstate, rnp_secret_count(&rnp) > 0 && rnp_public_count(&rnp) > 0);

        /* Make sure just generated key is present in the keyring */
        rnp_assert_true(rstate, rnp_find_key(&rnp, userId));

        /* Cleanup */
        close(pipefd[0]);
        rnp_end(&rnp);

        for (unsigned int cleartext = 0; cleartext <= 1; ++cleartext) {
            for (unsigned int armored = 0; armored <= 1; ++armored) {
                if (cleartext && !armored) {
                    // This combination doesn't make sense
                    continue;
                }

                /* Setup password input and rnp structure */
                rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));

                /* Load keyring */
                rnp_assert_ok(rstate, rnp_load_keyrings(&rnp, true));
                rnp_assert_true(rstate, rnp_secret_count(&rnp) > 0);

                /* Setup signing context */
                rnp_ctx_init(&ctx, &rnp.rng);
                ctx.armor = armored;
                ctx.halg = pgp_str_to_hash_alg(hashAlg[i]);
                ctx.filename = strdup("dummyfile.dat");
                ctx.clearsign = cleartext;
                rnp_assert_int_not_equal(rstate, ctx.halg, PGP_HASH_UNKNOWN);
                rnp_signer_info_t sinfo = {};
                sinfo.key = rnp_key_store_get_key_by_name(rnp.secring, userId, NULL);
                sinfo.halg = ctx.halg;
                assert_non_null(sinfo.key);
                rnp_assert_non_null(rstate, list_append(&ctx.signers, &sinfo, sizeof(sinfo)));

                /* Signing the memory */
                ret = rnp_protect_mem(&rnp,
                                      &ctx,
                                      memToSign,
                                      strlen(memToSign),
                                      signatureBuf,
                                      sizeof(signatureBuf),
                                      &siglen);

                /* Make sure operation succeeded, and cleanup */
                rnp_assert_int_equal(rstate, ret, RNP_SUCCESS);
                close(pipefd[0]);
                rnp_ctx_free(&ctx);

                /* Verify the memory */
                rnp_ctx_init(&ctx, &rnp.rng);
                ctx.armor = armored;
                ret = rnp_process_mem(&rnp,
                                      &ctx,
                                      signatureBuf,
                                      siglen,
                                      recoveredSig,
                                      sizeof(recoveredSig),
                                      &reslen);
                /* Ensure signature verification passed */
                rnp_assert_int_equal(rstate, ret, RNP_SUCCESS);
                if (cleartext) {
                    rnp_strip_eol(recoveredSig);
                }
                assert_string_equal(recoveredSig, memToSign);

                /* Corrupt the signature */
                /* TODO be smarter about this */
                signatureBuf[siglen / 2] ^= 0x0C;

                ret = rnp_process_mem(&rnp,
                                      &ctx,
                                      signatureBuf,
                                      siglen,
                                      recoveredSig,
                                      sizeof(recoveredSig),
                                      &reslen);
                /* Ensure that signature verification fails */
                rnp_assert_int_not_equal(rstate, ret, RNP_SUCCESS);
                rnp_end(&rnp);
            }
        }
    }
}

void
rnpkeys_generatekey_testEncryption(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
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
    char      memToEncrypt[] = "A simple test message";
    char      ciphertextBuf[4096] = {0};
    char      plaintextBuf[4096] = {0};
    char      userId[128] = {0};

    /* Setup password input and rnp structure */
    rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));

    strcpy(userId, "ciphertest");
    /* Generate the RSA key and make sure it was generated */
    set_default_rsa_key_desc(&rnp.action.generate_key_ctx, DEFAULT_PGP_HASH_ALG);
    strncpy((char *) rnp.action.generate_key_ctx.primary.keygen.cert.userid,
            userId,
            sizeof(rnp.action.generate_key_ctx.primary.keygen.cert.userid));
    rnp_assert_non_null(rstate, rnp_generate_key(&rnp));

    /* Load keyring */
    rnp_assert_ok(rstate, rnp_load_keyrings(&rnp, true));
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
            rnp_assert_ok(rstate, rnp_load_keyrings(&rnp, false));
            rnp_assert_int_equal(rstate, 0, rnp_secret_count(&rnp));

            /* setting the cipher and armored flags */
            rnp_ctx_init(&ctx, &rnp.rng);
            ctx.armor = armored;
            ctx.filename = strdup("dummyfile.dat");
            ctx.ealg = pgp_str_to_cipher(cipherAlg[i]);
            /* checking whether we have correct cipher constant */
            rnp_assert_true(rstate,
                            (ctx.ealg != DEFAULT_PGP_SYMM_ALG) ||
                              (strcmp(cipherAlg[i], "AES256") == 0));
            pgp_key_t *key;
            rnp_assert_non_null(
              rstate, key = rnp_key_store_get_key_by_name(rnp.pubring, userId, NULL));
            rnp_assert_non_null(rstate, list_append(&ctx.recipients, &key, sizeof(key)));
            /* Encrypting the memory */
            size_t       reslen = 0;
            rnp_result_t ret = rnp_protect_mem(&rnp,
                                               &ctx,
                                               memToEncrypt,
                                               strlen(memToEncrypt),
                                               ciphertextBuf,
                                               sizeof(ciphertextBuf),
                                               &reslen);
            rnp_assert_int_equal(rstate, ret, RNP_SUCCESS);
            rnp_ctx_free(&ctx);
            rnp_end(&rnp);

            /* Setting up rnp again and decrypting memory */
            rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));

            /* Loading the keyrings */
            rnp_assert_ok(rstate, rnp_load_keyrings(&rnp, true));
            rnp_assert_true(rstate, rnp_secret_count(&rnp) > 0);

            /* Setting the decryption context */
            rnp_ctx_init(&ctx, &rnp.rng);
            ctx.armor = armored;

            /* Decrypting the memory */
            size_t tmp = sizeof(plaintextBuf);
            rnp_assert_int_equal(
              rstate,
              rnp_process_mem(
                &rnp, &ctx, ciphertextBuf, reslen, plaintextBuf, sizeof(plaintextBuf), &tmp),
              RNP_SUCCESS);

            /* Ensure plaintext recovered */
            rnp_assert_int_equal(rstate, tmp, strlen(memToEncrypt));
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

    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    const char *hashAlg[] = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA224", "SM3"};
    const char *keystores[] = {RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG21, RNP_KEYSTORE_KBX};
    rnp_t       rnp;
    int         pipefd[2];
    char *      rnp_home = rnp_compose_path(rstate->home, ".rnp", NULL);

    for (size_t i = 0; i < sizeof(hashAlg) / sizeof(hashAlg[0]); i++) {
        for (size_t j = 0; j < sizeof(keystores) / sizeof(keystores[0]); j++) {
            delete_recursively(rnp_home);
            /* Setting up rnp again and decrypting memory */
            printf("keystore: %s\n", keystores[j]);
            rnp_assert_ok(rstate, setup_rnp_common(&rnp, keystores[j], NULL, pipefd));

            set_default_rsa_key_desc(&rnp.action.generate_key_ctx,
                                     pgp_str_to_hash_alg(hashAlg[i]));
            rnp_assert_int_not_equal(
              rstate,
              rnp.action.generate_key_ctx.primary.keygen.crypto.hash_alg,
              PGP_HASH_UNKNOWN);
            rnp_assert_int_not_equal(rstate,
                                     rnp.action.generate_key_ctx.subkey.keygen.crypto.hash_alg,
                                     PGP_HASH_UNKNOWN);

            /* Generate key with specified parameters */
            rnp_assert_non_null(rstate, rnp_generate_key(&rnp));

            /* Load the newly generated rnp key */
            rnp_assert_ok(rstate, rnp_load_keyrings(&rnp, true));
            rnp_assert_true(rstate, rnp_secret_count(&rnp) > 0 && rnp_public_count(&rnp) > 0);

            /* Some minor checks */
            for (size_t i = 0; i < rnp_key_store_get_key_count(rnp.pubring); i++) {
                assert_true(pgp_key_is_public(rnp_key_store_get_key(rnp.pubring, i)));
            }

            for (size_t i = 0; i < rnp_key_store_get_key_count(rnp.secring); i++) {
                assert_true(pgp_key_is_secret(rnp_key_store_get_key(rnp.secring, i)));
            }

            // G10 doesn't support metadata
            if (strcmp(keystores[j], RNP_KEYSTORE_G10) != 0) {
                rnp_assert_true(rstate, rnp_find_key(&rnp, getenv("LOGNAME")));
            }

            /* Close pipe and free allocated memory */
            close(pipefd[0]);
            rnp_end(&rnp); // Free memory and other allocated resources.
        }
    }
    free(rnp_home);
}

void
rnpkeys_generatekey_verifyUserIdOption(void **state)
{
    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new keypair
     * Verify the key was generated with the correct UserId. */

    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    char              userId[1024] = {0};
    const char *      userIds[] = {"rnpkeys_generatekey_verifyUserIdOption_MD5",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA-1",
                             "rnpkeys_generatekey_verifyUserIdOption_RIPEMD160",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA256",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA384",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA512",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA224"};

    const char *keystores[] = {RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG21, RNP_KEYSTORE_KBX};
    rnp_t       rnp;
    int         pipefd[2];
    char *      rnp_home = rnp_compose_path(rstate->home, ".rnp", NULL);

    for (size_t i = 0; i < sizeof(userIds) / sizeof(userIds[0]); i++) {
        for (size_t j = 0; j < sizeof(keystores) / sizeof(keystores[0]); j++) {
            delete_recursively(rnp_home);
            /* Set the user id to be used*/
            snprintf(userId, sizeof(userId), "%s", userIds[i]);

            /*Initialize the basic RNP structure. */
            rnp_assert_ok(rstate, setup_rnp_common(&rnp, keystores[j], NULL, pipefd));

            set_default_rsa_key_desc(&rnp.action.generate_key_ctx, PGP_HASH_SHA256);
            strncpy((char *) rnp.action.generate_key_ctx.primary.keygen.cert.userid,
                    userId,
                    sizeof(rnp.action.generate_key_ctx.primary.keygen.cert.userid));
            /* Generate the key with corresponding userId */
            rnp_assert_non_null(rstate, rnp_generate_key(&rnp));

            /*Load the newly generated rnp key*/
            rnp_assert_ok(rstate, rnp_load_keyrings(&rnp, true));
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
    free(rnp_home);
}

void
rnpkeys_generatekey_verifykeyHomeDirOption(void **state)
{
    /* Try to generate keypair in different home directories */

    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
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
    rnp_assert_non_null(rstate, rnp_generate_key(&rnp));

    /* Pubring and secring should now exist */
    rnp_assert_true(rstate, path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    rnp_assert_true(rstate, path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    rnp_assert_ok(rstate, rnp_load_keyrings(&rnp, true));
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
    strncpy((char *) rnp.action.generate_key_ctx.primary.keygen.cert.userid,
            "newhomekey",
            sizeof(rnp.action.generate_key_ctx.primary.keygen.cert.userid));
    rnp_assert_non_null(rstate, rnp_generate_key(&rnp));

    /* Pubring and secring should now exist */
    rnp_assert_true(rstate, path_file_exists(newhome, "pubring.gpg", NULL));
    rnp_assert_true(rstate, path_file_exists(newhome, "secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    rnp_assert_ok(rstate, rnp_load_keyrings(&rnp, true));
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

    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
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
    rnp_assert_non_null(rstate, rnp_generate_key(&rnp));

    /* Pubring and secring should now exist, but only for the KBX */
    rnp_assert_true(rstate, path_file_exists(ourdir, ".rnp/pubring.kbx", NULL));
    rnp_assert_true(rstate, path_file_exists(ourdir, ".rnp/secring.kbx", NULL));
    rnp_assert_false(rstate, path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    rnp_assert_false(rstate, path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    rnp_assert_ok(rstate, rnp_load_keyrings(&rnp, true));
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
    strncpy((char *) rnp.action.generate_key_ctx.primary.keygen.cert.userid,
            "newhomekey",
            sizeof(rnp.action.generate_key_ctx.primary.keygen.cert.userid));
    rnp_assert_non_null(rstate, rnp_generate_key(&rnp));

    /* Pubring and secring should now exist, but only for the KBX */
    rnp_assert_true(rstate, path_file_exists(newhome, "pubring.kbx", NULL));
    rnp_assert_true(rstate, path_file_exists(newhome, "secring.kbx", NULL));
    rnp_assert_false(rstate, path_file_exists(newhome, "pubring.gpg", NULL));
    rnp_assert_false(rstate, path_file_exists(newhome, "secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    rnp_assert_ok(rstate, rnp_load_keyrings(&rnp, true));
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
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
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
    rnp_assert_null(rstate, rnp_generate_key(&rnp));

    close(pipefd[0]);
    rnp_end(&rnp);
}

static bool
ask_expert_details(rnp_t *ctx, rnp_cfg_t *ops, const char *rsp)
{
    /* Run tests*/
    bool      ret = true;
    rnp_cfg_t cfg = {0};
    int       pipefd[2] = {0};
    int       user_input_pipefd[2] = {0};
    size_t    rsp_len;

    rsp_len = strlen(rsp);
    *ctx = (rnp_t){0};
    if (pipe(pipefd) == -1) {
        ret = false;
        goto end;
    }
    rnp_cfg_setint(ops, CFG_PASSFD, pipefd[0]);
    write_pass_to_pipe(pipefd[1], 2);
    if (!rnpkeys_init(&cfg, ctx, ops, true)) {
        return false;
    }

    /* Write response to fd */
    if (pipe(user_input_pipefd) == -1) {
        ret = false;
        goto end;
    }
    for (size_t i = 0; i < rsp_len;) {
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
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    rnp_t             rnp;
    rnp_cfg_t         ops = {0};
    /* let's shortcut some lines for easier reading */
    rnp_keygen_crypto_params_t *keyp = &rnp.action.generate_key_ctx.primary.keygen.crypto;
    rnp_keygen_crypto_params_t *subkeyp = &rnp.action.generate_key_ctx.subkey.keygen.crypto;

    rnp_assert_true(rstate, rnp_cfg_setbool(&ops, CFG_EXPERT, true));
    rnp_assert_true(rstate, rnp_cfg_setint(&ops, CFG_S2K_ITER, 1));

    /* ecdsa/ecdh p256 keypair */
    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "19\n1\n"));
    rnp_assert_int_equal(rstate, keyp->key_alg, PGP_PKA_ECDSA);
    rnp_assert_int_equal(rstate, subkeyp->key_alg, PGP_PKA_ECDH);
    rnp_assert_int_equal(rstate, keyp->ecc.curve, PGP_CURVE_NIST_P_256);
    rnp_assert_int_equal(rstate, keyp->hash_alg, PGP_HASH_SHA256);
    rnp_assert_int_equal(rstate, subkeyp->ecc.curve, PGP_CURVE_NIST_P_256);
    rnp_end(&rnp);

    /* ecdsa/ecdh p384 keypair */
    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "19\n2\n"));
    rnp_assert_int_equal(rstate, keyp->key_alg, PGP_PKA_ECDSA);
    rnp_assert_int_equal(rstate, subkeyp->key_alg, PGP_PKA_ECDH);
    rnp_assert_int_equal(rstate, keyp->ecc.curve, PGP_CURVE_NIST_P_384);
    rnp_assert_int_equal(rstate, keyp->hash_alg, PGP_HASH_SHA384);
    rnp_assert_int_equal(rstate, subkeyp->ecc.curve, PGP_CURVE_NIST_P_384);
    rnp_end(&rnp);

    /* ecdsa/ecdh p521 keypair */
    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "19\n3\n"));
    rnp_assert_int_equal(rstate, keyp->key_alg, PGP_PKA_ECDSA);
    rnp_assert_int_equal(rstate, subkeyp->key_alg, PGP_PKA_ECDH);
    rnp_assert_int_equal(rstate, keyp->ecc.curve, PGP_CURVE_NIST_P_521);
    rnp_assert_int_equal(rstate, keyp->hash_alg, PGP_HASH_SHA512);
    rnp_assert_int_equal(rstate, subkeyp->ecc.curve, PGP_CURVE_NIST_P_521);
    rnp_end(&rnp);

    /* ecdsa/ecdh brainpool256 keypair */
    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "19\n4\n"));
    rnp_assert_int_equal(rstate, keyp->key_alg, PGP_PKA_ECDSA);
    rnp_assert_int_equal(rstate, subkeyp->key_alg, PGP_PKA_ECDH);
    rnp_assert_int_equal(rstate, keyp->ecc.curve, PGP_CURVE_BP256);
    rnp_assert_int_equal(rstate, keyp->hash_alg, PGP_HASH_SHA256);
    rnp_assert_int_equal(rstate, subkeyp->ecc.curve, PGP_CURVE_BP256);
    rnp_end(&rnp);

    /* ecdsa/ecdh brainpool384 keypair */
    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "19\n5\n"));
    rnp_assert_int_equal(rstate, keyp->key_alg, PGP_PKA_ECDSA);
    rnp_assert_int_equal(rstate, subkeyp->key_alg, PGP_PKA_ECDH);
    rnp_assert_int_equal(rstate, keyp->ecc.curve, PGP_CURVE_BP384);
    rnp_assert_int_equal(rstate, keyp->hash_alg, PGP_HASH_SHA384);
    rnp_assert_int_equal(rstate, subkeyp->ecc.curve, PGP_CURVE_BP384);
    rnp_end(&rnp);

    /* ecdsa/ecdh brainpool512 keypair */
    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "19\n6\n"));
    rnp_assert_int_equal(rstate, keyp->key_alg, PGP_PKA_ECDSA);
    rnp_assert_int_equal(rstate, subkeyp->key_alg, PGP_PKA_ECDH);
    rnp_assert_int_equal(rstate, keyp->ecc.curve, PGP_CURVE_BP512);
    rnp_assert_int_equal(rstate, keyp->hash_alg, PGP_HASH_SHA512);
    rnp_assert_int_equal(rstate, subkeyp->ecc.curve, PGP_CURVE_BP512);
    rnp_end(&rnp);

    /* ecdsa/ecdh secp256k1 keypair */
    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "19\n7\n"));
    rnp_assert_int_equal(rstate, keyp->key_alg, PGP_PKA_ECDSA);
    rnp_assert_int_equal(rstate, subkeyp->key_alg, PGP_PKA_ECDH);
    rnp_assert_int_equal(rstate, keyp->ecc.curve, PGP_CURVE_P256K1);
    rnp_assert_int_equal(rstate, keyp->hash_alg, PGP_HASH_SHA256);
    rnp_assert_int_equal(rstate, subkeyp->ecc.curve, PGP_CURVE_P256K1);
    rnp_end(&rnp);

    /* eddsa/x25519 keypair */
    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "22\n"));
    rnp_assert_int_equal(rstate, keyp->key_alg, PGP_PKA_EDDSA);
    rnp_assert_int_equal(rstate, subkeyp->key_alg, PGP_PKA_ECDH);
    rnp_assert_int_equal(rstate, keyp->ecc.curve, PGP_CURVE_ED25519);
    rnp_assert_int_equal(rstate, keyp->hash_alg, PGP_HASH_SHA256);
    rnp_assert_int_equal(rstate, subkeyp->ecc.curve, PGP_CURVE_25519);
    rnp_end(&rnp);

    /* rsa/rsa 1024 key */
    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "1\n1024\n"));
    rnp_assert_int_equal(rstate, keyp->key_alg, PGP_PKA_RSA);
    rnp_assert_int_equal(rstate, keyp->rsa.modulus_bit_len, 1024);
    rnp_assert_int_equal(rstate, subkeyp->key_alg, PGP_PKA_RSA);
    rnp_assert_int_equal(rstate, subkeyp->rsa.modulus_bit_len, 1024);
    rnp_end(&rnp);

    /* rsa 4096 key, asked twice */
    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "1\n1023\n4096\n"));
    rnp_assert_int_equal(rstate, keyp->key_alg, PGP_PKA_RSA);
    rnp_assert_int_equal(rstate, keyp->rsa.modulus_bit_len, 4096);
    rnp_assert_int_equal(rstate, subkeyp->key_alg, PGP_PKA_RSA);
    rnp_assert_int_equal(rstate, subkeyp->rsa.modulus_bit_len, 4096);
    rnp_end(&rnp);

    /* sm2 key */
    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "99\n"));
    rnp_assert_int_equal(rstate, keyp->key_alg, PGP_PKA_SM2);
    rnp_assert_int_equal(rstate, keyp->ecc.curve, PGP_CURVE_SM2_P_256);
    rnp_assert_int_equal(rstate, keyp->hash_alg, PGP_HASH_SM3);
    rnp_assert_int_equal(rstate, subkeyp->key_alg, PGP_PKA_SM2);
    rnp_assert_int_equal(rstate, subkeyp->ecc.curve, PGP_CURVE_SM2_P_256);
    rnp_end(&rnp);

    rnp_cfg_free(&ops);
}

void
generatekeyECDSA_explicitlySetSmallOutputDigest_DigestAlgAdjusted(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    rnp_t             rnp;
    rnp_cfg_t         ops = {0};

    rnp_assert_true(rstate, rnp_cfg_setbool(&ops, CFG_EXPERT, true));
    rnp_assert_true(rstate, rnp_cfg_setstr(&ops, CFG_HASH, "SHA1"));
    rnp_assert_true(rstate, rnp_cfg_setint(&ops, CFG_S2K_ITER, 1));

    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "19\n2\n"));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.keygen.crypto.hash_alg, PGP_HASH_SHA384);

    rnp_cfg_free(&ops);
    rnp_end(&rnp);
}

void
generatekeyECDSA_explicitlySetBiggerThanNeededDigest_ShouldSuceed(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    rnp_t             rnp;
    rnp_cfg_t         ops = {0};

    rnp_assert_true(rstate, rnp_cfg_setbool(&ops, CFG_EXPERT, true));
    rnp_assert_true(rstate, rnp_cfg_setstr(&ops, CFG_HASH, "SHA512"));
    rnp_assert_true(rstate, rnp_cfg_setint(&ops, CFG_S2K_ITER, 1));

    rnp_assert_true(rstate, ask_expert_details(&rnp, &ops, "19\n2\n"));
    rnp_assert_int_equal(
      rstate, rnp.action.generate_key_ctx.primary.keygen.crypto.hash_alg, PGP_HASH_SHA512);

    rnp_cfg_free(&ops);
    rnp_end(&rnp);
}

void
generatekeyECDSA_explicitlySetUnknownDigest_ShouldFail(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    rnp_t             rnp;
    rnp_cfg_t         ops = {0};

    rnp_assert_true(rstate, rnp_cfg_setbool(&ops, CFG_EXPERT, true));
    rnp_assert_true(rstate, rnp_cfg_setstr(&ops, CFG_HASH, "WRONG_DIGEST_ALGORITHM"));
    rnp_assert_true(rstate, rnp_cfg_setint(&ops, CFG_S2K_ITER, 1));

    // Finds out that hash doesn't exist and returns an error
    rnp_assert_false(rstate, ask_expert_details(&rnp, &ops, "19\n2\n"));
    rnp_cfg_free(&ops);
    rnp_end(&rnp);
}

/* This tests some of the mid-level key generation functions and their
 * generated sigs in the keyring.
 */
void
test_generated_key_sigs(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    rnp_key_store_t * pubring = NULL;
    rnp_key_store_t * secring = NULL;
    pgp_key_t *       primary_pub = NULL, *primary_sec = NULL;
    pgp_key_t *       sub_pub = NULL, *sub_sec = NULL;
    pgp_userid_pkt_t  uid = {0};
    rnp_t             rnp;
    rnp_ctx_t         rnp_ctx;

    // create a couple keyrings
    pubring = (rnp_key_store_t *) calloc(1, sizeof(*pubring));
    secring = (rnp_key_store_t *) calloc(1, sizeof(*secring));
    assert_non_null(pubring);
    assert_non_null(secring);

    rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, NULL));
    rnp_ctx_init(&rnp_ctx, &rnp.rng);

    uid.tag = PGP_PTAG_CT_USER_ID;

    // primary
    {
        pgp_key_t                 pub = {0};
        pgp_key_t                 sec = {0};
        rnp_keygen_primary_desc_t desc;
        pgp_fingerprint_t         fp = {};
        pgp_sig_subpkt_t *        subpkt = NULL;
        pgp_signature_t *         psig = NULL;
        pgp_signature_t *         ssig = NULL;

        memset(&desc, 0, sizeof(desc));
        desc.crypto.key_alg = PGP_PKA_RSA;
        desc.crypto.rsa.modulus_bit_len = 1024;
        desc.crypto.rng = &global_rng;
        strcpy((char *) desc.cert.userid, "test");

        // generate
        assert_true(pgp_generate_primary_key(&desc, true, &sec, &pub, GPG_KEY_STORE));

        // add to our rings
        assert_true(rnp_key_store_add_key(pubring, &pub));
        assert_true(rnp_key_store_add_key(secring, &sec));
        // retrieve back from our rings (for later)
        primary_pub = rnp_key_store_get_key_by_grip(pubring, pgp_key_get_grip(&pub));
        primary_sec = rnp_key_store_get_key_by_grip(secring, pgp_key_get_grip(&pub));
        assert_non_null(primary_pub);
        assert_non_null(primary_sec);

        // check packet and subsig counts
        assert_int_equal(3, pgp_key_get_rawpacket_count(&pub));
        assert_int_equal(3, pgp_key_get_rawpacket_count(&sec));
        assert_int_equal(1, pgp_key_get_subsig_count(&pub));
        assert_int_equal(1, pgp_key_get_subsig_count(&sec));
        psig = &pgp_key_get_subsig(&pub, 0)->sig;
        ssig = &pgp_key_get_subsig(&sec, 0)->sig;
        // make sure our sig MPI is not NULL
        assert_int_not_equal(psig->material.rsa.s.len, 0);
        assert_int_not_equal(ssig->material.rsa.s.len, 0);
        // make sure we're targeting the right packet
        assert_int_equal(PGP_PTAG_CT_SIGNATURE, pgp_key_get_rawpacket(&pub, 2)->tag);
        assert_int_equal(PGP_PTAG_CT_SIGNATURE, pgp_key_get_rawpacket(&sec, 2)->tag);

        // validate the userid self-sig
        uid.uid = (uint8_t *) pgp_key_get_userid(&pub, 0);
        uid.uid_len = strlen((char *) uid.uid);
        assert_rnp_success(signature_validate_certification(
          psig, pgp_key_get_pkt(&pub), &uid, pgp_key_get_material(&pub)));
        assert_true(signature_get_keyfp(psig, &fp));
        assert_true(fingerprint_equal(&fp, pgp_key_get_fp(&pub)));
        // check subpackets and their contents
        subpkt = signature_get_subpkt(psig, PGP_SIG_SUBPKT_ISSUER_FPR);
        assert_non_null(subpkt);
        assert_true(subpkt->hashed);
        subpkt = signature_get_subpkt(psig, PGP_SIG_SUBPKT_ISSUER_KEY_ID);
        assert_non_null(subpkt);
        assert_false(subpkt->hashed);
        assert_int_equal(
          0, memcmp(subpkt->fields.issuer, pgp_key_get_keyid(&pub), PGP_KEY_ID_SIZE));
        subpkt = signature_get_subpkt(psig, PGP_SIG_SUBPKT_CREATION_TIME);
        assert_non_null(subpkt);
        assert_true(subpkt->hashed);
        assert_true(subpkt->fields.create <= time(NULL));

        uid.uid = (uint8_t *) pgp_key_get_userid(&sec, 0);
        uid.uid_len = strlen((char *) uid.uid);
        assert_rnp_success(signature_validate_certification(
          ssig, pgp_key_get_pkt(&sec), &uid, pgp_key_get_material(&sec)));
        assert_true(signature_get_keyfp(ssig, &fp));
        assert_true(fingerprint_equal(&fp, pgp_key_get_fp(&sec)));

        // modify a hashed portion of the sig packets
        psig->hashed_data[32] ^= 0xff;
        ssig->hashed_data[32] ^= 0xff;
        // ensure validation fails
        uid.uid = (uint8_t *) pgp_key_get_userid(&pub, 0);
        uid.uid_len = strlen((char *) uid.uid);
        assert_rnp_failure(signature_validate_certification(
          psig, pgp_key_get_pkt(&pub), &uid, pgp_key_get_material(&pub)));
        uid.uid = (uint8_t *) pgp_key_get_userid(&sec, 0);
        uid.uid_len = strlen((char *) uid.uid);
        assert_rnp_failure(signature_validate_certification(
          ssig, pgp_key_get_pkt(&sec), &uid, pgp_key_get_material(&sec)));
        // restore the original data
        psig->hashed_data[32] ^= 0xff;
        ssig->hashed_data[32] ^= 0xff;
        // ensure validation fails with incorrect uid
        uid.uid = (uint8_t *) "fake";
        uid.uid_len = strlen((char *) uid.uid);
        assert_rnp_failure(signature_validate_certification(
          psig, pgp_key_get_pkt(&pub), &uid, pgp_key_get_material(&pub)));
        assert_rnp_failure(signature_validate_certification(
          ssig, pgp_key_get_pkt(&sec), &uid, pgp_key_get_material(&sec)));

        // validate via an alternative method
        pgp_signatures_info_t result = {0};
        // primary_pub + pubring
        assert_rnp_success(validate_pgp_key_signatures(&result, primary_pub, pubring));
        assert_true(check_signatures_info(&result));
        free_signatures_info(&result);
        // primary_sec + pubring
        assert_rnp_success(validate_pgp_key_signatures(&result, primary_sec, pubring));
        assert_true(check_signatures_info(&result));
        free_signatures_info(&result);
        // primary_pub + secring
        assert_rnp_success(validate_pgp_key_signatures(&result, primary_pub, secring));
        assert_true(check_signatures_info(&result));
        free_signatures_info(&result);
        // primary_sec + secring
        assert_rnp_success(validate_pgp_key_signatures(&result, primary_sec, secring));
        assert_true(check_signatures_info(&result));
        free_signatures_info(&result);

        // do at least one modification test for validate_pgp_key_signatures too
        // modify a hashed portion of the sig packet, offset may change in future
        pgp_key_get_rawpacket(primary_pub, 2)->raw[37] ^= 0xff;
        // ensure validation fails
        assert_rnp_success(validate_pgp_key_signatures(&result, primary_pub, pubring));
        assert_false(check_signatures_info(&result));
        free_signatures_info(&result);
        // restore the original data
        pgp_key_get_rawpacket(primary_pub, 2)->raw[37] ^= 0xff;
    }

    // sub
    {
        pgp_key_t                pub = {0};
        pgp_key_t                sec = {0};
        rnp_keygen_subkey_desc_t desc;
        pgp_fingerprint_t        fp = {};
        pgp_sig_subpkt_t *       subpkt = NULL;
        pgp_signature_t *        psig = NULL;
        pgp_signature_t *        ssig = NULL;

        memset(&desc, 0, sizeof(desc));
        desc.crypto.key_alg = PGP_PKA_RSA;
        desc.crypto.rsa.modulus_bit_len = 1024;
        desc.crypto.rng = &global_rng;

        // generate
        assert_true(pgp_generate_subkey(
          &desc, true, primary_sec, primary_pub, &sec, &pub, NULL, GPG_KEY_STORE));

        // check packet and subsig counts
        assert_int_equal(2, pgp_key_get_rawpacket_count(&pub));
        assert_int_equal(2, pgp_key_get_rawpacket_count(&sec));
        assert_int_equal(1, pgp_key_get_subsig_count(&pub));
        assert_int_equal(1, pgp_key_get_subsig_count(&sec));
        psig = &pgp_key_get_subsig(&pub, 0)->sig;
        ssig = &pgp_key_get_subsig(&sec, 0)->sig;
        // make sure our sig MPI is not NULL
        assert_int_not_equal(psig->material.rsa.s.len, 0);
        assert_int_not_equal(ssig->material.rsa.s.len, 0);
        // make sure we're targeting the right packet
        assert_int_equal(PGP_PTAG_CT_SIGNATURE, pgp_key_get_rawpacket(&pub, 1)->tag);
        assert_int_equal(PGP_PTAG_CT_SIGNATURE, pgp_key_get_rawpacket(&sec, 1)->tag);
        // validate the binding sig
        assert_rnp_success(signature_validate_binding(
          psig, pgp_key_get_pkt(primary_pub), pgp_key_get_pkt(&pub)));
        assert_true(signature_get_keyfp(psig, &fp));
        assert_true(fingerprint_equal(&fp, pgp_key_get_fp(primary_pub)));
        // check subpackets and their contents
        subpkt = signature_get_subpkt(psig, PGP_SIG_SUBPKT_ISSUER_FPR);
        assert_non_null(subpkt);
        assert_true(subpkt->hashed);
        subpkt = signature_get_subpkt(psig, PGP_SIG_SUBPKT_ISSUER_KEY_ID);
        assert_non_null(subpkt);
        assert_false(subpkt->hashed);
        assert_int_equal(
          0, memcmp(subpkt->fields.issuer, pgp_key_get_keyid(primary_pub), PGP_KEY_ID_SIZE));
        subpkt = signature_get_subpkt(psig, PGP_SIG_SUBPKT_CREATION_TIME);
        assert_non_null(subpkt);
        assert_true(subpkt->hashed);
        assert_true(subpkt->fields.create <= time(NULL));

        assert_rnp_success(signature_validate_binding(
          ssig, pgp_key_get_pkt(primary_pub), pgp_key_get_pkt(&sec)));
        assert_true(signature_get_keyfp(ssig, &fp));
        assert_true(fingerprint_equal(&fp, pgp_key_get_fp(primary_sec)));

        // modify a hashed portion of the sig packets
        psig->hashed_data[10] ^= 0xff;
        ssig->hashed_data[10] ^= 0xff;
        // ensure validation fails
        assert_rnp_failure(signature_validate_binding(
          psig, pgp_key_get_pkt(primary_pub), pgp_key_get_pkt(&pub)));
        assert_rnp_failure(signature_validate_binding(
          ssig, pgp_key_get_pkt(primary_pub), pgp_key_get_pkt(&sec)));
        // restore the original data
        psig->hashed_data[10] ^= 0xff;
        ssig->hashed_data[10] ^= 0xff;

        // add to our rings
        assert_true(rnp_key_store_add_key(pubring, &pub));
        assert_true(rnp_key_store_add_key(secring, &sec));
        // retrieve back from our rings
        sub_pub = rnp_key_store_get_key_by_grip(pubring, pgp_key_get_grip(&pub));
        sub_sec = rnp_key_store_get_key_by_grip(secring, pgp_key_get_grip(&pub));
        assert_non_null(sub_pub);
        assert_non_null(sub_sec);

        // TODO: validate_pgp_key_signatures expects key->packets[] to contain
        // both the primary and sub, so we have to fake it.
        pgp_key_t fake = {0};
        for (size_t i = 0; i < pgp_key_get_rawpacket_count(primary_pub); i++) {
            pgp_rawpacket_t *packet = pgp_key_get_rawpacket(primary_pub, i);
            pgp_key_add_rawpacket(&fake, packet->raw, packet->length, packet->tag);
        }
        for (size_t i = 0; i < pgp_key_get_rawpacket_count(sub_pub); i++) {
            pgp_rawpacket_t *packet = pgp_key_get_rawpacket(sub_pub, i);
            pgp_key_add_rawpacket(&fake, packet->raw, packet->length, packet->tag);
        }
        // validate via an alternative method
        pgp_signatures_info_t result = {0};
        assert_rnp_success(validate_pgp_key_signatures(&result, &fake, pubring));
        assert_true(check_signatures_info(&result));
        free_signatures_info(&result);
        pgp_key_free_data(&fake);
    }

    rnp_key_store_free(pubring);
    rnp_key_store_free(secring);
    rnp_ctx_free(&rnp_ctx);
    rnp_end(&rnp);
}
