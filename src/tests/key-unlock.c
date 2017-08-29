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

#include "../librekey/key_store_pgp.h"
#include "pgp-key.h"

#include "rnp_tests.h"
#include "support.h"
#include "utils.h"
#include "hash.h"

// this is a passphrase callback that will always fail
static bool
failing_passphrase_callback(const pgp_passphrase_ctx_t *ctx,
                            char *                      passphrase,
                            size_t                      passphrase_size,
                            void *                      userdata)
{
    return false;
}

// this is a passphrase callback that should never be called
static bool
asserting_passphrase_callback(const pgp_passphrase_ctx_t *ctx,
                              char *                      passphrase,
                              size_t                      passphrase_size,
                              void *                      userdata)
{
    assert_false(true);
    return false;
}

// this is a passphrase callback that just copies the string in userdata to
// the passphrase buffer
static bool
string_copy_passphrase_callback(const pgp_passphrase_ctx_t *ctx,
                                char *                      passphrase,
                                size_t                      passphrase_size,
                                void *                      userdata)
{
    const char *str = (const char *) userdata;
    strncpy(passphrase, str, passphrase_size - 1);
    return true;
}

void
test_key_unlock_pgp(void **state)
{
    rnp_test_state_t *        rstate = *state;
    char                      path[PATH_MAX];
    rnp_t                     rnp;
    const pgp_key_t *         key = NULL;
    rnp_ctx_t                 ctx;
    const char *              data = "my test data";
    char                      signature[512] = {0};
    int                       siglen = 0;
    char                      encrypted[512] = {0};
    int                       enclen = 0;
    char                      decrypted[512] = {0};
    int                       declen = 0;
    pgp_passphrase_provider_t provider = {0};
    static const char *       keyids[] = {"7bc6709b15c23a4a", // primary
                                   "1ed63ee56fadc34d",
                                   "1d7e8a5393c997a8",
                                   "8a05b89fad5aded1",
                                   "2fcadf05ffa501bb", // primary
                                   "54505a936a4a970e",
                                   "326ef111425d14a5"};

    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/1/", NULL);
    rnp_assert_ok(rstate, setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, path, NULL));
    rnp_assert_ok(rstate, rnp_key_store_load_keys(&rnp, true));

    for (size_t i = 0; i < ARRAY_SIZE(keyids); i++) {
        const char *keyid = keyids[i];
        key = NULL;
        rnp_assert_true(rstate,
                        rnp_key_store_get_key_by_name(rnp.io, rnp.secring, keyid, &key));
        assert_non_null(key);
        // all keys in this keyring are encrypted and thus should be locked initially
        rnp_assert_true(rstate, pgp_key_is_locked(key));
    }

    // try signing with a failing passphrase provider (should fail)
    rnp.passphrase_provider =
      (pgp_passphrase_provider_t){.callback = failing_passphrase_callback, .userdata = NULL};
    rnp_ctx_init(&ctx, &rnp);
    ctx.halg = pgp_str_to_hash_alg("SHA1");
    memset(signature, 0, sizeof(signature));
    siglen = rnp_sign_memory(
      &ctx, keyids[0], data, strlen(data), signature, sizeof(signature), false);
    rnp_assert_int_equal(rstate, 0, siglen);
    rnp_ctx_free(&ctx);

    // grab the signing key to unlock
    rnp_assert_true(rstate,
                    rnp_key_store_get_key_by_name(rnp.io, rnp.secring, keyids[0], &key));

    // try to unlock with a failing passphrase provider
    provider =
      (pgp_passphrase_provider_t){.callback = failing_passphrase_callback, .userdata = NULL};
    rnp_assert_false(rstate, pgp_key_unlock((pgp_key_t *) key, &provider));
    rnp_assert_true(rstate, pgp_key_is_locked(key));

    // try to unlock with an incorrect passphrase
    provider = (pgp_passphrase_provider_t){.callback = string_copy_passphrase_callback,
                                           .userdata = "badpass"};
    rnp_assert_false(rstate, pgp_key_unlock((pgp_key_t *) key, &provider));
    rnp_assert_true(rstate, pgp_key_is_locked(key));

    // unlock with the signing key
    provider = (pgp_passphrase_provider_t){.callback = string_copy_passphrase_callback,
                                           .userdata = "password"};
    rnp_assert_true(rstate, pgp_key_unlock((pgp_key_t *) key, &provider));
    rnp_assert_false(rstate, pgp_key_is_locked(key));

    // now the signing key is unlocked, confirm that no passphrase is required for signing
    rnp.passphrase_provider =
      (pgp_passphrase_provider_t){.callback = asserting_passphrase_callback, .userdata = NULL};

    // sign, with no passphrase
    rnp_ctx_init(&ctx, &rnp);
    ctx.halg = pgp_str_to_hash_alg("SHA1");
    memset(signature, 0, sizeof(signature));
    siglen = rnp_sign_memory(
      &ctx, keyids[0], data, strlen(data), signature, sizeof(signature), false);
    rnp_assert_int_not_equal(rstate, 0, siglen);
    rnp_ctx_free(&ctx);

    // verify
    rnp_ctx_init(&ctx, &rnp);
    ctx.armour = false;
    rnp_assert_int_equal(rstate, 1, rnp_verify_memory(&ctx, signature, siglen, NULL, 0));
    rnp_ctx_free(&ctx);

    // verify (negative)
    rnp_ctx_init(&ctx, &rnp);
    signature[siglen / 2] ^= 0xff;
    ctx.armour = false;
    rnp_assert_int_equal(rstate, 0, rnp_verify_memory(&ctx, signature, siglen, NULL, 0));
    rnp_ctx_free(&ctx);

    // lock the signing key
    pgp_key_lock((pgp_key_t *) key);
    rnp_assert_true(rstate, pgp_key_is_locked(key));
    rnp.passphrase_provider =
      (pgp_passphrase_provider_t){.callback = failing_passphrase_callback, .userdata = NULL};

    // sign, with no passphrase (should now fail)
    rnp_ctx_init(&ctx, &rnp);
    ctx.halg = pgp_str_to_hash_alg("SHA1");
    memset(signature, 0, sizeof(signature));
    siglen = rnp_sign_memory(
      &ctx, keyids[0], data, strlen(data), signature, sizeof(signature), false);
    rnp_assert_int_equal(rstate, 0, siglen);
    rnp_ctx_free(&ctx);

    // encrypt
    rnp_ctx_init(&ctx, &rnp);
    ctx.ealg = PGP_SA_AES_256;
    // Note: keyids[1] is an encrypting subkey
    enclen =
      rnp_encrypt_memory(&ctx, keyids[1], data, strlen(data), encrypted, sizeof(encrypted));
    rnp_assert_true(rstate, enclen > 0);
    rnp_ctx_free(&ctx);

    // try decrypting with a failing passphrase provider (should fail)
    rnp.passphrase_provider =
      (pgp_passphrase_provider_t){.callback = failing_passphrase_callback, .userdata = NULL};
    rnp_ctx_init(&ctx, &rnp);
    declen = rnp_decrypt_memory(&ctx, encrypted, enclen, decrypted, sizeof(decrypted));
    rnp_assert_true(rstate, declen <= 0);
    rnp_ctx_free(&ctx);

    // grab the encrypting key to unlock
    key = NULL;
    rnp_assert_true(rstate,
                    rnp_key_store_get_key_by_name(rnp.io, rnp.secring, keyids[1], &key));

    // unlock the encrypting key
    provider = (pgp_passphrase_provider_t){.callback = string_copy_passphrase_callback,
                                           .userdata = "password"};
    rnp_assert_true(rstate, pgp_key_unlock((pgp_key_t *) key, &provider));
    rnp_assert_false(rstate, pgp_key_is_locked(key));

    // decrypt, with no passphrase
    rnp_ctx_init(&ctx, &rnp);
    declen = rnp_decrypt_memory(&ctx, encrypted, enclen, decrypted, sizeof(decrypted));
    rnp_assert_int_equal(rstate, declen, strlen(data));
    assert_string_equal(data, decrypted);
    rnp_ctx_free(&ctx);

    // lock the encrypting key
    pgp_key_lock((pgp_key_t *) key);
    rnp_assert_true(rstate, pgp_key_is_locked(key));
    rnp.passphrase_provider =
      (pgp_passphrase_provider_t){.callback = failing_passphrase_callback, .userdata = NULL};

    // decrypt, with no passphrase (should now fail)
    rnp_ctx_init(&ctx, &rnp);
    declen = rnp_decrypt_memory(&ctx, encrypted, enclen, decrypted, sizeof(decrypted));
    rnp_assert_true(rstate, declen <= 0);
    rnp_ctx_free(&ctx);

    // cleanup
    rnp_end(&rnp);
}
