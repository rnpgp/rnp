/*
 * Copyright (c) 2018-2019 [Ribose Inc](https://www.ribose.com).
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
#include "../librepgp/stream-packet.h"

static bool
all_keys_valid(const rnp_key_store_t *keyring)
{
    char keyid[PGP_KEY_ID_SIZE * 2 + 3] = {0};

    for (size_t i = 0; i < rnp_key_store_get_key_count(keyring); i++) {
        pgp_key_t *key = rnp_key_store_get_key(keyring, i);
        if (!key->valid) {
            assert_true(rnp_hex_encode(pgp_key_get_keyid(key),
                                       PGP_KEY_ID_SIZE,
                                       keyid,
                                       sizeof(keyid),
                                       RNP_HEX_LOWERCASE));
            RNP_LOG("key %s is not valid", keyid);
            return false;
        }
    }
    return true;
}

TEST_F(rnp_tests, test_key_validate)
{
    rnp_key_store_t *pubring;
    rnp_key_store_t *secring;
    pgp_key_t *      key = NULL;

    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, "data/keyrings/1/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    /* this keyring has one expired subkey */
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "1d7e8a5393c997a8", NULL));
    assert_false(key->valid);
    key->valid = true;
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    /* secret key doesn't have expired binding signature so considered as valid */
    secring = rnp_key_store_new(PGP_KEY_STORE_GPG, "data/keyrings/1/secring.gpg");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(secring, "1d7e8a5393c997a8", NULL));
    assert_true(key->valid);
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, "data/keyrings/2/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    secring = rnp_key_store_new(PGP_KEY_STORE_GPG, "data/keyrings/2/secring.gpg");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(PGP_KEY_STORE_KBX, "data/keyrings/3/pubring.kbx");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));

    secring = rnp_key_store_new(PGP_KEY_STORE_G10, "data/keyrings/3/private-keys-v1.d");
    assert_non_null(secring);
    pgp_key_provider_t key_provider = {.callback = rnp_key_provider_store,
                                       .userdata = pubring};
    assert_true(rnp_key_store_load_from_path(secring, &key_provider));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(pubring);
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, "data/keyrings/4/pubring.pgp");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    secring = rnp_key_store_new(PGP_KEY_STORE_GPG, "data/keyrings/4/secring.pgp");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, "data/keyrings/5/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    secring = rnp_key_store_new(PGP_KEY_STORE_GPG, "data/keyrings/5/secring.gpg");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(secring);
}

#define DATA_PATH "data/test_forged_keys/"

static void
key_store_add(rnp_key_store_t *keyring, const char *keypath)
{
    pgp_source_t           keysrc = {};
    pgp_transferable_key_t tkey = {};

    assert_rnp_success(init_file_src(&keysrc, keypath));
    assert_rnp_success(process_pgp_key(&keysrc, &tkey));
    assert_true(rnp_key_store_add_transferable_key(keyring, &tkey));
    transferable_key_destroy(&tkey);
    src_close(&keysrc);
}

static bool
key_check(const rnp_key_store_t *keyring, const std::string &keyid, bool valid)
{
    pgp_key_t *key = rnp_tests_get_key_by_id(keyring, keyid, NULL);
    return key && (key->validated) && (key->valid == valid);
}

TEST_F(rnp_tests, test_forged_key_validate)
{
    rnp_key_store_t *pubring;
    pgp_key_t *      key = NULL;

    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, "");
    assert_non_null(pubring);

    /* load valid dsa-eg key */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub.pgp");
    assert_true(key_check(pubring, "C8A10A7D78273E10", true));
    rnp_key_store_clear(pubring);

    /* load dsa-eg key with forged self-signature and binding. Subkey will not be valid as
     * well. */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub-forged-key.pgp");
    assert_true(key_check(pubring, "C8A10A7D78273E10", false));
    assert_true(key_check(pubring, "02A5715C3537717E", false));
    rnp_key_store_clear(pubring);

    /* load dsa-eg key with forged key material */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub-forged-material.pgp");
    key = rnp_tests_get_key_by_id(pubring, "C8A10A7D78273E10", NULL);
    assert_null(key);
    key = rnp_tests_key_search(pubring, "dsa-eg");
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load dsa-eg keypair with forged subkey binding signature */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub-forged-subkey.pgp");
    assert_true(key_check(pubring, "02A5715C3537717E", false));
    assert_true(key_check(pubring, "C8A10A7D78273E10", true));
    rnp_key_store_clear(pubring);

    /* load valid eddsa key */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub.pgp");
    assert_true(key_check(pubring, "CC786278981B0728", true));
    rnp_key_store_clear(pubring);

    /* load eddsa key with forged self-signature */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-forged-key.pgp");
    assert_true(key_check(pubring, "CC786278981B0728", false));
    rnp_key_store_clear(pubring);

    /* load eddsa key with forged key material */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-forged-material.pgp");
    key = rnp_tests_key_search(pubring, "ecc-25519");
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load valid ecdsa/ecdh p-256 keypair */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", true));
    assert_true(key_check(pubring, "37E285E9E9851491", true));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh key with forged self-signature. Both valid since there is valid binding.
     */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-key.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", true));
    assert_true(key_check(pubring, "37E285E9E9851491", true));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh key with forged key material. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-material.pgp");
    key = rnp_tests_get_key_by_id(pubring, "23674F21B2441527", NULL);
    assert_null(key);
    key = rnp_tests_key_search(pubring, "ecc-p256");
    assert_non_null(key);
    assert_false(key->valid);
    assert_true(key_check(pubring, "37E285E9E9851491", false));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair with forged subkey binding signature */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-subkey.pgp");
    assert_true(key_check(pubring, "37E285E9E9851491", false));
    assert_true(key_check(pubring, "23674F21B2441527", true));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair without certification: valid since have binding */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-no-certification.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", true));
    assert_true(key_check(pubring, "37E285E9E9851491", true));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair without certification and invalid binding */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-no-cert-malf-binding.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", false));
    assert_true(key_check(pubring, "37E285E9E9851491", false));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair without subkey binding */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-no-binding.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", true));
    assert_true(key_check(pubring, "37E285E9E9851491", false));
    rnp_key_store_clear(pubring);

    /* load valid rsa/rsa keypair */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub.pgp");
    assert_true(key_check(pubring, "2FB9179118898E8B", true));
    assert_true(key_check(pubring, "6E2F73008F8B8D6E", true));
    rnp_key_store_clear(pubring);

    /* load rsa/rsa key with forged self-signature. Valid because of valid binding. */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-key.pgp");
    assert_true(key_check(pubring, "2FB9179118898E8B", true));
    assert_true(key_check(pubring, "6E2F73008F8B8D6E", true));
    rnp_key_store_clear(pubring);

    /* load rsa/rsa key with forged key material. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-material.pgp");
    key = rnp_tests_get_key_by_id(pubring, "2FB9179118898E8B", NULL);
    assert_null(key);
    key = rnp_tests_key_search(pubring, "rsa-rsa");
    assert_non_null(key);
    assert_false(key->valid);
    assert_true(key_check(pubring, "6E2F73008F8B8D6E", false));
    rnp_key_store_clear(pubring);

    /* load rsa/rsa keypair with forged subkey binding signature */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-subkey.pgp");
    assert_true(key_check(pubring, "2FB9179118898E8B", true));
    assert_true(key_check(pubring, "6E2F73008F8B8D6E", false));
    rnp_key_store_clear(pubring);

    /* load rsa/rsa keypair with future creation date */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-future-key.pgp");
    assert_true(key_check(pubring, "3D032D00EE1EC3F5", false));
    assert_true(key_check(pubring, "021085B640CE8DCE", false));
    rnp_key_store_clear(pubring);

    /* load eddsa/rsa keypair with certification with future creation date - valid because of
     * binding. */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-future-cert.pgp");
    assert_true(key_check(pubring, "D3B746FA852C2BE8", true));
    assert_true(key_check(pubring, "EB8C21ACDC15CA14", true));
    rnp_key_store_clear(pubring);

    /* load eddsa/rsa keypair with certification with future creation date - invalid because of
     * invalid binding. */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-future-cert-malf-bind.pgp");
    assert_true(key_check(pubring, "D3B746FA852C2BE8", false));
    assert_true(key_check(pubring, "EB8C21ACDC15CA14", false));
    rnp_key_store_clear(pubring);

    /* load ecdsa/rsa keypair with expired subkey */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-expired-subkey.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", true));
    assert_true(key_check(pubring, "37E285E9E9851491", false));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair with expired key */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-expired-key.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", false));
    assert_true(key_check(pubring, "37E285E9E9851491", false));
    rnp_key_store_clear(pubring);

    rnp_key_store_free(pubring);
}

#define KEYSIG_PATH "data/test_key_validity/"

TEST_F(rnp_tests, test_key_validity)
{
    rnp_key_store_t *pubring;
    pgp_key_t *      key = NULL;

    /* Case1:
     * Keys: Alice [pub]
     * Alice is signed by Basil, but without the Basil's key.
     * Result: Alice [valid]
     */
    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, KEYSIG_PATH "case1/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_true(key->valid);
    rnp_key_store_free(pubring);

    /* Case2:
     * Keys: Alice [pub], Basil [pub]
     * Alice is signed by Basil, Basil is signed by Alice, but Alice's self-signature is
     * corrupted.
     * Result: Alice [invalid], Basil [valid]
     */
    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, KEYSIG_PATH "case2/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_false(key->valid);
    assert_non_null(key = rnp_tests_key_search(pubring, "Basil <basil@rnp>"));
    assert_true(key->valid);
    rnp_key_store_free(pubring);

    /* Case3:
     * Keys: Alice [pub], Basil [pub]
     * Alice is signed by Basil, but doesn't have self-signature
     * Result: Alice [invalid]
     */
    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, KEYSIG_PATH "case3/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_false(key->valid);
    assert_non_null(key = rnp_tests_key_search(pubring, "Basil <basil@rnp>"));
    assert_true(key->valid);
    rnp_key_store_free(pubring);

    /* Case4:
     * Keys Alice [pub, sub]
     * Alice subkey has invalid binding signature
     * Result: Alice [valid], Alice sub [invalid]
     */
    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, KEYSIG_PATH "case4/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_true(key->valid);
    assert_int_equal(pgp_key_get_subkey_count(key), 1);
    pgp_key_t *subkey = NULL;
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid);
    rnp_key_store_free(pubring);

    /* Case5:
     * Keys Alice [pub, sub], Basil [pub]
     * Alice subkey has valid binding signature, but from the key Basil
     * Result: Alice [valid], Alice sub [invalid]
     *
     * Note: to re-generate keyring file, use generate.cpp from case5 folder.
     *       To build it, feed -DBUILD_TESTING_GENERATORS=On to the cmake.
     */
    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, KEYSIG_PATH "case5/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_true(key->valid);
    assert_int_equal(pgp_key_get_subkey_count(key), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid);
    rnp_key_store_free(pubring);

    /* Case6:
     * Keys Alice [pub, sub]
     * Key Alice has revocation signature by Alice, and subkey doesn't
     * Result: Alice [invalid], Alice sub [invalid]
     */
    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, KEYSIG_PATH "case6/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_false(key->valid);
    assert_int_equal(pgp_key_get_subkey_count(key), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid);
    rnp_key_store_free(pubring);

    /* Case7:
     * Keys Alice [pub, sub]
     * Alice subkey has revocation signature by Alice
     * Result: Alice [valid], Alice sub [invalid]
     */
    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, KEYSIG_PATH "case7/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_true(key->valid);
    assert_int_equal(pgp_key_get_subkey_count(key), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid);
    rnp_key_store_free(pubring);

    /* Case8:
     * Keys Alice [pub, sub]
     * Userid is stripped from the key, but it still has valid subkey binding
     * Result: Alice [valid], Alice sub[valid]
     */
    pubring = rnp_key_store_new(PGP_KEY_STORE_GPG, KEYSIG_PATH "case8/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "0451409669FFDE3C", NULL));
    assert_true(key->valid);
    assert_int_equal(pgp_key_get_subkey_count(key), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_true(subkey->valid);
    rnp_key_store_free(pubring);
}
