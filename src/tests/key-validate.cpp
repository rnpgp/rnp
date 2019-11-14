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

    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/1/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    /* this keyring has one expired subkey */
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "1d7e8a5393c997a8", NULL));
    assert_false(key->valid);
    key->valid = true;
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    secring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/1/secring.gpg");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(secring, "1d7e8a5393c997a8", NULL));
    assert_false(key->valid);
    key->valid = true;
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/2/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    secring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/2/secring.gpg");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(RNP_KEYSTORE_KBX, "data/keyrings/3/pubring.kbx");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));

    secring = rnp_key_store_new(RNP_KEYSTORE_G10, "data/keyrings/3/private-keys-v1.d");
    assert_non_null(secring);
    pgp_key_provider_t key_provider = {.callback = rnp_key_provider_store,
                                       .userdata = pubring};
    assert_true(rnp_key_store_load_from_path(secring, &key_provider));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(pubring);
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/4/pubring.pgp");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    secring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/4/secring.pgp");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/5/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    secring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/5/secring.gpg");
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

TEST_F(rnp_tests, test_forged_key_validate)
{
    rnp_key_store_t *pubring;
    pgp_key_t *      key = NULL;

    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "");
    assert_non_null(pubring);

    /* load valid dsa-eg key */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub.pgp");
    key = rnp_tests_get_key_by_id(pubring, "C8A10A7D78273E10", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load dsa-eg key with forged self-signature. Subkey will not be valid as well. */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub-forged-key.pgp");
    key = rnp_tests_get_key_by_id(pubring, "C8A10A7D78273E10", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "02A5715C3537717E", NULL);
    assert_non_null(key);
    assert_false(key->valid);
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
    key = rnp_tests_get_key_by_id(pubring, "02A5715C3537717E", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "C8A10A7D78273E10", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load valid eddsa key */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub.pgp");
    key = rnp_tests_get_key_by_id(pubring, "CC786278981B0728", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load eddsa key with forged self-signature */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-forged-key.pgp");
    key = rnp_tests_get_key_by_id(pubring, "CC786278981B0728", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load eddsa key with forged key material */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-forged-material.pgp");
    key = rnp_tests_key_search(pubring, "ecc-25519");
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load valid ecdsa/ecdh p-256 keypair */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub.pgp");
    key = rnp_tests_get_key_by_id(pubring, "23674F21B2441527", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh key with forged self-signature. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-key.pgp");
    key = rnp_tests_get_key_by_id(pubring, "23674F21B2441527", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh key with forged key material. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-material.pgp");
    key = rnp_tests_get_key_by_id(pubring, "23674F21B2441527", NULL);
    assert_null(key);
    key = rnp_tests_key_search(pubring, "ecc-p256");
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair with forged subkey binding signature */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-subkey.pgp");
    key = rnp_tests_get_key_by_id(pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "23674F21B2441527", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair without certification */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-no-certification.pgp");
    key = rnp_tests_get_key_by_id(pubring, "23674F21B2441527", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair without subkey binding */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-no-binding.pgp");
    key = rnp_tests_get_key_by_id(pubring, "23674F21B2441527", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load valid rsa/rsa keypair */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub.pgp");
    key = rnp_tests_get_key_by_id(pubring, "2FB9179118898E8B", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "6E2F73008F8B8D6E", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load rsa/rsa key with forged self-signature. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-key.pgp");
    key = rnp_tests_get_key_by_id(pubring, "2FB9179118898E8B", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "6E2F73008F8B8D6E", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load rsa/rsa key with forged key material. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-material.pgp");
    key = rnp_tests_get_key_by_id(pubring, "2FB9179118898E8B", NULL);
    assert_null(key);
    key = rnp_tests_key_search(pubring, "rsa-rsa");
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "6E2F73008F8B8D6E", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load rsa/rsa keypair with forged subkey binding signature */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-subkey.pgp");
    key = rnp_tests_get_key_by_id(pubring, "6E2F73008F8B8D6E", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "2FB9179118898E8B", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load rsa/rsa keypair with future creation date */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-future-key.pgp");
    key = rnp_tests_get_key_by_id(pubring, "3D032D00EE1EC3F5", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "021085B640CE8DCE", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load eddsa/rsa keypair with certification with future creation date */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-future-cert.pgp");
    key = rnp_tests_get_key_by_id(pubring, "D3B746FA852C2BE8", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "EB8C21ACDC15CA14", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load ecdsa/rsa keypair with expired subkey */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-expired-subkey.pgp");
    key = rnp_tests_get_key_by_id(pubring, "23674F21B2441527", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair with expired key */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-expired-key.pgp");
    key = rnp_tests_get_key_by_id(pubring, "23674F21B2441527", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_tests_get_key_by_id(pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    rnp_key_store_free(pubring);
}
