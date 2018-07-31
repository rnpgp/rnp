/*
 * Copyright (c) 2018, [Ribose Inc](https://www.ribose.com).
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

static bool
all_keys_valid(const rnp_key_store_t *keyring)
{
    char keyid[PGP_KEY_ID_SIZE * 2 + 3] = {0};

    for (list_item *ki = list_front(keyring->keys); ki; ki = list_next(ki)) {
        pgp_key_t *key = (pgp_key_t*) ki;
        if (!key->valid) {
            assert_true(rnp_hex_encode(key->keyid, PGP_KEY_ID_SIZE, keyid, sizeof(keyid), RNP_HEX_LOWERCASE));
            RNP_LOG("key %s is not valid", keyid);
            return false;
        }
    }
    return true;
}

void
test_key_validate(void **state)
{
    pgp_io_t          io = pgp_io_from_fp(stderr, stdout, stdout);
    rnp_key_store_t * pubring;
    rnp_key_store_t * secring;

    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/1/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_file(&io, pubring, NULL));
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    secring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/1/secring.gpg");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_file(&io, secring, NULL));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/2/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_file(&io, pubring, NULL));
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    secring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/2/secring.gpg");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_file(&io, secring, NULL));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(RNP_KEYSTORE_KBX, "data/keyrings/3/pubring.kbx");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_file(&io, pubring, NULL));
    assert_true(all_keys_valid(pubring));

    secring = rnp_key_store_new(RNP_KEYSTORE_G10, "data/keyrings/3/private-keys-v1.d");
    assert_non_null(secring);
    pgp_key_provider_t key_provider = {.callback = rnp_key_provider_store,
                                       .userdata = pubring};
    assert_true(rnp_key_store_load_from_file(&io, secring, &key_provider));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(pubring);
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/4/pubring.pgp");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_file(&io, pubring, NULL));
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    secring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/4/secring.pgp");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_file(&io, secring, NULL));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(secring);

    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/5/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_file(&io, pubring, NULL));
    assert_true(all_keys_valid(pubring));
    rnp_key_store_free(pubring);

    secring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/5/secring.gpg");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_file(&io, secring, NULL));
    assert_true(all_keys_valid(secring));
    rnp_key_store_free(secring);
}