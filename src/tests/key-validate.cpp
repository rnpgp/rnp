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
#include "../librepgp/stream-packet.h"

static bool
all_keys_valid(const rnp_key_store_t *keyring)
{
    char keyid[PGP_KEY_ID_SIZE * 2 + 3] = {0};

    for (list_item *ki = list_front(keyring->keys); ki; ki = list_next(ki)) {
        pgp_key_t *key = (pgp_key_t *) ki;
        if (!key->valid) {
            assert_true(rnp_hex_encode(
              key->keyid, PGP_KEY_ID_SIZE, keyid, sizeof(keyid), RNP_HEX_LOWERCASE));
            RNP_LOG("key %s is not valid", keyid);
            return false;
        }
    }
    return true;
}

void
test_key_validate(void **state)
{
    pgp_io_t         io = pgp_io_from_fp(stderr, stdout, stdout);
    rnp_key_store_t *pubring;
    rnp_key_store_t *secring;

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

static void
load_signature(pgp_rawpacket_t *packet, pgp_signature_t *sig)
{
    pgp_source_t memsrc = {};
    assert_rnp_success(init_mem_src(&memsrc, packet->raw, packet->length, false));
    assert_rnp_success(stream_parse_signature(&memsrc, sig));
    src_close(&memsrc);
}

static void
save_signature(pgp_rawpacket_t *packet, pgp_signature_t *sig)
{
    pgp_dest_t memdst = {};
    assert_rnp_success(init_mem_dest(&memdst, packet->raw, packet->length));
    assert_true(stream_write_signature(sig, &memdst));
    dst_close(&memdst, false);
}

static void
forge_signature_material(pgp_rawpacket_t *packet)
{
    pgp_signature_t sig = {};
    assert_int_equal(packet->tag, PGP_PTAG_CT_SIGNATURE);
    load_signature(packet, &sig);

    switch (sig.palg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        sig.material.rsa.s.mpi[8] ^= 0xff;
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDSA:
        sig.material.ecc.s.mpi[8] ^= 0xff;
        break;
    case PGP_PKA_DSA:
        sig.material.dsa.s.mpi[8] ^= 0xff;
        break;
    default:
        RNP_LOG("Unsupported algorithm %d", sig.palg);
        assert_true(false);
        break;
    }

    save_signature(packet, &sig);
    free_signature(&sig);
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

void
test_forged_key_validate(void **state)
{
    rnp_key_store_t *pubring;
    pgp_key_t *      key = NULL;
    pgp_io_t         io = pgp_io_from_fp(stderr, stdout, stdout);

    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "");
    assert_non_null(pubring);

    /* load valid dsa-eg key */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "C8A10A7D78273E10", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load dsa-eg key with forged self-signature. Subkey will not be valid as well. */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub-forged-key.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "C8A10A7D78273E10", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_key_store_get_key_by_name(&io, pubring, "02A5715C3537717E", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load dsa-eg key with forged key material */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub-forged-material.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "C8A10A7D78273E10", NULL);
    assert_null(key);
    key = rnp_key_store_get_key_by_name(&io, pubring, "dsa-eg", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load dsa-eg keypair with forged subkey binding signature */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub-forged-subkey.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "02A5715C3537717E", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_key_store_get_key_by_name(&io, pubring, "C8A10A7D78273E10", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load valid eddsa key */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "CC786278981B0728", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load eddsa key with forged self-signature */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-forged-key.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "CC786278981B0728", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load eddsa key with forged key material */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-forged-material.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "ecc-25519", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load valid ecdsa/ecdh p-256 keypair */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "23674F21B2441527", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    key = rnp_key_store_get_key_by_name(&io, pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh key with forged self-signature. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-key.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "23674F21B2441527", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_key_store_get_key_by_name(&io, pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh key with forged key material. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-material.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "23674F21B2441527", NULL);
    assert_null(key);
    key = rnp_key_store_get_key_by_name(&io, pubring, "ecc-p256", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_key_store_get_key_by_name(&io, pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair with forged subkey binding signature */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-subkey.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "37E285E9E9851491", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_key_store_get_key_by_name(&io, pubring, "23674F21B2441527", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load valid rsa/rsa keypair */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "2FB9179118898E8B", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    key = rnp_key_store_get_key_by_name(&io, pubring, "6E2F73008F8B8D6E", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    /* load rsa/rsa key with forged self-signature. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-key.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "2FB9179118898E8B", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_key_store_get_key_by_name(&io, pubring, "6E2F73008F8B8D6E", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load rsa/rsa key with forged key material. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-material.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "2FB9179118898E8B", NULL);
    assert_null(key);
    key = rnp_key_store_get_key_by_name(&io, pubring, "rsa-rsa", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_key_store_get_key_by_name(&io, pubring, "6E2F73008F8B8D6E", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    rnp_key_store_clear(pubring);

    /* load rsa/rsa keypair with forged subkey binding signature */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-subkey.pgp");
    key = rnp_key_store_get_key_by_name(&io, pubring, "6E2F73008F8B8D6E", NULL);
    assert_non_null(key);
    assert_false(key->valid);
    key = rnp_key_store_get_key_by_name(&io, pubring, "2FB9179118898E8B", NULL);
    assert_non_null(key);
    assert_true(key->valid);
    rnp_key_store_clear(pubring);

    rnp_key_store_free(pubring);
}