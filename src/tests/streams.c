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

#include "rnp_tests.h"
#include "support.h"
#include "utils.h"
#include "rnp.h"
#include "hash.h"
#include "pgp-key.h"
#include <time.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-key.h>
#include <librepgp/stream-dump.h>

static bool
stream_hash_file(pgp_hash_t *hash, const char *path)
{
    uint8_t      readbuf[1024];
    ssize_t      read;
    pgp_source_t src;
    bool         res = false;

    if (init_file_src(&src, path)) {
        return false;
    }

    do {
        read = src_read(&src, readbuf, sizeof(readbuf));
        if (read < 0) {
            goto finish;
        } else if (read == 0) {
            break;
        }

        if (pgp_hash_add(hash, readbuf, read)) {
            goto finish;
        }
    } while (1);

    res = true;
finish:
    src_close(&src);
    return res;
}

void
test_stream_signatures(void **state)
{
    rnp_key_store_t *pubring;
    rnp_key_store_t *secring;
    pgp_signature_t  sig;
    pgp_hash_t       hash_orig;
    pgp_hash_t       hash_forged;
    pgp_hash_t       hash;
    pgp_hash_alg_t   halg;
    pgp_source_t     sigsrc;
    pgp_io_t         io = {.errs = stderr, .res = stdout, .outs = stdout};
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    pgp_pubkey_t *   pubkey = NULL;
    pgp_key_t *      seckey = NULL;
    rng_t            rng;

    /* we need rng for key validation */
    assert_true(rng_init(&rng, RNG_SYSTEM));
    /* load keys */
    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/test_stream_signatures/pub.asc");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_file(&io, pubring, true, NULL));
    /* load signature */
    assert_rnp_success(init_file_src(&sigsrc, "data/test_stream_signatures/source.txt.sig"));
    assert_rnp_success(stream_parse_signature(&sigsrc, &sig));
    src_close(&sigsrc);
    /* hash signed file */
    halg = sig.halg;
    assert_true(pgp_hash_create(&hash_orig, halg));
    assert_true(stream_hash_file(&hash_orig, "data/test_stream_signatures/source.txt"));
    /* hash forged file */
    assert_true(pgp_hash_create(&hash_forged, halg));
    assert_true(
      stream_hash_file(&hash_forged, "data/test_stream_signatures/source_forged.txt"));
    /* find signing key */
    assert_true(signature_get_keyid(&sig, keyid));
    assert_non_null(rnp_key_store_get_key_by_id(&io, pubring, keyid, NULL, &pubkey));
    assert_non_null(pubkey);
    /* validate signature and fields */
    assert_true(pgp_hash_copy(&hash, &hash_orig));
    assert_int_equal(signature_get_creation(&sig), 1522241943);
    assert_rnp_success(signature_validate(&sig, pubkey, &hash, &rng));
    /* check forged file */
    assert_true(pgp_hash_copy(&hash, &hash_forged));
    assert_rnp_failure(signature_validate(&sig, pubkey, &hash, &rng));
    free_signature(&sig);
    /* now let's create signature and sign file */

    /* load secret key */
    secring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/test_stream_signatures/sec.asc");
    assert_non_null(secring);
    assert_true(rnp_key_store_load_from_file(&io, secring, true, NULL));
    seckey = rnp_key_store_get_key_by_id(&io, secring, keyid, NULL, NULL);
    assert_non_null(seckey);
    assert_true(pgp_is_key_secret(seckey));
    /* fill signature */
    uint32_t create = time(NULL);
    uint32_t expire = 123456;
    memset(&sig, 0, sizeof(sig));
    sig.version = 4;
    sig.halg = halg;
    sig.palg = seckey->key.seckey.pubkey.alg;
    sig.type = PGP_SIG_BINARY;
    assert_true(
      signature_set_keyfp(&sig, seckey->fingerprint.fingerprint, seckey->fingerprint.length));
    assert_true(signature_set_keyid(&sig, seckey->keyid));
    assert_true(signature_set_creation(&sig, create));
    assert_true(signature_set_expiration(&sig, expire));
    assert_true(signature_fill_hashed_data(&sig));
    /* try to sign without decrypting of the secret key */
    assert_true(pgp_hash_copy(&hash, &hash_orig));
    assert_rnp_failure(signature_calculate(&sig, &seckey->key.seckey, &hash, &rng));
    /* now unlock the key and sign */
    pgp_password_provider_t pswd_prov = {.callback = rnp_password_provider_string,
                                         .userdata = "password"};
    assert_true(pgp_key_unlock(seckey, &pswd_prov));
    assert_true(pgp_hash_copy(&hash, &hash_orig));
    assert_rnp_success(signature_calculate(&sig, &seckey->key.seckey, &hash, &rng));
    /* now verify signature */
    assert_true(pgp_hash_copy(&hash, &hash_orig));
    /* validate signature and fields */
    assert_int_equal(signature_get_creation(&sig), create);
    assert_int_equal(signature_get_expiration(&sig), expire);
    assert_rnp_success(signature_validate(&sig, pubkey, &hash, &rng));
    free_signature(&sig);
    /* cleanup */
    rnp_key_store_free(pubring);
    rnp_key_store_free(secring);
    pgp_hash_finish(&hash_orig, NULL);
    pgp_hash_finish(&hash_forged, NULL);
    rng_destroy(&rng);
}

void
test_stream_key_load(void **state)
{
    pgp_source_t            keysrc = {0};
    pgp_dest_t              keydst = {0};
    pgp_key_sequence_t      keyseq;
    pgp_transferable_key_t *key = NULL;

    /* public keyring, read-save-read-save armored-read */
    assert_rnp_success(init_file_src(&keysrc, "data/keyrings/1/pubring.gpg"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_true(list_length(keyseq.keys) > 1);
    src_close(&keysrc);

    assert_rnp_success(init_file_dest(&keydst, "keyout.gpg", true));
    assert_rnp_success(write_pgp_keys(&keyseq, &keydst, false));
    dst_close(&keydst, false);
    key_sequence_destroy(&keyseq);

    assert_rnp_success(init_file_src(&keysrc, "keyout.gpg"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    src_close(&keysrc);

    assert_rnp_success(init_file_dest(&keydst, "keyout.asc", true));
    assert_rnp_success(write_pgp_keys(&keyseq, &keydst, true));
    dst_close(&keydst, false);
    key_sequence_destroy(&keyseq);

    assert_rnp_success(init_file_src(&keysrc, "keyout.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    src_close(&keysrc);
    key_sequence_destroy(&keyseq);

    /* secret keyring */
    assert_rnp_success(init_file_src(&keysrc, "data/keyrings/1/secring.gpg"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_true(list_length(keyseq.keys) > 1);
    src_close(&keysrc);

    assert_rnp_success(init_file_dest(&keydst, "keyout-sec.gpg", true));
    assert_rnp_success(write_pgp_keys(&keyseq, &keydst, false));
    dst_close(&keydst, false);
    key_sequence_destroy(&keyseq);

    assert_rnp_success(init_file_src(&keysrc, "keyout-sec.gpg"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    src_close(&keysrc);

    assert_rnp_success(init_file_dest(&keydst, "keyout-sec.asc", true));
    assert_rnp_success(write_pgp_keys(&keyseq, &keydst, true));
    dst_close(&keydst, false);
    key_sequence_destroy(&keyseq);

    assert_rnp_success(init_file_src(&keysrc, "keyout-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    src_close(&keysrc);
    key_sequence_destroy(&keyseq);

    /* armored v3 public key */
    assert_rnp_success(init_file_src(&keysrc, "data/keyrings/4/rsav3-p.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(list_front(keyseq.keys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* armored v3 secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/keyrings/4/rsav3-s.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(list_front(keyseq.keys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* rsa/rsa public key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/rsa-rsa-pub.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_int_equal(list_length(key->subkeys), 1);
    assert_non_null(list_front(key->subkeys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* rsa/rsa secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/rsa-rsa-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_int_equal(list_length(key->subkeys), 1);
    assert_non_null(list_front(key->subkeys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* dsa/el-gamal public key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/dsa-eg-pub.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_int_equal(list_length(key->subkeys), 1);
    assert_non_null(list_front(key->subkeys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* dsa/el-gamal secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/dsa-eg-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_int_equal(list_length(key->subkeys), 1);
    assert_non_null(list_front(key->subkeys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* curve 25519 ecc public key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-25519-pub.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(list_front(keyseq.keys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* curve 25519 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-25519-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_int_equal(list_length(key->subkeys), 0);
    assert_null(list_front(key->subkeys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* p-256 ecc public key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-p256-pub.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_int_equal(list_length(key->subkeys), 1);
    assert_non_null(list_front(key->subkeys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* p-256 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-p256-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_int_equal(list_length(key->subkeys), 1);
    assert_non_null(list_front(key->subkeys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* p-384 ecc public key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-p384-pub.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_int_equal(list_length(key->subkeys), 1);
    assert_non_null(list_front(key->subkeys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* p-384 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-p384-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_int_equal(list_length(key->subkeys), 1);
    assert_non_null(list_front(key->subkeys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* p-521 ecc public key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-p521-pub.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_int_equal(list_length(key->subkeys), 1);
    assert_non_null(list_front(key->subkeys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* p-521 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-p521-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_int_equal(list_length(key->subkeys), 1);
    assert_non_null(list_front(key->subkeys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* Brainpool P256 ecc public key, not supported now */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-bp256-pub.asc"));
    assert_rnp_failure(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 0);
    assert_null(list_front(keyseq.keys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* Brainpool P256 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-bp256-sec.asc"));
    assert_rnp_failure(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 0);
    assert_null(list_front(keyseq.keys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* Brainpool P384 ecc public key, not supported now */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-bp384-pub.asc"));
    assert_rnp_failure(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 0);
    assert_null(list_front(keyseq.keys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* Brainpool P384 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-bp384-sec.asc"));
    assert_rnp_failure(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 0);
    assert_null(list_front(keyseq.keys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* Brainpool P512 ecc public key, not supported now */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-bp512-pub.asc"));
    assert_rnp_failure(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 0);
    assert_null(list_front(keyseq.keys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* Brainpool P512 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-bp512-sec.asc"));
    assert_rnp_failure(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 0);
    assert_null(list_front(keyseq.keys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* secp256k1 ecc public key, not supported now */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-p256k1-pub.asc"));
    assert_rnp_failure(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 0);
    assert_null(list_front(keyseq.keys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* secp256k1 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-p256k1-sec.asc"));
    assert_rnp_failure(process_pgp_keys(&keysrc, &keyseq));
    assert_int_equal(list_length(keyseq.keys), 0);
    assert_null(list_front(keyseq.keys));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);
}

void
test_stream_key_decrypt(void **state)
{
    pgp_source_t               keysrc = {0};
    pgp_key_sequence_t         keyseq;
    pgp_transferable_key_t *   key = NULL;
    pgp_transferable_subkey_t *subkey = NULL;

    /* load and decrypt secret keyring */
    assert_rnp_success(init_file_src(&keysrc, "data/keyrings/1/secring.gpg"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    for (list_item *li = list_front(keyseq.keys); li; li = list_next(li)) {
        key = (pgp_transferable_key_t *) li;
        assert_rnp_failure(decrypt_secret_key(&key->key, "passw0rd"));
        assert_rnp_success(decrypt_secret_key(&key->key, "password"));

        for (list_item *sli = list_front(key->subkeys); sli; sli = list_next(sli)) {
            subkey = (pgp_transferable_subkey_t *) sli;
            assert_rnp_failure(decrypt_secret_key(&subkey->subkey, "passw0rd"));
            assert_rnp_success(decrypt_secret_key(&subkey->subkey, "password"));
        }
    }
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* armored v3 secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/keyrings/4/rsav3-s.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_rnp_failure(decrypt_secret_key(&key->key, "passw0rd"));
    assert_rnp_success(decrypt_secret_key(&key->key, "password"));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* rsa/rsa secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/rsa-rsa-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_rnp_success(decrypt_secret_key(&key->key, "password"));
    assert_non_null(subkey = (pgp_transferable_subkey_t *) list_front(key->subkeys));
    assert_rnp_success(decrypt_secret_key(&subkey->subkey, "password"));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* dsa/el-gamal secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/dsa-eg-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_rnp_success(decrypt_secret_key(&key->key, "password"));
    assert_non_null(subkey = (pgp_transferable_subkey_t *) list_front(key->subkeys));
    assert_rnp_success(decrypt_secret_key(&subkey->subkey, "password"));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* curve 25519 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-25519-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_rnp_success(decrypt_secret_key(&key->key, "password"));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* p-256 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-p256-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_rnp_success(decrypt_secret_key(&key->key, "password"));
    assert_non_null(subkey = (pgp_transferable_subkey_t *) list_front(key->subkeys));
    assert_rnp_success(decrypt_secret_key(&subkey->subkey, "password"));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* p-384 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-p384-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_rnp_success(decrypt_secret_key(&key->key, "password"));
    assert_non_null(subkey = (pgp_transferable_subkey_t *) list_front(key->subkeys));
    assert_rnp_success(decrypt_secret_key(&subkey->subkey, "password"));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);

    /* p-521 ecc secret key */
    assert_rnp_success(init_file_src(&keysrc, "data/test_stream_key_load/ecc-p521-sec.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_rnp_success(decrypt_secret_key(&key->key, "password"));
    assert_non_null(subkey = (pgp_transferable_subkey_t *) list_front(key->subkeys));
    assert_rnp_success(decrypt_secret_key(&subkey->subkey, "password"));
    key_sequence_destroy(&keyseq);
    src_close(&keysrc);
}

void
test_stream_key_encrypt(void **state)
{
    pgp_source_t               keysrc = {0};
    pgp_dest_t                 keydst = {0};
    uint8_t                    keybuf[16384];
    size_t                     keylen;
    pgp_key_sequence_t         keyseq;
    pgp_key_sequence_t         keyseq2;
    pgp_transferable_key_t *   key = NULL;
    pgp_transferable_subkey_t *subkey = NULL;
    rng_t                      rng;

    /* we need rng for key encryption */
    assert_true(rng_init(&rng, RNG_SYSTEM));

    /* load and decrypt secret keyring, then re-encrypt and reload keys */
    assert_rnp_success(init_file_src(&keysrc, "data/keyrings/1/secring.gpg"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    src_close(&keysrc);
    for (list_item *li = list_front(keyseq.keys); li; li = list_next(li)) {
        key = (pgp_transferable_key_t *) li;
        assert_rnp_success(decrypt_secret_key(&key->key, "password"));

        for (list_item *sli = list_front(key->subkeys); sli; sli = list_next(sli)) {
            subkey = (pgp_transferable_subkey_t *) sli;
            assert_rnp_success(decrypt_secret_key(&subkey->subkey, "password"));
        }

        /* change password and encryption algorithm */
        key->key.sec_protection.symm_alg = PGP_SA_CAMELLIA_192;
        assert_rnp_success(encrypt_secret_key(&key->key, "passw0rd", &rng));
        for (list_item *sli = list_front(key->subkeys); sli; sli = list_next(sli)) {
            subkey = (pgp_transferable_subkey_t *) sli;
            subkey->subkey.sec_protection.symm_alg = PGP_SA_CAMELLIA_256;
            assert_rnp_success(encrypt_secret_key(&subkey->subkey, "passw0rd", &rng));
        }
        /* write changed key */
        assert_rnp_success(init_mem_dest(&keydst, keybuf, sizeof(keybuf)));
        assert_rnp_success(write_pgp_key(key, &keydst, false));
        keylen = keydst.writeb;
        dst_close(&keydst, false);
        /* load and decrypt changed key */
        assert_rnp_success(init_mem_src(&keysrc, keybuf, keylen, false));
        assert_rnp_success(process_pgp_keys(&keysrc, &keyseq2));
        src_close(&keysrc);
        assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq2.keys));
        assert_int_equal(key->key.sec_protection.symm_alg, PGP_SA_CAMELLIA_192);
        assert_rnp_success(decrypt_secret_key(&key->key, "passw0rd"));

        for (list_item *sli = list_front(key->subkeys); sli; sli = list_next(sli)) {
            subkey = (pgp_transferable_subkey_t *) sli;
            assert_int_equal(subkey->subkey.sec_protection.symm_alg, PGP_SA_CAMELLIA_256);
            assert_rnp_success(decrypt_secret_key(&subkey->subkey, "passw0rd"));
        }
        /* write key without the password */
        key->key.sec_protection.s2k.usage = PGP_S2KU_NONE;
        assert_rnp_success(encrypt_secret_key(&key->key, NULL, NULL));
        for (list_item *sli = list_front(key->subkeys); sli; sli = list_next(sli)) {
            subkey = (pgp_transferable_subkey_t *) sli;
            subkey->subkey.sec_protection.s2k.usage = PGP_S2KU_NONE;
            assert_rnp_success(encrypt_secret_key(&subkey->subkey, NULL, NULL));
        }
        /* write changed key */
        assert_rnp_success(init_mem_dest(&keydst, keybuf, sizeof(keybuf)));
        assert_rnp_success(write_pgp_key(key, &keydst, false));
        keylen = keydst.writeb;
        dst_close(&keydst, false);
        key_sequence_destroy(&keyseq2);
        /* load non-encrypted key */
        assert_rnp_success(init_mem_src(&keysrc, keybuf, keylen, false));
        assert_rnp_success(process_pgp_keys(&keysrc, &keyseq2));
        src_close(&keysrc);
        assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq2.keys));
        assert_int_equal(key->key.sec_protection.s2k.usage, PGP_S2KU_NONE);
        assert_rnp_success(decrypt_secret_key(&key->key, NULL));

        for (list_item *sli = list_front(key->subkeys); sli; sli = list_next(sli)) {
            subkey = (pgp_transferable_subkey_t *) sli;
            assert_int_equal(subkey->subkey.sec_protection.s2k.usage, PGP_S2KU_NONE);
            assert_rnp_success(decrypt_secret_key(&subkey->subkey, NULL));
        }
        key_sequence_destroy(&keyseq2);
    }
    key_sequence_destroy(&keyseq);
    rng_destroy(&rng);
}

void
test_stream_key_signatures(void **state)
{
    rnp_key_store_t *          pubring;
    pgp_source_t               keysrc = {0};
    pgp_key_sequence_t         keyseq;
    pgp_transferable_key_t *   key = NULL;
    pgp_transferable_subkey_t *subkey = NULL;
    pgp_transferable_userid_t *uid = NULL;
    rng_t                      rng;
    pgp_signature_t *          sig;
    pgp_io_t                   io = {.errs = stderr, .res = stdout, .outs = stdout};
    uint8_t                    keyid[PGP_KEY_ID_SIZE];
    pgp_pubkey_t *             pubkey = NULL;
    pgp_hash_t                 hash;

    /* we need rng for key validation */
    assert_true(rng_init(&rng, RNG_SYSTEM));

    /* v3 public key */
    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/4/rsav3-p.asc");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_file(&io, pubring, true, NULL));
    assert_rnp_success(init_file_src(&keysrc, "data/keyrings/4/rsav3-p.asc"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    src_close(&keysrc);
    assert_int_equal(list_length(keyseq.keys), 1);
    assert_non_null(key = (pgp_transferable_key_t *) list_front(keyseq.keys));
    assert_non_null(uid = (pgp_transferable_userid_t *) list_front(key->userids));
    assert_non_null(sig = (pgp_signature_t *) list_front(uid->signatures));
    assert_true(signature_get_keyid(sig, keyid));
    assert_non_null(rnp_key_store_get_key_by_id(&io, pubring, keyid, NULL, &pubkey));
    assert_non_null(pubkey);
    /* check certification signature */
    assert_true(signature_hash_certification(sig, &key->key, &uid->uid, &hash));
    assert_rnp_success(signature_validate(sig, pubkey, &hash, &rng));
    /* modify userid and check signature */
    uid->uid.uid[2] = '?';
    assert_true(signature_hash_certification(sig, &key->key, &uid->uid, &hash));
    assert_rnp_failure(signature_validate(sig, pubkey, &hash, &rng));
    rnp_key_store_free(pubring);
    key_sequence_destroy(&keyseq);

    /* keyring */
    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "data/keyrings/1/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_file(&io, pubring, false, NULL));
    assert_rnp_success(init_file_src(&keysrc, "data/keyrings/1/pubring.gpg"));
    assert_rnp_success(process_pgp_keys(&keysrc, &keyseq));
    src_close(&keysrc);

    /* check key signatures */
    for (list_item *li = list_front(keyseq.keys); li; li = list_next(li)) {
        key = (pgp_transferable_key_t *) li;

        for (list_item *uli = list_front(key->userids); uli; uli = list_next(uli)) {
            uid = (pgp_transferable_userid_t *) uli;

            /* userid certifications */
            for (list_item *sli = list_front(uid->signatures); sli; sli = list_next(sli)) {
                sig = (pgp_signature_t *) sli;

                assert_true(signature_get_keyid(sig, keyid));
                assert_non_null(
                  rnp_key_store_get_key_by_id(&io, pubring, keyid, NULL, &pubkey));
                assert_non_null(pubkey);

                assert_true(signature_hash_certification(sig, &key->key, &uid->uid, &hash));
                assert_rnp_success(signature_validate(sig, pubkey, &hash, &rng));
                /* modify userid and check signature */
                uid->uid.uid[2] = '?';
                assert_true(signature_hash_certification(sig, &key->key, &uid->uid, &hash));
                assert_rnp_failure(signature_validate(sig, pubkey, &hash, &rng));
            }
        }

        /* subkey binding signatures */
        for (list_item *sli = list_front(key->subkeys); sli; sli = list_next(sli)) {
            subkey = (pgp_transferable_subkey_t *) sli;
            sig = (pgp_signature_t *) list_front(subkey->signatures);
            assert_non_null(sig);
            assert_true(signature_get_keyid(sig, keyid));
            assert_non_null(rnp_key_store_get_key_by_id(&io, pubring, keyid, NULL, &pubkey));
            assert_non_null(pubkey);
            assert_true(signature_hash_binding(sig, &key->key, &subkey->subkey, &hash));
            assert_rnp_success(signature_validate(sig, pubkey, &hash, &rng));
        }
    }

    rnp_key_store_free(pubring);
    key_sequence_destroy(&keyseq);
    rng_destroy(&rng);
}

void
test_stream_dumper(void **state)
{
    pgp_source_t   src;
    pgp_dest_t     dst;
    rnp_dump_ctx_t ctx = {0};

    assert_rnp_success(init_file_src(&src, "data/keyrings/1/pubring.gpg"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/keyrings/1/secring.gpg"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/keyrings/4/rsav3-p.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/keyrings/4/rsav3-s.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_repgp/encrypted_text.gpg"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_repgp/signed.gpg"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_stream_key_load/dsa-eg-pub.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_stream_key_load/dsa-eg-sec.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_stream_key_load/ecc-25519-pub.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_stream_key_load/ecc-25519-sec.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_stream_key_load/ecc-p256-pub.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_stream_key_load/ecc-p256-sec.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_stream_key_load/ecc-p384-pub.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_stream_key_load/ecc-p384-sec.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_stream_key_load/ecc-p521-pub.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);

    assert_rnp_success(init_file_src(&src, "data/test_stream_key_load/ecc-p521-sec.asc"));
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    assert_rnp_success(stream_dump_packets(&ctx, &src, &dst));
    src_close(&src);
    dst_close(&dst, false);
}
