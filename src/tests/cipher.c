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

#include <crypto/common.h>
#include <crypto.h>
#include <pgp-key.h>
#include <rnp/rnp.h>

#include "rnp_tests.h"
#include "support.h"
#include "fingerprint.h"

extern rng_t global_rng;

void
hash_test_success(void **state)
{
    rnp_test_state_t *rstate = *state;
    pgp_hash_t        hash = {0};
    uint8_t           hash_output[PGP_MAX_HASH_SIZE];

    const pgp_hash_alg_t hash_algs[] = {PGP_HASH_MD5,
                                        PGP_HASH_SHA1,
                                        PGP_HASH_SHA256,
                                        PGP_HASH_SHA384,
                                        PGP_HASH_SHA512,
                                        PGP_HASH_SHA224,
                                        PGP_HASH_SM3,
                                        PGP_HASH_SHA3_256,
                                        PGP_HASH_SHA3_512,
                                        PGP_HASH_UNKNOWN};

    const uint8_t test_input[3] = {'a', 'b', 'c'};
    const char *  hash_alg_expected_outputs[] = {
      "900150983CD24FB0D6963F7D28E17F72",
      "A9993E364706816ABA3E25717850C26C9CD0D89D",
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
      "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1"
      "E7CC2358BAECA"
      "134C825A7",
      "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A27"
      "4FC1A836BA3C2"
      "3A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
      "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7",
      "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0",
      "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532",
      "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E1"
      "0E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0"};

    for (int i = 0; hash_algs[i] != PGP_HASH_UNKNOWN; ++i) {
        rnp_assert_int_equal(rstate, 1, pgp_hash_create(&hash, hash_algs[i]));
        size_t hash_size = pgp_digest_length(hash_algs[i]);

        rnp_assert_int_equal(rstate, hash_size * 2, strlen(hash_alg_expected_outputs[i]));

        pgp_hash_add(&hash, test_input, 1);
        pgp_hash_add(&hash, test_input + 1, sizeof(test_input) - 1);
        pgp_hash_finish(&hash, hash_output);

        rnp_assert_int_equal(
          rstate,
          0,
          test_value_equal(
            pgp_hash_name(&hash), hash_alg_expected_outputs[i], hash_output, hash_size));
    }
}

void
cipher_test_success(void **state)
{
    rnp_test_state_t *rstate = *state;
    const uint8_t     key[16] = {0};
    uint8_t           iv[16];
    pgp_symm_alg_t    alg = PGP_SA_AES_128;
    pgp_crypt_t       crypt;

    uint8_t cfb_data[20] = {0};
    memset(iv, 0x42, sizeof(iv));

    rnp_assert_int_equal(rstate, 1, pgp_cipher_cfb_start(&crypt, alg, key, iv));

    rnp_assert_int_equal(
      rstate, 0, pgp_cipher_cfb_encrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data)));

    rnp_assert_int_equal(rstate,
                         0,
                         test_value_equal("AES CFB encrypt",
                                          "BFDAA57CB812189713A950AD9947887983021617",
                                          cfb_data,
                                          sizeof(cfb_data)));
    rnp_assert_int_equal(rstate, 0, pgp_cipher_cfb_finish(&crypt));

    rnp_assert_int_equal(rstate, 1, pgp_cipher_cfb_start(&crypt, alg, key, iv));
    rnp_assert_int_equal(
      rstate, 0, pgp_cipher_cfb_decrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data)));
    rnp_assert_int_equal(rstate,
                         0,
                         test_value_equal("AES CFB decrypt",
                                          "0000000000000000000000000000000000000000",
                                          cfb_data,
                                          sizeof(cfb_data)));
    rnp_assert_int_equal(rstate, 0, pgp_cipher_cfb_finish(&crypt));
}

void
pkcs1_rsa_test_success(void **state)
{
    rnp_test_state_t *  rstate = *state;
    uint8_t             ptext[1024 / 8] = {'a', 'b', 'c', 0};
    uint8_t             dec[1024 / 8];
    pgp_rsa_encrypted_t enc;
    size_t              dec_size;

    const pgp_pubkey_t *pub_key;
    pgp_seckey_t *      sec_key;

    const pgp_rsa_key_t *key_rsa;

    const rnp_keygen_crypto_params_t key_desc = {.key_alg = PGP_PKA_RSA,
                                                 .hash_alg = PGP_HASH_SHA256,
                                                 .rsa = {.modulus_bit_len = 1024},
                                                 .rng = &global_rng};
    sec_key = calloc(1, sizeof(*sec_key));
    assert_non_null(sec_key);
    assert_true(pgp_generate_seckey(&key_desc, sec_key));
    rnp_assert_non_null(rstate, sec_key);
    pub_key = &sec_key->pubkey;
    rnp_assert_non_null(rstate, pub_key);
    key_rsa = &sec_key->pubkey.key.rsa;

#if defined(DEBUG_PRINT)
    char *tmp = hex_encode(ptext, sizeof(ptext));
    printf("PT = 0x%s\n", tmp);
    free(tmp);
    printf("N = ");
    bn_print_fp(stdout, pub_rsa->n);
    printf("\n");
    printf("E = ");
    bn_print_fp(stdout, pub_rsa->e);
    printf("\n");
    printf("P = ");
    bn_print_fp(stdout, sec_rsa->p);
    printf("\n");
    printf("Q = ");
    bn_print_fp(stdout, sec_rsa->q);
    printf("\n");
    printf("D = ");
    bn_print_fp(stdout, sec_rsa->d);
    printf("\n");
#endif

    assert_rnp_success(rsa_encrypt_pkcs1(&global_rng, &enc, ptext, 3, key_rsa));
    rnp_assert_int_equal(rstate, enc.m.len, 1024 / 8);

    memset(dec, 0, sizeof(dec));
    dec_size = 0;
    assert_rnp_success(rsa_decrypt_pkcs1(&global_rng, dec, &dec_size, &enc, key_rsa));

#if defined(DEBUG_PRINT)
    tmp = hex_encode(ctext, ctext_size);
    printf("C = 0x%s\n", tmp);
    free(tmp);
    tmp = hex_encode(decrypted, decrypted_size);
    printf("PD = 0x%s\n", tmp);
    free(tmp);
#endif

    test_value_equal("RSA 1024 decrypt", "616263", dec, 3);
    rnp_assert_int_equal(rstate, dec_size, 3);
    pgp_seckey_free(sec_key);
    free(sec_key);
}

void
rnp_test_eddsa(void **state)
{
    const rnp_keygen_crypto_params_t key_desc = {
      .key_alg = PGP_PKA_EDDSA, .hash_alg = PGP_HASH_SHA256, .rng = &global_rng};

    pgp_seckey_t *seckey = calloc(1, sizeof(*seckey));
    assert_non_null(seckey);

    assert_true(pgp_generate_seckey(&key_desc, seckey));

    const uint8_t      hash[32] = {0};
    pgp_ec_signature_t sig = {{{0}}};

    assert_rnp_success(
      eddsa_sign(&global_rng, &sig, hash, sizeof(hash), &seckey->pubkey.key.ec));

    assert_rnp_success(eddsa_verify(&sig, hash, sizeof(hash), &seckey->pubkey.key.ec));

    // cut one byte off hash -> invalid sig
    assert_rnp_failure(eddsa_verify(&sig, hash, sizeof(hash) - 1, &seckey->pubkey.key.ec));

    // swap r/s -> invalid sig
    pgp_mpi_t tmp = sig.r;
    sig.r = sig.s;
    sig.s = tmp;
    assert_rnp_failure(eddsa_verify(&sig, hash, sizeof(hash), &seckey->pubkey.key.ec));

    pgp_seckey_free(seckey);
    free(seckey);
}

static void
elgamal_roundtrip(rnp_test_state_t *state, pgp_eg_key_t *key)
{
    const uint8_t      in_b[] = {0x01, 0x02, 0x03, 0x04, 0x17};
    pgp_eg_encrypted_t enc = {{{0}}};
    uint8_t            res[1024];
    size_t             res_len = 0;

    rnp_assert_int_equal(
      state, elgamal_encrypt_pkcs1(&global_rng, &enc, in_b, sizeof(in_b), key), RNP_SUCCESS);
    rnp_assert_int_equal(
      state, elgamal_decrypt_pkcs1(&global_rng, res, &res_len, &enc, key), RNP_SUCCESS);
    rnp_assert_int_equal(state, res_len, sizeof(in_b));
    rnp_assert_int_equal(
      state, 0, test_value_equal("ElGamal decrypt", "0102030417", res, res_len));
}

void
raw_elgamal_fixed_512bit_key_test_success(void **state)
{
    rnp_test_state_t *rstate = *state;
    // largest prime under 512 bits
    const uint8_t p512[64] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0xC7,
    };

    pgp_eg_key_t key_elg;
    bignum_t *   p, *g, *x, *y;

    // Allocate needed memory
    p = bn_bin2bn(p512, sizeof(p512), NULL);
    rnp_assert_non_null(rstate, p);

    g = bn_new();
    rnp_assert_non_null(rstate, g);

    x = bn_new();
    rnp_assert_non_null(rstate, x);

    y = bn_new();
    rnp_assert_non_null(rstate, y);

    bn_set_word(g, 3);
    bn_set_word(x, 0xCAB5432);
    bn_mod_exp(y, g, x, p);

    rnp_assert_true(rstate, bn2mpi(p, &key_elg.p));
    rnp_assert_true(rstate, bn2mpi(g, &key_elg.g));
    rnp_assert_true(rstate, bn2mpi(x, &key_elg.x));
    rnp_assert_true(rstate, bn2mpi(y, &key_elg.y));

    elgamal_roundtrip(rstate, &key_elg);

    // Free heap
    bn_clear_free(p);
    bn_clear_free(g);
    bn_clear_free(x);
    bn_clear_free(y);
}

void
raw_elgamal_random_key_test_success(void **state)
{
    rnp_test_state_t *rstate = *state;
    pgp_eg_key_t      key;

    rnp_assert_int_equal(rstate, elgamal_generate(&global_rng, &key, 1024), RNP_SUCCESS);
    elgamal_roundtrip(rstate, &key);
}

void
ecdsa_signverify_success(void **state)
{
    rnp_test_state_t *rstate = *state;
    uint8_t           message[64];

    struct curve {
        pgp_curve_t id;
        size_t      size;
    } curves[] = {
      {PGP_CURVE_NIST_P_256, 32}, {PGP_CURVE_NIST_P_384, 48}, {PGP_CURVE_NIST_P_521, 64}};

    for (size_t i = 0; i < ARRAY_SIZE(curves); i++) {
        // Generate test data. Mainly to make valgrind not to complain about unitialized data
        rnp_assert_true(rstate, rng_get_data(&global_rng, message, sizeof(message)));

        pgp_ec_signature_t               sig = {{{0}}};
        const rnp_keygen_crypto_params_t key_desc = {.key_alg = PGP_PKA_ECDSA,
                                                     .hash_alg = PGP_HASH_SHA512,
                                                     .ecc = {.curve = curves[i].id},
                                                     .rng = &global_rng};

        pgp_seckey_t *seckey1 = calloc(1, sizeof(*seckey1));
        assert_non_null(seckey1);

        pgp_seckey_t *seckey2 = calloc(1, sizeof(*seckey1));
        assert_non_null(seckey2);

        rnp_assert_true(rstate, pgp_generate_seckey(&key_desc, seckey1));
        rnp_assert_true(rstate, pgp_generate_seckey(&key_desc, seckey2));

        const pgp_ec_key_t *key1 = &seckey1->pubkey.key.ec;
        const pgp_ec_key_t *key2 = &seckey2->pubkey.key.ec;

        assert_rnp_success(ecdsa_sign(&global_rng, &sig, message, curves[i].size, key1));

        assert_rnp_success(ecdsa_verify(&sig, message, curves[i].size, key1));

        // Fails because of different key used
        assert_rnp_failure(ecdsa_verify(&sig, message, curves[i].size, key2));

        // Fails because message won't verify
        message[0] = ~message[0];
        assert_rnp_failure(ecdsa_verify(&sig, message, sizeof(message), key1));

        pgp_seckey_free(seckey1);
        free(seckey1);
        pgp_seckey_free(seckey2);
        free(seckey2);
    }
}

void
ecdh_roundtrip(void **state)
{
    struct curve {
        pgp_curve_t id;
        size_t      size;
    } curves[] = {
      {PGP_CURVE_NIST_P_256, 32}, {PGP_CURVE_NIST_P_384, 48}, {PGP_CURVE_NIST_P_521, 66}};

    rnp_test_state_t *   rstate = *state;
    pgp_ecdh_encrypted_t enc;
    uint8_t              plaintext[32] = {0};
    size_t               plaintext_len = sizeof(plaintext);
    uint8_t              result[32] = {0};
    size_t               result_len = sizeof(result);

    for (size_t i = 0; i < ARRAY_SIZE(curves); i++) {
        const rnp_keygen_crypto_params_t key_desc = {.key_alg = PGP_PKA_ECDH,
                                                     .hash_alg = PGP_HASH_SHA512,
                                                     .ecc = {.curve = curves[i].id},
                                                     .rng = &global_rng};

        pgp_seckey_t ecdh_key1;
        memset(&ecdh_key1, 0, sizeof(ecdh_key1));
        rnp_assert_true(rstate, pgp_generate_seckey(&key_desc, &ecdh_key1));

        pgp_fingerprint_t ecdh_key1_fpr;
        memset(&ecdh_key1_fpr, 0, sizeof(ecdh_key1_fpr));
        assert_rnp_success(pgp_fingerprint(&ecdh_key1_fpr, &ecdh_key1.pubkey));

        assert_rnp_success(ecdh_encrypt_pkcs5(&global_rng,
                                              &enc,
                                              plaintext,
                                              plaintext_len,
                                              &ecdh_key1.pubkey.key.ec,
                                              &ecdh_key1_fpr));

        assert_rnp_success(ecdh_decrypt_pkcs5(
          result, &result_len, &enc, &ecdh_key1.pubkey.key.ec, &ecdh_key1_fpr));

        rnp_assert_int_equal(rstate, plaintext_len, result_len);
        rnp_assert_int_equal(rstate, memcmp(plaintext, result, result_len), 0);
        pgp_seckey_free(&ecdh_key1);
    }
}

void
ecdh_decryptionNegativeCases(void **state)
{
    rnp_test_state_t *   rstate = *state;
    uint8_t              plaintext[32] = {0};
    size_t               plaintext_len = sizeof(plaintext);
    uint8_t              result[32] = {0};
    size_t               result_len = sizeof(result);
    pgp_ecdh_encrypted_t enc;

    const rnp_keygen_crypto_params_t key_desc = {.key_alg = PGP_PKA_ECDH,
                                                 .hash_alg = PGP_HASH_SHA512,
                                                 .ecc = {.curve = PGP_CURVE_NIST_P_256},
                                                 .rng = &global_rng};

    pgp_seckey_t ecdh_key1;
    memset(&ecdh_key1, 0, sizeof(ecdh_key1));
    rnp_assert_true(rstate, pgp_generate_seckey(&key_desc, &ecdh_key1));

    pgp_fingerprint_t ecdh_key1_fpr;
    memset(&ecdh_key1_fpr, 0, sizeof(ecdh_key1_fpr));
    assert_rnp_success(pgp_fingerprint(&ecdh_key1_fpr, &ecdh_key1.pubkey));

    assert_rnp_success(ecdh_encrypt_pkcs5(
      &global_rng, &enc, plaintext, plaintext_len, &ecdh_key1.pubkey.key.ec, &ecdh_key1_fpr));

    rnp_assert_int_equal(
      rstate,
      ecdh_decrypt_pkcs5(NULL, 0, &enc, &ecdh_key1.pubkey.key.ec, &ecdh_key1_fpr),
      RNP_ERROR_BAD_PARAMETERS);

    rnp_assert_int_equal(rstate,
                         ecdh_decrypt_pkcs5(result, &result_len, &enc, NULL, &ecdh_key1_fpr),
                         RNP_ERROR_BAD_PARAMETERS);

    rnp_assert_int_equal(
      rstate,
      ecdh_decrypt_pkcs5(result, &result_len, NULL, &ecdh_key1.pubkey.key.ec, &ecdh_key1_fpr),
      RNP_ERROR_BAD_PARAMETERS);

    size_t mlen = enc.mlen;
    enc.mlen = 0;
    rnp_assert_int_equal(
      rstate,
      ecdh_decrypt_pkcs5(result, &result_len, &enc, &ecdh_key1.pubkey.key.ec, &ecdh_key1_fpr),
      RNP_ERROR_GENERIC);

    enc.mlen = mlen - 1;
    rnp_assert_int_equal(
      rstate,
      ecdh_decrypt_pkcs5(result, &result_len, &enc, &ecdh_key1.pubkey.key.ec, &ecdh_key1_fpr),
      RNP_ERROR_GENERIC);

    int key_wrapping_alg = ecdh_key1.pubkey.key.ec.key_wrap_alg;
    ecdh_key1.pubkey.key.ec.key_wrap_alg = PGP_SA_IDEA;
    rnp_assert_int_equal(
      rstate,
      ecdh_decrypt_pkcs5(result, &result_len, &enc, &ecdh_key1.pubkey.key.ec, &ecdh_key1_fpr),
      RNP_ERROR_NOT_SUPPORTED);
    ecdh_key1.pubkey.key.ec.key_wrap_alg = key_wrapping_alg;

    pgp_seckey_free(&ecdh_key1);
}

void
sm2_roundtrip(void **state)
{
    rnp_test_state_t *rstate = *state;
    uint8_t           key[27] = {0};
    uint8_t           decrypted[27];
    size_t            decrypted_size;

    const rnp_keygen_crypto_params_t key_desc = {.key_alg = PGP_PKA_SM2,
                                                 .hash_alg = PGP_HASH_SM3,
                                                 .ecc = {.curve = PGP_CURVE_SM2_P_256},
                                                 .rng = &global_rng};

    assert_true(rng_get_data(&global_rng, key, sizeof(key)));

    pgp_seckey_t *sec_key = calloc(1, sizeof(*sec_key));
    assert_non_null(sec_key);
    assert_true(pgp_generate_seckey(&key_desc, sec_key));

    rnp_assert_non_null(rstate, sec_key);

    const pgp_pubkey_t *pub_key = &sec_key->pubkey;
    rnp_assert_non_null(rstate, pub_key);

    const pgp_ec_key_t *eckey = &pub_key->key.ec;

    uint8_t             hashes[] = {PGP_HASH_SM3, PGP_HASH_SHA256, PGP_HASH_SHA512};
    pgp_sm2_encrypted_t enc;
    rnp_result_t        ret;

    for (size_t i = 0; i < ARRAY_SIZE(hashes); ++i) {
        ret = sm2_encrypt(&global_rng, &enc, key, sizeof(key), hashes[i], eckey);
        rnp_assert_int_equal(rstate, ret, RNP_SUCCESS);

        memset(decrypted, 0, sizeof(decrypted));
        decrypted_size = sizeof(decrypted);
        ret = sm2_decrypt(decrypted, &decrypted_size, &enc, eckey);
        rnp_assert_int_equal(rstate, ret, RNP_SUCCESS);
        rnp_assert_int_equal(rstate, decrypted_size, sizeof(key));
        for (size_t i = 0; i < decrypted_size; ++i) {
            rnp_assert_int_equal(rstate, key[i], decrypted[i]);
        }
    }

    pgp_seckey_free(sec_key);
    free(sec_key);
}

void
test_dsa_roundtrip(void **state)
{
    rnp_test_state_t *  rstate = *state;
    uint8_t             message[PGP_MAX_HASH_SIZE];
    pgp_seckey_t        sec_key1 = {{0}};
    pgp_dsa_signature_t sig = {{{0}}};

    struct key_params {
        size_t         p;
        size_t         q;
        pgp_hash_alg_t h;
    } keys[] = {
      // all 1024 key-hash combinations
      {1024, 160, PGP_HASH_SHA1},
      {1024, 160, PGP_HASH_SHA224},
      {1024, 160, PGP_HASH_SHA256},
      {1024, 160, PGP_HASH_SHA384},
      {1024, 160, PGP_HASH_SHA512},
      // all 2048 key-hash combinations
      {2048, 256, PGP_HASH_SHA256},
      {2048, 256, PGP_HASH_SHA384},
      {2048, 256, PGP_HASH_SHA512},
      // misc
      {1088, 224, PGP_HASH_SHA512},
      {1024, 256, PGP_HASH_SHA256},
    };

    assert_true(rng_get_data(&global_rng, message, sizeof(message)));

    for (size_t i = 0; i < ARRAY_SIZE(keys); i++) {
        memset(&sig, 0, sizeof(sig));
        const rnp_keygen_crypto_params_t key_desc = {
          .key_alg = PGP_PKA_DSA,
          .hash_alg = keys[i].h,
          .dsa = {.p_bitlen = keys[i].p, .q_bitlen = keys[i].q},
          .rng = &global_rng};

        assert_true(pgp_generate_seckey(&key_desc, &sec_key1));
        // try to prevent timeouts in travis-ci
        printf("p: %zu q: %zu h: %s\n",
               key_desc.dsa.p_bitlen,
               key_desc.dsa.q_bitlen,
               pgp_show_hash_alg(key_desc.hash_alg));
        fflush(stdout);

        pgp_dsa_key_t *key1 = &sec_key1.pubkey.key.dsa;

        size_t h_size = pgp_digest_length(keys[i].h);
        rnp_assert_int_equal(
          rstate, dsa_sign(&global_rng, &sig, message, h_size, key1), RNP_SUCCESS);
        rnp_assert_int_equal(rstate, dsa_verify(&sig, message, h_size, key1), RNP_SUCCESS);
        pgp_seckey_free(&sec_key1);
    }
}

void
test_dsa_verify_negative(void **state)
{
    rnp_test_state_t *  rstate = *state;
    uint8_t             message[PGP_MAX_HASH_SIZE];
    pgp_seckey_t        sec_key1 = {{0}};
    pgp_seckey_t        sec_key2 = {{0}};
    pgp_dsa_signature_t sig = {{{0}}};

    struct key_params {
        size_t         p;
        size_t         q;
        pgp_hash_alg_t h;
    } key = {1024, 160, PGP_HASH_SHA1};

    assert_true(rng_get_data(&global_rng, message, sizeof(message)));

    memset(&sig, 0, sizeof(sig));
    const rnp_keygen_crypto_params_t key_desc = {.key_alg = PGP_PKA_DSA,
                                                 .hash_alg = key.h,
                                                 .dsa = {.p_bitlen = key.p, .q_bitlen = key.q},
                                                 .rng = &global_rng};

    assert_true(pgp_generate_seckey(&key_desc, &sec_key1));
    // try to prevent timeouts in travis-ci
    printf("p: %zu q: %zu h: %s\n",
           key_desc.dsa.p_bitlen,
           key_desc.dsa.q_bitlen,
           pgp_show_hash_alg(key_desc.hash_alg));
    assert_true(pgp_generate_seckey(&key_desc, &sec_key2));

    pgp_dsa_key_t *key1 = &sec_key1.pubkey.key.dsa;
    pgp_dsa_key_t *key2 = &sec_key2.pubkey.key.dsa;

    size_t h_size = pgp_digest_length(key.h);
    rnp_assert_int_equal(
      rstate, dsa_sign(&global_rng, &sig, message, h_size, key1), RNP_SUCCESS);
    // wrong key used
    rnp_assert_int_equal(
      rstate, dsa_verify(&sig, message, h_size, key2), RNP_ERROR_SIGNATURE_INVALID);
    // different message
    message[0] = ~message[0];
    rnp_assert_int_equal(
      rstate, dsa_verify(&sig, message, h_size, key1), RNP_ERROR_SIGNATURE_INVALID);
    pgp_seckey_free(&sec_key1);
    pgp_seckey_free(&sec_key2);
}
