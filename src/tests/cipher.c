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

#include <rsa.h>
#include <dsa.h>
#include <eddsa.h>
#include <elgamal.h>
#include <crypto.h>
#include <packet.h>
#include <pgp-key.h>
#include <bn.h>
#include <rnp/rnp.h>
#include <ecdsa.h>
#include <ecdh.h>

#include "rnp_tests.h"
#include "support.h"

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
      "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0"};

    for (int i = 0; hash_algs[i] != PGP_HASH_UNKNOWN; ++i) {
        rnp_assert_int_equal(rstate, 1, pgp_hash_create(&hash, hash_algs[i]));
        unsigned hash_size = pgp_hash_output_length(&hash);

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

    uint8_t block[16] = {0};
    uint8_t cfb_data[20] = {0};

    rnp_assert_int_equal(rstate, 1, pgp_crypt_any(&crypt, alg));

    rnp_assert_int_equal(rstate, 1, pgp_encrypt_init(&crypt));

    memset(iv, 0x42, sizeof(iv));

    rnp_assert_int_equal(rstate, 0, pgp_cipher_set_key(&crypt, key));
    rnp_assert_int_equal(rstate, 0, pgp_cipher_block_encrypt(&crypt, block, block));

    rnp_assert_int_equal(
      rstate,
      0,
      test_value_equal(
        "AES ECB encrypt", "66E94BD4EF8A2C3B884CFA59CA342B2E", block, sizeof(block)));

    rnp_assert_int_equal(rstate, 0, pgp_cipher_block_decrypt(&crypt, block, block));

    rnp_assert_int_equal(
      rstate,
      0,
      test_value_equal(
        "AES ECB decrypt", "00000000000000000000000000000000", block, sizeof(block)));

    rnp_assert_int_equal(rstate, 0, pgp_cipher_set_iv(&crypt, iv));
    rnp_assert_int_equal(
      rstate, 0, pgp_cipher_cfb_encrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data)));

    rnp_assert_int_equal(rstate,
                         0,
                         test_value_equal("AES CFB encrypt",
                                          "BFDAA57CB812189713A950AD9947887983021617",
                                          cfb_data,
                                          sizeof(cfb_data)));

    rnp_assert_int_equal(rstate, 0, pgp_cipher_set_iv(&crypt, iv));
    rnp_assert_int_equal(
      rstate, 0, pgp_cipher_cfb_decrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data)));
    rnp_assert_int_equal(rstate,
                         0,
                         test_value_equal("AES CFB decrypt",
                                          "0000000000000000000000000000000000000000",
                                          cfb_data,
                                          sizeof(cfb_data)));
    rnp_assert_int_equal(rstate, 0, pgp_cipher_finish(&crypt));
}

void
pkcs1_rsa_test_success(void **state)
{
    rnp_test_state_t *rstate = *state;
    uint8_t           ptext[1024 / 8] = {'a', 'b', 'c', 0};

    uint8_t    ctext[1024 / 8];
    uint8_t    decrypted[1024 / 8];
    int        ctext_size, decrypted_size;
    pgp_key_t *pgp_key;

    const pgp_pubkey_t *pub_key;
    const pgp_seckey_t *sec_key;

    const pgp_rsa_pubkey_t *pub_rsa;
    const pgp_rsa_seckey_t *sec_rsa;

    const rnp_keygen_desc_t key_desc = {.crypto = {.key_alg = PGP_PKA_RSA,
                                                   .hash_alg = PGP_HASH_SHA256,
                                                   .sym_alg = PGP_SA_AES_128,
                                                   .rsa = {.modulus_bit_len = 1024}}};
    pgp_key = pgp_generate_keypair(&key_desc, NULL);
    rnp_assert_non_null(rstate, pgp_key);

    sec_key = pgp_get_seckey(pgp_key);
    rnp_assert_non_null(rstate, sec_key);

    pub_key = pgp_get_pubkey(pgp_key);
    rnp_assert_non_null(rstate, pub_key);

    pub_rsa = &pub_key->key.rsa;
    sec_rsa = &sec_key->key.rsa;

#if defined(DEBUG_PRINT)
    char *tmp = hex_encode(ptext, sizeof(ptext));
    printf("PT = 0x%s\n", tmp);
    free(tmp);
    printf("N = ");
    BN_print_fp(stdout, pub_rsa->n);
    printf("\n");
    printf("E = ");
    BN_print_fp(stdout, pub_rsa->e);
    printf("\n");
    printf("P = ");
    BN_print_fp(stdout, sec_rsa->p);
    printf("\n");
    printf("Q = ");
    BN_print_fp(stdout, sec_rsa->q);
    printf("\n");
    printf("D = ");
    BN_print_fp(stdout, sec_rsa->d);
    printf("\n");
#endif

    ctext_size = pgp_rsa_encrypt_pkcs1(ctext, sizeof(ctext), ptext, 3, pub_rsa);

    rnp_assert_int_equal(rstate, ctext_size, 1024 / 8);

    memset(decrypted, 0, sizeof(decrypted));
    decrypted_size =
      pgp_rsa_decrypt_pkcs1(decrypted, sizeof(decrypted), ctext, ctext_size, sec_rsa, pub_rsa);

#if defined(DEBUG_PRINT)
    tmp = hex_encode(ctext, ctext_size);
    printf("C = 0x%s\n", tmp);
    free(tmp);
    tmp = hex_encode(decrypted, decrypted_size);
    printf("PD = 0x%s\n", tmp);
    free(tmp);
#endif

    test_value_equal("RSA 1024 decrypt", "616263", decrypted, 3);

    rnp_assert_int_equal(rstate, decrypted_size, 3);
    pgp_key_free(pgp_key);
}

void
rnp_test_eddsa(void **state)
{
    rnp_test_state_t *      rstate = *state;
    const rnp_keygen_desc_t key_desc = {.crypto = {.key_alg = PGP_PKA_EDDSA,
                                                   .hash_alg = PGP_HASH_SHA256,
                                                   .sym_alg = PGP_SA_AES_128}};
    pgp_key_t *pgp_key = pgp_generate_keypair(&key_desc, NULL);
    rnp_assert_non_null(rstate, pgp_key);

    const uint8_t hash[32] = {0};
    BIGNUM *      r = BN_new();
    BIGNUM *      s = BN_new();

    rnp_assert_int_equal(rstate,
                         pgp_eddsa_sign_hash(r,
                                             s,
                                             hash,
                                             sizeof(hash),
                                             &pgp_key->key.seckey.key.ecc,
                                             &pgp_key->key.seckey.pubkey.key.ecc),
                         0);

    rnp_assert_int_equal(
      rstate,
      pgp_eddsa_verify_hash(r, s, hash, sizeof(hash), &pgp_key->key.seckey.pubkey.key.ecc),
      1);

    // swap r/s -> invalid sig
    rnp_assert_int_equal(
      rstate,
      pgp_eddsa_verify_hash(s, r, hash, sizeof(hash), &pgp_key->key.seckey.pubkey.key.ecc),
      0);

    // cut one byte off hash -> invalid sig
    rnp_assert_int_equal(
      rstate,
      pgp_eddsa_verify_hash(r, s, hash, sizeof(hash) - 1, &pgp_key->key.seckey.pubkey.key.ecc),
      0);

    BN_free(r);
    BN_free(s);
    pgp_key_free(pgp_key);
}

void
raw_elg_test_success(void **state)
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

    pgp_elgamal_pubkey_t pub_elg;
    pgp_elgamal_seckey_t sec_elg;
    uint8_t              encm[64];
    uint8_t              g_to_k[64];
    uint8_t              decryption_result[1024];
    const uint8_t        plaintext[] = {0x01, 0x02, 0x03, 0x04, 0x17};

    // Allocate needed memory
    pub_elg.p = BN_bin2bn(p512, sizeof(p512), NULL);
    rnp_assert_non_null(rstate, pub_elg.p);

    pub_elg.g = BN_new();
    rnp_assert_non_null(rstate, pub_elg.g);

    sec_elg.x = BN_new();
    rnp_assert_non_null(rstate, sec_elg.x);

    pub_elg.y = BN_new();
    rnp_assert_non_null(rstate, pub_elg.y);

    BN_set_word(pub_elg.g, 3);
    BN_set_word(sec_elg.x, 0xCAB5432);
    BN_mod_exp(pub_elg.y, pub_elg.g, sec_elg.x, pub_elg.p);

    // Encrypt
    unsigned ctext_size =
      pgp_elgamal_public_encrypt_pkcs1(g_to_k, encm, plaintext, sizeof(plaintext), &pub_elg);
    rnp_assert_int_not_equal(rstate, ctext_size, -1);
    rnp_assert_int_equal(rstate, ctext_size % 2, 0);
    ctext_size /= 2;

#if defined(DEBUG_PRINT)
    BIGNUM *tmp = BN_new();

    printf("\tP\t= ");
    BN_print_fp(stdout, pub_elg.p);
    printf("\n");
    printf("\tG\t= ");
    BN_print_fp(stdout, pub_elg.g);
    printf("\n");
    printf("\tY\t= ");
    BN_print_fp(stdout, pub_elg.y);
    printf("\n");
    printf("\tX\t= ");
    BN_print_fp(stdout, sec_elg.x);
    printf("\n");

    BN_bin2bn(g_to_k, ctext_size, tmp);
    printf("\tGtk\t= ");
    BN_print_fp(stdout, tmp);
    printf("\n");

    BN_bin2bn(encm, ctext_size, tmp);
    printf("\tMM\t= ");
    BN_print_fp(stdout, tmp);
    printf("\n");

    BN_clear_free(tmp);
#endif

    rnp_assert_int_not_equal(
      rstate,
      pgp_elgamal_private_decrypt_pkcs1(
        decryption_result, g_to_k, encm, ctext_size, &sec_elg, &pub_elg),
      -1);

    rnp_assert_int_equal(
      rstate,
      0,
      test_value_equal("ElGamal decrypt", "0102030417", decryption_result, sizeof(plaintext)));

    // Free heap
    BN_clear_free(pub_elg.p);
    BN_clear_free(pub_elg.g);
    BN_clear_free(sec_elg.x);
    BN_clear_free(pub_elg.y);
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

    for (int i = 0; i < ARRAY_SIZE(curves); i++) {
        pgp_ecc_sig_t           sig = {NULL, NULL};
        const rnp_keygen_desc_t key_desc = {.crypto = {.key_alg = PGP_PKA_ECDSA,
                                                       .hash_alg = PGP_HASH_SHA512,
                                                       .sym_alg = PGP_SA_AES_128,
                                                       .ecc = {.curve = curves[i].id}}};

        pgp_key_t *pgp_key1 = pgp_generate_keypair(&key_desc, NULL);
        rnp_assert_non_null(rstate, pgp_key1);

        pgp_key_t *pgp_key2 = pgp_generate_keypair(&key_desc, NULL);
        rnp_assert_non_null(rstate, pgp_key2);

        const pgp_ecc_pubkey_t *pub_key1 = &pgp_key1->key.pubkey.key.ecc;
        const pgp_ecc_pubkey_t *pub_key2 = &pgp_key2->key.pubkey.key.ecc;
        const pgp_ecc_seckey_t *prv_key1 = &pgp_key1->key.seckey.key.ecc;

        rnp_assert_int_equal(
          rstate,
          pgp_ecdsa_sign_hash(&sig, message, curves[i].size, prv_key1, pub_key1),
          PGP_E_OK);

        rnp_assert_int_equal(
          rstate, pgp_ecdsa_verify_hash(&sig, message, curves[i].size, pub_key1), PGP_E_OK);

        // Fails because of different key used
        rnp_assert_int_equal(rstate,
                             pgp_ecdsa_verify_hash(&sig, message, curves[i].size, pub_key2),
                             PGP_E_V_BAD_SIGNATURE);

        // Fails because message won't verify
        message[0] = ~message[0];
        rnp_assert_int_equal(rstate,
                             pgp_ecdsa_verify_hash(&sig, message, sizeof(message), pub_key1),
                             PGP_E_V_BAD_SIGNATURE);

        BN_clear_free(sig.r);
        BN_clear_free(sig.s);
        pgp_key_free(pgp_key1);
        pgp_key_free(pgp_key2);
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

    rnp_test_state_t *rstate = *state;
    uint8_t           wrapped_key[48] = {0};
    size_t            wrapped_key_len = sizeof(wrapped_key);
    uint8_t           plaintext[32] = {0};
    size_t            plaintext_len = sizeof(plaintext);
    uint8_t           result[32] = {0};
    size_t            result_len = sizeof(result);
    botan_mp_t        tmp_eph_key;

    rnp_assert_int_equal(rstate, botan_mp_init(&tmp_eph_key), 0);

    for (int i = 0; i < ARRAY_SIZE(curves); i++) {
        const rnp_keygen_desc_t key_desc = {.key_alg = PGP_PKA_ECDH,
                                            .hash_alg = PGP_HASH_SHA512,
                                            .sym_alg = PGP_SA_AES_256,
                                            .ecc = {.curve = curves[i].id}};

        const size_t expected_result_byte_size = curves[i].size * 2 + 1;
        pgp_key_t *  ecdh_key1 = pgp_generate_keypair(&key_desc, NULL);

        rnp_assert_int_equal(rstate,
                             pgp_ecdh_encrypt_pkcs5(plaintext,
                                                    plaintext_len,
                                                    wrapped_key,
                                                    &wrapped_key_len,
                                                    tmp_eph_key,
                                                    &ecdh_key1->key.pubkey.key.ecdh,
                                                    &ecdh_key1->sigfingerprint),
                             RNP_SUCCESS);

        size_t num_bytes = 0;
        rnp_assert_int_equal(rstate, botan_mp_num_bytes(tmp_eph_key, &num_bytes), 0);
        rnp_assert_int_equal(rstate, num_bytes, expected_result_byte_size);

        rnp_assert_int_equal(rstate,
                             pgp_ecdh_decrypt_pkcs5(result,
                                                    &result_len,
                                                    wrapped_key,
                                                    wrapped_key_len,
                                                    tmp_eph_key,
                                                    &ecdh_key1->key.seckey.key.ecc,
                                                    &ecdh_key1->key.pubkey.key.ecdh,
                                                    &ecdh_key1->sigfingerprint),
                             RNP_SUCCESS);

        rnp_assert_int_equal(rstate, plaintext_len, result_len);
        rnp_assert_int_equal(rstate, memcmp(plaintext, result, result_len), 0);
        pgp_key_free(ecdh_key1);
    }

    botan_mp_destroy(tmp_eph_key);
}

void
ecdh_decryptionNegativeCases(void **state)
{
    rnp_test_state_t *rstate = *state;
    uint8_t           wrapped_key[48] = {0};
    size_t            wrapped_key_len = sizeof(wrapped_key);
    uint8_t           plaintext[32] = {0};
    size_t            plaintext_len = sizeof(plaintext);
    uint8_t           result[32] = {0};
    size_t            result_len = sizeof(result);
    botan_mp_t        tmp_eph_key;

    rnp_assert_int_equal(rstate, botan_mp_init(&tmp_eph_key), 0);

    const rnp_keygen_desc_t key_desc = {.key_alg = PGP_PKA_ECDH,
                                        .hash_alg = PGP_HASH_SHA512,
                                        .sym_alg = PGP_SA_AES_256,
                                        .ecc = {.curve = PGP_CURVE_NIST_P_256}};

    const size_t expected_result_byte_size = 32 * 2 + 1;
    pgp_key_t *  ecdh_key1 = pgp_generate_keypair(&key_desc, NULL);

    rnp_assert_int_equal(rstate,
                         pgp_ecdh_encrypt_pkcs5(plaintext,
                                                plaintext_len,
                                                wrapped_key,
                                                &wrapped_key_len,
                                                tmp_eph_key,
                                                &ecdh_key1->key.pubkey.key.ecdh,
                                                &ecdh_key1->sigfingerprint),
                         RNP_SUCCESS);

    size_t num_bytes = 0;
    rnp_assert_int_equal(rstate, botan_mp_num_bytes(tmp_eph_key, &num_bytes), 0);
    rnp_assert_int_equal(rstate, num_bytes, expected_result_byte_size);

    rnp_assert_int_equal(rstate,
                         pgp_ecdh_decrypt_pkcs5(NULL,
                                                0,
                                                wrapped_key,
                                                wrapped_key_len,
                                                tmp_eph_key,
                                                &ecdh_key1->key.seckey.key.ecc,
                                                &ecdh_key1->key.pubkey.key.ecdh,
                                                &ecdh_key1->sigfingerprint),
                         RNP_ERROR_BAD_PARAMETERS);

    rnp_assert_int_equal(rstate,
                         pgp_ecdh_decrypt_pkcs5(result,
                                                &result_len,
                                                wrapped_key,
                                                wrapped_key_len,
                                                tmp_eph_key,
                                                NULL,
                                                &ecdh_key1->key.pubkey.key.ecdh,
                                                &ecdh_key1->sigfingerprint),
                         RNP_ERROR_BAD_PARAMETERS);

    rnp_assert_int_equal(rstate,
                         pgp_ecdh_decrypt_pkcs5(result,
                                                &result_len,
                                                NULL,
                                                wrapped_key_len,
                                                tmp_eph_key,
                                                &ecdh_key1->key.seckey.key.ecc,
                                                &ecdh_key1->key.pubkey.key.ecdh,
                                                &ecdh_key1->sigfingerprint),
                         RNP_ERROR_BAD_PARAMETERS);

    rnp_assert_int_equal(rstate,
                         pgp_ecdh_decrypt_pkcs5(result,
                                                &result_len,
                                                wrapped_key,
                                                0,
                                                tmp_eph_key,
                                                &ecdh_key1->key.seckey.key.ecc,
                                                &ecdh_key1->key.pubkey.key.ecdh,
                                                &ecdh_key1->sigfingerprint),
                         RNP_ERROR_GENERIC);

    rnp_assert_int_equal(rstate,
                         pgp_ecdh_decrypt_pkcs5(result,
                                                &result_len,
                                                wrapped_key,
                                                wrapped_key_len - 1,
                                                tmp_eph_key,
                                                &ecdh_key1->key.seckey.key.ecc,
                                                &ecdh_key1->key.pubkey.key.ecdh,
                                                &ecdh_key1->sigfingerprint),
                         RNP_ERROR_GENERIC);

    size_t tmp = result_len - 1;
    rnp_assert_int_equal(rstate,
                         pgp_ecdh_decrypt_pkcs5(result,
                                                &tmp,
                                                wrapped_key,
                                                wrapped_key_len,
                                                tmp_eph_key,
                                                &ecdh_key1->key.seckey.key.ecc,
                                                &ecdh_key1->key.pubkey.key.ecdh,
                                                &ecdh_key1->sigfingerprint),
                         RNP_ERROR_SHORT_BUFFER);

    int key_wrapping_alg = ecdh_key1->key.pubkey.key.ecdh.kdf.wrap_alg;
    ecdh_key1->key.pubkey.key.ecdh.kdf.wrap_alg = PGP_SA_IDEA;
    rnp_assert_int_equal(rstate,
                         pgp_ecdh_decrypt_pkcs5(result,
                                                &result_len,
                                                wrapped_key,
                                                wrapped_key_len,
                                                tmp_eph_key,
                                                &ecdh_key1->key.seckey.key.ecc,
                                                &ecdh_key1->key.pubkey.key.ecdh,
                                                &ecdh_key1->sigfingerprint),
                         RNP_ERROR_NOT_SUPPORTED);
    ecdh_key1->key.pubkey.key.ecdh.kdf.wrap_alg = key_wrapping_alg;

    // Change ephemeral key, so that it fails to decrypt
    botan_mp_clear(tmp_eph_key);
    rnp_assert_int_equal(rstate,
                         pgp_ecdh_decrypt_pkcs5(result,
                                                &result_len,
                                                wrapped_key,
                                                wrapped_key_len,
                                                tmp_eph_key,
                                                &ecdh_key1->key.seckey.key.ecc,
                                                &ecdh_key1->key.pubkey.key.ecdh,
                                                &ecdh_key1->sigfingerprint),
                         RNP_ERROR_GENERIC);

    rnp_assert_int_equal(rstate, plaintext_len, result_len);
    rnp_assert_int_equal(rstate, memcmp(plaintext, result, result_len), 0);
    pgp_key_free(ecdh_key1);

    botan_mp_destroy(tmp_eph_key);
}
