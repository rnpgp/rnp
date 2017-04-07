#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

#include <crypto.h>
#include <keyring.h>
#include <packet.h>
#include <mj.h>

#if defined(USE_BN_INTERFACE)
  #include "bn.h"
#else
  #include <openssl/bn.h>
#endif

// returns new string containing hex value
char* hex_encode(const uint8_t v[], size_t len)
{
   char* s;
   size_t i;

   s = malloc(2*len + 1);
   if(s == NULL)
      return NULL;

   char hex_chars[] = "0123456789ABCDEF";

   for (i = 0; i < len; ++i)
   {
      uint8_t b0 = 0x0F & (v[i] >> 4);
      uint8_t b1 = 0x0F & (v[i]);
      const char c1 = hex_chars[b0];
      const char c2 = hex_chars[b1];
      s[2*i] = c1;
      s[2*i+1] = c2;
   }
   s[2*len] = 0;

   return s;
}

int test_value_equal(const char* what,
                     const char* expected_value,
                     const uint8_t v[], size_t v_len)
{
   if(strlen(expected_value) != v_len*2)
   {
      fprintf(stderr, "Bad length for %s expected %zu bytes got %zu\n", what, strlen(expected_value), 2*v_len);
      return 1;
   }

   char* produced = hex_encode(v, v_len);

   // fixme - expects expected_value is also uppercase
   if(strcmp(produced, expected_value) != 0)
   {
      fprintf(stderr, "Bad value for %s expected %s got %s\n", what, expected_value, produced);
      free(produced);
      return 1;
   }

   free(produced);
   return 0;
}

static void hash_test_success(void **state)
{
   pgp_hash_t hash;
   uint8_t hash_output[PGP_MAX_HASH_SIZE];

   const pgp_hash_alg_t hash_algs[] = {
      PGP_HASH_MD5,
      PGP_HASH_SHA1,
      PGP_HASH_SHA256,
      PGP_HASH_SHA384,
      PGP_HASH_SHA512,
      PGP_HASH_SHA224,
      PGP_HASH_UNKNOWN
   };

   const uint8_t test_input[3] = { 'a', 'b', 'c' };
   const char* hash_alg_expected_outputs[] = {
      "900150983CD24FB0D6963F7D28E17F72",
      "A9993E364706816ABA3E25717850C26C9CD0D89D",
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
      "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7",
      "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
      "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7"
   };

   for(int i = 0; hash_algs[i] != PGP_HASH_UNKNOWN; ++i)
   {
      unsigned hash_size = pgp_hash_size(hash_algs[i]);

      //printf("Testing hash # %d size %d\n", i+1, hash_size);

      assert_int_equal(hash_size*2, strlen(hash_alg_expected_outputs[i]));

      assert_int_equal(1, pgp_hash_any(&hash, hash_algs[i]));

      hash.init(&hash);
      hash.add(&hash, test_input, 1);
      hash.add(&hash, test_input + 1, sizeof(test_input) - 1);
      hash.finish(&hash, hash_output);

      test_value_equal(hash.name,
                       hash_alg_expected_outputs[i],
                       hash_output, hash_size);
   }
}

static void cipher_test_success(void **state)
{
   const uint8_t key[16] = { 0 };
   uint8_t iv[16];
   pgp_symm_alg_t alg = PGP_SA_AES_128;
   pgp_crypt_t crypt;

   uint8_t block[16] = { 0 };
   uint8_t cfb_data[20] = { 0 };

   assert_int_equal(1, pgp_crypt_any(&crypt, alg));

   pgp_encrypt_init(&crypt);

   memset(iv, 0x42, sizeof(iv));

   crypt.set_crypt_key(&crypt, key);
   crypt.block_encrypt(&crypt, block, block);

   test_value_equal("AES ECB encrypt",
                    "66E94BD4EF8A2C3B884CFA59CA342B2E",
                    block, sizeof(block));

   crypt.block_decrypt(&crypt, block, block);

   test_value_equal("AES ECB decrypt",
                    "00000000000000000000000000000000",
                    block, sizeof(block));

   crypt.set_iv(&crypt, iv);
   crypt.cfb_encrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data));

   test_value_equal("AES CFB encrypt",
                    "BFDAA57CB812189713A950AD9947887983021617",
                    cfb_data, sizeof(cfb_data));

   crypt.set_iv(&crypt, iv);
   crypt.cfb_decrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data));
   test_value_equal("AES CFB decrypt",
                    "0000000000000000000000000000000000000000",
                    cfb_data, sizeof(cfb_data));

}

//#define DEBUG_PRINT

static void raw_rsa_test_success(void **state)
{
   uint8_t ptext[1024/8] = { 'a', 'b', 'c', 0 };

   uint8_t ctext[1024/8];
   uint8_t decrypted[1024/8];
   int ctext_size, decrypted_size;
   pgp_key_t* pgp_key;

   const pgp_pubkey_t* pub_key;
   const pgp_seckey_t* sec_key;

   const pgp_rsa_pubkey_t* pub_rsa;
   const pgp_rsa_seckey_t* sec_rsa;

   pgp_key = pgp_rsa_new_key(1024, 65537, "userid", "AES-128");
   sec_key = pgp_get_seckey(pgp_key);
   pub_key = pgp_get_pubkey(pgp_key);
   pub_rsa = &pub_key->key.rsa;
   sec_rsa = &sec_key->key.rsa;

#if defined(DEBUG_PRINT)
   printf("PT = 0x%s\n", hex_encode(ptext, sizeof(ptext)));
   printf("N = 0x%s\n", BN_bn2hex(pub_rsa->n));
   printf("E = 0x%s\n", BN_bn2hex(pub_rsa->e));
   printf("P = 0x%s\n", BN_bn2hex(sec_rsa->p));
   printf("Q = 0x%s\n", BN_bn2hex(sec_rsa->q));
   printf("D = 0x%s\n", BN_bn2hex(sec_rsa->d));
#endif

   ctext_size = pgp_rsa_public_encrypt(ctext, ptext, sizeof(ptext), pub_rsa);

   assert_int_equal(ctext_size, 1024/8);

   memset(decrypted, 0, sizeof(decrypted));
   decrypted_size = pgp_rsa_private_decrypt(decrypted, ctext, ctext_size,
                                            sec_rsa, pub_rsa);

#if defined(DEBUG_PRINT)
   printf("C = 0x%s\n", hex_encode(ctext, ctext_size));
   printf("PD = 0x%s\n", hex_encode(decrypted, decrypted_size));
#endif

   test_value_equal("RSA 1024 decrypt", "616263", decrypted, 3);

   assert_int_equal(decrypted_size, 1024/8);

}

static void raw_elg_test_success(void **state)
{
   // largest prime under 512 bits
   const uint8_t p512[64] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0xC7,
   };

   pgp_elgamal_pubkey_t pub_elg;
   pgp_elgamal_seckey_t sec_elg;
   uint8_t   encm[1024];
   uint8_t   g_to_k[1024];
   uint8_t decr[1024];
   const uint8_t plaintext[5] = { 1, 2, 3, 4, 23 };
   BN_CTX* ctx = BN_CTX_new();

   sec_elg.x = BN_new();
   BN_set_word(sec_elg.x, 0xDEADBEEF);

   pub_elg.g = BN_new();
   pub_elg.y = BN_new();

   pub_elg.p = BN_bin2bn(p512, sizeof(p512), NULL);

   // G = 3
   BN_set_word(pub_elg.g, 3);
   BN_set_word(sec_elg.x, 0xCAB5432);

   BN_mod_exp(pub_elg.y, pub_elg.g, sec_elg.x, pub_elg.p, ctx);

   BN_CTX_free(ctx);

   pgp_elgamal_public_encrypt(g_to_k, encm, plaintext, sizeof(plaintext), &pub_elg);

   unsigned ctext_size = pgp_elgamal_public_encrypt(g_to_k, encm, plaintext, sizeof(plaintext), &pub_elg);

   assert_int_equal(ctext_size % 2, 0);
   ctext_size /= 2;

#if defined(DEBUG_PRINT)
   printf("P = 0x%s\n", BN_bn2hex(pub_elg.p));
   printf("G = 0x%s\n", BN_bn2hex(pub_elg.g));
   printf("Y = 0x%s\n", BN_bn2hex(pub_elg.y));
   printf("X = 0x%s\n", BN_bn2hex(sec_elg.x));
   BIGNUM* x = BN_bin2bn(g_to_k, ctext_size, NULL);
   printf("Gtk = 0x%s\n", BN_bn2hex(x));
   printf("MM = ");
   for(size_t i = 0; i != ctext_size; ++i)
   {
      printf("%02X", encm[i]);
   }
   printf("\n");
#endif

   pgp_elgamal_private_decrypt(decr, g_to_k, encm, ctext_size, &sec_elg, &pub_elg);

   test_value_equal("ElGamal decrypt", "0102030417", decr, 5);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(hash_test_success),
        cmocka_unit_test(cipher_test_success),
        cmocka_unit_test(raw_rsa_test_success),
        cmocka_unit_test(raw_elg_test_success),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
