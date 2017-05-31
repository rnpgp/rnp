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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <ftw.h>

#include <cmocka.h>

#include <crypto.h>
#include <keyring.h>
#include <packet.h>
#include <bn.h>

#include <rnp.h>
#include <sys/stat.h>

/* Check if a file exists.
 * Use with assert_true and assert_false.
 */
int
file_exists(const char *path)
{
    struct stat st = {0};
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Check if a file is empty
 * Use with assert_true and assert_false.
 */
int
file_empty(const char *path)
{
    struct stat st = {0};
    return stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 0;
}

/* Concatenate multiple strings into a full path.
 * A directory separator is added between components.
 * Must be called in between va_start and va_end.
 * Final argument of calling function must be NULL.
 */
void
vpaths_concat(char *buffer, size_t buffer_size, const char *first, va_list ap)
{
    size_t      length = strlen(first);
    const char *s;

    assert_true(length < buffer_size);

    memset(buffer, 0, buffer_size);

    strncpy(buffer, first, buffer_size - 1);
    while ((s = va_arg(ap, const char *))) {
        length += strlen(s) + 1;
        assert_true(length < buffer_size);
        strncat(buffer, "/", buffer_size - 1);
        strncat(buffer, s, buffer_size - 1);
    }
}

/* Concatenate multiple strings into a full path.
 * Final argument must be NULL.
 */
char *
paths_concat(char *buffer, size_t buffer_length, const char *first, ...)
{
    va_list ap;

    va_start(ap, first);
    vpaths_concat(buffer, buffer_length, first, ap);
    va_end(ap);
    return buffer;
}

/* Concatenate multiple strings into a full path and
 * check that the file exists.
 * Final argument must be NULL.
 */
int
path_file_exists(const char *first, ...)
{
    va_list ap;
    char    buffer[512] = {0};

    va_start(ap, first);
    vpaths_concat(buffer, sizeof(buffer), first, ap);
    va_end(ap);
    return file_exists(buffer);
}

/* Concatenate multiple strings into a full path and
 * create the directory.
 * Final argument must be NULL.
 */
void
path_mkdir(mode_t mode, const char *first, ...)
{
    va_list ap;
    char    buffer[512];

    /* sanity check - should always be an absolute path */
    assert_true(first[0] == '/');

    va_start(ap, first);
    vpaths_concat(buffer, sizeof(buffer), first, ap);
    va_end(ap);

    assert_int_equal(0, mkdir(buffer, mode));
}

int
remove_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    int ret = remove(fpath);
    if (ret)
        perror(fpath);

    return ret;
}

/* Recursively remove a directory.
 * The path must be a full path and must be located in /tmp, for safety.
 */
void
delete_recursively(const char *path)
{
    /* sanity check, we should only be purging things from /tmp/ */
    assert_int_equal(strncmp(path, "/tmp/", 5), 0);
    assert_true(strlen(path) > 5);

    nftw(path, remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

/* Creates and returns a temporary directory path.
 * Caller must free the string.
 */
static char *
make_temp_dir()
{
    const char *template = "/tmp/rnp-cmocka-XXXXXX";
    char *buffer = calloc(1, strlen(template) + 1);
    strncpy(buffer, template, strlen(template));
    return mkdtemp(buffer);
}

// returns new string containing hex value
char *
hex_encode(const uint8_t v[], size_t len)
{
    char * s;
    size_t i;

    s = malloc(2 * len + 1);
    if (s == NULL)
        return NULL;

    char hex_chars[] = "0123456789ABCDEF";

    for (i = 0; i < len; ++i) {
        uint8_t    b0 = 0x0F & (v[i] >> 4);
        uint8_t    b1 = 0x0F & (v[i]);
        const char c1 = hex_chars[b0];
        const char c2 = hex_chars[b1];
        s[2 * i] = c1;
        s[2 * i + 1] = c2;
    }
    s[2 * len] = 0;

    return s;
}

int
test_value_equal(const char *what, const char *expected_value, const uint8_t v[], size_t v_len)
{
    assert_int_equal(strlen(expected_value), v_len * 2);

    char *produced = hex_encode(v, v_len);

    // fixme - expects expected_value is also uppercase
    assert_string_equal(produced, expected_value);

    free(produced);
    return 0;
}

static void
hash_test_success(void **state)
{
    pgp_hash_t hash;
    uint8_t    hash_output[PGP_MAX_HASH_SIZE];

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
      "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA"
      "134C825A7",
      "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C2"
      "3A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
      "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7",
      "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0"};

    for (int i = 0; hash_algs[i] != PGP_HASH_UNKNOWN; ++i) {
        assert_int_equal(1, pgp_hash_create(&hash, hash_algs[i]));
        unsigned hash_size = pgp_hash_output_length(&hash);

        assert_int_equal(hash_size * 2, strlen(hash_alg_expected_outputs[i]));

        pgp_hash_add(&hash, test_input, 1);
        pgp_hash_add(&hash, test_input + 1, sizeof(test_input) - 1);
        pgp_hash_finish(&hash, hash_output);

        test_value_equal(
          pgp_hash_name(&hash), hash_alg_expected_outputs[i], hash_output, hash_size);
    }
}

static void
cipher_test_success(void **state)
{
    const uint8_t  key[16] = {0};
    uint8_t        iv[16];
    pgp_symm_alg_t alg = PGP_SA_AES_128;
    pgp_crypt_t    crypt;

    uint8_t block[16] = {0};
    uint8_t cfb_data[20] = {0};

    assert_int_equal(1, pgp_crypt_any(&crypt, alg));

    pgp_encrypt_init(&crypt);

    memset(iv, 0x42, sizeof(iv));

    pgp_cipher_set_key(&crypt, key);
    pgp_cipher_block_encrypt(&crypt, block, block);

    test_value_equal(
      "AES ECB encrypt", "66E94BD4EF8A2C3B884CFA59CA342B2E", block, sizeof(block));

    pgp_cipher_block_decrypt(&crypt, block, block);

    test_value_equal(
      "AES ECB decrypt", "00000000000000000000000000000000", block, sizeof(block));

    pgp_cipher_set_iv(&crypt, iv);
    pgp_cipher_cfb_encrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data));

    test_value_equal("AES CFB encrypt",
                     "BFDAA57CB812189713A950AD9947887983021617",
                     cfb_data,
                     sizeof(cfb_data));

    pgp_cipher_set_iv(&crypt, iv);
    pgp_cipher_cfb_decrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data));
    test_value_equal("AES CFB decrypt",
                     "0000000000000000000000000000000000000000",
                     cfb_data,
                     sizeof(cfb_data));
    pgp_cipher_finish(&crypt);
}

static void
pkcs1_rsa_test_success(void **state)
{
    uint8_t ptext[1024 / 8] = {'a', 'b', 'c', 0};

    uint8_t    ctext[1024 / 8];
    uint8_t    decrypted[1024 / 8];
    int        ctext_size, decrypted_size;
    pgp_key_t *pgp_key;

    const pgp_pubkey_t *pub_key;
    const pgp_seckey_t *sec_key;

    const pgp_rsa_pubkey_t *pub_rsa;
    const pgp_rsa_seckey_t *sec_rsa;

    pgp_key = pgp_rsa_new_key(1024, 65537, "userid", "AES-128");
    sec_key = pgp_get_seckey(pgp_key);
    pub_key = pgp_get_pubkey(pgp_key);
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

    assert_int_equal(ctext_size, 1024 / 8);

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

    assert_int_equal(decrypted_size, 3);
    pgp_keydata_free(pgp_key);
}

static void
raw_elg_test_success(void **state)
{
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
    BN_CTX               ctx;

    // Allocate needed memory
    pub_elg.p = BN_bin2bn(p512, sizeof(p512), NULL);
    pub_elg.g = BN_new();
    sec_elg.x = BN_new();
    pub_elg.y = BN_new();

    BN_set_word(pub_elg.g, 3);
    BN_set_word(sec_elg.x, 0xCAB5432);
    BN_mod_exp(pub_elg.y, pub_elg.g, sec_elg.x, pub_elg.p, &ctx);

    // Encrypt
    unsigned ctext_size =
      pgp_elgamal_public_encrypt_pkcs1(g_to_k, encm, plaintext, sizeof(plaintext), &pub_elg);
    assert_int_not_equal(ctext_size, -1);
    assert_int_equal(ctext_size % 2, 0);
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

    assert_int_not_equal(pgp_elgamal_private_decrypt_pkcs1(
                           decryption_result, g_to_k, encm, ctext_size, &sec_elg, &pub_elg),
                         -1);

    test_value_equal("ElGamal decrypt", "0102030417", decryption_result, sizeof(plaintext));

    // Free heap
    BN_clear_free(pub_elg.p);
    BN_clear_free(pub_elg.g);
    BN_clear_free(sec_elg.x);
    BN_clear_free(pub_elg.y);
}

char *
uint_to_string(char *buff, const int buffsize, unsigned int num, int base)
{
    char *ptr;
    ptr = &buff[buffsize - 1];
    *ptr = '\0';

    do {
        *--ptr = "0123456789abcdef"[num % base];
        num /= base;
    } while (num != 0);

    return ptr;
}

static int
setupPassphrasefd(int *pipefd)
{
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 0;
    }

    /*Write and close fd*/
    const char *password = "passwordforkeygeneration\0";
    assert_int_equal(write(pipefd[1], password, strlen(password)), strlen(password));
    close(pipefd[1]);
    return 1;
}

static void
rnpkeys_generatekey_testSignature(void **state)
{
    const char *hashAlg[] = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SM3", NULL};

    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new pair of private/public key
     * Sign a message, then verify it
     */
    rnp_t     rnp;
    const int numbits = 1024;
    char      passfd[4] = {0};
    int       pipefd[2];

    char memToSign[] = "A simple test message";
    char signatureBuf[4096] = {0};
    char recoveredSig[4096] = {0};
    char userId[128];

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);

    for (int i = 0; hashAlg[i] != NULL; i++) {
        /*Initialize the basic RNP structure. */
        memset(&rnp, '\0', sizeof(rnp));
        /*Set the default parameters*/
        rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
        rnp_setvar(&rnp, "res", "<stdout>");

        rnp_setvar(&rnp, "format", "human");
        rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 16));
        rnp_setvar(&rnp, "need seckey", "true");

        int retVal = rnp_init(&rnp);
        assert_int_equal(retVal, 1); // Ensure the rnp core structure is correctly initialized.

        memset(userId, 0, sizeof(userId));
        strcpy(userId, "sigtest_");
        strcat(userId, hashAlg[i]);

        retVal = rnp_generate_key(&rnp, userId, numbits);
        assert_int_equal(retVal, 1); // Ensure the key was generated

        /*Load the newly generated rnp key*/
        retVal = rnp_load_keys(&rnp);
        assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

        retVal = rnp_find_key(&rnp, userId);
        assert_int_equal(retVal, 1); // Ensure the key can be found with the userId

        for (unsigned int cleartext = 0; cleartext <= 1; ++cleartext) {
            for (unsigned int armored = 0; armored <= 1; ++armored) {
                const int skip_null = (cleartext == 1) ? 1 : 0;

                if (cleartext == 1 && armored == 0) {
                    // This combination doesn't work...
                    continue;
                }

                close(pipefd[0]);
                /* Setup the pass phrase fd to avoid user-input*/
                assert_int_equal(setupPassphrasefd(pipefd), 1);

                rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 16));
                assert_int_equal(rnp_setvar(&rnp, "hash", hashAlg[i]), 1);

                retVal = rnp_sign_memory(&rnp,
                                         userId,
                                         memToSign,
                                         strlen(memToSign) - skip_null,
                                         signatureBuf,
                                         sizeof(signatureBuf),
                                         armored,
                                         cleartext);

                assert_int_not_equal(retVal, 0); // Ensure signature operation succeeded

                const int sigLen = retVal;

                retVal = rnp_verify_memory(
                  &rnp, signatureBuf, sigLen, recoveredSig, sizeof(recoveredSig), armored);
                // Ensure signature verification passed
                assert_int_equal(retVal, strlen(memToSign) - (skip_null ? 1 : 0));
                assert_string_equal(recoveredSig, memToSign);

                // TODO be smarter about this
                signatureBuf[50] ^= 0x0C; // corrupt the signature

                retVal = rnp_verify_memory(
                  &rnp, signatureBuf, sigLen, recoveredSig, sizeof(recoveredSig), armored);
                assert_int_equal(retVal,
                                 0); // Ensure signature verification fails for invalid sig
            }
        }

        rnp_end(&rnp); // Free memory and other allocated resources.
    }
}

static void
rnpkeys_generatekey_testEncryption(void **state)
{
    const char *cipherAlg[] = {"Blowfish",
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
    const int numbits = 1024;
    char      passfd[4] = {0};
    int       pipefd[2];

    char memToEncrypt[] = "A simple test message";
    char ciphertextBuf[4096] = {0};
    char plaintextBuf[4096] = {0};
    char userId[128] = {0};

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);

    /*Initialize the basic RNP structure. */
    memset(&rnp, '\0', sizeof(rnp));

    /*Set the default parameters*/
    rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
    rnp_setvar(&rnp, "res", "<stdout>");

    rnp_setvar(&rnp, "format", "human");
    rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 16));
    rnp_setvar(&rnp, "need seckey", "true");

    int retVal = rnp_init(&rnp);
    assert_int_equal(retVal, 1); // Ensure the rnp core structure is correctly initialized.

    strcpy(userId, "ciphertest");

    retVal = rnp_generate_key(&rnp, userId, numbits);
    assert_int_equal(retVal, 1); // Ensure the key was generated

    /*Load the newly generated rnp key*/
    retVal = rnp_load_keys(&rnp);
    assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

    retVal = rnp_find_key(&rnp, userId);
    assert_int_equal(retVal, 1); // Ensure the key can be found with the userId

    for (int i = 0; cipherAlg[i] != NULL; i++) {
        for (unsigned int armored = 0; armored <= 1; ++armored) {
            rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 16));
            assert_int_equal(rnp_setvar(&rnp, "cipher", cipherAlg[i]), 1);

            retVal = rnp_encrypt_memory(&rnp,
                                        userId,
                                        memToEncrypt,
                                        strlen(memToEncrypt),
                                        ciphertextBuf,
                                        sizeof(ciphertextBuf),
                                        armored);
            assert_int_not_equal(retVal, 0); // Ensure signature operation succeeded

            const int ctextLen = retVal;

            close(pipefd[0]);
            /* Setup the pass phrase fd to avoid user-input*/
            assert_int_equal(setupPassphrasefd(pipefd), 1);
            retVal = rnp_decrypt_memory(
              &rnp, ciphertextBuf, ctextLen, plaintextBuf, sizeof(plaintextBuf), armored);

            // Ensure plaintext recovered
            assert_int_equal(retVal, strlen(memToEncrypt));
            assert_string_equal(memToEncrypt, plaintextBuf);
        }
    }
    rnp_end(&rnp); // Free memory and other allocated resources.
}

static void
rnpkeys_generatekey_verifySupportedHashAlg(void **state)
{
    const char *hashAlg[] = {"MD5",
                             "SHA1",
                             //"RIPEMD160",
                             "SHA256",
                             "SHA384",
                             "SHA512",
                             "SHA224",
                             "SM3"};

    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new pair of private/public key
     * Verify the key was generated with the correct UserId.*/
    rnp_t     rnp;
    const int numbits = 1024;
    char      passfd[4] = {0};
    int       pipefd[2];

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);

    for (int i = 0; i < sizeof(hashAlg) / sizeof(hashAlg[0]); i++) {
        /*Initialize the basic RNP structure. */
        memset(&rnp, '\0', sizeof(rnp));

        /*Set the default parameters*/
        rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
        rnp_setvar(&rnp, "res", "<stdout>");
        rnp_setvar(&rnp, "format", "human");
        rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
        assert_int_equal(rnp_setvar(&rnp, "hash", hashAlg[i]), 1);

        int retVal = rnp_init(&rnp);
        assert_int_equal(retVal, 1); // Ensure the rnp core structure is correctly initialized.

        retVal = rnp_generate_key(&rnp, NULL, numbits);
        assert_int_equal(retVal, 1); // Ensure the key was generated

        /*Load the newly generated rnp key*/
        retVal = rnp_load_keys(&rnp);
        assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

        retVal = rnp_find_key(&rnp, getenv("LOGNAME"));
        assert_int_equal(retVal, 1); // Ensure the key can be found with the userId

        rnp_end(&rnp); // Free memory and other allocated resources.
    }
}

static void
rnpkeys_generatekey_verifyUserIdOption(void **state)
{
    char        userId[1024] = {0};
    const char *UserId[] = {"rnpkeys_generatekey_verifyUserIdOption_MD5",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA-1",
                            "rnpkeys_generatekey_verifyUserIdOption_RIPEMD160",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA256",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA384",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA512",
                            "rnpkeys_generatekey_verifyUserIdOption_SHA224"};

    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new pair of private/public key
     * Verify the key was generated with the correct UserId.*/
    rnp_t     rnp;
    const int numbits = 1024;
    char      passfd[4] = {0};
    int       pipefd[2];

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);

    for (int i = 0; i < sizeof(UserId) / sizeof(UserId[0]); i++) {
        /* Set the user id to be used*/
        snprintf(userId, sizeof(userId), "%s", UserId[i]);

        /*Initialize the basic RNP structure. */
        memset(&rnp, '\0', sizeof(rnp));

        /*Set the default parameters*/
        rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
        rnp_setvar(&rnp, "res", "<stdout>");
        rnp_setvar(&rnp, "format", "human");
        rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
        assert_int_equal(rnp_setvar(&rnp, "hash", "SHA256"), 1);

        int retVal = rnp_init(&rnp);
        assert_int_equal(retVal, 1); // Ensure the rnp core structure is correctly initialized.

        retVal = rnp_generate_key(&rnp, userId, numbits);
        assert_int_equal(retVal, 1); // Ensure the key was generated

        /*Load the newly generated rnp key*/
        retVal = rnp_load_keys(&rnp);
        assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

        retVal = rnp_find_key(&rnp, userId);
        assert_int_equal(retVal, 1); // Ensure the key can be found with the userId

        rnp_end(&rnp); // Free memory and other allocated resources.
    }
}

static void
rnpkeys_generatekey_verifykeyHomeDirOption(void **state)
{
    const char *ourdir = (char *) *state;
    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new pair of private/public key
     * Verify the key was generated with the correct UserId.*/
    rnp_t     rnp;
    const int numbits = 1024;
    char      passfd[4] = {0};
    int       pipefd[2];

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);

    /*Initialize the basic RNP structure. */
    memset(&rnp, '\0', sizeof(rnp));

    /*Set the default parameters*/
    rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
    rnp_setvar(&rnp, "res", "<stdout>");
    rnp_setvar(&rnp, "format", "human");
    rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
    assert_int_equal(rnp_setvar(&rnp, "hash", "SHA256"), 1);

    assert_int_equal(1, rnp_init(&rnp));

    // pubring and secring should not exist yet
    assert_false(path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    assert_false(path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    // Ensure the key was generated.
    assert_int_equal(1, rnp_generate_key(&rnp, NULL, numbits));

    // pubring and secring should now exist
    assert_true(path_file_exists(ourdir, ".rnp/pubring.gpg", NULL));
    assert_true(path_file_exists(ourdir, ".rnp/secring.gpg", NULL));

    assert_int_equal(1, rnp_load_keys(&rnp));
    assert_int_equal(1, rnp_find_key(&rnp, getenv("LOGNAME")));
    rnp_end(&rnp);

    // Now we start over with a new home.
    memset(&rnp, 0, sizeof(rnp));
    // Create a directory "newhome" within this tests temporary directory.
    char newhome[256];
    paths_concat(newhome, sizeof(newhome), ourdir, "newhome", NULL);
    path_mkdir(0700, newhome, NULL);

    // Set the homedir to our newhome path.
    assert_int_equal(1, rnp_setvar(&rnp, "homedir", newhome));

    /*Set the default parameters*/
    rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
    rnp_setvar(&rnp, "res", "<stdout>");
    rnp_setvar(&rnp, "format", "human");
    rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));

    assert_int_equal(rnp_setvar(&rnp, "hash", "SHA256"), 1);

    assert_int_equal(1, rnp_init(&rnp));

    // pubring and secring should not exist yet
    assert_false(path_file_exists(newhome, ".rnp/pubring.gpg", NULL));
    assert_false(path_file_exists(newhome, ".rnp/secring.gpg", NULL));

    // Ensure the key was generated.
    assert_int_equal(1, rnp_generate_key(&rnp, "newhomekey", numbits));

    // pubring and secring should now exist
    assert_true(path_file_exists(newhome, ".rnp/pubring.gpg", NULL));
    assert_true(path_file_exists(newhome, ".rnp/secring.gpg", NULL));

    // Load the keys in our newhome directory
    assert_int_equal(1, rnp_load_keys(&rnp));

    // We should NOT find this key.
    assert_int_equal(0, rnp_find_key(&rnp, getenv("LOGNAME")));

    // We should find this key, instead.
    assert_int_equal(1, rnp_find_key(&rnp, "newhomekey"));

    rnp_end(&rnp); // Free memory and other allocated resources.
}

static void
rnpkeys_generatekey_verifykeyNonexistingHomeDir(void **state)
{
    const char *ourdir = (char *) *state;
    const int   numbits = 1024;
    char        passfd[4] = {0};
    int         pipefd[2];
    rnp_t       rnp;
    char        fakedir[256];

    // fakedir is a directory that does not exist
    paths_concat(fakedir, sizeof(fakedir), ourdir, "fake", NULL);

    /****************************************************************/
    // First, make sure init succeeds with the default (using $HOME)
    memset(&rnp, '\0', sizeof(rnp));
    assert_int_equal(1, rnp_init(&rnp));
    rnp_end(&rnp);

    /****************************************************************/
    // Ensure it fails when we set an invalid "homedir"
    memset(&rnp, '\0', sizeof(rnp));
    rnp_setvar(&rnp, "homedir", fakedir);
    assert_int_equal(0, rnp_init(&rnp));
    rnp_end(&rnp);

    /****************************************************************/
    // Ensure it fails when we do not explicitly set "homedir" and
    // $HOME is invalid.
    memset(&rnp, '\0', sizeof(rnp));
    assert_int_equal(0, setenv("HOME", fakedir, 1));
    assert_int_equal(0, rnp_init(&rnp));
    // Restore our original $HOME.
    assert_int_equal(0, setenv("HOME", ourdir, 1));
    rnp_end(&rnp);

    /****************************************************************/
    // Ensure key generation fails when we set an invalid "homedir"
    // after rnp_init.
    memset(&rnp, '\0', sizeof(rnp));
    assert_int_equal(setupPassphrasefd(pipefd), 1);
    rnp_setvar(&rnp, "res", "<stdout>");
    rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
    assert_int_equal(1, rnp_init(&rnp));
    rnp_setvar(&rnp, "homedir", fakedir);
    assert_int_equal(0, rnp_generate_key(&rnp, NULL, numbits));
    rnp_end(&rnp);
}

static void
rnpkeys_generatekey_verifykeyHomeDirNoPermission(void **state)
{
    const char *ourdir = (char *) *state;

    char nopermsdir[256];
    paths_concat(nopermsdir, sizeof(nopermsdir), ourdir, "noperms", NULL);
    path_mkdir(0000, nopermsdir, NULL);

    rnp_t     rnp;
    const int numbits = 1024;
    char      passfd[4] = {0};
    int       pipefd[2];

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);

    /* Set the home directory to a non-default value and ensure the read/write permission
     * for the specified directory*/
    int retVal = setenv("HOME", nopermsdir, 1);
    assert_int_equal(retVal, 0); // Ensure the enviornment variable was set

    /*Initialize the basic RNP structure. */
    memset(&rnp, '\0', sizeof(rnp));

    /*Set the default parameters*/
    rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
    rnp_setvar(&rnp, "res", "<stdout>");
    rnp_setvar(&rnp, "format", "human");
    rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
    assert_int_equal(rnp_setvar(&rnp, "hash", "SHA256"), 1);

    retVal = rnp_init(&rnp);
    assert_int_equal(retVal, 1); // Ensure the rnp core structure is correctly initialized.

    retVal = rnp_generate_key(&rnp, NULL, numbits);
    assert_int_equal(
      retVal,
      0); // Ensure the key was NOT generated as the directory has only list read permissions.

    rnp_end(&rnp); // Free memory and other allocated resources.
}

static void
rnpkeys_exportkey_verifyUserId(void **state)
{
    /* * Execute the Generate-key command to generate a new pair of private/public key
     * Verify the key was generated with the correct UserId.
     */
    rnp_t     rnp;
    const int numbits = 1024;
    char      passfd[4] = {0};
    int       pipefd[2];
    char *    exportedkey = NULL;

    /* Setup the pass phrase fd to avoid user-input*/
    assert_int_equal(setupPassphrasefd(pipefd), 1);
    /*Initialize the basic RNP structure. */
    memset(&rnp, '\0', sizeof(rnp));

    /*Set the default parameters*/
    rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
    rnp_setvar(&rnp, "res", "<stdout>");
    rnp_setvar(&rnp, "format", "human");
    rnp_setvar(&rnp, "userid", getenv("LOGNAME"));
    rnp_setvar(&rnp, "pass-fd", uint_to_string(passfd, 4, pipefd[0], 10));
    assert_int_equal(rnp_setvar(&rnp, "hash", "SHA256"), 1);

    int retVal = rnp_init(&rnp);
    assert_int_equal(retVal, 1); // Ensure the rnp core structure is correctly initialized.

    retVal = rnp_generate_key(&rnp, NULL, numbits);
    assert_int_equal(retVal, 1); // Ensure the key was generated.

    /*Load the newly generated rnp key*/
    retVal = rnp_load_keys(&rnp);
    assert_int_equal(retVal, 1); // Ensure the keyring is loaded.

    /*try to export the key without passing userid from the interface;
     * stack MUST query the set userid option to find the key*/
    exportedkey = rnp_export_key(&rnp, NULL);
    assert_non_null(exportedkey);

    /*try to export the key with specified userid parameter from the interface;
     * stack MUST NOT query the set userid option to find the key*/
    exportedkey = NULL;
    exportedkey = rnp_export_key(&rnp, getenv("LOGNAME"));
    assert_non_null(exportedkey);

    /* try to export the key with specified userid parameter (which is wrong) from the
     * interface;
     * stack MUST NOT be able to find the key*/
    exportedkey = NULL;
    exportedkey = rnp_export_key(&rnp, "LOGNAME");
    assert_null(exportedkey);

    rnp_end(&rnp); // Free memory and other allocated resources.
}

static int
setup_test(void **state)
{
    *state = make_temp_dir();
    assert_int_equal(0, setenv("HOME", (char *) *state, 1));
    assert_int_equal(0, chdir((char *) *state));
    return 0;
}

static int
teardown_test(void **state)
{
    delete_recursively((char *) *state);
    free(*state);
    *state = NULL;
    return 0;
}

int
main(void)
{
    int ret;
    /* Create a temporary HOME.
     * This is just an extra guard to protect against accidental
     * modifications of a user's HOME.
     */
    char *tmphome = make_temp_dir();
    assert_int_equal(0, setenv("HOME", tmphome, 1));
    assert_int_equal(0, chdir(tmphome));

    struct CMUnitTest tests[] = {
      cmocka_unit_test(hash_test_success),
      cmocka_unit_test(cipher_test_success),
      cmocka_unit_test(pkcs1_rsa_test_success),
      cmocka_unit_test(raw_elg_test_success),
      cmocka_unit_test(rnpkeys_generatekey_testSignature),
      cmocka_unit_test(rnpkeys_generatekey_testEncryption),
      cmocka_unit_test(rnpkeys_generatekey_verifySupportedHashAlg),
      cmocka_unit_test(rnpkeys_generatekey_verifyUserIdOption),
      cmocka_unit_test(rnpkeys_generatekey_verifykeyHomeDirOption),
      cmocka_unit_test(rnpkeys_generatekey_verifykeyNonexistingHomeDir),
      cmocka_unit_test(rnpkeys_generatekey_verifykeyHomeDirNoPermission),
      cmocka_unit_test(rnpkeys_exportkey_verifyUserId),
    };

    /* Each test entry will invoke setup_test before running
     * and teardown_test after running. */
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        tests[i].setup_func = setup_test;
        tests[i].teardown_func = teardown_test;
    }
    ret = cmocka_run_group_tests(tests, NULL, NULL);

    delete_recursively(tmphome);
    free(tmphome);
    return ret;
}
