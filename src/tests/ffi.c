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

#include <rnp/rnp2.h>
#include "rnp_tests.h"
#include "support.h"

static int
test_ffi_cb(void *app_ctx, const char *pgp_context, char buf[], size_t buf_len)
{
    printf("got password callback for %s\n", pgp_context);
    strcpy(buf, "testing");
    return 0;
}

const char *test_pub_key =
  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
  "Version: rnp 0.8.0~\n"
  "\n"
  "xo0EWcpWwgEEALrh0ia9CTSLFT1mtASffG6MGWaewji/B4A/7CnNLdn4SM7qBVWtEdBxUIiKw3RO\n"
  "Mcddaewm554hLDn6+MKmOwr+y3zCRKbqwnj0FZpMDjo5Lh6rvXEXmLujnW1cz5iYW6YIdS207W3D\n"
  "rX0drR8vziMht0Z04cu2/dYJBTZsnek9ABEBAAHNC1Rlc3QgdXNlcmlkwrUEEwECACkFAlnKVsIC\n"
  "Gy8CGQEFCwkIBwIGFQgJCgsCBRYCAwEACRC+8H1ZgunpnAAAFEsD/3MOlBh/9ZbLGy7r1B3+wL5u\n"
  "liBwp+3wbnmLtTMySxwHHzVeL66+6PVDWr/ovAcBiIAAdvzg0ofEoo/dw2MvYaavY7mBuQyydRU/\n"
  "MCvFRmdxCMzCm7R3EjqWC1cRQJ2I00jhT1hb8TDQ5lZ3cB8MFjdtQ14AU3hiHOoqFWtX8/vP\n"
  "=iWmK\n"
  "-----END PGP PUBLIC KEY BLOCK-----\n";

void
test_ffi_api(void **state)
{
    rnp_test_state_t *rstate = *state;

    // FIXME
    const char *test_userid = "Test userid";
    const char *sec_path = "/tmp/secring";
    const char *pub_path = "/tmp/pubring";
    const char *plaintext_message = "Hi there\n";

    rnp_keyring_t keyring;
    rnp_result_t  result;

    result = rnp_keyring_open(&keyring, "GPG", pub_path, sec_path, test_ffi_cb, NULL);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    result = rnp_generate_private_key(keyring,
                                      test_userid,
                                      "SHA1",
                                      "RSA",
                                      "1024",
                                      "primary pass",
                                      0,
                                      "RSA",
                                      "1024",
                                      "subkey pass",
                                      0);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    char *exported_key = NULL;
    result = rnp_export_public_key(keyring, test_userid, &exported_key);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    printf("%s\n", exported_key);

    uint8_t *ciphertext = NULL;
    size_t   ctext_len = 0;
    result = rnp_encrypt(keyring,
                         test_userid,
                         "AES-128",
                         "zlib",
                         6,
                         true,
                         (const uint8_t *) plaintext_message,
                         strlen(plaintext_message),
                         &ciphertext,
                         &ctext_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    printf("%s\n", ciphertext);

    uint8_t *decrypted;
    size_t   decrypted_len;
    result = rnp_decrypt(keyring, ciphertext, ctext_len, &decrypted, &decrypted_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    printf("Decrypted=");
    for (size_t i = 0; i != decrypted_len; ++i)
        printf("%c", decrypted[i]);
    printf("\n");

    rnp_buffer_free(decrypted);
    rnp_buffer_free(ciphertext);

    uint8_t *sig = NULL;
    size_t   sig_len = 0;
    result = rnp_sign(keyring,
                      test_userid,
                      "SHA256",
                      false,
                      true,
                      (const uint8_t *) plaintext_message,
                      strlen(plaintext_message),
                      &sig,
                      &sig_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    printf("%s\n", sig);

    uint8_t *recovered_msg;
    size_t   recovered_msg_len;
    result = rnp_verify(keyring, sig, sig_len, &recovered_msg, &recovered_msg_len);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);

    result = rnp_insert_armored_public_key(keyring, test_pub_key);
    rnp_assert_int_equal(rstate, result, RNP_SUCCESS);
    // TODO test the key we just loaded (eg verify a signature)

    rnp_keyring_close(keyring);
}
