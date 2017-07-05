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

#ifndef RNP_TESTS_H
#define RNP_TESTS_H

typedef struct {
    char *home;
    int   not_fatal;
} rnp_test_state_t;

void rnpkeys_exportkey_verifyUserId(void **state);

void rnpkeys_generatekey_testSignature(void **state);

void rnpkeys_generatekey_testEncryption(void **state);

void rnpkeys_generatekey_verifySupportedHashAlg(void **state);

void rnpkeys_generatekey_verifyUserIdOption(void **state);

void rnpkeys_generatekey_verifykeyHomeDirOption(void **state);

void rnpkeys_generatekey_verifykeyKBXHomeDirOption(void **state);

void rnpkeys_generatekey_verifykeyNonexistingHomeDir(void **state);

void rnpkeys_generatekey_verifykeyHomeDirNoPermission(void **state);

void rnp_test_eddsa(void **state);

void hash_test_success(void **state);

void cipher_test_success(void **state);

void pkcs1_rsa_test_success(void **state);

void raw_elg_test_success(void **state);

void ecdsa_signverify_success(void **state);

void rnpkeys_generatekey_testExpertMode(void **state);

#define rnp_assert_int_equal(state, a, b)           \
    do {                                            \
        int _rnp_a = (a);                           \
        int _rnp_b = (b);                           \
        if (state->not_fatal && _rnp_a != _rnp_b) { \
            return;                                 \
        }                                           \
        assert_int_equal(_rnp_a, _rnp_b);           \
    } while (0)

#define rnp_assert_int_not_equal(state, a, b)       \
    do {                                            \
        int _rnp_a = (a);                           \
        int _rnp_b = (b);                           \
        if (state->not_fatal && _rnp_a == _rnp_b) { \
            return;                                 \
        }                                           \
        assert_int_not_equal(_rnp_a, _rnp_b);       \
    } while (0)

#define rnp_assert_true(state, a)          \
    do {                                   \
        int _rnp_a = (a);                  \
        if (state->not_fatal && !_rnp_a) { \
            return;                        \
        }                                  \
        assert_true(_rnp_a);               \
    } while (0)

#define rnp_assert_false(state, a)        \
    do {                                  \
        int _rnp_a = (a);                 \
        if (state->not_fatal && _rnp_a) { \
            return;                       \
        }                                 \
        assert_false(_rnp_a);             \
    } while (0)

#define rnp_assert_non_null(state, a)             \
    do {                                          \
        void *_rnp_a = (void *) (a);              \
        if (state->not_fatal && _rnp_a == NULL) { \
            return;                               \
        }                                         \
        assert_non_null(_rnp_a);                  \
    } while (0)

#define rnp_assert_null(state, a)                 \
    do {                                          \
        void *_rnp_a = (void *) (a);              \
        if (state->not_fatal && _rnp_a != NULL) { \
            return;                               \
        }                                         \
        assert_null(_rnp_a);                      \
    } while (0)

#define rnp_assert_ok(state, a)                     \
    {                                               \
        int _rnp_a = (a);                           \
        if (state->not_fatal && _rnp_a != RNP_OK) { \
            return;                                 \
        }                                           \
        assert_int_equal(_rnp_a, RNP_OK);           \
    }

#define rnp_assert_fail(state, a)                     \
    {                                                 \
        int _rnp_a = (a);                             \
        if (state->not_fatal && _rnp_a != RNP_FAIL) { \
            return;                                   \
        }                                             \
        assert_int_equal(_rnp_a, RNP_FAIL);           \
    }

#endif // RNP_TESTS_H
