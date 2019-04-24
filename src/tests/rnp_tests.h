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
    char *original_dir;
    char *home;
    char *data_dir;
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

void rnp_test_x25519(void **state);

void hash_test_success(void **state);

void cipher_test_success(void **state);

void pkcs1_rsa_test_success(void **state);

void raw_elgamal_random_key_test_success(void **state);

void ecdsa_signverify_success(void **state);

void rnpkeys_generatekey_testExpertMode(void **state);

void generatekeyECDSA_explicitlySetSmallOutputDigest_DigestAlgAdjusted(void **state);

void generatekeyECDSA_explicitlySetBiggerThanNeededDigest_ShouldSuceed(void **state);

void generatekeyECDSA_explicitlySetUnknownDigest_ShouldFail(void **state);

void s2k_iteration_tuning(void **state);

void test_utils_list(void **state);

void test_rnpcfg(void **state);

void test_load_user_prefs(void **state);

void ecdh_roundtrip(void **state);

void ecdh_decryptionNegativeCases(void **state);

void sm2_roundtrip(void **state);
void sm2_sm3_signature_test(void **state);
void sm2_sha256_signature_test(void **state);

void test_load_v3_keyring_pgp(void **state);

void test_load_v4_keyring_pgp(void **state);

void test_load_keyring_and_count_pgp(void **state);

void test_load_check_bitfields_and_times(void **state);

void test_load_check_bitfields_and_times_v3(void **state);

void test_load_g10(void **state);

void test_load_armored_pub_sec(void **state);

void test_load_merge(void **state);

void test_load_public_from_secret(void **state);

void test_key_import(void **state);

void test_key_grip(void **state);

void test_key_prefs(void **state);

void test_load_subkey(void **state);

void test_key_unlock_pgp(void **state);

void test_key_validate(void **state);

void test_forged_key_validate(void **state);

void test_key_protect_load_pgp(void **state);

void test_key_add_userid(void **state);

void test_generated_key_sigs(void **state);

void test_key_store_search(void **state);

void test_key_store_search_by_name(void **state);

void test_ffi_api(void **state);

void test_ffi_homedir(void **state);

void test_ffi_keygen_json_pair(void **state);

void test_ffi_keygen_json_pair_dsa_elg(void **state);

void test_ffi_keygen_json_primary(void **state);

void test_ffi_keygen_json_sub(void **state);

void test_ffi_keygen_json_sub_pass_required(void **state);

void test_ffi_key_generate_misc(void **state);

void test_ffi_key_generate_rsa(void **state);

void test_ffi_key_generate_dsa(void **state);

void test_ffi_key_generate_ecdsa(void **state);

void test_ffi_key_generate_eddsa(void **state);

void test_ffi_key_generate_sm2(void **state);

void test_ffi_key_generate_ex(void **state);

void test_ffi_add_userid(void **state);

void test_ffi_detect_key_format(void **state);

void test_ffi_load_keys(void **state);

void test_ffi_clear_keys(void **state);

void test_ffi_save_keys(void **state);

void test_ffi_encrypt_pass(void **state);

void test_ffi_encrypt_pk(void **state);

void test_ffi_encrypt_and_sign(void **state);

void test_ffi_signatures_memory(void **state);

void test_ffi_signatures_detached_memory(void **state);

void test_ffi_signatures_detached(void **state);

void test_ffi_signatures(void **state);

void test_ffi_encrypt_pk_key_provider(void **state);

void test_ffi_key_to_json(void **state);

void test_ffi_key_iter(void **state);

void test_ffi_locate_key(void **state);

void test_ffi_signatures_detached_memory_g10(void **state);

void test_ffi_enarmor_dearmor(void **state);

void test_ffi_version(void **state);

void test_ffi_key_export(void **state);

void test_ffi_key_dump(void **state);

void test_ffi_pkt_dump(void **state);

void test_dsa_roundtrip(void **state);

void test_dsa_verify_negative(void **state);

void test_stream_memory(void **state);

void test_stream_file(void **state);

void test_stream_signatures(void **state);

void test_stream_signatures_revoked_key(void **state);

void test_stream_key_load(void **state);

void test_stream_key_load_errors(void **state);

void test_stream_key_decrypt(void **state);

void test_stream_key_encrypt(void **state);

void test_stream_key_signatures(void **state);

void test_stream_dumper(void **state);

void test_stream_z(void **state);

void test_stream_verify_no_key(void **state);

void test_stream_key_signature_validate(void **state);

void test_stream_814_dearmor_double_free(void **state);

void test_stream_825_dearmor_blank_line(void **state);

void test_stream_dearmor_edge_cases(void **state);

void test_cli_rnpkeys(void **state);

void test_cli_rnp(void **state);

void test_cli_rnp_keyfile(void **state);

void test_cli_g10_operations(void **state);

void test_cli_examples(void **state);

void test_cli_redumper(void **state);

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

#define rnp_assert_ok(state, a)                   \
    {                                             \
        int _rnp_a = (a);                         \
        if (state->not_fatal && _rnp_a != true) { \
            return;                               \
        }                                         \
        assert_int_equal(_rnp_a, true);           \
    }

#define rnp_assert_fail(state, a)         \
    {                                     \
        int _rnp_a = (a);                 \
        if (state->not_fatal && _rnp_a) { \
            return;                       \
        }                                 \
        assert_int_equal(_rnp_a, false);  \
    }

#define assert_rnp_success(a) assert_int_equal(RNP_SUCCESS, a)

#define assert_rnp_failure(a) assert_int_not_equal(RNP_SUCCESS, a)

#endif // RNP_TESTS_H
