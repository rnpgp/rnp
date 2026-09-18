#include "../rnp_tests.h"
#include "../support.h"

/* Issue #2470: rnp_op_sign_set_file_name/mtime (and the encrypt equivalents)
 * used to silently discard the filename/mtime in ENABLE_CRYPTO_REFRESH builds.
 * Per review on #2470/#2486, the fix is version-aware and keyed off the
 * actual output version (v6_output), not the build flag or a hard error:
 *   - The setters ALWAYS return RNP_SUCCESS -- they only store the value.
 *   - build_literal_hdr() omits filename/mtime from v6 literal packets, since
 *     RFC 9580 says they SHOULD NOT be set for v6 (not MUST NOT).
 *   - rnp_op_sign_execute()/rnp_op_encrypt_execute() still return
 *     RNP_SUCCESS when a non-default filename/mtime was requested for v6
 *     output (all-v6 signing keys on the sign path; PKESKv6+SKESKv6 =>
 *     SEIPDv2 on the encrypt path) -- only a warning is logged, and the
 *     fields are silently dropped from the packet.
 *   - v4 output still embeds and round-trips filename/mtime, even in an
 *     ENABLE_CRYPTO_REFRESH build.
 */

TEST_F(rnp_tests, test_ffi_literal_hdr_crypto_refresh_2470)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    /* --- 1. Setters always succeed, regardless of build or value --- */
    {
        rnp_op_sign_t sop = NULL;
        rnp_input_t   input = NULL;
        rnp_output_t  output = NULL;
        assert_rnp_success(rnp_input_from_memory(&input, (const uint8_t *) "test", 4, false));
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_rnp_success(rnp_op_sign_create(&sop, ffi, input, output));

        assert_rnp_success(rnp_op_sign_set_file_name(sop, "secret.txt"));
        assert_rnp_success(rnp_op_sign_set_file_mtime(sop, 1700000000));
        assert_rnp_success(rnp_op_sign_set_file_name(sop, NULL));
        assert_rnp_success(rnp_op_sign_set_file_name(sop, ""));
        assert_rnp_success(rnp_op_sign_set_file_mtime(sop, 0));

        rnp_op_sign_destroy(sop);
        rnp_input_destroy(input);
        rnp_output_destroy(output);

        rnp_op_encrypt_t eop = NULL;
        assert_rnp_success(rnp_input_from_memory(&input, (const uint8_t *) "test", 4, false));
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_rnp_success(rnp_op_encrypt_create(&eop, ffi, input, output));

        assert_rnp_success(rnp_op_encrypt_set_file_name(eop, "secret.txt"));
        assert_rnp_success(rnp_op_encrypt_set_file_mtime(eop, 1700000000));
        assert_rnp_success(rnp_op_encrypt_set_file_name(eop, NULL));
        assert_rnp_success(rnp_op_encrypt_set_file_mtime(eop, 0));

        rnp_op_encrypt_destroy(eop);
        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }

    /* --- 2. v4 signing key: filename/mtime embedded and round-trips,
     *        even in an ENABLE_CRYPTO_REFRESH build. --- */
    {
        rnp_op_generate_t genop = NULL;
        assert_rnp_success(rnp_op_generate_create(&genop, ffi, "EDDSA"));
        assert_rnp_success(rnp_op_generate_set_userid(genop, "v4 signer"));
        assert_rnp_success(rnp_op_generate_add_usage(genop, "sign"));
        assert_rnp_success(rnp_op_generate_set_expiration(genop, 0));
        assert_rnp_success(rnp_op_generate_execute(genop));
        rnp_key_handle_t v4key = NULL;
        assert_rnp_success(rnp_op_generate_get_key(genop, &v4key));
        rnp_op_generate_destroy(genop);

        rnp_op_sign_t sop = NULL;
        rnp_input_t   input = NULL;
        rnp_output_t  output = NULL;
        assert_rnp_success(rnp_input_from_memory(&input, (const uint8_t *) "test", 4, false));
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_rnp_success(rnp_op_sign_create(&sop, ffi, input, output));
        assert_rnp_success(rnp_op_sign_add_signature(sop, v4key, NULL));
        assert_rnp_success(rnp_op_sign_set_file_name(sop, "secret.txt"));
        assert_rnp_success(rnp_op_sign_set_file_mtime(sop, 1700000000));

        assert_rnp_success(rnp_op_sign_execute(sop));

        uint8_t *buf = NULL;
        size_t   len = 0;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));

        rnp_input_t  vinput = NULL;
        rnp_output_t voutput = NULL;
        assert_rnp_success(rnp_input_from_memory(&vinput, buf, len, false));
        assert_rnp_success(rnp_output_to_null(&voutput));
        rnp_op_verify_t vop = NULL;
        assert_rnp_success(rnp_op_verify_create(&vop, ffi, vinput, voutput));
        assert_rnp_success(rnp_op_verify_execute(vop));

        char    *filename = NULL;
        uint32_t mtime = 0;
        assert_rnp_success(rnp_op_verify_get_file_info(vop, &filename, &mtime));
        assert_string_equal(filename, "secret.txt");
        assert_int_equal(mtime, 1700000000);
        rnp_buffer_destroy(filename);

        rnp_op_verify_destroy(vop);
        rnp_input_destroy(vinput);
        rnp_output_destroy(voutput);
        rnp_op_sign_destroy(sop);
        rnp_input_destroy(input);
        rnp_output_destroy(output);
        rnp_key_handle_destroy(v4key);
    }

#if defined(ENABLE_CRYPTO_REFRESH)
    /* --- 3. v6 signing key: non-default filename/mtime is accepted by the
     *        setters and by execute() (RFC 9580 says SHOULD NOT, not MUST
     *        NOT), but is silently omitted from the v6 literal packet with
     *        just a warning logged. Verify via round-trip that the filename
     *        does NOT come through, unlike the v4 case in part 2. --- */
    {
        rnp_op_generate_t genop = NULL;
        assert_rnp_success(rnp_op_generate_create(&genop, ffi, "EDDSA"));
        assert_rnp_success(rnp_op_generate_set_v6_key(genop));
        assert_rnp_success(rnp_op_generate_set_userid(genop, "v6 signer"));
        assert_rnp_success(rnp_op_generate_add_usage(genop, "sign"));
        assert_rnp_success(rnp_op_generate_set_expiration(genop, 0));
        assert_rnp_success(rnp_op_generate_execute(genop));
        rnp_key_handle_t v6key = NULL;
        assert_rnp_success(rnp_op_generate_get_key(genop, &v6key));
        rnp_op_generate_destroy(genop);

        rnp_op_sign_t sop = NULL;
        rnp_input_t   input = NULL;
        rnp_output_t  output = NULL;
        assert_rnp_success(rnp_input_from_memory(&input, (const uint8_t *) "test", 4, false));
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_rnp_success(rnp_op_sign_create(&sop, ffi, input, output));
        assert_rnp_success(rnp_op_sign_add_signature(sop, v6key, NULL));
        assert_rnp_success(rnp_op_sign_set_file_name(sop, "secret.txt"));
        assert_rnp_success(rnp_op_sign_set_file_mtime(sop, 1700000000));

        /* execute() succeeds -- filename/mtime is a SHOULD NOT, not a hard
         * error -- but the fields are omitted from the packet, not embedded. */
        assert_rnp_success(rnp_op_sign_execute(sop));

        uint8_t *buf = NULL;
        size_t   len = 0;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));

        rnp_input_t  vinput = NULL;
        rnp_output_t voutput = NULL;
        assert_rnp_success(rnp_input_from_memory(&vinput, buf, len, false));
        assert_rnp_success(rnp_output_to_null(&voutput));
        rnp_op_verify_t vop = NULL;
        assert_rnp_success(rnp_op_verify_create(&vop, ffi, vinput, voutput));
        assert_rnp_success(rnp_op_verify_execute(vop));

        char    *filename = NULL;
        uint32_t mtime = 1;
        assert_rnp_success(rnp_op_verify_get_file_info(vop, &filename, &mtime));
        /* Requested "secret.txt" / 1700000000 did NOT make it through. */
        assert_string_equal(filename, "");
        assert_int_equal(mtime, 0);
        rnp_buffer_destroy(filename);

        rnp_op_verify_destroy(vop);
        rnp_input_destroy(vinput);
        rnp_output_destroy(voutput);
        rnp_op_sign_destroy(sop);
        rnp_input_destroy(input);
        rnp_output_destroy(output);

        /* Defaults on v6 output: unchanged behavior, still a no-op success. */
        rnp_op_sign_t sop2 = NULL;
        assert_rnp_success(rnp_input_from_memory(&input, (const uint8_t *) "test", 4, false));
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_rnp_success(rnp_op_sign_create(&sop2, ffi, input, output));
        assert_rnp_success(rnp_op_sign_add_signature(sop2, v6key, NULL));
        assert_rnp_success(rnp_op_sign_execute(sop2));
        rnp_op_sign_destroy(sop2);
        rnp_input_destroy(input);
        rnp_output_destroy(output);

        rnp_key_handle_destroy(v6key);
    }

    /* --- 4. v6-capable recipient key with PKESKv6 enabled: non-default
     *        filename/mtime is accepted by execute() but silently omitted
     *        from the v6 literal packet (warning only, per RFC 9580 SHOULD
     *        NOT). Uses the RFC 9580 Appendix A.4 sample v6 key -- same
     *        fixture and keyid used by test_ffi_encrypt_pk_with_v6_key in
     *        ffi-enc.cpp -- rather than a freshly generated key, since
     *        rnp_op_encrypt_enable_pkesk_v6() must be called explicitly to
     *        opt into v6 PKESK even with a v6-capable recipient key. */
    {
        assert_true(import_all_keys(ffi, "data/RFC9580/A.4.transferable-seckey-v6.asc"));

        rnp_key_handle_t key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "12c83f1e706f6308", &key));
        assert_non_null(key);

        rnp_op_encrypt_t eop = NULL;
        rnp_input_t      input = NULL;
        rnp_output_t     output = NULL;
        assert_rnp_success(rnp_input_from_memory(&input, (const uint8_t *) "test", 4, false));
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_rnp_success(rnp_op_encrypt_create(&eop, ffi, input, output));
        assert_rnp_success(rnp_op_encrypt_add_recipient(eop, key));
        assert_rnp_success(rnp_op_encrypt_enable_pkesk_v6(eop));
        assert_rnp_success(rnp_op_encrypt_set_file_name(eop, "secret.txt"));
        assert_rnp_success(rnp_op_encrypt_set_file_mtime(eop, 1700000000));

        assert_rnp_success(rnp_op_encrypt_execute(eop));

        uint8_t *buf = NULL;
        size_t   len = 0;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));

        /* Confirm the requested filename/mtime did NOT survive onto the v6
         * literal packet -- only a warning was logged, per RFC 9580 SHOULD
         * NOT (not MUST NOT). Read buf/len BEFORE destroying output, since
         * get_buf(..., false) returns a pointer into output's own buffer.
         * The A.4 secret key is unprotected (no passphrase needed to
         * unlock it) -- confirmed by test_ffi_decrypt_v6_pkesk_test_vector
         * in ffi-enc.cpp, which decrypts with this same key set with no
         * password provider at all. */
        rnp_input_t  dinput = NULL;
        rnp_output_t doutput = NULL;
        assert_rnp_success(rnp_input_from_memory(&dinput, buf, len, false));
        assert_rnp_success(rnp_output_to_null(&doutput));
        rnp_op_verify_t dverify = NULL;
        assert_rnp_success(rnp_op_verify_create(&dverify, ffi, dinput, doutput));
        assert_rnp_success(rnp_op_verify_execute(dverify));

        char    *filename = NULL;
        uint32_t mtime = 1;
        assert_rnp_success(rnp_op_verify_get_file_info(dverify, &filename, &mtime));
        assert_string_equal(filename, "");
        assert_int_equal(mtime, 0);
        rnp_buffer_destroy(filename);

        rnp_op_verify_destroy(dverify);
        rnp_input_destroy(dinput);
        rnp_output_destroy(doutput);

        rnp_op_encrypt_destroy(eop);
        rnp_input_destroy(input);
        rnp_output_destroy(output);

        /* Defaults on v6 output: unchanged behavior, still a no-op success. */
        rnp_op_encrypt_t eop2 = NULL;
        assert_rnp_success(rnp_input_from_memory(&input, (const uint8_t *) "test", 4, false));
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_rnp_success(rnp_op_encrypt_create(&eop2, ffi, input, output));
        assert_rnp_success(rnp_op_encrypt_add_recipient(eop2, key));
        assert_rnp_success(rnp_op_encrypt_enable_pkesk_v6(eop2));
        assert_rnp_success(rnp_op_encrypt_execute(eop2));
        rnp_op_encrypt_destroy(eop2);
        rnp_input_destroy(input);
        rnp_output_destroy(output);

        rnp_key_handle_destroy(key);
    }
#endif

    rnp_ffi_destroy(ffi);
}
