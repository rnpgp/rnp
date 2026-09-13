#include "../rnp_tests.h"
#include "../support.h"

/* Issue #2470: rnp_op_sign_set_file_name/mtime (and the encrypt equivalents)
 * silently discarded the filename/mtime in ENABLE_CRYPTO_REFRESH builds,
 * since build_literal_hdr() never writes them per RFC 9580. The setters must
 * now reject non-default values with RNP_ERROR_NOT_SUPPORTED instead of
 * returning RNP_SUCCESS and dropping the data. */
TEST_F(rnp_tests, test_ffi_literal_hdr_crypto_refresh_2470)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    rnp_op_sign_t sop = NULL;
    /* op creation itself doesn't require valid keys for setter-only checks */
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_input_from_memory(&input, (const uint8_t *) "test", 4, false));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_op_sign_create(&sop, ffi, input, output));

#if defined(ENABLE_CRYPTO_REFRESH)
    /* Non-empty filename / non-zero mtime must be rejected, not silently dropped. */
    assert_int_equal(rnp_op_sign_set_file_name(sop, "secret.txt"), RNP_ERROR_NOT_SUPPORTED);
    assert_int_equal(rnp_op_sign_set_file_mtime(sop, 1700000000), RNP_ERROR_NOT_SUPPORTED);
    /* Defaults (NULL / empty / zero) remain accepted as no-ops. */
    assert_rnp_success(rnp_op_sign_set_file_name(sop, NULL));
    assert_rnp_success(rnp_op_sign_set_file_name(sop, ""));
    assert_rnp_success(rnp_op_sign_set_file_mtime(sop, 0));
#else
    assert_rnp_success(rnp_op_sign_set_file_name(sop, "secret.txt"));
    assert_rnp_success(rnp_op_sign_set_file_mtime(sop, 1700000000));
#endif

    rnp_op_sign_destroy(sop);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    rnp_op_encrypt_t eop = NULL;
    assert_rnp_success(rnp_input_from_memory(&input, (const uint8_t *) "test", 4, false));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_op_encrypt_create(&eop, ffi, input, output));

#if defined(ENABLE_CRYPTO_REFRESH)
    assert_int_equal(rnp_op_encrypt_set_file_name(eop, "secret.txt"), RNP_ERROR_NOT_SUPPORTED);
    assert_int_equal(rnp_op_encrypt_set_file_mtime(eop, 1700000000), RNP_ERROR_NOT_SUPPORTED);
    assert_rnp_success(rnp_op_encrypt_set_file_name(eop, NULL));
    assert_rnp_success(rnp_op_encrypt_set_file_mtime(eop, 0));
#else
    assert_rnp_success(rnp_op_encrypt_set_file_name(eop, "secret.txt"));
    assert_rnp_success(rnp_op_encrypt_set_file_mtime(eop, 1700000000));
#endif

    rnp_op_encrypt_destroy(eop);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_ffi_destroy(ffi);
}