#include "../rnp_tests.h"
#include "../support.h"

/* Issue #2468: rnp_signature_get_revoker() used to return an allocated
 * empty string ("") instead of NULL when the signature has no
 * revocation-key subpacket, making it impossible for callers to
 * distinguish "no revoker" from "revoker with an empty fingerprint" and
 * inconsistent with sibling getters such as rnp_signature_get_key_server.
 * Fix: when !sig.has_revoker(), *revoker is set to NULL and RNP_SUCCESS
 * is returned, matching the convention used elsewhere in the FFI.
 */

TEST_F(rnp_tests, test_ffi_signature_get_revoker_2468)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    /* Generate a plain signing key with no designated revoker at all. */
    rnp_op_generate_t genop = NULL;
    assert_rnp_success(rnp_op_generate_create(&genop, ffi, "EDDSA"));
    assert_rnp_success(rnp_op_generate_set_userid(genop, "no revoker"));
    assert_rnp_success(rnp_op_generate_add_usage(genop, "sign"));
    assert_rnp_success(rnp_op_generate_set_expiration(genop, 0));
    assert_rnp_success(rnp_op_generate_execute(genop));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_op_generate_get_key(genop, &key));
    rnp_op_generate_destroy(genop);

    /* --- 1. Edge cases: NULL handle / NULL out-param still fail. --- */
    assert_rnp_failure(rnp_signature_get_revoker(NULL, NULL));

    /* --- 2. Direct signature with no revoker subpacket set: must return
     *        NULL, not an allocated empty string. --- */
    rnp_signature_handle_t newsig = NULL;
    assert_rnp_success(rnp_key_direct_signature_create(key, NULL, &newsig));

    char *revoker = (char *) 0x1; /* poison value, to be overwritten */
    assert_rnp_failure(rnp_signature_get_revoker(NULL, &revoker));
    assert_rnp_failure(rnp_signature_get_revoker(newsig, NULL));
    assert_rnp_success(rnp_signature_get_revoker(newsig, &revoker));
    assert_null(revoker);
    /* No rnp_buffer_destroy() needed/expected on NULL. */

    rnp_signature_handle_destroy(newsig);

    /* --- 3. Same signature, now with a revoker set: must return the
     *        actual fingerprint, unaffected by the fix. --- */
    rnp_key_handle_t revoker_key = NULL;
    assert_rnp_success(rnp_op_generate_create(&genop, ffi, "EDDSA"));
    assert_rnp_success(rnp_op_generate_set_userid(genop, "revoker key"));
    assert_rnp_success(rnp_op_generate_add_usage(genop, "sign"));
    assert_rnp_success(rnp_op_generate_set_expiration(genop, 0));
    assert_rnp_success(rnp_op_generate_execute(genop));
    assert_rnp_success(rnp_op_generate_get_key(genop, &revoker_key));
    rnp_op_generate_destroy(genop);

    assert_rnp_success(rnp_key_direct_signature_create(key, NULL, &newsig));
    assert_rnp_success(rnp_key_signature_set_revoker(newsig, revoker_key, 0));

    char *revoker2 = NULL;
    assert_rnp_success(rnp_signature_get_revoker(newsig, &revoker2));
    assert_non_null(revoker2);
    assert_true(strlen(revoker2) > 0);
    rnp_buffer_destroy(revoker2);

    rnp_signature_handle_destroy(newsig);
    rnp_key_handle_destroy(key);
    rnp_key_handle_destroy(revoker_key);
    rnp_ffi_destroy(ffi);
}
