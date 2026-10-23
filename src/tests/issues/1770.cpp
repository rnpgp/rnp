#include "../rnp_tests.h"
#include "../support.h"
#include "librepgp/stream-armor.h"
#include "librepgp/stream-packet.h"

/* Issue #1770: decrypt RFC 9580 messages produced for a v4 ECDH
 * Curve25519Legacy subkey.
 *
 * Two things in the v6 PKESK path were wrong:
 *   - encrypted_try_key() stripped a leading symmetric-algorithm octet
 *     for every algorithm that has a PKESK checksum. RFC 9580 §5.1.2 and
 *     §11.5 put that octet only in a v3 PKESK. v6 carries the cipher in
 *     the v2 SEIPD header, so the stripped byte was the first session-key
 *     octet and the ECDH checksum no longer matched.
 *   - A v6 PKESK with a zero-length key-version/fingerprint field
 *     (anonymous recipient, RFC 9580 §5.1.2 / §5.1.8) was rejected as
 *     malformed, so it never reached the hidden-recipient key search.
 *
 * Samples are from Delta Chat / rpgp (anonymous PKESK) and sq (PKESK with
 * the recipient fingerprint). The v1 message is the same key and plaintext
 * in the legacy framing and must keep working.
 */

#if defined(ENABLE_CRYPTO_REFRESH)

static const char *KEY_PATH = "data/test_messages/pkeskv6-ecdh/seckey.asc";
static const char *V1_ANON = "data/test_messages/pkeskv6-ecdh/seipdv1-anon.asc";
static const char *V2_ANON = "data/test_messages/pkeskv6-ecdh/seipdv2-anon.asc";
static const char *V2_FP = "data/test_messages/pkeskv6-ecdh/seipdv2-fp.asc";

/* v4 Key ID of the Curve25519Legacy encryption subkey (low 64 bits). */
static const char *ENC_KEYID = "9C5EECAF63C38506";

static void
expect_plaintext(rnp_output_t output, const char *plaintext)
{
    uint8_t *buf = NULL;
    size_t   len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, strlen(plaintext));
    assert_memory_equal(buf, plaintext, len);
}

static void
expect_good_signature(rnp_op_verify_t verify)
{
    size_t count = 0;
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &count));
    assert_int_equal(count, 1);
    rnp_op_verify_signature_t sig = NULL;
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_int_equal(rnp_op_verify_signature_get_status(sig), RNP_SUCCESS);
}

static void
expect_protection(rnp_op_verify_t verify, const char *mode, const char *cipher)
{
    char *got_mode = NULL;
    char *got_cipher = NULL;
    bool  valid = false;
    assert_rnp_success(
      rnp_op_verify_get_protection_info(verify, &got_mode, &got_cipher, &valid));
    assert_string_equal(got_mode, mode);
    assert_string_equal(got_cipher, cipher);
    assert_true(valid);
    rnp_buffer_destroy(got_mode);
    rnp_buffer_destroy(got_cipher);
}

static void
expect_recipient(rnp_op_verify_t verify, const char *keyid, bool hidden_used)
{
    size_t count = 0;
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 1);
    rnp_recipient_handle_t recipient = NULL;
    assert_rnp_success(rnp_op_verify_get_recipient_at(verify, 0, &recipient));
    char *alg = NULL;
    char *got = NULL;
    assert_rnp_success(rnp_recipient_get_alg(recipient, &alg));
    assert_string_equal(alg, "ECDH");
    rnp_buffer_destroy(alg);
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &got));
    assert_string_equal(got, keyid);
    rnp_buffer_destroy(got);

    recipient = NULL;
    assert_rnp_success(rnp_op_verify_get_used_recipient(verify, &recipient));
    assert_non_null(recipient);
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &got));
    /* Anonymous packets store no key id. After a successful try, the
     * handle reports the key that actually decrypted. */
    assert_string_equal(got, hidden_used ? ENC_KEYID : keyid);
    rnp_buffer_destroy(got);
}

/* Parse the leading PKESK and write it back. An anonymous v6 packet must
 * keep the zero-length fingerprint field (RFC 9580 §5.1.2). */
static void
expect_pkesk_roundtrip(const char *path, pgp_pkesk_version_t version, size_t fp_size)
{
    pgp_source_t file = {};
    assert_rnp_success(init_file_src(&file, path));
    assert_true(file.is_armored());
    pgp_source_t armored = {};
    assert_rnp_success(init_armored_src(&armored, &file));

    pgp_pk_sesskey_t pkey;
    assert_rnp_success(pkey.parse(armored));
    assert_int_equal(pkey.version, version);
    assert_int_equal(pkey.alg, PGP_PKA_ECDH);
    if (version == PGP_PKSK_V6) {
        assert_int_equal(pkey.fp.size(), fp_size);
        if (!fp_size) {
            assert_true(pkey.key_id == pgp::KeyID({}));
        } else {
            pgp::KeyID expect{};
            assert_int_equal(fp_size, PGP_FINGERPRINT_V4_SIZE);
            memcpy(expect.data(), pkey.fp.data() + fp_size - PGP_KEY_ID_SIZE, expect.size());
            assert_true(pkey.key_id == expect);
        }
    } else {
        assert_true(pkey.key_id == pgp::KeyID({}));
    }

    pgp_dest_t dst = {};
    assert_rnp_success(init_mem_dest(&dst, NULL, 0));
    pkey.write(dst);
    assert_int_equal(dst.werr, RNP_SUCCESS);

    pgp_source_t mem = {};
    assert_rnp_success(init_mem_src(&mem, mem_dest_get_memory(&dst), dst.writeb, false));
    pgp_pk_sesskey_t again;
    assert_rnp_success(again.parse(mem));
    assert_int_equal(again.version, pkey.version);
    assert_int_equal(again.alg, pkey.alg);
    assert_true(again.key_id == pkey.key_id);
    assert_true(again.fp == pkey.fp);
    assert_int_equal(again.material_buf.size(), pkey.material_buf.size());
    assert_memory_equal(
      again.material_buf.data(), pkey.material_buf.data(), pkey.material_buf.size());

    mem.close();
    dst_close(&dst, false);
    armored.close();
    file.close();
}

static void
open_verify(rnp_ffi_t        ffi,
            const char *     path,
            rnp_input_t *    input,
            rnp_output_t *   output,
            rnp_op_verify_t *verify,
            uint32_t         flags)
{
    assert_rnp_success(rnp_input_from_path(input, path));
    assert_rnp_success(rnp_output_to_memory(output, 0));
    assert_rnp_success(rnp_op_verify_create(verify, ffi, *input, *output));
    if (flags) {
        assert_rnp_success(rnp_op_verify_set_flags(*verify, flags));
    }
}

TEST_F(rnp_tests, test_ffi_pkesk_v6_ecdh_legacy_1770)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_true(import_all_keys(ffi, KEY_PATH));

    expect_pkesk_roundtrip(V2_FP, PGP_PKSK_V6, PGP_FINGERPRINT_V4_SIZE);
    expect_pkesk_roundtrip(V2_ANON, PGP_PKSK_V6, 0);
    expect_pkesk_roundtrip(V1_ANON, PGP_PKSK_V3, 0);

    /* Visible v6 PKESK (fingerprint of the v4 subkey) + SEIPD v2 AES-256-OCB.
     * No hidden-recipient flag: the fingerprint selects the key. sq sample,
     * unsigned. */
    {
        rnp_input_t     input = NULL;
        rnp_output_t    output = NULL;
        rnp_op_verify_t verify = NULL;
        open_verify(ffi, V2_FP, &input, &output, &verify, 0);
        assert_rnp_success(rnp_op_verify_execute(verify));
        expect_plaintext(output, "hello v2 visible\n");
        expect_protection(verify, "aead-ocb", "AES256");
        expect_recipient(verify, ENC_KEYID, false);
        size_t sigs = 99;
        assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigs));
        assert_int_equal(sigs, 0);
        rnp_op_verify_destroy(verify);
        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }

    /* Anonymous v6 PKESK + SEIPD v2 AES-128-OCB. Refused unless the caller
     * allows a hidden recipient, then the signature verifies. */
    {
        rnp_input_t     input = NULL;
        rnp_output_t    output = NULL;
        rnp_op_verify_t verify = NULL;
        open_verify(ffi, V2_ANON, &input, &output, &verify, 0);
        assert_int_equal(rnp_op_verify_execute(verify), RNP_ERROR_NO_SUITABLE_KEY);
        rnp_op_verify_destroy(verify);
        rnp_input_destroy(input);
        rnp_output_destroy(output);

        open_verify(ffi, V2_ANON, &input, &output, &verify, RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT);
        assert_rnp_success(rnp_op_verify_execute(verify));
        expect_plaintext(output, "hello from deltachat core");
        expect_protection(verify, "aead-ocb", "AES128");
        expect_recipient(verify, "0000000000000000", true);
        expect_good_signature(verify);
        rnp_op_verify_destroy(verify);
        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }

    /* Same key and plaintext, legacy anonymous v3 PKESK + SEIPD v1. */
    {
        rnp_input_t     input = NULL;
        rnp_output_t    output = NULL;
        rnp_op_verify_t verify = NULL;
        open_verify(ffi, V1_ANON, &input, &output, &verify, 0);
        assert_int_equal(rnp_op_verify_execute(verify), RNP_ERROR_NO_SUITABLE_KEY);
        rnp_op_verify_destroy(verify);
        rnp_input_destroy(input);
        rnp_output_destroy(output);

        open_verify(ffi, V1_ANON, &input, &output, &verify, RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT);
        assert_rnp_success(rnp_op_verify_execute(verify));
        expect_plaintext(output, "hello from deltachat core");
        expect_protection(verify, "cfb-mdc", "AES128");
        expect_recipient(verify, "0000000000000000", true);
        expect_good_signature(verify);
        rnp_op_verify_destroy(verify);
        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }

    rnp_ffi_destroy(ffi);
}

#endif
