/*
 * Copyright (c) 2026, [Ribose Inc](https://www.ribose.com).
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
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* FFI-level encrypt/sign round-trip fuzz target.
 *
 * Threat model: the encode direction of OpenPGP processing - building
 * PKESK/SKESK, SEIPD v1/v2 (AEAD), compressed and literal data packets,
 * armor framing and signatures - is driven by attacker-influenced key
 * material and options, and its output is parsed back by the same library.
 * The existing targets exercise only the decode side, leaving
 * src/librepgp/stream-write.cpp and the encryption crypto paths dark.
 *
 * Input layout (all option bytes are consumed before the payload):
 *   [0]  operation: 0 encrypt(password), 1 encrypt(recipient),
 *                   2 encrypt+sign, 3 sign-only
 *   [1]  cipher index, [2] aead index, [3] aead chunk bits,
 *   [4]  compression index, [5] compression level
 *   [6]  flags: bit0 armor, bit1 nowrap, bit2 pkesk v6, bit3 skesk v6,
 *               bit4 prefer pqc subkey, bit5 force recipient, bit6 force password
 *   [7]  signature hash index, [8] s2k hash index, [9] s2k iterations class,
 *   [10] s2k cipher index, [11] recipient key selector, [12] signer key selector
 *   [13] password length (clamped)
 *   [..] password bytes, remaining bytes: keyring material for a permissive
 *        import, reused as the message payload.
 *
 * The produced ciphertext is parsed back via rnp_op_verify_execute over the
 * same key store, exercising the reader on rnp's own writer output.
 * Documented errors (unsupported algorithm names, unusable keys) are ignored
 * by design; crashes on attacker-controlled data are the signal. */

#include <rnp/rnp.h>
#include <rnp/rnp_err.h>
#include <string.h>

#define MAX_PASSWORD_LEN 32
#define ROUNDTRIP_MAX_ALLOC (16 * 1024 * 1024)

static const char *ciphers[] = {"IDEA",
                                "TRIPLEDES",
                                "CAST5",
                                "BLOWFISH",
                                "AES128",
                                "AES192",
                                "AES256",
                                "TWOFISH",
                                "CAMELLIA128",
                                "CAMELLIA192",
                                "CAMELLIA256",
                                "SM4"};
static const char *aeads[] = {"None", "OCB", "EAX", "GCM"};
static const char *comps[] = {"Uncompressed", "ZIP", "ZLIB", "BZip2"};
static const char *hashes[] = {
  "MD5", "SHA-1", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-512", "RIPEMD160"};

static char   encrt_password[MAX_PASSWORD_LEN + 1];
static size_t encrt_password_len = 0;

static bool
encrt_password_provider(rnp_ffi_t        ffi,
                        void *           app_ctx,
                        rnp_key_handle_t key,
                        const char *     key_info,
                        char *           buf,
                        size_t           buf_len)
{
    (void) ffi;
    (void) app_ctx;
    (void) key;
    (void) key_info;
    if (!buf || !buf_len) {
        return false;
    }
    size_t len = encrt_password_len;
    if (len > buf_len - 1) {
        len = buf_len - 1;
    }
    memcpy(buf, encrt_password, len);
    buf[len] = '\0';
    return true;
}

/* Select the (selector % count)-th key of the key store. With secret set, a
 * key holding a secret part is preferred (needed for signing). */
static rnp_key_handle_t
encrt_pick_key(rnp_ffi_t ffi, uint8_t selector, bool secret)
{
    rnp_identifier_iterator_t it = NULL;
    rnp_key_handle_t          found = NULL;
    const char *              id = NULL;
    size_t                    count = 0;
    size_t                    skip = 0;
    size_t                    idx = 0;
    bool                      have_secret = false;

    if (rnp_identifier_iterator_create(ffi, &it, "fingerprint") != RNP_SUCCESS) {
        return NULL;
    }
    while (rnp_identifier_iterator_next(it, &id) == RNP_SUCCESS && id) {
        count++;
    }
    rnp_identifier_iterator_destroy(it);
    if (!count) {
        return NULL;
    }
    skip = selector % count;
    if (rnp_identifier_iterator_create(ffi, &it, "fingerprint") != RNP_SUCCESS) {
        return NULL;
    }
    idx = 0;
    while (rnp_identifier_iterator_next(it, &id) == RNP_SUCCESS && id) {
        if (idx++ < skip) {
            continue;
        }
        if (!rnp_locate_key(ffi, "fingerprint", id, &found) && found && secret) {
            if (!rnp_key_have_secret(found, &have_secret) && have_secret) {
                break;
            }
            rnp_key_handle_destroy(found);
            found = NULL;
            /* keep walking: a later key may hold the secret part */
            continue;
        }
        break;
    }
    rnp_identifier_iterator_destroy(it);
    return found;
}

static void
encrt_verify_roundtrip(rnp_ffi_t ffi, const uint8_t *data, size_t size)
{
    rnp_input_t     vin = NULL;
    rnp_output_t    vout = NULL;
    rnp_op_verify_t vop = NULL;

    if (rnp_input_from_memory(&vin, data, size, false)) {
        return;
    }
    if (rnp_output_to_memory(&vout, ROUNDTRIP_MAX_ALLOC)) {
        rnp_input_destroy(vin);
        return;
    }
    if (!rnp_op_verify_create(&vop, ffi, vin, vout)) {
        (void) rnp_op_verify_execute(vop);
        rnp_op_verify_destroy(vop);
    }
    rnp_output_destroy(vout);
    rnp_input_destroy(vin);
}

#ifdef RNP_RUN_TESTS
int encrypt_roundtrip_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int
encrypt_roundtrip_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
#else
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
#endif
{
    if (size < 16) {
        return 0;
    }

    uint8_t mode = data[0] % 4;
    uint8_t pwdlen = data[13] % (MAX_PASSWORD_LEN + 1);
    if (size < 14 + (size_t) pwdlen + 1) {
        return 0;
    }
    memcpy(encrt_password, data + 14, pwdlen);
    encrt_password[pwdlen] = '\0';
    encrt_password_len = pwdlen;
    const uint8_t *msg = data + 14 + pwdlen;
    size_t         msglen = size - 14 - pwdlen;

    rnp_ffi_t ffi = NULL;
    if (rnp_ffi_create(&ffi, "GPG", "GPG")) {
        return 0;
    }
    (void) rnp_ffi_set_pass_provider(ffi, encrt_password_provider, NULL);

    /* import keyring material, permissively */
    rnp_input_t in = NULL;
    char *      results = NULL;
    if (!rnp_input_from_memory(&in, msg, msglen, false)) {
        (void) rnp_import_keys(ffi,
                               in,
                               RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS |
                                 RNP_LOAD_SAVE_PERMISSIVE,
                               &results);
        rnp_buffer_destroy(results);
        rnp_input_destroy(in);
    }

    /* build the protected message */
    rnp_input_t  src = NULL;
    rnp_output_t out = NULL;
    if (rnp_input_from_memory(&src, msg, msglen, false)) {
        rnp_ffi_destroy(ffi);
        return 0;
    }
    if (rnp_output_to_memory(&out, ROUNDTRIP_MAX_ALLOC)) {
        rnp_input_destroy(src);
        rnp_ffi_destroy(ffi);
        return 0;
    }

    if (mode == 3) {
        /* sign-only */
        rnp_op_sign_t op = NULL;
        if (!rnp_op_sign_create(&op, ffi, src, out)) {
            (void) rnp_op_sign_set_hash(op, hashes[data[7] % 8]);
            (void) rnp_op_sign_set_armor(op, data[6] & 1);
            rnp_key_handle_t skey = encrt_pick_key(ffi, data[12], true);
            if (skey) {
                (void) rnp_op_sign_add_signature(op, skey, NULL);
                rnp_key_handle_destroy(skey);
            }
            (void) rnp_op_sign_execute(op);
            rnp_op_sign_destroy(op);
        }
    } else {
        rnp_op_encrypt_t op = NULL;
        if (!rnp_op_encrypt_create(&op, ffi, src, out)) {
            (void) rnp_op_encrypt_set_cipher(op, ciphers[data[1] % 12]);
            (void) rnp_op_encrypt_set_aead(op, aeads[data[2] % 4]);
            (void) rnp_op_encrypt_set_aead_bits(op, data[3] % 17);
            (void) rnp_op_encrypt_set_compression(op, comps[data[4] % 4], data[5] % 10);
            (void) rnp_op_encrypt_set_armor(op, data[6] & 1);
            (void) rnp_op_encrypt_set_flags(op, (data[6] & 2) ? RNP_ENCRYPT_NOWRAP : 0);
            (void) rnp_op_encrypt_set_hash(op, hashes[data[7] % 8]);
            (void) rnp_op_encrypt_set_file_name(op, "fuzz");
            (void) rnp_op_encrypt_set_file_mtime(op, 0);
#ifdef RNP_EXPERIMENTAL_CRYPTO_REFRESH
            if (data[6] & 4) {
                (void) rnp_op_encrypt_enable_pkesk_v6(op);
            }
            if (data[6] & 8) {
                (void) rnp_op_encrypt_enable_skesk_v6(op);
            }
#endif
#ifdef RNP_EXPERIMENTAL_PQC
            if (data[6] & 16) {
                (void) rnp_op_encrypt_prefer_pqc_enc_subkey(op);
            }
#endif
            if ((mode == 0) || (data[6] & 64)) {
                (void) rnp_op_encrypt_add_password(op,
                                                   encrt_password,
                                                   hashes[data[8] % 8],
                                                   (size_t)(data[9] % 4 + 1) * 1024,
                                                   ciphers[data[10] % 12]);
            }
            if ((mode == 1) || (mode == 2) || (data[6] & 32)) {
                rnp_key_handle_t rkey = encrt_pick_key(ffi, data[11], false);
                if (rkey) {
                    (void) rnp_op_encrypt_add_recipient(op, rkey);
                    rnp_key_handle_destroy(rkey);
                }
            }
            if (mode == 2) {
                rnp_key_handle_t skey = encrt_pick_key(ffi, data[12], true);
                if (skey) {
                    (void) rnp_op_encrypt_add_signature(op, skey, NULL);
                    rnp_key_handle_destroy(skey);
                }
            }
            (void) rnp_op_encrypt_execute(op);
            rnp_op_encrypt_destroy(op);
        }
    }
    rnp_input_destroy(src);

    /* parse rnp's own output back */
    uint8_t *obuf = NULL;
    size_t   olen = 0;
    if (!rnp_output_memory_get_buf(out, &obuf, &olen, false) && olen) {
        encrt_verify_roundtrip(ffi, obuf, olen);
    }
    rnp_output_destroy(out);
    rnp_ffi_destroy(ffi);
    return 0;
}
