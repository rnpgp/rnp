/*-
 * Copyright (c) 2017 Ribose Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <assert.h>
#include <botan/ffi.h>
#include "ec.h"
#include "ecdh.h"
#include "ecdsa.h"
#include "crypto.h"

#define MAX_SP800_56A_OTHER_INFO 54
#define OBFUSCATED_KEY_SIZE 40

/* Used by ECDH keys. Specifies which hash and wrapping algorithm
 * to be used (see point 15. of RFC 4880).
 *
 * Note: sync with ec_curves.
 */
static const struct ecdh_params_t {
    pgp_curve_t    curve;    /* Curve ID */
    pgp_hash_alg_t hash;     /* Hash used by kdf */
    pgp_symm_alg_t wrap_alg; /* Symmetric algorithm used to wrap KEK*/
} ecdh_params[] = {
  {.curve = PGP_CURVE_NIST_P_256, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
  {.curve = PGP_CURVE_NIST_P_384, .hash = PGP_HASH_SHA384, .wrap_alg = PGP_SA_AES_192},
  {.curve = PGP_CURVE_NIST_P_521, .hash = PGP_HASH_SHA512, .wrap_alg = PGP_SA_AES_256}};

// "Anonymous Sender " in hex
static const unsigned char ANONYMOUS_SENDER[] = {0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F,
                                                 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64,
                                                 0x65, 0x72, 0x20, 0x20, 0x20, 0x20};

// returns size of data written to other_info
static size_t
kdf_other_info_serialize(uint8_t                  other_info[MAX_SP800_56A_OTHER_INFO],
                         const ec_curve_desc_t *  ec_curve,
                         const pgp_fingerprint_t *fingerprint,
                         const pgp_hash_alg_t     kdf_hash,
                         const pgp_symm_alg_t     wrap_alg)
{
    if (fingerprint->length < 20) {
        RNP_LOG("Implementation error: unexpected fingerprint length");
        return false;
    }

    uint8_t *buf_ptr = &other_info[0];

    /* KDF-OtherInfo: AlgorithmID
     *   Current implementation will alwyas use SHA-512 and AES-256 for KEK wrapping
     */
    *(buf_ptr++) = ec_curve->OIDhex_len;
    memcpy(buf_ptr, ec_curve->OIDhex, ec_curve->OIDhex_len);
    buf_ptr += ec_curve->OIDhex_len;
    *(buf_ptr++) = PGP_PKA_ECDH;
    // size of following 3 params (each 1 byte)
    *(buf_ptr++) = 0x03;
    // Value reserved for future use
    *(buf_ptr++) = 0x01;
    // Hash used with KDF
    *(buf_ptr++) = kdf_hash;
    // Algorithm ID used for key wrapping
    *(buf_ptr++) = wrap_alg;

    /* KDF-OtherInfo: PartyUInfo
     *   20 bytes representing "Anonymous Sender "
     */
    memcpy(buf_ptr, ANONYMOUS_SENDER, sizeof(ANONYMOUS_SENDER));

    buf_ptr += sizeof(ANONYMOUS_SENDER);

    // keep 20, as per spec
    memcpy(buf_ptr, fingerprint->fingerprint, 20);
    return (buf_ptr - other_info) + 20 /*anonymous_sender*/;
}

static bool
pad_pkcs7(uint8_t *buf, size_t buf_len, size_t offset)
{
    if (buf_len < offset) {
        return false;
    }

    const uint8_t pad_byte = buf_len - offset;
    memset(buf + offset, pad_byte, pad_byte);
    return true;
}

static bool
unpad_pkcs7(uint8_t *buf, size_t buf_len, size_t *offset)
{
    if (!buf || !offset || !buf_len) {
        return false;
    }

    uint8_t        err = 0;
    const uint8_t  pad_byte = buf[buf_len - 1];
    const uint32_t pad_begin = buf_len - pad_byte;

    // TODO: Still >, <, and <=,==  are not constant time (maybe?)
    err |= (pad_byte > buf_len);
    err |= (pad_byte == 0);

    /* Check if padding is OK */
    for (size_t c = 0; c < buf_len; c++) {
        err |= (buf[c] ^ pad_byte) * (pad_begin <= c);
    }

    *offset = pad_begin;
    return (err == 0);
}

// Produces kek of size kek_len which corresponds to length of wrapping key
static bool
compute_kek(uint8_t *              kek,
            size_t                 kek_len,
            const uint8_t *        other_info,
            size_t                 other_info_size,
            const ec_curve_desc_t *curve_desc,
            const botan_mp_t       ec_pubkey,
            const botan_privkey_t  ec_prvkey,
            const pgp_hash_alg_t   hash_alg)
{
    botan_pk_op_ka_t op_key_agreement = NULL;
    uint8_t          point_bytes[MAX_CURVE_BYTELEN * 2 + 1] = {0};
    bool             ret = true;

    // Name of Botan's KDF and backing hash algorithm
    const char *hash_botan_name = pgp_hash_name_botan(hash_alg);
    if (!hash_botan_name) {
        return false;
    }

    char botan_kdf_name[64] = {0};
    snprintf(botan_kdf_name, 64, "SP800-56A(%s)", hash_botan_name);

    if (botan_mp_to_bin(ec_pubkey, point_bytes) < 0) {
        return false;
    }

    size_t num_bytes = 0;
    if (botan_mp_num_bytes(ec_pubkey, &num_bytes) < 0) {
        return false;
    }

    if (botan_pk_op_key_agreement_create(&op_key_agreement, ec_prvkey, botan_kdf_name, 0) ||
        botan_pk_op_key_agreement(op_key_agreement,
                                  kek,
                                  &kek_len,
                                  point_bytes,
                                  num_bytes,
                                  other_info,
                                  other_info_size)) {
        ret = false;
        goto end;
    }

end:
    ret &= !botan_pk_op_key_agreement_destroy(op_key_agreement);
    return ret;
}

bool
set_ecdh_params(pgp_seckey_t *seckey, pgp_curve_t curve_id)
{
    for (int i = 0; i < ARRAY_SIZE(ecdh_params); i++) {
        if (ecdh_params[i].curve == curve_id) {
            seckey->pubkey.key.ecdh.kdf_hash_alg = ecdh_params[i].hash;
            seckey->pubkey.key.ecdh.key_wrap_alg = ecdh_params[i].wrap_alg;
            return true;
        }
    }

    return false;
}

rnp_result
pgp_ecdh_encrypt_pkcs5(const uint8_t *const     session_key,
                       size_t                   session_key_len,
                       uint8_t *                wrapped_key,
                       size_t *                 wrapped_key_len,
                       botan_mp_t               ephemeral_key,
                       const pgp_ecdh_pubkey_t *pubkey,
                       const pgp_fingerprint_t *fingerprint)
{
    botan_privkey_t eph_prv_key = NULL;
    botan_rng_t     rng = NULL;
    rnp_result      ret = RNP_ERROR_GENERIC;
    uint8_t         m[OBFUSCATED_KEY_SIZE];
    size_t          m_len = sizeof(m);
    uint8_t         other_info[MAX_SP800_56A_OTHER_INFO];
    uint8_t *       tmp_buf = NULL;
    uint8_t         kek[32] = {0}; // Size of SHA-256 or smaller

    if ((session_key_len > OBFUSCATED_KEY_SIZE) || !ephemeral_key || !pubkey || !wrapped_key ||
        !wrapped_key_len || !fingerprint || !pubkey->ec.point) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const ec_curve_desc_t *curve_desc = get_curve_desc(pubkey->ec.curve);
    if (!curve_desc) {
        return RNP_ERROR_NOT_SUPPORTED;
    }

    if (*wrapped_key_len < ECDH_WRAPPED_KEY_SIZE) {
        return RNP_ERROR_SHORT_BUFFER;
    }

    // See 13.5 of RFC 4880 for definition of other_info_size
    const size_t other_info_size = (pubkey->ec.curve == PGP_CURVE_NIST_P_256) ? 54 : 51;
    const size_t key_len = BITS_TO_BYTES(curve_desc->bitlen) * 2 + 1;
    const size_t kek_len = pgp_key_size(pubkey->key_wrap_alg);

    size_t tmp_len = kdf_other_info_serialize(
      other_info, curve_desc, fingerprint, pubkey->kdf_hash_alg, pubkey->key_wrap_alg);

    if (tmp_len != other_info_size) {
        RNP_LOG("Serialization of other info failed");
        return RNP_ERROR_GENERIC;
    }

    // Generate ephemeral key pair from public key of other party
    if (botan_rng_init(&rng, NULL)) {
        return RNP_ERROR_GENERIC;
    }

    if (botan_privkey_create_ecdh(&eph_prv_key, rng, curve_desc->botan_name)) {
        goto end;
    }

    if (!compute_kek(kek,
                     kek_len,
                     other_info,
                     other_info_size,
                     curve_desc,
                     pubkey->ec.point->mp,
                     eph_prv_key,
                     pubkey->kdf_hash_alg)) {
        RNP_LOG("KEK computation failed");
        goto end;
    }

    /*
     * Pad m with PKCS-5 to 40 bytes
     */
    memcpy(m, session_key, session_key_len);
    if (!pad_pkcs7(m, OBFUSCATED_KEY_SIZE, session_key_len)) {
        // Should never happen
        goto end;
    }

    /* 3394 wrapping adds 8 bytes */
    if (botan_key_wrap3394(m, m_len, kek, kek_len, wrapped_key, wrapped_key_len) ||
        (*wrapped_key_len != ECDH_WRAPPED_KEY_SIZE)) {
        goto end;
    }

    tmp_buf = malloc(key_len);
    if (!tmp_buf) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto end;
    }

    tmp_len = key_len;
    if (botan_pk_op_key_agreement_export_public(eph_prv_key, tmp_buf, &tmp_len)) {
        goto end;
    }

    if (tmp_len > key_len) {
        goto end;
    }

    if (botan_mp_from_bin(ephemeral_key, tmp_buf, tmp_len)) {
        goto end;
    }

    // All OK
    ret = RNP_SUCCESS;

end:
    ret |= botan_rng_destroy(rng);
    ret |= botan_privkey_destroy(eph_prv_key);
    free(tmp_buf);
    return ret;
}

rnp_result
pgp_ecdh_decrypt_pkcs5(uint8_t *                session_key,
                       size_t *                 session_key_len,
                       uint8_t *                wrapped_key,
                       size_t                   wrapped_key_len,
                       const botan_mp_t         ephemeral_key,
                       const pgp_ecc_seckey_t * seckey,
                       const pgp_ecdh_pubkey_t *pubkey,
                       const pgp_fingerprint_t *fingerprint)
{
    rnp_result ret = RNP_ERROR_GENERIC;
    // Size of SHA-256 or smaller
    uint8_t         kek[MAX_SYMM_KEY_SIZE];
    uint8_t         other_info[MAX_SP800_56A_OTHER_INFO];
    botan_privkey_t prv_key = NULL;
    uint8_t         key[OBFUSCATED_KEY_SIZE] = {0};
    size_t          key_len = sizeof(key);

    if (!session_key_len || !session_key_len || !wrapped_key || !seckey || !seckey->x ||
        !seckey->x->mp || !pubkey) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const ec_curve_desc_t *curve_desc = get_curve_desc(pubkey->ec.curve);
    if (!curve_desc) {
        return RNP_ERROR_NOT_SUPPORTED;
    }

    const pgp_symm_alg_t wrap_alg = pubkey->key_wrap_alg;
    const pgp_hash_alg_t kdf_hash = pubkey->kdf_hash_alg;
    /* Ensure that AES is used for wrapping */
    if ((wrap_alg != PGP_SA_AES_128) && (wrap_alg != PGP_SA_AES_192) &&
        (wrap_alg != PGP_SA_AES_256)) {
        return RNP_ERROR_NOT_SUPPORTED;
    }

    // See 13.5 of RFC 4880 for definition of other_info_size
    const size_t other_info_size =
      (curve_desc->rnp_curve_id == PGP_CURVE_NIST_P_256) ? 54 : 51;
    const size_t tmp_len =
      kdf_other_info_serialize(other_info, curve_desc, fingerprint, kdf_hash, wrap_alg);

    if (other_info_size != tmp_len) {
        RNP_LOG("Serialization of other info failed");
        goto end;
    }

    if (botan_privkey_load_ecdh(&prv_key, seckey->x->mp, curve_desc->botan_name)) {
        goto end;
    }

    /* Security: Always return same error code in case compute_kek,
     *           botan_key_unwrap3394 or unpad_pkcs7 fails
     */
    size_t kek_len = pgp_key_size(wrap_alg);
    if (!compute_kek(kek,
                     kek_len,
                     other_info,
                     other_info_size,
                     curve_desc,
                     ephemeral_key,
                     prv_key,
                     kdf_hash)) {
        goto end;
    }

    size_t offset = 0;
    if (botan_key_unwrap3394(wrapped_key, wrapped_key_len, kek, kek_len, key, &key_len)) {
        goto end;
    }

    if (!unpad_pkcs7(key, key_len, &offset)) {
        goto end;
    }

    if (*session_key_len < offset) {
        ret = RNP_ERROR_SHORT_BUFFER;
        goto end;
    }

    *session_key_len = offset;
    memcpy(session_key, key, *session_key_len);

    ret = RNP_SUCCESS;

end:
    botan_privkey_destroy(prv_key);
    return ret;
}
