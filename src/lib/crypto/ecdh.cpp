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
#include <botan/ffi.h>
#include "ecdh.h"
#include "hash.h"
#include "symmetric.h"
#include "types.h"
#include "utils.h"
#include "mem.h"

#define MAX_SP800_56A_OTHER_INFO 56
// Keys up to 312 bits (+1 bytes of PKCS5 padding)
#define MAX_SESSION_KEY_SIZE 40

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
  {.curve = PGP_CURVE_NIST_P_521, .hash = PGP_HASH_SHA512, .wrap_alg = PGP_SA_AES_256},
  {.curve = PGP_CURVE_BP256, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
  {.curve = PGP_CURVE_BP384, .hash = PGP_HASH_SHA384, .wrap_alg = PGP_SA_AES_192},
  {.curve = PGP_CURVE_BP512, .hash = PGP_HASH_SHA512, .wrap_alg = PGP_SA_AES_256},
  {.curve = PGP_CURVE_25519, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
  {.curve = PGP_CURVE_P256K1, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
};

// "Anonymous Sender " in hex
static const unsigned char ANONYMOUS_SENDER[] = {0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F,
                                                 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64,
                                                 0x65, 0x72, 0x20, 0x20, 0x20, 0x20};

// returns size of data written to other_info
static size_t
kdf_other_info_serialize(uint8_t                  other_info[MAX_SP800_56A_OTHER_INFO],
                         const ec_curve_desc_t *  ec_curve,
                         const pgp_fingerprint_t &fingerprint,
                         const pgp_hash_alg_t     kdf_hash,
                         const pgp_symm_alg_t     wrap_alg)
{
    if (fingerprint.length < 20) {
        RNP_LOG("Implementation error: unexpected fingerprint length");
        return false;
    }

    uint8_t *buf_ptr = &other_info[0];

    /* KDF-OtherInfo: AlgorithmID
     *   Current implementation will always use SHA-512 and AES-256 for KEK wrapping
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
    memcpy(buf_ptr, fingerprint.fingerprint, 20);
    return (buf_ptr - other_info) + 20 /*anonymous_sender*/;
}

static bool
pad_pkcs7(uint8_t *buf, size_t buf_len, size_t offset)
{
    if (buf_len <= offset) {
        // Must have at least 1 byte of padding
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
            const pgp_mpi_t *      ec_pubkey,
            const botan_privkey_t  ec_prvkey,
            const pgp_hash_alg_t   hash_alg)
{
    const uint8_t *p = ec_pubkey->mpi;
    uint8_t        p_len = ec_pubkey->len;

    if (curve_desc->rnp_curve_id == PGP_CURVE_25519) {
        if ((p_len != 33) || (p[0] != 0x40)) {
            return false;
        }
        p++;
        p_len--;
    }

    rnp::secure_array<uint8_t, MAX_CURVE_BYTELEN * 2 + 1> s;

    botan_pk_op_ka_t op_key_agreement = NULL;
    bool             ret = false;
    char             kdf_name[32] = {0};
    size_t           s_len = s.size();

    if (botan_pk_op_key_agreement_create(&op_key_agreement, ec_prvkey, "Raw", 0) ||
        botan_pk_op_key_agreement(op_key_agreement, s.data(), &s_len, p, p_len, NULL, 0)) {
        goto end;
    }

    snprintf(kdf_name, sizeof(kdf_name), "SP800-56A(%s)", pgp_hash_name_botan(hash_alg));
    ret = !botan_kdf(
      kdf_name, kek, kek_len, s.data(), s_len, NULL, 0, other_info, other_info_size);
end:
    return ret && !botan_pk_op_key_agreement_destroy(op_key_agreement);
}

bool
ecdh_set_params(pgp_ec_key_t *key, pgp_curve_t curve_id)
{
    for (size_t i = 0; i < ARRAY_SIZE(ecdh_params); i++) {
        if (ecdh_params[i].curve == curve_id) {
            key->kdf_hash_alg = ecdh_params[i].hash;
            key->key_wrap_alg = ecdh_params[i].wrap_alg;
            return true;
        }
    }

    return false;
}

static bool
ecdh_load_public_key(botan_pubkey_t *pubkey, const pgp_ec_key_t *key)
{
    bool res = false;

    const ec_curve_desc_t *curve = get_curve_desc(key->curve);
    if (!curve) {
        RNP_LOG("unknown curve");
        return false;
    }

    if (curve->rnp_curve_id == PGP_CURVE_25519) {
        if ((key->p.len != 33) || (key->p.mpi[0] != 0x40)) {
            return false;
        }
        rnp::secure_array<uint8_t, 32> pkey;
        memcpy(pkey.data(), key->p.mpi + 1, 32);
        return !botan_pubkey_load_x25519(pubkey, pkey.data());
    }

    if (!mpi_bytes(&key->p) || (key->p.mpi[0] != 0x04)) {
        RNP_LOG("Failed to load public key");
        return false;
    }

    botan_mp_t   px = NULL;
    botan_mp_t   py = NULL;
    const size_t curve_order = BITS_TO_BYTES(curve->bitlen);

    if (botan_mp_init(&px) || botan_mp_init(&py) ||
        botan_mp_from_bin(px, &key->p.mpi[1], curve_order) ||
        botan_mp_from_bin(py, &key->p.mpi[1 + curve_order], curve_order)) {
        goto end;
    }

    if (!(res = !botan_pubkey_load_ecdh(pubkey, px, py, curve->botan_name))) {
        RNP_LOG("failed to load ecdh public key");
    }
end:
    botan_mp_destroy(px);
    botan_mp_destroy(py);
    return res;
}

static bool
ecdh_load_secret_key(botan_privkey_t *seckey, const pgp_ec_key_t *key)
{
    const ec_curve_desc_t *curve = get_curve_desc(key->curve);

    if (!curve) {
        return false;
    }

    if (curve->rnp_curve_id == PGP_CURVE_25519) {
        if (key->x.len != 32) {
            RNP_LOG("wrong x25519 key");
            return false;
        }
        /* need to reverse byte order since in mpi we have big-endian */
        rnp::secure_array<uint8_t, 32> prkey;
        for (int i = 0; i < 32; i++) {
            prkey[i] = key->x.mpi[31 - i];
        }
        return !botan_privkey_load_x25519(seckey, prkey.data());
    }

    bignum_t *x = NULL;
    if (!(x = mpi2bn(&key->x))) {
        return false;
    }
    bool res = !botan_privkey_load_ecdh(seckey, BN_HANDLE_PTR(x), curve->botan_name);
    bn_free(x);
    return res;
}

rnp_result_t
ecdh_validate_key(rng_t *rng, const pgp_ec_key_t *key, bool secret)
{
    botan_pubkey_t  bpkey = NULL;
    botan_privkey_t bskey = NULL;
    rnp_result_t    ret = RNP_ERROR_BAD_PARAMETERS;

    const ec_curve_desc_t *curve_desc = get_curve_desc(key->curve);
    if (!curve_desc) {
        return RNP_ERROR_NOT_SUPPORTED;
    }

    if (!ecdh_load_public_key(&bpkey, key) ||
        botan_pubkey_check_key(bpkey, rng_handle(rng), 0)) {
        goto done;
    }
    if (!secret) {
        ret = RNP_SUCCESS;
        goto done;
    }

    if (!ecdh_load_secret_key(&bskey, key) ||
        botan_privkey_check_key(bskey, rng_handle(rng), 0)) {
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    botan_privkey_destroy(bskey);
    botan_pubkey_destroy(bpkey);
    return ret;
}

rnp_result_t
ecdh_encrypt_pkcs5(rng_t *                  rng,
                   pgp_ecdh_encrypted_t *   out,
                   const uint8_t *const     in,
                   size_t                   in_len,
                   const pgp_ec_key_t *     key,
                   const pgp_fingerprint_t &fingerprint)
{
    botan_privkey_t eph_prv_key = NULL;
    rnp_result_t    ret = RNP_ERROR_GENERIC;
    uint8_t         other_info[MAX_SP800_56A_OTHER_INFO];
    uint8_t         kek[32] = {0}; // Size of SHA-256 or smaller
    // 'm' is padded to the 8-byte granularity
    uint8_t      m[MAX_SESSION_KEY_SIZE];
    const size_t m_padded_len = ((in_len / 8) + 1) * 8;

    if (!key || !out || !in || (in_len > sizeof(m))) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const ec_curve_desc_t *curve_desc = get_curve_desc(key->curve);
    if (!curve_desc) {
        RNP_LOG("unsupported curve");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    // +8 because of AES-wrap adds 8 bytes
    if (ECDH_WRAPPED_KEY_SIZE < (m_padded_len + 8)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // See 13.5 of RFC 4880 for definition of other_info_size
    const size_t other_info_size = curve_desc->OIDhex_len + 46;
    const size_t kek_len = pgp_key_size(key->key_wrap_alg);
    size_t       tmp_len = kdf_other_info_serialize(
      other_info, curve_desc, fingerprint, key->kdf_hash_alg, key->key_wrap_alg);

    if (tmp_len != other_info_size) {
        RNP_LOG("Serialization of other info failed");
        return RNP_ERROR_GENERIC;
    }

    if (!strcmp(curve_desc->botan_name, "curve25519")) {
        if (botan_privkey_create(&eph_prv_key, "Curve25519", "", rng_handle(rng))) {
            goto end;
        }
    } else {
        if (botan_privkey_create(
              &eph_prv_key, "ECDH", curve_desc->botan_name, rng_handle(rng))) {
            goto end;
        }
    }

    if (!compute_kek(kek,
                     kek_len,
                     other_info,
                     other_info_size,
                     curve_desc,
                     &key->p,
                     eph_prv_key,
                     key->kdf_hash_alg)) {
        RNP_LOG("KEK computation failed");
        goto end;
    }

    memcpy(m, in, in_len);
    if (!pad_pkcs7(m, m_padded_len, in_len)) {
        // Should never happen
        goto end;
    }

    out->mlen = sizeof(out->m);
    if (botan_key_wrap3394(m, m_padded_len, kek, kek_len, out->m, &out->mlen)) {
        goto end;
    }

    /* we need to prepend 0x40 for the x25519 */
    if (key->curve == PGP_CURVE_25519) {
        out->p.len = sizeof(out->p.mpi) - 1;
        if (botan_pk_op_key_agreement_export_public(
              eph_prv_key, out->p.mpi + 1, &out->p.len)) {
            goto end;
        }
        out->p.mpi[0] = 0x40;
        out->p.len++;
    } else {
        out->p.len = sizeof(out->p.mpi);
        if (botan_pk_op_key_agreement_export_public(eph_prv_key, out->p.mpi, &out->p.len)) {
            goto end;
        }
    }

    // All OK
    ret = RNP_SUCCESS;
end:
    botan_privkey_destroy(eph_prv_key);
    return ret;
}

rnp_result_t
ecdh_decrypt_pkcs5(uint8_t *                   out,
                   size_t *                    out_len,
                   const pgp_ecdh_encrypted_t *in,
                   const pgp_ec_key_t *        key,
                   const pgp_fingerprint_t &   fingerprint)
{
    if (!out_len || !in || !key || !mpi_bytes(&key->x)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const ec_curve_desc_t *curve_desc = get_curve_desc(key->curve);
    if (!curve_desc) {
        RNP_LOG("unknown curve");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    const pgp_symm_alg_t wrap_alg = key->key_wrap_alg;
    const pgp_hash_alg_t kdf_hash = key->kdf_hash_alg;
    /* Ensure that AES is used for wrapping */
    if ((wrap_alg != PGP_SA_AES_128) && (wrap_alg != PGP_SA_AES_192) &&
        (wrap_alg != PGP_SA_AES_256)) {
        RNP_LOG("non-aes wrap algorithm");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    // See 13.5 of RFC 4880 for definition of other_info_size
    uint8_t      other_info[MAX_SP800_56A_OTHER_INFO];
    const size_t other_info_size = curve_desc->OIDhex_len + 46;
    const size_t tmp_len =
      kdf_other_info_serialize(other_info, curve_desc, fingerprint, kdf_hash, wrap_alg);

    if (other_info_size != tmp_len) {
        RNP_LOG("Serialization of other info failed");
        return RNP_ERROR_GENERIC;
    }

    botan_privkey_t prv_key = NULL;
    if (!ecdh_load_secret_key(&prv_key, key)) {
        RNP_LOG("failed to load ecdh secret key");
        return RNP_ERROR_GENERIC;
    }

    // Size of SHA-256 or smaller
    rnp::secure_array<uint8_t, MAX_SYMM_KEY_SIZE>    kek;
    rnp::secure_array<uint8_t, MAX_SESSION_KEY_SIZE> deckey;

    size_t       deckey_len = deckey.size();
    size_t       offset = 0;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    /* Security: Always return same error code in case compute_kek,
     *           botan_key_unwrap3394 or unpad_pkcs7 fails
     */
    size_t kek_len = pgp_key_size(wrap_alg);
    if (!compute_kek(kek.data(),
                     kek_len,
                     other_info,
                     other_info_size,
                     curve_desc,
                     &in->p,
                     prv_key,
                     kdf_hash)) {
        goto end;
    }

    if (botan_key_unwrap3394(
          in->m, in->mlen, kek.data(), kek_len, deckey.data(), &deckey_len)) {
        goto end;
    }

    if (!unpad_pkcs7(deckey.data(), deckey_len, &offset)) {
        goto end;
    }

    if (*out_len < offset) {
        ret = RNP_ERROR_SHORT_BUFFER;
        goto end;
    }

    *out_len = offset;
    memcpy(out, deckey.data(), *out_len);
    ret = RNP_SUCCESS;
end:
    botan_privkey_destroy(prv_key);
    return ret;
}
