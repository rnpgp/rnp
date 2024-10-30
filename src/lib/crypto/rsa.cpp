/*-
 * Copyright (c) 2017-2024 Ribose Inc.
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

#include <string>
#include <cstring>
#include <botan/ffi.h>
#include "hash_botan.hpp"
#include "crypto/rsa.h"
#include "config.h"
#include "utils.h"
#include "bn.h"

namespace pgp {
namespace rsa {

rnp_result_t
Key::validate(rnp::RNG &rng, bool secret) const noexcept
{
    bignum_t *      bn = NULL;
    bignum_t *      be = NULL;
    bignum_t *      bp = NULL;
    bignum_t *      bq = NULL;
    botan_pubkey_t  bpkey = NULL;
    botan_privkey_t bskey = NULL;
    rnp_result_t    ret = RNP_ERROR_GENERIC;

    /* load and check public key part */
    if (!(bn = mpi2bn(n)) || !(be = mpi2bn(e))) {
        RNP_LOG("out of memory");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    if (botan_pubkey_load_rsa(&bpkey, bn->mp, BN_HANDLE_PTR(be)) != 0) {
        goto done;
    }

    if (botan_pubkey_check_key(bpkey, rng.handle(), 0)) {
        goto done;
    }

    if (!secret) {
        ret = RNP_SUCCESS;
        goto done;
    }

    /* load and check secret key part */
    if (!(bp = mpi2bn(p)) || !(bq = mpi2bn(q))) {
        RNP_LOG("out of memory");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    /* p and q are reversed from normal usage in PGP */
    if (botan_privkey_load_rsa(
          &bskey, BN_HANDLE_PTR(bq), BN_HANDLE_PTR(bp), BN_HANDLE_PTR(be))) {
        goto done;
    }

    if (botan_privkey_check_key(bskey, rng.handle(), 0)) {
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    botan_pubkey_destroy(bpkey);
    botan_privkey_destroy(bskey);
    bn_free(bn);
    bn_free(be);
    bn_free(bp);
    bn_free(bq);
    return ret;
}

static bool
load_public_key(botan_pubkey_t *bkey, const Key &key)
{
    bignum_t *n = NULL;
    bignum_t *e = NULL;
    bool      res = false;

    *bkey = NULL;
    n = mpi2bn(key.n);
    e = mpi2bn(key.e);

    if (!n || !e) {
        RNP_LOG("out of memory");
        goto done;
    }

    res = !botan_pubkey_load_rsa(bkey, BN_HANDLE_PTR(n), BN_HANDLE_PTR(e));
done:
    bn_free(n);
    bn_free(e);
    return res;
}

static bool
load_secret_key(botan_privkey_t *bkey, const Key &key)
{
    bignum_t *p = NULL;
    bignum_t *q = NULL;
    bignum_t *e = NULL;
    bool      res = false;

    *bkey = NULL;
    p = mpi2bn(key.p);
    q = mpi2bn(key.q);
    e = mpi2bn(key.e);

    if (!p || !q || !e) {
        RNP_LOG("out of memory");
        goto done;
    }

    /* p and q are reversed from normal usage in PGP */
    res = !botan_privkey_load_rsa(bkey, BN_HANDLE_PTR(q), BN_HANDLE_PTR(p), BN_HANDLE_PTR(e));
done:
    bn_free(p);
    bn_free(q);
    bn_free(e);
    return res;
}

rnp_result_t
Key::encrypt_pkcs1(rnp::RNG &     rng,
                   Encrypted &    out,
                   const uint8_t *in,
                   size_t         in_len) const noexcept
{
    rnp_result_t          ret = RNP_ERROR_GENERIC;
    botan_pubkey_t        rsa_key = NULL;
    botan_pk_op_encrypt_t enc_op = NULL;

    if (!load_public_key(&rsa_key, *this)) {
        RNP_LOG("failed to load key");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (botan_pk_op_encrypt_create(&enc_op, rsa_key, "PKCS1v15", 0) != 0) {
        goto done;
    }

    out.m.len = PGP_MPINT_SIZE;
    if (botan_pk_op_encrypt(enc_op, rng.handle(), out.m.mpi, &out.m.len, in, in_len)) {
        out.m.len = 0;
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    botan_pk_op_encrypt_destroy(enc_op);
    botan_pubkey_destroy(rsa_key);
    return ret;
}

rnp_result_t
Key::verify_pkcs1(const Signature &sig,
                  pgp_hash_alg_t   hash_alg,
                  const uint8_t *  hash,
                  size_t           hash_len) const noexcept
{
    char                 padding_name[64] = {0};
    botan_pubkey_t       rsa_key = NULL;
    botan_pk_op_verify_t verify_op = NULL;
    rnp_result_t         ret = RNP_ERROR_SIGNATURE_INVALID;

    if (!load_public_key(&rsa_key, *this)) {
        RNP_LOG("failed to load key");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    snprintf(padding_name,
             sizeof(padding_name),
             "EMSA-PKCS1-v1_5(Raw,%s)",
             rnp::Hash_Botan::name_backend(hash_alg));

    if (botan_pk_op_verify_create(&verify_op, rsa_key, padding_name, 0) != 0) {
        goto done;
    }

    if (botan_pk_op_verify_update(verify_op, hash, hash_len) != 0) {
        goto done;
    }

    if (botan_pk_op_verify_finish(verify_op, sig.s.mpi, sig.s.len) != 0) {
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    botan_pk_op_verify_destroy(verify_op);
    botan_pubkey_destroy(rsa_key);
    return ret;
}

rnp_result_t
Key::sign_pkcs1(rnp::RNG &     rng,
                Signature &    sig,
                pgp_hash_alg_t hash_alg,
                const uint8_t *hash,
                size_t         hash_len) const noexcept
{
    if (!q.bytes()) {
        RNP_LOG("private key not set");
        return RNP_ERROR_GENERIC;
    }

    botan_privkey_t rsa_key;
    if (!load_secret_key(&rsa_key, *this)) {
        RNP_LOG("failed to load key");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    char padding_name[64] = {0};
    snprintf(padding_name,
             sizeof(padding_name),
             "EMSA-PKCS1-v1_5(Raw,%s)",
             rnp::Hash_Botan::name_backend(hash_alg));

    rnp_result_t       ret = RNP_ERROR_GENERIC;
    botan_pk_op_sign_t sign_op;
    if (botan_pk_op_sign_create(&sign_op, rsa_key, padding_name, 0) != 0) {
        goto done;
    }

    if (botan_pk_op_sign_update(sign_op, hash, hash_len)) {
        goto done;
    }

    sig.s.len = PGP_MPINT_SIZE;
    if (botan_pk_op_sign_finish(sign_op, rng.handle(), sig.s.mpi, &sig.s.len)) {
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    botan_pk_op_sign_destroy(sign_op);
    botan_privkey_destroy(rsa_key);
    return ret;
}

rnp_result_t
Key::decrypt_pkcs1(rnp::RNG &       rng,
                   uint8_t *        out,
                   size_t &         out_len,
                   const Encrypted &in) const noexcept
{
    if (!q.bytes()) {
        RNP_LOG("private key not set");
        return RNP_ERROR_GENERIC;
    }

    botan_privkey_t rsa_key = NULL;
    if (!load_secret_key(&rsa_key, *this)) {
        RNP_LOG("failed to load key");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    size_t                skip = 0;
    botan_pk_op_decrypt_t decrypt_op = NULL;
    rnp_result_t          ret = RNP_ERROR_GENERIC;
    if (botan_pk_op_decrypt_create(&decrypt_op, rsa_key, "PKCS1v15", 0)) {
        goto done;
    }
    /* Skip trailing zeroes if any as Botan3 doesn't like m.len > e.len */
    while ((in.m.len - skip > e.len) && !in.m.mpi[skip]) {
        skip++;
    }
    out_len = PGP_MPINT_SIZE;
    if (botan_pk_op_decrypt(decrypt_op, out, &out_len, in.m.mpi + skip, in.m.len - skip)) {
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    botan_privkey_destroy(rsa_key);
    botan_pk_op_decrypt_destroy(decrypt_op);
    return ret;
}

rnp_result_t
Key::generate(rnp::RNG &rng, size_t numbits) noexcept
{
    if ((numbits < 1024) || (numbits > PGP_MPINT_BITS)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    botan_privkey_t rsa_key = NULL;
    rnp_result_t    ret = RNP_ERROR_GENERIC;
    int             cmp;
    bignum_t *      bn = bn_new();
    bignum_t *      be = bn_new();
    bignum_t *      bp = bn_new();
    bignum_t *      bq = bn_new();
    bignum_t *      bd = bn_new();
    bignum_t *      bu = bn_new();

    if (!bn || !be || !bp || !bq || !bd || !bu) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto end;
    }

    if (botan_privkey_create(&rsa_key, "RSA", std::to_string(numbits).c_str(), rng.handle())) {
        goto end;
    }

    if (botan_privkey_check_key(rsa_key, rng.handle(), 1) != 0) {
        goto end;
    }

    if (botan_privkey_get_field(BN_HANDLE_PTR(bn), rsa_key, "n") ||
        botan_privkey_get_field(BN_HANDLE_PTR(be), rsa_key, "e") ||
        botan_privkey_get_field(BN_HANDLE_PTR(bd), rsa_key, "d") ||
        botan_privkey_get_field(BN_HANDLE_PTR(bp), rsa_key, "p") ||
        botan_privkey_get_field(BN_HANDLE_PTR(bq), rsa_key, "q")) {
        goto end;
    }

    /* RFC 4880, 5.5.3 tells that p < q. GnuPG relies on this. */
    (void) botan_mp_cmp(&cmp, BN_HANDLE_PTR(bp), BN_HANDLE_PTR(bq));
    if (cmp > 0) {
        (void) botan_mp_swap(BN_HANDLE_PTR(bp), BN_HANDLE_PTR(bq));
    }

    if (botan_mp_mod_inverse(BN_HANDLE_PTR(bu), BN_HANDLE_PTR(bp), BN_HANDLE_PTR(bq)) != 0) {
        RNP_LOG("Error computing RSA u param");
        ret = RNP_ERROR_BAD_STATE;
        goto end;
    }

    bn2mpi(bn, n);
    bn2mpi(be, e);
    bn2mpi(bp, p);
    bn2mpi(bq, q);
    bn2mpi(bd, d);
    bn2mpi(bu, u);

    ret = RNP_SUCCESS;
end:
    botan_privkey_destroy(rsa_key);
    bn_free(bn);
    bn_free(be);
    bn_free(bp);
    bn_free(bq);
    bn_free(bd);
    bn_free(bu);
    return ret;
}

} // namespace rsa
} // namespace pgp
