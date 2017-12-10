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

/*-
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Alistair Crooks (agc@NetBSD.org)
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
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** \file
 */
#include <string.h>
#include <stdbool.h>
#include <rnp/rnp_def.h>

#include "config.h"
#include "types.h"
#include "utils.h"
#include "crypto/rsa.h"
#include <botan/ffi.h>

#include "hash.h"

/**
   \ingroup Core_Crypto
   \brief Decrypt PKCS1 formatted RSA ciphertext
   \param out Where to write decrypted data to
   \param in Encrypted data
   \param length Length of encrypted data
   \param pubkey RSA public key
   \return size of recovered plaintext
*/
int
pgp_rsa_encrypt_pkcs1(rng_t *                 rng,
                      uint8_t *               out,
                      size_t                  out_len,
                      const uint8_t *         in,
                      const size_t            in_len,
                      const pgp_rsa_pubkey_t *pubkey)
{
    int                   retval = -1;
    botan_pubkey_t        rsa_key = NULL;
    botan_pk_op_encrypt_t enc_op = NULL;

    if (botan_pubkey_load_rsa(&rsa_key, pubkey->n->mp, pubkey->e->mp) != 0) {
        goto done;
    }

    if (botan_pubkey_check_key(rsa_key, rng_handle(rng), 1) != 0) {
        goto done;
    }

    if (botan_pk_op_encrypt_create(&enc_op, rsa_key, "PKCS1v15", 0) != 0) {
        goto done;
    }

    if (botan_pk_op_encrypt(enc_op, rng_handle(rng), out, &out_len, in, in_len) == 0) {
        retval = (int) out_len;
    }

done:
    botan_pk_op_encrypt_destroy(enc_op);
    botan_pubkey_destroy(rsa_key);

    return retval;
}

bool
pgp_rsa_pkcs1_verify_hash(rng_t *                 rng,
                          const uint8_t *         sig_buf,
                          size_t                  sig_buf_size,
                          pgp_hash_alg_t          hash_alg,
                          const uint8_t *         hash,
                          size_t                  hash_len,
                          const pgp_rsa_pubkey_t *pubkey)
{
    char                 padding_name[64] = {0};
    botan_pubkey_t       rsa_key = NULL;
    botan_pk_op_verify_t verify_op = NULL;
    bool                 result = false;

    snprintf(padding_name,
             sizeof(padding_name),
             "EMSA-PKCS1-v1_5(Raw,%s)",
             pgp_hash_name_botan(hash_alg));

    botan_pubkey_load_rsa(&rsa_key, pubkey->n->mp, pubkey->e->mp);

    if (botan_pubkey_check_key(rsa_key, rng_handle(rng), 1) != 0) {
        goto done;
    }

    if (botan_pk_op_verify_create(&verify_op, rsa_key, padding_name, 0) != 0) {
        goto done;
    }

    if (botan_pk_op_verify_update(verify_op, hash, hash_len) != 0) {
        goto done;
    }

    result = (botan_pk_op_verify_finish(verify_op, sig_buf, sig_buf_size) == 0);

done:
    botan_pk_op_verify_destroy(verify_op);
    botan_pubkey_destroy(rsa_key);
    return result;
}

/**
   \ingroup Core_Crypto
   \brief Signs data with RSA
   \param out Where to write signature
   \param in Data to sign
   \param length Length of data
   \param seckey RSA secret key
   \param pubkey RSA public key
   \return number of bytes decrypted
*/
int
pgp_rsa_pkcs1_sign_hash(rng_t *                 rng,
                        uint8_t *               sig_buf,
                        size_t                  sig_buf_size,
                        pgp_hash_alg_t          hash_alg,
                        const uint8_t *         hash_buf,
                        size_t                  hash_len,
                        const pgp_rsa_seckey_t *seckey,
                        const pgp_rsa_pubkey_t *pubkey)
{
    char               padding_name[64] = {0};
    botan_privkey_t    rsa_key;
    botan_pk_op_sign_t sign_op;

    if (seckey->q == NULL) {
        (void) fprintf(stderr, "private key not set in pgp_rsa_private_encrypt\n");
        return 0;
    }

    snprintf(padding_name,
             sizeof(padding_name),
             "EMSA-PKCS1-v1_5(Raw,%s)",
             pgp_hash_name_botan(hash_alg));

    /* p and q are reversed from normal usage in PGP */
    botan_privkey_load_rsa(&rsa_key, seckey->q->mp, seckey->p->mp, pubkey->e->mp);

    if (botan_privkey_check_key(rsa_key, rng_handle(rng), 0) != 0) {
        botan_privkey_destroy(rsa_key);
        return 0;
    }

    if (botan_pk_op_sign_create(&sign_op, rsa_key, padding_name, 0) != 0) {
        botan_privkey_destroy(rsa_key);
        return 0;
    }

    if (botan_pk_op_sign_update(sign_op, hash_buf, hash_len) != 0 ||
        botan_pk_op_sign_finish(sign_op, rng_handle(rng), sig_buf, &sig_buf_size) != 0) {
        botan_pk_op_sign_destroy(sign_op);
        botan_privkey_destroy(rsa_key);
        return 0;
    }

    botan_pk_op_sign_destroy(sign_op);
    botan_privkey_destroy(rsa_key);

    return (int) sig_buf_size;
}

/**
\ingroup Core_Crypto
\brief Decrypts RSA-encrypted data
\param out Where to write the plaintext
\param in Encrypted data
\param length Length of encrypted data
\param seckey RSA secret key
\param pubkey RSA public key
\return size of recovered plaintext
*/
int
pgp_rsa_decrypt_pkcs1(rng_t *                 rng,
                      uint8_t *               out,
                      size_t                  out_len,
                      const uint8_t *         in,
                      size_t                  in_len,
                      const pgp_rsa_seckey_t *seckey,
                      const pgp_rsa_pubkey_t *pubkey)
{
    int                   retval = -1;
    botan_privkey_t       rsa_key = NULL;
    botan_pk_op_decrypt_t decrypt_op = NULL;

    if (botan_privkey_load_rsa(&rsa_key, seckey->q->mp, seckey->p->mp, pubkey->e->mp) != 0) {
        goto done;
    }

    if (botan_privkey_check_key(rsa_key, rng_handle(rng), 0) != 0) {
        goto done;
    }

    if (botan_pk_op_decrypt_create(&decrypt_op, rsa_key, "PKCS1v15", 0) != 0) {
        goto done;
    }

    if (botan_pk_op_decrypt(decrypt_op, out, &out_len, (uint8_t *) in, in_len) == 0) {
        retval = (int) out_len;
    }

done:
    botan_privkey_destroy(rsa_key);
    botan_pk_op_decrypt_destroy(decrypt_op);
    return retval;
}

int
pgp_genkey_rsa(rng_t *rng, pgp_seckey_t *seckey, size_t numbits)
{
    botan_privkey_t rsa_key = NULL;
    int             ret = 0, cmp;

    seckey->pubkey.key.rsa.n = bn_new();
    seckey->pubkey.key.rsa.e = bn_new();
    seckey->key.rsa.p = bn_new();
    seckey->key.rsa.q = bn_new();
    seckey->key.rsa.d = bn_new();
    seckey->key.rsa.u = bn_new();

    if (!seckey->pubkey.key.rsa.n || !seckey->pubkey.key.rsa.e || !seckey->key.rsa.p ||
        !seckey->key.rsa.q || !seckey->key.rsa.d || !seckey->key.rsa.u) {
        goto end;
    }

    if (botan_privkey_create_rsa(&rsa_key, rng_handle(rng), numbits) != 0)
        goto end;

    if (botan_privkey_check_key(rsa_key, rng_handle(rng), 1) != 0)
        goto end;

    /* Calls below never fail as calls above were OK */
    (void) botan_privkey_rsa_get_n(seckey->pubkey.key.rsa.n->mp, rsa_key);
    (void) botan_privkey_rsa_get_e(seckey->pubkey.key.rsa.e->mp, rsa_key);
    (void) botan_privkey_rsa_get_d(seckey->key.rsa.d->mp, rsa_key);
    (void) botan_privkey_rsa_get_p(seckey->key.rsa.p->mp, rsa_key);
    (void) botan_privkey_rsa_get_q(seckey->key.rsa.q->mp, rsa_key);

    /* RFC 4880, 5.5.3 tells that p < q. GnuPG relies on this. */
    (void) botan_mp_cmp(&cmp, seckey->key.rsa.p->mp, seckey->key.rsa.q->mp);
    if (cmp > 0) {
        (void) botan_mp_swap(seckey->key.rsa.p->mp, seckey->key.rsa.q->mp);
    }

    if (botan_mp_mod_inverse(
          seckey->key.rsa.u->mp, seckey->key.rsa.p->mp, seckey->key.rsa.q->mp) != 0) {
        RNP_LOG("Error computing RSA u param");
        goto end;
    }

    ret = 1;

end:
    botan_privkey_destroy(rsa_key);
    return ret;
}
