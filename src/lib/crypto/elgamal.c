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

#include <stdlib.h>
#include <string.h>
#include <botan/ffi.h>

#include "utils.h"

#include "crypto/elgamal.h"
#include "crypto/bn.h"

int
pgp_elgamal_public_encrypt_pkcs1(rng_t *                     rng,
                                 uint8_t *                   g2k,
                                 uint8_t *                   encm,
                                 const uint8_t *             in,
                                 size_t                      length,
                                 const pgp_elgamal_pubkey_t *pubkey)
{
    botan_pubkey_t        key = NULL;
    botan_pk_op_encrypt_t op_ctx = NULL;
    int                   ret = -1;
    size_t                p_len = 0;
    uint8_t *             bt_ciphertext = NULL;

    if (botan_mp_num_bytes(pubkey->p->mp, &p_len)) {
        RNP_LOG("Wrong public key");
    }

    // Initialize RNG and encrypt
    if (botan_pubkey_load_elgamal(&key, pubkey->p->mp, pubkey->g->mp, pubkey->y->mp)) {
        RNP_LOG("Failed to load public key");
        goto end;
    }

    if (botan_pubkey_check_key(key, rng_handle(rng), 1)) {
        RNP_LOG("Wrong public key");
        goto end;
    }

    /* Max size of an output len is twice an order of underlying group (twice byte-size of p)
     * Allocate all buffers needed for encryption and post encryption processing */
    size_t out_len = p_len * 2;
    bt_ciphertext = calloc(out_len, 1);
    if (!bt_ciphertext) {
        RNP_LOG("Memory allocation failure");
        goto end;
    }

    if (botan_pk_op_encrypt_create(&op_ctx, key, "PKCS1v15", 0)) {
        RNP_LOG("Failed to create operation context");
        goto end;
    }

    if (botan_pk_op_encrypt(op_ctx, rng_handle(rng), bt_ciphertext, &out_len, in, length)) {
        RNP_LOG("Encryption fails");
        goto end;
    }

    /*
     * Botan's ElGamal formats the g^k and msg*(y^k) together into a single byte string.
     * We have to parse out the two values after encryption, as rnp stores those values
     * separatelly.
     */
    memcpy(g2k, bt_ciphertext, p_len);
    memcpy(encm, bt_ciphertext + p_len, p_len);

    // All operations OK and `out_len' correctly set. Reset ret
    ret = 0;

end:
    ret |= botan_pk_op_encrypt_destroy(op_ctx);
    ret |= botan_pubkey_destroy(key);
    free(bt_ciphertext);

    if (ret) {
        // Some error has occured
        return -1;
    }

    return out_len;
}

int
pgp_elgamal_private_decrypt_pkcs1(rng_t *                     rng,
                                  uint8_t *                   out,
                                  const uint8_t *             g2k,
                                  const uint8_t *             in,
                                  size_t                      length,
                                  const pgp_elgamal_seckey_t *seckey,
                                  const pgp_elgamal_pubkey_t *pubkey)
{
    botan_privkey_t       key = NULL;
    botan_pk_op_decrypt_t op_ctx = NULL;
    int                   ret = -1;
    size_t                out_len = 0;
    size_t                p_len = 0;
    uint8_t *             bt_plaintext = NULL;

    // Output len is twice an order of underlying group
    if (botan_mp_num_bytes(pubkey->p->mp, &p_len)) {
        RNP_LOG("Wrong public key");
        goto end;
    }

    if (length != p_len) {
        RNP_LOG("Wrong size of modulus in public key");
        goto end;
    }

    /* Max size of an output len is twice an order of underlying group (twice byte-size of p)
     * Allocate all buffers needed for encryption and post encryption processing */
    out_len = p_len * 2;

    bt_plaintext = calloc(out_len, 1);
    if (!bt_plaintext) {
        RNP_LOG("Memory allocation failure");
        goto end;
    }

    if (botan_privkey_load_elgamal(&key, pubkey->p->mp, pubkey->g->mp, seckey->x->mp)) {
        RNP_LOG("Failed to load private key");
        goto end;
    }

    if (botan_privkey_check_key(key, rng_handle(rng), 1)) {
        RNP_LOG("Wrong private key");
        goto end;
    }

    memcpy(bt_plaintext, g2k, p_len);
    memcpy(bt_plaintext + p_len, in, p_len);

    if (botan_pk_op_decrypt_create(&op_ctx, key, "PKCS1v15", 0)) {
        RNP_LOG("Failed to create operation context");
        goto end;
    }

    if (botan_pk_op_decrypt(op_ctx, out, &out_len, bt_plaintext, p_len * 2)) {
        RNP_LOG("Decryption failed");
        goto end;
    }

    // All operations OK and `out_len' correctly set. Reset ret
    ret = 0;

end:
    if (op_ctx != NULL) {
        ret |= botan_pk_op_decrypt_destroy(op_ctx);
    }
    if (key != NULL) {
        ret |= botan_privkey_destroy(key);
    }
    if (bt_plaintext != NULL) {
        free(bt_plaintext);
    }

    if (ret) {
        // Some error has occured
        return -1;
    }

    return (int) out_len;
}
