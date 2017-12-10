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
#include "crypto/bn.h"
#include "crypto/dsa.h"
#include <botan/ffi.h>

static DSA_SIG *
DSA_SIG_new()
{
    DSA_SIG *sig = calloc(1, sizeof(DSA_SIG));
    if (sig) {
        sig->r = BN_new();
        sig->s = BN_new();
    }
    return sig;
}

void
DSA_SIG_free(DSA_SIG *sig)
{
    if (sig) {
        BN_clear_free(sig->r);
        BN_clear_free(sig->s);
        free(sig);
    }
}

unsigned
pgp_dsa_verify(const uint8_t *         hash,
               size_t                  hash_length,
               const pgp_dsa_sig_t *   sig,
               const pgp_dsa_pubkey_t *dsa)
{
    botan_pubkey_t       dsa_key;
    botan_pk_op_verify_t verify_op;
    uint8_t *            encoded_signature = NULL;
    size_t               q_bytes = 0;
    unsigned int         valid;

    botan_pubkey_load_dsa(&dsa_key, dsa->p->mp, dsa->q->mp, dsa->g->mp, dsa->y->mp);

    botan_mp_num_bytes(dsa->q->mp, &q_bytes);

    encoded_signature = calloc(2, q_bytes);
    BN_bn2bin(sig->r, encoded_signature);
    BN_bn2bin(sig->s, encoded_signature + q_bytes);

    botan_pk_op_verify_create(&verify_op, dsa_key, "Raw", 0);
    botan_pk_op_verify_update(verify_op, hash, hash_length);
    valid = (botan_pk_op_verify_finish(verify_op, encoded_signature, 2 * q_bytes) == 0);
    botan_pk_op_verify_destroy(verify_op);
    botan_pubkey_destroy(dsa_key);

    free(encoded_signature);

    return valid;
}

DSA_SIG *
pgp_dsa_sign(rng_t *                 rng,
             uint8_t *               hashbuf,
             unsigned                hashsize,
             const pgp_dsa_seckey_t *secdsa,
             const pgp_dsa_pubkey_t *pubdsa)
{
    botan_privkey_t    dsa_key;
    botan_pk_op_sign_t sign_op;
    size_t             q_bytes = 0;
    size_t             sigbuf_size = 0;
    uint8_t *          sigbuf = NULL;
    DSA_SIG *          ret;

    botan_privkey_load_dsa(
      &dsa_key, pubdsa->p->mp, pubdsa->q->mp, pubdsa->g->mp, secdsa->x->mp);

    botan_pk_op_sign_create(&sign_op, dsa_key, "Raw", 0);
    botan_pk_op_sign_update(sign_op, hashbuf, hashsize);

    botan_mp_num_bytes(pubdsa->q->mp, &q_bytes);
    sigbuf_size = q_bytes * 2;
    sigbuf = calloc(sigbuf_size, 1);

    botan_pk_op_sign_finish(sign_op, rng_handle(rng), sigbuf, &sigbuf_size);
    botan_pk_op_sign_destroy(sign_op);
    botan_privkey_destroy(dsa_key);

    // Now load the DSA (r,s) values from the signature
    ret = DSA_SIG_new();

    botan_mp_from_bin(ret->r->mp, sigbuf, q_bytes);
    botan_mp_from_bin(ret->s->mp, sigbuf + q_bytes, q_bytes);

    return ret;
}
