/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
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

#ifndef RNP_DSA_H_
#define RNP_DSA_H_

#include <stdint.h>
#include "crypto/bn.h"

/* TODO key generation */

/** Structure to hold one DSA public key params.
 *
 * \see RFC4880 5.5.2
 */
typedef struct {
    BIGNUM *p; /* DSA prime p */
    BIGNUM *q; /* DSA group order q */
    BIGNUM *g; /* DSA group generator g */
    BIGNUM *y; /* DSA public key value y (= g^x mod p
                * with x being the secret) */
} pgp_dsa_pubkey_t;

/** pgp_dsa_seckey_t */
typedef struct pgp_dsa_seckey_t {
    BIGNUM *x;
} pgp_dsa_seckey_t;

/** Struct to hold params of a DSA signature */
typedef struct pgp_dsa_sig_t {
    BIGNUM *r; /* DSA value r */
    BIGNUM *s; /* DSA value s */
} pgp_dsa_sig_t;

/*
* This type is used to represent any signature where
* a pair of MPIs is used (DSA, ECDSA, EdDSA, ...)
*/
typedef struct DSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
} DSA_SIG;

/* DSA signature/verify */
typedef struct DSA_SIG_st DSA_SIG;

int pgp_dsa_size(const pgp_dsa_pubkey_t *);

DSA_SIG *pgp_dsa_sign(uint8_t *, unsigned, const pgp_dsa_seckey_t *, const pgp_dsa_pubkey_t *);

unsigned pgp_dsa_verify(const uint8_t *,
                        size_t,
                        const pgp_dsa_sig_t *,
                        const pgp_dsa_pubkey_t *);

void DSA_SIG_free(DSA_SIG *sig);
#endif
