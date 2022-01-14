/*
 * Copyright (c) 2021, [Ribose Inc](https://www.ribose.com).
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
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef ECDH_UTILS_H_
#define ECDH_UTILS_H_

#include "ecdh.h"

#define MAX_SP800_56A_OTHER_INFO 56
// Keys up to 312 bits (+1 bytes of PKCS5 padding)
#define MAX_SESSION_KEY_SIZE 40
#define MAX_AES_KEY_SIZE 32

size_t kdf_other_info_serialize(uint8_t                  other_info[MAX_SP800_56A_OTHER_INFO],
                                const ec_curve_desc_t *  ec_curve,
                                const pgp_fingerprint_t &fingerprint,
                                const pgp_hash_alg_t     kdf_hash,
                                const pgp_symm_alg_t     wrap_alg);

bool pad_pkcs7(uint8_t *buf, size_t buf_len, size_t offset);

bool unpad_pkcs7(uint8_t *buf, size_t buf_len, size_t *offset);

#endif // ECDH_UTILS_H_
