/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#include <stdio.h>
#include <botan/ffi.h>

#include "crypto/s2k.h"

bool
pgp_s2k_derive_key(pgp_s2k_t *s2k, const char *passphrase, uint8_t *key, int keysize)
{
    uint8_t *saltptr = NULL;
    unsigned iterations = 1;

    switch (s2k->specifier) {
    case PGP_S2KS_SIMPLE:
        break;
    case PGP_S2KS_SALTED:
        saltptr = s2k->salt;
        break;
    case PGP_S2KS_ITERATED_AND_SALTED:
        saltptr = s2k->salt;
        iterations = pgp_s2k_decode_iterations(s2k->iterations);
        break;
    default:
        return false;
    }

    if (pgp_s2k_iterated(s2k->hash_alg, key, keysize, passphrase, saltptr, iterations)) {
        (void) fprintf(stderr, "s2k_derive_key: s2k failed\n");
        return false;
    }

    return true;
}

int
pgp_s2k_simple(pgp_hash_alg_t alg, uint8_t *out, size_t output_len, const char *passphrase)
{
    return pgp_s2k_salted(alg, out, output_len, passphrase, NULL);
}

int
pgp_s2k_salted(pgp_hash_alg_t alg,
               uint8_t *      out,
               size_t         output_len,
               const char *   passphrase,
               const uint8_t *salt)
{
    return pgp_s2k_iterated(alg, out, output_len, passphrase, salt, 1);
}

int
pgp_s2k_iterated(pgp_hash_alg_t alg,
                 uint8_t *      out,
                 size_t         output_len,
                 const char *   passphrase,
                 const uint8_t *salt,
                 size_t         iterations)
{
    char s2k_algo_str[128];
    snprintf(s2k_algo_str, sizeof(s2k_algo_str), "OpenPGP-S2K(%s)", pgp_hash_name_botan(alg));

    return botan_pbkdf(s2k_algo_str,
                       out,
                       output_len,
                       passphrase,
                       salt,
                       salt == NULL ? 0 : PGP_SALT_SIZE,
                       iterations);
}

size_t
pgp_s2k_decode_iterations(uint8_t c)
{
    // See RFC 4880 section 3.7.1.3
    return (16 + (c & 0x0F)) << ((c >> 4) + 6);
}

size_t
pgp_s2k_round_iterations(size_t iterations)
{
    return pgp_s2k_decode_iterations(pgp_s2k_encode_iterations(iterations));
}

uint8_t
pgp_s2k_encode_iterations(size_t iterations)
{
    /* For compatibility, when an S2K specifier is used, the special value
     * 254 or 255 is stored in the position where the hash algorithm octet
     * would have been in the old data structure. This is then followed
     * immediately by a one-octet algorithm identifier, and then by the S2K
     * specifier as encoded above.
     * 0:           secret data is unencrypted (no passphrase)
     * 255 or 254:  followed by algorithm octet and S2K specifier
     * Cipher alg:  use Simple S2K algorithm using MD5 hash
     * For more info refer to rfc 4880 section 3.7.2.1.
     */
    for (uint16_t c = 0; c < 256; ++c) {
        if (pgp_s2k_decode_iterations(c) >= iterations) {
            return c;
        }
    }
    return 255;
}
