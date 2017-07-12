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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
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

#include "hash.h"
#include "types.h"
#include "rnpdefs.h"
#include "rnpsdk.h"
#include <botan/ffi.h>
#include <stdio.h>

static pgp_map_t hash_alg_map[] = {
  {PGP_HASH_MD5, "MD5"},
  {PGP_HASH_SHA1, "SHA1"},
  {PGP_HASH_RIPEMD, "RIPEMD160"},
  {PGP_HASH_SHA256, "SHA256"},
  {PGP_HASH_SHA384, "SHA384"},
  {PGP_HASH_SHA512, "SHA512"},
  {PGP_HASH_SHA224, "SHA224"},
  {PGP_HASH_SM3, "SM3"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

/**
 * \ingroup Core_Print
 *
 * returns description of the Hash Algorithm type
 * \param hash Hash Algorithm type
 * \return string or "Unknown"
 */
const char *
pgp_show_hash_alg(uint8_t hash)
{
    return pgp_str_from_map(hash, hash_alg_map);
}

/**
\ingroup Core_Hashes
\brief Returns hash enum corresponding to given string
\param hash Text name of hash algorithm i.e. "SHA1"
\returns Corresponding enum i.e. PGP_HASH_SHA1
*/
pgp_hash_alg_t
pgp_str_to_hash_alg(const char *hash)
{
    if (hash == NULL) {
        return PGP_DEFAULT_HASH_ALGORITHM;
    }
    for (int i = 0; hash_alg_map[i].string != NULL; ++i) {
        if (rnp_strcasecmp(hash, hash_alg_map[i].string) == 0) {
            return hash_alg_map[i].type;
        }
    }
    return PGP_HASH_UNKNOWN;
}

const char *
pgp_hash_name_botan(pgp_hash_alg_t hash)
{
    switch (hash) {
#if defined(BOTAN_HAS_MD5)
    case PGP_HASH_MD5:
        return "MD5";
#endif

#if defined(BOTAN_HAS_SHA1)
    case PGP_HASH_SHA1:
        return "SHA-1";
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
    case PGP_HASH_RIPEMD:
        return "RIPEMD-160";
#endif

#if defined(BOTAN_HAS_SHA2_32)
    case PGP_HASH_SHA224:
        return "SHA-224";
    case PGP_HASH_SHA256:
        return "SHA-256";
#endif

#if defined(BOTAN_HAS_SHA2_64)
    case PGP_HASH_SHA384:
        return "SHA-384";
    case PGP_HASH_SHA512:
        return "SHA-512";
#endif

#if defined(BOTAN_HAS_SM3)
    case PGP_HASH_SM3:
        return "SM3";
#endif

    default:
        return NULL;
    }
}

/**
\ingroup Core_Hashes
\brief Setup hash for given hash algorithm
\param hash Hash to set up
\param alg Hash algorithm to use
*/
int
pgp_hash_create(pgp_hash_t *hash, pgp_hash_alg_t alg)
{
    const char * hash_name = pgp_hash_name_botan(alg);
    botan_hash_t impl;
    size_t       outlen;
    int          rc;

    if (hash_name == NULL) {
        return RNP_FAIL;
    }

    rc = botan_hash_init(&impl, hash_name, 0);
    if (rc != 0) {
        (void) fprintf(stderr, "Error creating hash object for '%s'", hash_name);
        return RNP_FAIL;
    }

    rc = botan_hash_output_length(impl, &outlen);
    if (rc != 0) {
        botan_hash_destroy(hash->handle);
        (void) fprintf(stderr, "In pgp_hash_create, botan_hash_output_length failed");
        return RNP_FAIL;
    }

    hash->_output_len = outlen;
    hash->_alg = alg;
    hash->handle = impl;
    return RNP_OK;
}

void
pgp_hash_add(pgp_hash_t *hash, const uint8_t *data, size_t length)
{
    botan_hash_update(hash->handle, data, length);
}

/**
\ingroup Core_Hashes
\brief Add to the hash
\param hash Hash to add to
\param n Int to add
\param length Length of int in bytes
*/
void
pgp_hash_add_int(pgp_hash_t *hash, unsigned n, size_t length)
{
    uint8_t c;

    while (length--) {
        c = n >> (length * 8);
        pgp_hash_add(hash, &c, 1);
    }
}

size_t
pgp_hash_finish(pgp_hash_t *hash, uint8_t *out)
{
    size_t outlen = hash->_output_len;
    int    rc = botan_hash_final(hash->handle, out);
    if (rc != 0) {
        (void) fprintf(stderr, "digest_finish botan_hash_final failed");
        return 0;
    }
    botan_hash_destroy(hash->handle);
    hash->handle = NULL;
    hash->_output_len = 0;
    return outlen;
}

/**
   \ingroup Core_Hashes
   \brief Get Hash name
   \param hash Hash struct
   \return Hash name
*/
const char *
pgp_hash_name(const pgp_hash_t *hash)
{
    return pgp_show_hash_alg(hash->_alg);
}

size_t
pgp_hash_output_length(const pgp_hash_t *hash)
{
    return hash->_output_len;
}

pgp_hash_alg_t
pgp_hash_alg_type(const pgp_hash_t *hash)
{
    return hash->_alg;
}

/**
\ingroup HighLevel_Supported
\brief Is this Hash Algorithm supported?
\param hash_alg Hash Algorithm to check
\return 1 if supported; else 0
*/
unsigned
pgp_is_hash_alg_supported(const pgp_hash_alg_t *hash_alg)
{
    return pgp_hash_name_botan(*hash_alg) != NULL;
}

bool
pgp_hash_digest_length(pgp_hash_alg_t alg, size_t *output_length)
{
    bool ret = true;

    botan_hash_t handle = NULL;
    if (botan_hash_init(&handle, pgp_hash_name_botan(alg), 0) ||
        botan_hash_output_length(handle, output_length)) {
        ret = false;
    }

    botan_hash_destroy(handle);
    return ret;
}