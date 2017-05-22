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

/** \file
 */

#include "crypto.h"
#include "rnpdefs.h"

static int
digest_init(pgp_hash_t *hash, const char *name)
{
	if (hash->data) {
		(void) fprintf(stderr, "digest_init: %s hash data non-null\n", name);
	}
        botan_hash_t impl;
        int rc = botan_hash_init(&impl, name, 0);
        if (rc != 0) {
                return 0;
        }
        hash->data = impl;
        return 1;
}

static void
digest_add(pgp_hash_t *hash, const uint8_t *data, unsigned length)
{
	if (pgp_get_debug_level(__FILE__)) {
		hexdump(stderr, "digest_add", data, length);
	}
        botan_hash_update((botan_hash_t)hash->data, data, length);
}

static unsigned
digest_finish(pgp_hash_t *hash, uint8_t *out)
{
        size_t outlen;
        int rc = botan_hash_output_length((botan_hash_t)hash->data, &outlen);
        if (rc != 0) {
                (void) fprintf(stderr, "digest_finish botan_hash_output_length failed");
                return 0;
        }
        rc = botan_hash_final(hash->data, out);
        if (rc != 0) {
                (void) fprintf(stderr, "digest_finish botan_hash_final failed");
                return 0;
        }
	if (pgp_get_debug_level(__FILE__)) {
		hexdump(stderr, "digest_finish", out, outlen);
	}
        botan_hash_destroy(hash->data);
	hash->data = NULL;
	return outlen;
}

static int
md5_init(pgp_hash_t *hash)
{
        return digest_init(hash, "MD5");
}

static const pgp_hash_t md5 = {
	PGP_HASH_MD5,
	"MD5",
	md5_init,
	digest_add,
	digest_finish,
	NULL
};

/**
   \ingroup Core_Crypto
   \brief Initialise to MD5
   \param hash Hash to initialise
*/
void
pgp_hash_md5(pgp_hash_t *hash)
{
	*hash = md5;
}

static int
sha1_init(pgp_hash_t *hash)
{
        return digest_init(hash, "SHA-1");
}

static const pgp_hash_t sha1 = {
	PGP_HASH_SHA1,
	"SHA1",
	sha1_init,
	digest_add,
	digest_finish,
	NULL
};

/**
   \ingroup Core_Crypto
   \brief Initialise to SHA1
   \param hash Hash to initialise
*/
void
pgp_hash_sha1(pgp_hash_t *hash)
{
	*hash = sha1;
}

static int
sha256_init(pgp_hash_t *hash)
{
        return digest_init(hash, "SHA-256");
}

static const pgp_hash_t sha256 = {
	PGP_HASH_SHA256,
	"SHA256",
	sha256_init,
	digest_add,
	digest_finish,
	NULL
};

void
pgp_hash_sha256(pgp_hash_t *hash)
{
	*hash = sha256;
}

/*
 * SHA384
 */
static int
sha384_init(pgp_hash_t *hash)
{
        return digest_init(hash, "SHA-384");
}

static const pgp_hash_t sha384 = {
	PGP_HASH_SHA384,
	"SHA384",
	sha384_init,
	digest_add,
	digest_finish,
	NULL
};

void
pgp_hash_sha384(pgp_hash_t *hash)
{
	*hash = sha384;
}

/*
 * SHA512
 */
static int
sha512_init(pgp_hash_t *hash)
{
        return digest_init(hash, "SHA-512");
}

static const pgp_hash_t sha512 = {
	PGP_HASH_SHA512,
	"SHA512",
	sha512_init,
        digest_add,
	digest_finish,
	NULL
};

void
pgp_hash_sha512(pgp_hash_t *hash)
{
	*hash = sha512;
}

/*
 * SHA224
 */

static int
sha224_init(pgp_hash_t *hash)
{
        return digest_init(hash, "SHA-224");
}

static const pgp_hash_t sha224 = {
	PGP_HASH_SHA224,
	"SHA224",
	sha224_init,
	digest_add,
	digest_finish,
	NULL
};

void
pgp_hash_sha224(pgp_hash_t *hash)
{
	*hash = sha224;
}

/*
 * SM3
 */

static int
sm3_init(pgp_hash_t *hash)
{
        return digest_init(hash, "SM3");
}

static const pgp_hash_t sm3 = {
	PGP_HASH_SM3,
	"SM3",
	sm3_init,
	digest_add,
	digest_finish,
	NULL
};

void
pgp_hash_sm3(pgp_hash_t *hash)
{
	*hash = sm3;
}

/**
   \ingroup Core_Hashes
   \brief Get Hash name
   \param hash Hash struct
   \return Hash name
*/
const char     *
pgp_text_from_hash(pgp_hash_t *hash)
{
	return hash->name;
}
