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
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: symmetric.c,v 1.18 2010/11/07 08:39:59 agc Exp $");
#endif


#include <string.h>
#include <stdlib.h>

#include <botan/ffi.h>

#include "crypto.h"
#include "packet-show.h"
#include "rnpdefs.h"

static void 
std_set_iv(pgp_crypt_t *crypt, const uint8_t *iv)
{
	(void) memcpy(crypt->iv, iv, crypt->blocksize);
	crypt->num = 0;
}

static void 
std_set_key(pgp_crypt_t *crypt, const uint8_t *key)
{
	(void) memcpy(crypt->key, key, crypt->keysize);
}

static void 
std_resync(pgp_crypt_t *decrypt)
{
	if ((size_t) decrypt->num == decrypt->blocksize) {
		return;
	}

	memmove(decrypt->civ + decrypt->blocksize - decrypt->num, decrypt->civ,
		(unsigned)decrypt->num);
	(void) memcpy(decrypt->civ, decrypt->siv + decrypt->num,
	       decrypt->blocksize - decrypt->num);
	decrypt->num = 0;
}

static void 
std_finish(pgp_crypt_t *crypt)
{
	if (crypt->block_cipher_obj) {
		free(crypt->block_cipher_obj);
		crypt->block_cipher_obj = NULL;
	}
}

static int 
std_init(pgp_crypt_t *crypt, const char* cipher_name)
{
	if (crypt->block_cipher_obj)
        {
           botan_block_cipher_destroy(crypt->block_cipher_obj);
	}

        if (botan_block_cipher_init(crypt->block_cipher_obj, cipher_name) != 0)
        {
           (void) fprintf(stderr, "Block cipher %s not available", cipher_name);
           return 0;
        }

        if (botan_block_cipher_set_key(crypt->block_cipher_obj, crypt->key, crypt->keysize))
        {
           (void) fprintf(stderr, "failure setting key\n");
           return 0;
        }
	return 1;
}

static void 
std_block_encrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in)
{
   botan_block_cipher_encrypt_blocks(crypt->block_cipher_obj, in, out, 1);
}

static void 
std_block_decrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in)
{
   botan_block_cipher_decrypt_blocks(crypt->block_cipher_obj, in, out, 1);
}

static void 
std_cfb_encrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t bytes)
{
   for(size_t i = 0; i < bytes; ++i)
   {
      if (crypt->num == 0)
      {
         botan_block_cipher_encrypt_blocks(crypt->block_cipher_obj, crypt->iv, crypt->iv, 1);
      }
      out[i] = in[i] ^ crypt->iv[crypt->num];
      crypt->iv[crypt->num] = out[i];

      crypt->num = (crypt->num + 1) % crypt->blocksize;
   }
}

static void 
std_cfb_decrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t bytes)
{
   for(size_t i = 0; i < bytes; ++i)
   {
      uint8_t ciphertext = in[i];

      if (crypt->num == 0)
      {
         botan_block_cipher_encrypt_blocks(crypt->block_cipher_obj, crypt->iv, crypt->iv, 1);
      }

      out[i] = in[i] ^ crypt->iv[crypt->num];
      crypt->iv[crypt->num] = ciphertext;

      crypt->num = (crypt->num + 1) % crypt->blocksize;
   }
}

#define TRAILER		"","","","",0,NULL

#if defined(BOTAN_HAS_CAST)

static int 
cast5_init(pgp_crypt_t *crypt)
{
        return std_init(crypt, "CAST-5");
}

#define CAST_BLOCK 8
#define CAST_KEY_LENGTH 16

static pgp_crypt_t cast5 =
{
	PGP_SA_CAST5,
	CAST_BLOCK,
	CAST_KEY_LENGTH,
	std_set_iv,
	std_set_key,
	cast5_init,
	std_resync,
	std_block_encrypt,
	std_block_decrypt,
	std_cfb_encrypt,
	std_cfb_decrypt,
	std_finish,
	TRAILER
};

#endif

#if defined(BOTAN_HAS_IDEA)

static int 
idea_init(pgp_crypt_t *crypt)
{
        return std_init(crypt, "IDEA");
}

#define IDEA_BLOCK 8
#define IDEA_KEY_LENGTH 16

static const pgp_crypt_t idea =
{
	PGP_SA_IDEA,
	IDEA_BLOCK,
	IDEA_KEY_LENGTH,
	std_set_iv,
	std_set_key,
	idea_init,
	std_resync,
	std_block_encrypt,
	std_block_decrypt,
	std_cfb_encrypt,
	std_cfb_decrypt,
	std_finish,
	TRAILER
};

#endif

#if defined(BOTAN_HAS_AES)

/* AES with 128-bit key (AES) */

#define KEYBITS_AES128 128

static int 
aes128_init(pgp_crypt_t *crypt)
{
        return std_init(crypt, "AES-128");
}

#define AES_BLOCK_SIZE 8
#define AES128_KEY_LENGTH 16

static const pgp_crypt_t aes128 =
{
	PGP_SA_AES_128,
	AES_BLOCK_SIZE,
	AES128_KEY_LENGTH,
	std_set_iv,
	std_set_key,
	aes128_init,
	std_resync,
	std_block_encrypt,
	std_block_decrypt,
	std_cfb_encrypt,
	std_cfb_decrypt,
	std_finish,
	TRAILER
};

/* AES with 256-bit key */

#define AES256_KEY_LENGTH 32

static int 
aes256_init(pgp_crypt_t *crypt)
{
        return std_init(crypt, "AES-256");
}

static const pgp_crypt_t aes256 =
{
	PGP_SA_AES_256,
	AES_BLOCK_SIZE,
        AES256_KEY_LENGTH,
	std_set_iv,
	std_set_key,
	aes256_init,
	std_resync,
	std_block_encrypt,
	std_block_decrypt,
	std_cfb_encrypt,
	std_cfb_decrypt,
	std_finish,
	TRAILER
};

#endif

#if defined(BOTAN_HAS_DES)

/* Triple DES */

static int 
tripledes_init(pgp_crypt_t *crypt)
{
        return std_init(crypt, "3DES");
}

static const pgp_crypt_t tripledes =
{
	PGP_SA_TRIPLEDES,
	8,
	24,
	std_set_iv,
	std_set_key,
	tripledes_init,
	std_resync,
	std_block_encrypt,
	std_block_decrypt,
	std_cfb_encrypt,
	std_cfb_decrypt,
	std_finish,
	TRAILER
};

#endif

#if defined(BOTAN_HAS_CAMELLIA)

/* Camellia with 128-bit key (CAMELLIA) */

#define CAMELLIA_BLOCK_SIZE 16
#define CAMELLIA128_KEY_LENGTH 16

static int 
camellia128_init(pgp_crypt_t *crypt)
{
        return std_init(crypt, "Camellia-128");
}

static const pgp_crypt_t camellia128 =
{
	PGP_SA_CAMELLIA_128,
	CAMELLIA_BLOCK_SIZE,
        CAMELLIA128_KEY_LENGTH,
	std_set_iv,
	std_set_key,
	camellia128_init,
	std_resync,
	std_block_encrypt,
	std_block_decrypt,
	std_cfb_encrypt,
	std_cfb_decrypt,
	std_finish,
	TRAILER
};

/* Camellia with 256-bit key (CAMELLIA) */

#define CAMELLIA256_KEY_LENGTH 32

static int 
camellia256_init(pgp_crypt_t *crypt)
{
        return std_init(crypt, "Camellia-256");
}

static const pgp_crypt_t camellia256 =
{
	PGP_SA_CAMELLIA_256,
	CAMELLIA_BLOCK_SIZE,
        CAMELLIA256_KEY_LENGTH,
	std_set_iv,
	std_set_key,
	camellia256_init,
	std_resync,
	std_block_encrypt,
	std_block_decrypt,
	std_cfb_encrypt,
	std_cfb_decrypt,
	std_finish,
	TRAILER
};

#endif

static const pgp_crypt_t *
get_proto(pgp_symm_alg_t alg)
{
        // TODO: check botan/build.h macros?
	switch (alg) {
#if defined(BOTAN_HAS_CAST)
	case PGP_SA_CAST5:
		return &cast5;
#endif

#if defined(BOTAN_HAS_IDEA)
	case PGP_SA_IDEA:
		return &idea;
#endif

#if defined(BOTAN_HAS_AES)
	case PGP_SA_AES_128:
		return &aes128;
	case PGP_SA_AES_256:
		return &aes256;
#endif

#if defined(BOTAN_HAS_CAMELLIA)
	case PGP_SA_CAMELLIA_128:
		return &camellia128;
	case PGP_SA_CAMELLIA_256:
		return &camellia256;
#endif

#if defined(BOTAN_HAS_DES)
	case PGP_SA_TRIPLEDES:
		return &tripledes;
#endif

	default:
		(void) fprintf(stderr, "Unknown algorithm: %d (%s)\n",
			alg, pgp_show_symm_alg(alg));
	}
	return NULL;
}

int 
pgp_crypt_any(pgp_crypt_t *crypt, pgp_symm_alg_t alg)
{
	const pgp_crypt_t *ptr = get_proto(alg);

	if (ptr) {
		*crypt = *ptr;
		return 1;
	} else {
		(void) memset(crypt, 0x0, sizeof(*crypt));
		return 0;
	}
}

unsigned 
pgp_block_size(pgp_symm_alg_t alg)
{
	const pgp_crypt_t *p = get_proto(alg);

	return (p == NULL) ? 0 : (unsigned)p->blocksize;
}

unsigned 
pgp_key_size(pgp_symm_alg_t alg)
{
	const pgp_crypt_t *p = get_proto(alg);

	return (p == NULL) ? 0 : (unsigned)p->keysize;
}

void 
pgp_encrypt_init(pgp_crypt_t *encrypt)
{
	/* \todo should there be a separate pgp_encrypt_init? */
	pgp_decrypt_init(encrypt);
}

void 
pgp_decrypt_init(pgp_crypt_t *decrypt)
{
	decrypt->base_init(decrypt);
	decrypt->block_encrypt(decrypt, decrypt->siv, decrypt->iv);
	(void) memcpy(decrypt->civ, decrypt->siv, decrypt->blocksize);
	decrypt->num = 0;
}

size_t
pgp_decrypt_se(pgp_crypt_t *decrypt, void *outvoid, const void *invoid,
		size_t count)
{
	const uint8_t	*in = invoid;
	uint8_t		*out = outvoid;
	int              saved = (int)count;

	/*
	 * in order to support v3's weird resyncing we have to implement CFB
	 * mode ourselves
	 */
	while (count-- > 0) {
		uint8_t   t;

		if ((size_t) decrypt->num == decrypt->blocksize) {
			(void) memcpy(decrypt->siv, decrypt->civ,
					decrypt->blocksize);
			decrypt->block_decrypt(decrypt, decrypt->civ,
					decrypt->civ);
			decrypt->num = 0;
		}
		t = decrypt->civ[decrypt->num];
		*out++ = t ^ (decrypt->civ[decrypt->num++] = *in++);
	}

	return (size_t)saved;
}

size_t 
pgp_encrypt_se(pgp_crypt_t *encrypt, void *outvoid, const void *invoid,
	       size_t count)
{
	const uint8_t	*in = invoid;
	uint8_t		*out = outvoid;
	int              saved = (int)count;

	/*
	 * in order to support v3's weird resyncing we have to implement CFB
	 * mode ourselves
	 */
	while (count-- > 0) {
		if ((size_t) encrypt->num == encrypt->blocksize) {
			(void) memcpy(encrypt->siv, encrypt->civ,
					encrypt->blocksize);
			encrypt->block_encrypt(encrypt, encrypt->civ,
					encrypt->civ);
			encrypt->num = 0;
		}
		encrypt->civ[encrypt->num] = *out++ =
				encrypt->civ[encrypt->num] ^ *in++;
		++encrypt->num;
	}

	return (size_t)saved;
}

/**
\ingroup HighLevel_Supported
\brief Is this Symmetric Algorithm supported?
\param alg Symmetric Algorithm to check
\return 1 if supported; else 0
*/
unsigned 
pgp_is_sa_supported(pgp_symm_alg_t alg)
{
        const pgp_crypt_t* proto = get_proto(alg);
        if (proto != 0) {
                return 1;
        }

	fprintf(stderr, "\nWarning: %s not supported\n",
		pgp_show_symm_alg(alg));
	return 0;
}

size_t 
pgp_encrypt_se_ip(pgp_crypt_t *crypt, void *out, const void *in,
		  size_t count)
{
	if (!pgp_is_sa_supported(crypt->alg)) {
		return 0;
	}

	crypt->cfb_encrypt(crypt, out, in, count);

	/* \todo test this number was encrypted */
	return count;
}

size_t 
pgp_decrypt_se_ip(pgp_crypt_t *crypt, void *out, const void *in,
		  size_t count)
{
	if (!pgp_is_sa_supported(crypt->alg)) {
		return 0;
	}

	crypt->cfb_decrypt(crypt, out, in, count);

	/* \todo check this number was in fact decrypted */
	return count;
}
