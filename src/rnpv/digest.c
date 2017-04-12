/*-
 * Copyright (c) 2012 Alistair Crooks <agc@NetBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "digest.h"
#include "crypto.h"

#ifndef USE_ARG
#define	USE_ARG(x)	/*LINTED*/(void)&(x)
#endif

static uint8_t prefix_md5[] = {
	0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86,
	0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
};

static uint8_t prefix_sha1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0E, 0x03, 0x02,
	0x1A, 0x05, 0x00, 0x04, 0x14
};

static uint8_t prefix_sha256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

static uint8_t prefix_sha512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

#define V4_SIGNATURE		4

/*************************************************************************/

/* algorithm size (raw) */
int 
digest_alg_size(unsigned alg)
{
        return pgp_hash_size(alg);
}

/* initialise the hash structure */
int 
digest_init(digest_t *hash, const uint32_t hashalg)
{
	if (hash == NULL) {
		return 0;
	}
        hash->alg = hashalg;
        if (pgp_hash_any(&hash->ctx, hashalg) == 1)
        {
           if(!hash->ctx.init(&hash->ctx))
           {
              return 0;
           }
        }

        return 0;
}

typedef struct rec_t {
	const char	*s;
	const unsigned	 alg;
} rec_t;

static rec_t	hashalgs[] = {
	{	"md5",		MD5_HASH_ALG	},
	{	"sha1",		SHA1_HASH_ALG	},
	{	"ripemd",	RIPEMD_HASH_ALG	},
	{	"sha256",	SHA256_HASH_ALG	},
	{	"sha512",	SHA512_HASH_ALG	},
	{	NULL,		0		}
};

/* initialise by string alg name */
unsigned 
digest_get_alg(const char *hashalg)
{
	rec_t	*r;

	for (r = hashalgs ; hashalg && r->s ; r++) {
		if (strcasecmp(r->s, hashalg) == 0) {
			return r->alg;
		}
	}
	return 0;
}

int 
digest_update(digest_t *hash, const uint8_t *data, size_t length)
{
	if (hash == NULL || data == NULL) {
		return 0;
	}

        hash->ctx.add(&hash->ctx, data, length);
        return 1;
}

unsigned 
digest_final(uint8_t *out, digest_t *hash)
{
	if (hash == NULL || out == NULL) {
		return 0;
	}

        hash->ctx.finish(&hash->ctx, out);
        return digest_alg_size(hash->alg);
}

int
digest_length(digest_t *hash, unsigned hashedlen)
{
	uint8_t		 trailer[6];

	if (hash == NULL) {
		return 0;
	}
	trailer[0] = V4_SIGNATURE;
	trailer[1] = 0xFF;
	trailer[2] = (uint8_t)((hashedlen >> 24) & 0xff);
	trailer[3] = (uint8_t)((hashedlen >> 16) & 0xff);
	trailer[4] = (uint8_t)((hashedlen >> 8) & 0xff);
	trailer[5] = (uint8_t)(hashedlen & 0xff);
	digest_update(hash, trailer, sizeof(trailer));
	return 1;
}

unsigned
digest_get_prefix(unsigned hashalg, uint8_t *out_prefix, size_t size)
{
	if (out_prefix == NULL) {
		return 0;
	}

        const uint8_t* prefix = NULL;
        size_t prefix_size = 0;

	switch (hashalg) {
	case MD5_HASH_ALG:
           prefix = prefix_md5;
           prefix_size = sizeof(prefix_md5);
           break;

        case SHA1_HASH_ALG:
           prefix = prefix_sha1;
           prefix_size = sizeof(prefix_sha1);
           break;

	case SHA256_HASH_ALG:
           prefix = prefix_sha256;
           prefix_size = sizeof(prefix_sha256);
           break;

	case SHA512_HASH_ALG:
           prefix = prefix_sha512;
           prefix_size = sizeof(prefix_sha512);
           break;

	default:
           printf("digest_get_prefix: unknown hash algorithm: %d\n", hashalg);
           return 0;
	}

        // insufficient output space
        if (size < prefix_size) {
           return 0;
        }
        memcpy(out_prefix, prefix, prefix_size);
        return prefix_size;
}

