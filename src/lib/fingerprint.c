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

#include "fingerprint.h"
#include "hash.h"
#include "packet-create.h"
#include "utils.h"

/* hash a 32-bit integer */
static int
hash_uint32(pgp_hash_t *hash, uint32_t n)
{
    uint8_t ibuf[4];
    STORE32LE(ibuf, n);
    pgp_hash_add(hash, ibuf, sizeof(ibuf));
    return sizeof(ibuf);
}

/* hash a string - first length, then string itself */
static size_t
hash_string(pgp_hash_t *hash, const uint8_t *buf, size_t len)
{
    hash_uint32(hash, len);
    pgp_hash_add(hash, buf, len);
    return (len + 4);
}

/* hash a bignum, possibly padded - first length, then string itself */
static size_t
hash_bignum(pgp_hash_t *hash, const BIGNUM *bignum)
{
    uint8_t *bn;
    size_t   len;
    size_t   padbyte;

    if (BN_is_zero(bignum)) {
        hash_uint32(hash, 0);
        return sizeof(len);
    }
    if ((len = (size_t) BN_num_bytes(bignum)) < 1) {
        (void) fprintf(stderr, "hash_bignum: bad size\n");
        return 0;
    }
    if ((bn = calloc(1, len + 1)) == NULL) {
        (void) fprintf(stderr, "hash_bignum: bad bn alloc\n");
        return 0;
    }
    BN_bn2bin(bignum, bn + 1);
    bn[0] = 0x0;
    padbyte = (bn[1] & 0x80) ? 1 : 0;
    hash_string(hash, bn + 1 - padbyte, (unsigned) (len + padbyte));
    free(bn);
    return (sizeof(len) + len + padbyte);
}

rnp_result_t
ssh_fingerprint(pgp_fingerprint_t *fp, const pgp_pubkey_t *key)
{
    pgp_hash_t  hash = {0};
    const char *type;

    if (!pgp_hash_create(&hash, PGP_HASH_MD5)) {
        return RNP_ERROR_NOT_SUPPORTED;
    }

    type = (key->alg == PGP_PKA_RSA) ? "ssh-rsa" : "ssh-dss";
    hash_string(&hash, (const uint8_t *) (const void *) type, (unsigned) strlen(type));
    switch (key->alg) {
    case PGP_PKA_RSA:
        hash_bignum(&hash, key->key.rsa.e);
        hash_bignum(&hash, key->key.rsa.n);
        break;
    case PGP_PKA_DSA:
        hash_bignum(&hash, key->key.dsa.p);
        hash_bignum(&hash, key->key.dsa.q);
        hash_bignum(&hash, key->key.dsa.g);
        hash_bignum(&hash, key->key.dsa.y);
        break;
    default:
        pgp_hash_finish(&hash, fp->fingerprint);
        fp->length = 0;
        RNP_LOG("Algorithm not supported");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    fp->length = pgp_hash_finish(&hash, fp->fingerprint);
    return RNP_SUCCESS;
}

rnp_result_t
pgp_fingerprint(pgp_fingerprint_t *fp, const pgp_pubkey_t *key)
{
    pgp_memory_t *mem;
    pgp_hash_t    hash = {0};

    if (key->version == 2 || key->version == 3) {
        if (key->alg != PGP_PKA_RSA && key->alg != PGP_PKA_RSA_ENCRYPT_ONLY &&
            key->alg != PGP_PKA_RSA_SIGN_ONLY) {
            (void) fprintf(stderr, "pgp_fingerprint: bad algorithm\n");
            return RNP_ERROR_NOT_SUPPORTED;
        }
        if (!pgp_hash_create(&hash, PGP_HASH_MD5)) {
            (void) fprintf(stderr, "pgp_fingerprint: bad md5 alloc\n");
            return RNP_ERROR_NOT_SUPPORTED;
        }
        hash_bignum(&hash, key->key.rsa.n);
        hash_bignum(&hash, key->key.rsa.e);
        fp->length = pgp_hash_finish(&hash, fp->fingerprint);
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "v2/v3 fingerprint", fp->fingerprint, fp->length);
        }
    } else if (key->version == 4) {
        mem = pgp_memory_new();
        if (mem == NULL) {
            (void) fprintf(stderr, "can't allocate mem\n");
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        if (!pgp_build_pubkey(mem, key, 0)) {
            RNP_LOG("failed to build pubkey");
            pgp_memory_free(mem);
            return RNP_ERROR_GENERIC;
        }
        if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
            (void) fprintf(stderr, "pgp_fingerprint: bad sha1 alloc\n");
            pgp_memory_free(mem);
            return RNP_ERROR_NOT_SUPPORTED;
        }
        size_t len = pgp_mem_len(mem);
        pgp_hash_add_int(&hash, 0x99, 1);
        pgp_hash_add_int(&hash, len, 2);
        pgp_hash_add(&hash, pgp_mem_data(mem), len);
        fp->length = pgp_hash_finish(&hash, fp->fingerprint);
        pgp_memory_free(mem);
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "sha1 fingerprint", fp->fingerprint, fp->length);
        }
    } else {
        (void) fprintf(stderr, "pgp_fingerprint: unsupported key version\n");
        return false;
    }
    return true;
}

/**
 * \ingroup Core_Keys
 * \brief Calculate the Key ID from the public key.
 * \param keyid Space for the calculated ID to be stored
 * \param key The key for which the ID is calculated
 */

rnp_result_t
pgp_keyid(uint8_t *keyid, const size_t idlen, const pgp_pubkey_t *key)
{
    if (key->version == 2 || key->version == 3) {
        unsigned n;
        uint8_t  bn[RNP_BUFSIZ];

        if (key->alg != PGP_PKA_RSA && key->alg != PGP_PKA_RSA_ENCRYPT_ONLY &&
            key->alg != PGP_PKA_RSA_SIGN_ONLY) {
            (void) fprintf(stderr, "pgp_keyid: bad algorithm\n");
            return false;
        }

        n = (unsigned) BN_num_bytes(key->key.rsa.n);
        if (n > sizeof(bn)) {
            (void) fprintf(stderr, "pgp_keyid: bad num bytes\n");
            return false;
        }
        BN_bn2bin(key->key.rsa.n, bn);
        (void) memcpy(keyid, bn + n - idlen, idlen);
    } else {
        pgp_fingerprint_t finger;

        if (!pgp_fingerprint(&finger, key)) {
            return false;
        }
        (void) memcpy(keyid, finger.fingerprint + finger.length - idlen, idlen);
    }
    return true;
}
