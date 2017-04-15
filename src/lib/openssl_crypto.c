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
#include "config.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "crypto.h"
#include "keyring.h"
#include "readerwriter.h"
#include "rnpdefs.h"
#include "rnpdigest.h"
#include "packet.h"
#include "bn.h"
#include "rnpdigest.h"

#include <botan/ffi.h>

#define FAIL(str)  \
  do { \
    (void)fprintf(stderr, "%s:%u:%s(): "str"\n", __FILE__, __LINE__, __func__);  \
    goto end; \
  } while (0);

struct PGPV_BIGNUM_st {
   botan_mp_t mp;
};

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

unsigned 
pgp_dsa_verify(const uint8_t *hash, size_t hash_length,
	       const pgp_dsa_sig_t *sig,
	       const pgp_dsa_pubkey_t *dsa)
{
   botan_pubkey_t dsa_key;
   botan_pk_op_verify_t verify_op;
   uint8_t* encoded_signature = NULL;
   size_t q_bytes = 0;
   unsigned int valid;

   botan_pubkey_load_dsa(&dsa_key, dsa->p->mp, dsa->q->mp, dsa->g->mp, dsa->y->mp);

   botan_mp_num_bytes(dsa->q->mp, &q_bytes);

   encoded_signature = calloc(2, q_bytes);
   // sig->r, sig->s -> signature

   botan_pk_op_verify_create(&verify_op, dsa_key, "Raw", 0);
   botan_pk_op_verify_update(verify_op, hash, hash_length);
   valid = (botan_pk_op_verify_finish(verify_op, encoded_signature, 2*q_bytes) == 0);
   botan_pk_op_verify_destroy(verify_op);
   botan_pubkey_destroy(dsa_key);

   free(encoded_signature);

   return valid;
}

/**
   \ingroup Core_Crypto
   \brief Recovers message digest from the signature
   \param out Where to write decrypted data to
   \param in Encrypted data
   \param length Length of encrypted data
   \param pubkey RSA public key
   \return size of recovered message digest
*/
int 
pgp_rsa_public_decrypt(uint8_t *out,
			const uint8_t *in,
			size_t length,
			const pgp_rsa_pubkey_t *pubkey)
{
        size_t out_bytes = 0;
        size_t n_bytes = 0;
        botan_mp_t output, msg;

        botan_mp_init(&msg);
        botan_mp_from_bin(msg, in, length);

        botan_mp_init(&output);
        botan_mp_powmod(output, msg, pubkey->e->mp, pubkey->n->mp);

        // Handle any necessary zero padding
        botan_mp_num_bytes(output, &out_bytes);
        botan_mp_num_bytes(pubkey->n->mp, &n_bytes);

        if(n_bytes < out_bytes)
           return 0;

        botan_mp_to_bin(output, out + (n_bytes - out_bytes));

        return n_bytes;
}

/**
   \ingroup Core_Crypto
   \brief Signs data with RSA
   \param out Where to write signature
   \param in Data to sign
   \param length Length of data
   \param seckey RSA secret key
   \param pubkey RSA public key
   \return number of bytes decrypted
*/
int 
pgp_rsa_private_encrypt(uint8_t *out,
			const uint8_t *in,
			size_t in_length,
			const pgp_rsa_seckey_t *seckey,
			const pgp_rsa_pubkey_t * pubkey)
{

   botan_privkey_t rsa_key;
   botan_pk_op_sign_t sign_op;
   botan_rng_t rng;
   size_t out_length;

   if(seckey->q == NULL)
   {
      (void) fprintf(stderr, "private key not set in pgp_rsa_private_encrypt\n");
      return 0;
   }

   botan_rng_init(&rng, NULL);

   /* p and q are reversed from normal usage in PGP */
   botan_privkey_load_rsa(&rsa_key, seckey->q->mp, seckey->p->mp, seckey->d->mp);

   if(botan_privkey_check_key(rsa_key, rng, 0) != 0)
   {
      botan_privkey_destroy(rsa_key);
      botan_rng_destroy(rng);
      return 0;
   }

   if(botan_pk_op_sign_create(&sign_op, rsa_key, "Raw", 0) != 0)
   {
      botan_privkey_destroy(rsa_key);
      botan_rng_destroy(rng);
      return 0;
   }

   botan_pk_op_sign_update(sign_op, in, in_length);
   botan_pk_op_sign_finish(sign_op, rng, out, &out_length);

   botan_pk_op_sign_destroy(sign_op);
   botan_privkey_destroy(rsa_key);
   botan_rng_destroy(rng);

   return (int)out_length;
}

/**
\ingroup Core_Crypto
\brief Decrypts RSA-encrypted data
\param out Where to write the plaintext
\param in Encrypted data
\param length Length of encrypted data
\param seckey RSA secret key
\param pubkey RSA public key
\return size of recovered plaintext
*/
int 
pgp_rsa_private_decrypt(uint8_t *out,
			const uint8_t *in,
			size_t length,
			const pgp_rsa_seckey_t *seckey,
			const pgp_rsa_pubkey_t *pubkey)
{
   botan_privkey_t rsa_key;
   botan_rng_t rng;
   botan_pk_op_decrypt_t decrypt_op;
   size_t out_len = RNP_BUFSIZ; // in pgp_decrypt_decode_mpi

   botan_privkey_load_rsa(&rsa_key, seckey->q->mp, seckey->p->mp, pubkey->e->mp);

   botan_rng_init(&rng, NULL);
   if(botan_privkey_check_key(rsa_key, rng, 0) != 0)
   {
      botan_rng_destroy(rng);
      botan_privkey_destroy(rsa_key);
      return 0;
   }

   botan_pk_op_decrypt_create(&decrypt_op, rsa_key, "Raw", 0);

   if(botan_pk_op_decrypt(decrypt_op, out, &out_len, (uint8_t*)in, length) != 0)
   {
      out_len = 0;
   }

   botan_rng_destroy(rng);
   botan_privkey_destroy(rsa_key);
   botan_pk_op_decrypt_destroy(decrypt_op);
   return (int)out_len;
}

/**
   \ingroup Core_Crypto
   \brief RSA-encrypts data
   \param out Where to write the encrypted data
   \param in Plaintext
   \param length Size of plaintext
   \param pubkey RSA Public Key
*/
int 
pgp_rsa_public_encrypt(uint8_t *out,
			const uint8_t *in,
			size_t length,
			const pgp_rsa_pubkey_t *pubkey)
{

   botan_pubkey_t rsa_key;
   botan_pk_op_encrypt_t enc_op;

   botan_rng_t rng;

   botan_rng_init(&rng, NULL);

   botan_pubkey_load_rsa(&rsa_key, pubkey->n->mp, pubkey->e->mp);

   if (botan_pubkey_check_key(rsa_key, rng, 1) != 0)
   {
      return -1;
   }

   botan_pk_op_encrypt_create(&enc_op, rsa_key, "Raw", 0);

   size_t out_len = RNP_BUFSIZ; // in pgp_rsa_encrypt_mpi
   if(botan_pk_op_encrypt(enc_op, rng, out, &out_len, in, length) != 0)
   {
      return -1;
   }

   botan_pk_op_encrypt_destroy(enc_op);
   botan_pubkey_destroy(rsa_key);
   botan_rng_destroy(rng);

   return (int)out_len;
}

/**
   \ingroup Core_Crypto
   \brief Finalise openssl
   \note Would usually call pgp_finish() instead
   \sa pgp_finish()
*/
void 
pgp_crypto_finish(void)
{
   // No op
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

/**
* Create a new BIGNUM wrapper but just borrow an existing object
*/
static BIGNUM* new_BN_take_mp(botan_mp_t mp)
{
   PGPV_BIGNUM	*a;

   a = calloc(1, sizeof(*a));
   a->mp = mp;
   return a;
}


/**
 \ingroup HighLevel_KeyGenerate
 \brief Generates an RSA keypair
 \param numbits Modulus size
 \param e Public Exponent
 \param keydata Pointer to keydata struct to hold new key
 \return 1 if key generated successfully; otherwise 0
 \note It is the caller's responsibility to call pgp_keydata_free(keydata)
*/
static unsigned 
rsa_generate_keypair(pgp_key_t *keydata,
			const int numbits,
			const unsigned long e,
			const char *hashalg,
			const char *cipher)
{
	pgp_seckey_t *seckey;
	pgp_output_t *output;
	pgp_memory_t   *mem;
        botan_privkey_t rsa_key;
        botan_rng_t rng;
        botan_mp_t rsa_n, rsa_e, rsa_d, rsa_p, rsa_q, rsa_u;

	pgp_keydata_init(keydata, PGP_PTAG_CT_SECRET_KEY);
	seckey = pgp_get_writable_seckey(keydata);

	/* generate the key pair */

        if(e != 65537)
        {
           fprintf(stderr, "Unexpected RSA e value %zu, key generation failed\n", e);
           return 0;
        }

        if(botan_rng_init(&rng, NULL) != 0)
           return 0;
        if(botan_privkey_create_rsa(&rsa_key, rng, numbits) != 0)
           return 0;

        if(botan_privkey_check_key(rsa_key, rng, 1) != 0)
           return 0;

        botan_rng_destroy(rng);

	/* populate pgp key from ssl key */

	seckey->pubkey.version = PGP_V4;
	seckey->pubkey.birthtime = time(NULL);
	seckey->pubkey.days_valid = 0;
	seckey->pubkey.alg = PGP_PKA_RSA;

        botan_mp_init(&rsa_n);
        botan_mp_init(&rsa_e);
        botan_privkey_rsa_get_n(rsa_n, rsa_key);
        botan_privkey_rsa_get_e(rsa_e, rsa_key);

        // not released by this function
	seckey->pubkey.key.rsa.n = new_BN_take_mp(rsa_n);
	seckey->pubkey.key.rsa.e = new_BN_take_mp(rsa_e);

	seckey->s2k_usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
	seckey->s2k_specifier = PGP_S2KS_SALTED;
	/* seckey->s2k_specifier=PGP_S2KS_SIMPLE; */
	if ((seckey->hash_alg = pgp_str_to_hash_alg(hashalg)) == PGP_HASH_UNKNOWN) {
		seckey->hash_alg = PGP_HASH_SHA1;
	}
	seckey->alg = pgp_str_to_cipher(cipher);
	seckey->octetc = 0;
	seckey->checksum = 0;

        botan_mp_init(&rsa_d);
        botan_mp_init(&rsa_p);
        botan_mp_init(&rsa_q);
        botan_mp_init(&rsa_u);

        botan_privkey_rsa_get_p(rsa_p, rsa_key);
        botan_privkey_rsa_get_q(rsa_q, rsa_key);
        botan_privkey_rsa_get_d(rsa_d, rsa_key);

        if(botan_mp_mod_inverse(rsa_u, rsa_p, rsa_q) != 0 || botan_mp_is_zero(rsa_u))
        {
           fprintf(stderr, "Error computing RSA u param\n");
           return 0;
        }

	seckey->key.rsa.d = new_BN_take_mp(rsa_d);
	seckey->key.rsa.p = new_BN_take_mp(rsa_p);
	seckey->key.rsa.q = new_BN_take_mp(rsa_q);
	seckey->key.rsa.u = new_BN_take_mp(rsa_u);

	pgp_keyid(keydata->sigid, PGP_KEY_ID_SIZE, &keydata->key.seckey.pubkey, seckey->hash_alg);
	pgp_fingerprint(&keydata->sigfingerprint, &keydata->key.seckey.pubkey, seckey->hash_alg);

	/* Generate checksum */

	output = NULL;
	mem = NULL;

	pgp_setup_memory_write(&output, &mem, 128);

	pgp_push_checksum_writer(output, seckey);

	switch (seckey->pubkey.alg) {
	case PGP_PKA_DSA:
		return pgp_write_mpi(output, seckey->key.dsa.x);
	case PGP_PKA_RSA:
	case PGP_PKA_RSA_ENCRYPT_ONLY:
	case PGP_PKA_RSA_SIGN_ONLY:
		if (!pgp_write_mpi(output, seckey->key.rsa.d) ||
		    !pgp_write_mpi(output, seckey->key.rsa.p) ||
		    !pgp_write_mpi(output, seckey->key.rsa.q) ||
		    !pgp_write_mpi(output, seckey->key.rsa.u)) {
			return 0;
		}
		break;
	case PGP_PKA_ELGAMAL:
		return pgp_write_mpi(output, seckey->key.elgamal.x);

	default:
		(void) fprintf(stderr, "Bad seckey->pubkey.alg\n");
		return 0;
	}

	/* close rather than pop, since its the only one on the stack */
	pgp_writer_close(output);
	pgp_teardown_memory_write(output, mem);

	/* should now have checksum in seckey struct */

	return 1;
}

/**
 \ingroup HighLevel_KeyGenerate
 \brief Creates a self-signed RSA keypair
 \param numbits Modulus size
 \param e Public Exponent
 \param userid User ID
 \return The new keypair or NULL

 \note It is the caller's responsibility to call pgp_keydata_free(keydata)
 \sa rsa_generate_keypair()
 \sa pgp_keydata_free()
*/
pgp_key_t  *
pgp_rsa_new_selfsign_key(const int numbits,
				const unsigned long e,
				uint8_t *userid,
				const char *hashalg,
				const char *cipher)
{
	pgp_key_t  *keydata;

	keydata = pgp_keydata_new();
	if (!rsa_generate_keypair(keydata, numbits, e, hashalg, cipher) ||
	    !pgp_add_selfsigned_userid(keydata, userid)) {
		pgp_keydata_free(keydata);
		return NULL;
	}
	return keydata;
}

pgp_key_t  *
pgp_rsa_new_key(const int numbits,
		const unsigned long e,
		const char *hashalg,
		const char *cipher)
{
	pgp_key_t  *keydata;

	keydata = pgp_keydata_new();
	if (!rsa_generate_keypair(keydata, numbits, e, hashalg, cipher)) {
		pgp_keydata_free(keydata);
		return NULL;
	}
	return keydata;
}

void DSA_SIG_free(DSA_SIG* sig)
{
   BN_clear_free(sig->r);
   BN_clear_free(sig->s);
   free(sig);
}

DSA_SIG        *
pgp_dsa_sign(uint8_t *hashbuf,
		unsigned hashsize,
		const pgp_dsa_seckey_t *secdsa,
		const pgp_dsa_pubkey_t *pubdsa)
{
   botan_privkey_t dsa_key;
   botan_pk_op_sign_t sign_op;
   botan_rng_t rng;
   size_t q_bytes = 0;
   size_t sigbuf_size = 0;
   uint8_t* sigbuf = NULL;
   DSA_SIG* ret;

   botan_privkey_load_dsa(&dsa_key, pubdsa->p->mp, pubdsa->q->mp, pubdsa->g->mp, secdsa->x->mp);

   botan_rng_init(&rng, NULL);

   botan_pk_op_sign_create(&sign_op, dsa_key, "Raw", 0);
   botan_pk_op_sign_update(sign_op, hashbuf, hashsize);

   botan_mp_num_bytes(pubdsa->q->mp, &q_bytes);
   sigbuf_size = q_bytes * 2;
   sigbuf = calloc(sigbuf_size, 1);

   botan_pk_op_sign_finish(sign_op, rng, sigbuf, &sigbuf_size);
   botan_rng_destroy(rng);

   botan_pk_op_sign_destroy(sign_op);
   botan_privkey_destroy(dsa_key);

   // Now load the DSA (r,s) values from the signature
   ret = calloc(1, sizeof(DSA_SIG));
   botan_mp_init(&(ret->r->mp));
   botan_mp_init(&(ret->s->mp));

   botan_mp_from_bin(ret->r->mp, sigbuf, q_bytes);
   botan_mp_from_bin(ret->s->mp, sigbuf + q_bytes, q_bytes);

   return ret;

}

int
openssl_read_pem_seckey(const char *f, pgp_key_t *key, const char *type, int verbose)
{
        uint8_t keybuf[RNP_BUFSIZ] = { 0 };
	FILE	*fp;
	char	 prompt[BUFSIZ];
	char	*pass;
	int	 ok;
        size_t read;

        botan_rng_t rng;
        botan_privkey_t priv_key;

        // TODO
	if ((fp = fopen(f, "r")) == NULL) {
		if (verbose) {
			(void) fprintf(stderr, "can't open '%s'\n", f);
		}
		return 0;
	}

        read = fread(keybuf, 1, RNP_BUFSIZ, fp);

        if(!feof(fp))
        {
           return 0;
        }
	(void) fclose(fp);

        botan_rng_init(&rng, NULL);

	if (strcmp(type, "ssh-rsa") == 0)
        {
           if(botan_privkey_load(&priv_key, rng, keybuf, read, NULL) != 0)
           {
              (void) snprintf(prompt, sizeof(prompt), "rnp PEM %s passphrase: ", f);
              for(;;)
              {
                 pass = getpass(prompt);

                 if(botan_privkey_load(&priv_key, rng, keybuf, read, pass) == 0)
                    break;
              }
           }

           if(botan_privkey_check_key(priv_key, rng, 0) != 0)
           {
              return 0;
           }

           {
           botan_mp_t x;
           botan_mp_init(&x);
           botan_privkey_get_field(x, priv_key, "d");
           key->key.seckey.key.rsa.d = new_BN_take_mp(x);

           botan_mp_init(&x);
           botan_privkey_get_field(x, priv_key, "p");
           key->key.seckey.key.rsa.p = new_BN_take_mp(x);

           botan_mp_init(&x);
           botan_privkey_get_field(x, priv_key, "q");
           key->key.seckey.key.rsa.q = new_BN_take_mp(x);
           ok = 1;
           }
        }
        else if (strcmp(type, "ssh-dss") == 0)
        {
           if(botan_privkey_load(&priv_key, rng, keybuf, read, NULL) != 0)
           {
              ok = 0;
           }
           else
           {
              botan_mp_t x;
              botan_mp_init(&x);
              botan_privkey_get_field(x, priv_key, "x");
              key->key.seckey.key.dsa.x = new_BN_take_mp(x);
              ok = 1;
           }
	}
        else
        {
           ok = 0;
	}

        botan_rng_destroy(rng);
        botan_privkey_destroy(priv_key);

	return ok;
}

int
pgp_elgamal_public_encrypt(
      uint8_t *g2k,
      uint8_t *encm,
			const uint8_t *in,
			size_t length,
			const pgp_elgamal_pubkey_t *pubkey)
{
  botan_rng_t            rng            = NULL;
  botan_pubkey_t         key            = NULL;
  botan_pk_op_encrypt_t  op_ctx         = NULL;
  int                    ret            = -1;
  size_t                 p_len          = 0;
  uint8_t                *bt_ciphertext = NULL;

  if (botan_rng_init(&rng, NULL)) {

      FAIL("Random initialization failure");
  }

  if (botan_mp_num_bytes(pubkey->p->mp, &p_len)) {

      FAIL("Wrong public key");
  }

  // Initialize RNG and encrypt
  if (botan_pubkey_load_elgamal(&key, pubkey->p->mp, pubkey->g->mp, pubkey->y->mp) ||
      botan_pubkey_check_key(key, rng, 1)) {

      FAIL("Wrong public key");
  }

  /* Max size of an output len is twice an order of underlying group (twice byte-size of p)
   * Allocate all buffers needed for encryption and post encryption processing */
  size_t out_len = p_len*2;
  bt_ciphertext = calloc(out_len, 1);
  if (!bt_ciphertext) {

    FAIL("Memory allocation failure");
  }

  if (botan_pk_op_encrypt_create(&op_ctx, key, "Raw", 0) ||
      botan_pk_op_encrypt(op_ctx, rng, bt_ciphertext, &out_len, in, length)) {

      FAIL("Encryption fails");
  }

  /*
   * Botan's ElGamal formats the g^k and msg*(y^k) together into a single byte string.
   * We have to parse out the two values after encryption, as rnp stores those values separatelly.
   */
  memcpy(g2k, bt_ciphertext, p_len);
  memcpy(encm, bt_ciphertext + p_len, p_len);

  ret = (int)out_len;
end:
  if (botan_pk_op_encrypt_destroy(op_ctx) ||
      botan_pubkey_destroy(key) ||
      botan_rng_destroy(rng)) {

      // should never happen
      (void)fprintf(stderr, "%s:%d ERROR when deinitializing\n", __FILE__, __LINE__);
      ret = -1;
  }

  free(bt_ciphertext);
  return ret;
}

int
pgp_elgamal_private_decrypt(uint8_t *out,
				const uint8_t *g2k,
				const uint8_t *in,
				size_t length,
				const pgp_elgamal_seckey_t *seckey,
				const pgp_elgamal_pubkey_t *pubkey)
{
  botan_rng_t            rng          = NULL;
  botan_privkey_t        key          = NULL;
  botan_pk_op_decrypt_t  op_ctx       = NULL;
  int                    ret          = -1;
  size_t                 out_len      = 0;
  size_t                 p_len        = 0;
  uint8_t*               bt_plaintext = NULL;

  if (botan_rng_init(&rng, NULL)) {

      FAIL("Random initialization failure");
  }

  // Output len is twice an order of underlying group
  if (botan_mp_num_bytes(pubkey->p->mp, &p_len) ||
      (length != p_len)) {

      FAIL("Wrong public key");
  }

  /* Max size of an output len is twice an order of underlying group (twice byte-size of p)
   * Allocate all buffers needed for encryption and post encryption processing */
  out_len = p_len*2;

  bt_plaintext = calloc(out_len, 1);
  if (!bt_plaintext) {

      FAIL("Memory allocation failure");
  }

  if (botan_privkey_load_elgamal(&key, pubkey->p->mp, pubkey->g->mp, seckey->x->mp) ||
      botan_privkey_check_key(key, rng, 1)) {

      FAIL("Wrong private key");
  }

  memcpy(bt_plaintext, g2k, p_len);
  memcpy(bt_plaintext + p_len, in, p_len);

  if (botan_pk_op_decrypt_create(&op_ctx, key, "Raw", 0) ||
      botan_pk_op_decrypt(op_ctx, out, &out_len, bt_plaintext, p_len*2)) {

      FAIL("Decryption fails");
  }

  ret = (int)out_len;

end:
  if (botan_pk_op_decrypt_destroy(op_ctx) ||
      botan_privkey_destroy(key) ||
      botan_rng_destroy(rng)) {

      ret = -1;
  }

  free(bt_plaintext);
  return ret;
}
