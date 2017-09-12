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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
* Currently we use some definitions/enums from other others, including
* - rnp_result
* - pgp_hash_alg_t
* - pgp_pubkey_alg_t
*
* It might be good to consolidate these definitions into one spot, or
* else replicate them here in new enums and make this header freestanding.
*/
#include <rnp_def.h>
#include <repgp_def.h>

#if defined(__cplusplus)
extern "C" {
#endif

/*
* Opaque structures for key types
*/
typedef struct rnp_publickey_st * rnp_public_key;
typedef struct rnp_privatekey_st *rnp_private_key;

// typedef struct rnp_keyring_st* rnp_keyring;

/* Operations on public keys */

/**
* Load a public key
* @param key a pointer, on success will be assigned to the new object
* @param buf the serialized key (either binary or ASCII formats accepted)
* @param buf_len length of buf in bytes
*/
rnp_result rnp_public_key_load(rnp_public_key *key, const uint8_t buf[], size_t buf_len);

/**
* @param key the public key
* @param uid on success will be set to the UID of the key
*/
rnp_result rnp_public_key_get_uid(rnp_public_key key, char **uid);

/**
* @param key the public key
* @param fprint on success will be set to the fingerprint of the key
*/
rnp_result rnp_public_key_get_fprint(rnp_public_key key, char **fprint);

/* Operations on private keys */

/**
* Callback used for getting a passphrase.
* @param app_ctx provided by application
* @param key the key that is being decrypted
* @param pass to which the callback should write the returned
* passphrase, NULL terminated.
* @param pass_len the size of pass buffer
* @return 0 on success, or any other value to stop decryption.
*/
typedef int (*rnp_passphrase_cb)(void *          app_ctx,
                                 rnp_private_key key,
                                 char            buf[],
                                 size_t          buf_len);

/*
* Load a private key into memory. Initially it will be encrypted,
* assuming the input is encrypted.
*/
rnp_result rnp_private_key_load(rnp_private_key *key, const uint8_t buf[], size_t buf_len);

rnp_result rnp_private_key_is_decrypted(rnp_private_key key);

rnp_result rnp_private_key_decrypt(rnp_private_key key, rnp_passphrase_cb cb, void *app_ctx);

/**
* @param sub_alg may be 0 (NONE) to disable subkeys
*/
rnp_result rnp_generate_key(rnp_private_key *key,
                            const char *     userid,
                            pgp_pubkey_alg_t prim_alg,
                            pgp_pubkey_alg_t sub_alg,
                            pgp_hash_alg_t   signature_hash,
                            uint32_t         expiration);

rnp_result rnp_private_set_hash_prefs(rnp_private_key key,
                                      const uint8_t   hash_prefs[],
                                      size_t          len_hash_prefs);
/* TODO other set_*_prefs plus get_*_prefs */

/**
* Export the public key associated with this key
*/
rnp_result rnp_private_export_public(rnp_private_key key,
                                     bool            armor,
                                     uint8_t **      output,
                                     size_t *        output_len);

/**
* Export an unencrypted private key
*/
rnp_result rnp_private_export(rnp_private_key key,
                              bool            armor,
                              uint8_t **      output,
                              size_t *        output_len);

/**
* Export an encrypted private key
*/
rnp_result rnp_private_export_encrypted(rnp_private_key key,
                                        const char *    passphrase,
                                        pgp_symm_alg_t  cipher,
                                        pgp_hash_alg_t  s2k_hash,
                                        uint32_t        s2k_hash_iterations,
                                        uint8_t **      output,
                                        size_t *        output_len);

/* Signature/verification operations */

enum rnp_signature_type { SIG_NORMAL, SIG_ARMOR, SIG_DETACHED };

/**
* Sign a message
* @param key the private key, must be decrypted
* @param hash the hash
* @param type the signature type (binary, armored, or detached)
* @param msg the message to sign
* @param msg_len the length of msg in bytes
* @param sig on success, the output signature buffer
* @param sig_len on success, the length of sig in bytes
*/
rnp_result rnp_sign(rnp_private_key    key,
                    pgp_hash_alg_t     hash,
                    rnp_signature_type type,
                    const uint8_t      msg[],
                    size_t             msg_len,
                    uint8_t **         sig,
                    size_t *           sig_len);

/**
* Verify a signature with embedded message
* @param key the public key
* @param sig the signature
* @param sig_len length of signature in bytes
* @param msg on succes, output buffer to the message
* @param msg_len on success, length of msg in bytes
* @param hash_used if non-null and on success, set to the
* hash algorithm used to create the signature.
*/
rnp_result rnp_verify(rnp_public_key  key,
                      const uint8_t   sig[],
                      size_t          sig_len,
                      uint8_t **      msg,
                      size_t *        msg_len,
                      pgp_hash_alg_t *hash_used);

/**
* Verify a detached signature
* @param key the key to verify with
* @param msg the message bits being verified
* @param msg_len length of msg in bytes
* @parma sig the signature
* @param sig_len length of signature in bytes
* @param hash_used if non-null, and the signature is verified,
* the hash algorithm used to create the signature will be returned.
* @return RNP_SUCCESS if valid otherwise error
*/
rnp_result rnp_verify_detached(rnp_public_key  key,
                               const uint8_t   msg[],
                               size_t          msg_len,
                               const uint8_t   sig[],
                               size_t          sig_len,
                               pgp_hash_alg_t *hash_used);

/* Encryption/decryption operations */

rnp_result rnp_encrypt(rnp_public_key key,
                       pgp_symm_alg_t cipher,
                       const uint8_t  msg[],
                       size_t         msg_len,
                       bool           armor,
                       uint8_t **     output,
                       size_t *       output_len);

/**
* Decrypt a message
* @param key the private key to attempt decryption with
* @param msg the ciphertext
* @param msg_len length of msg in bytes
* @param output pointer that will be set to a newly allocated
* buffer, length *output_len, free with rnp_buffer_free
* @param output_len will be set to the length of output
* @param cipher_used if non-null will be set to the cipher used
* to encrypt the message.
*/
rnp_result rnp_decrypt(rnp_private_key key,
                       const uint8_t   msg[],
                       size_t          msg_len,
                       uint8_t **      output,
                       size_t *        output_len,
                       pgp_symm_alg_t *cipher_used);

/* TODO define functions for password-based encryption */

/* TODO define functions for encrypt+sign */

/**
* Free a buffer previously allocated by a function in this header.
*/
void rnp_buffer_free(void *ptr);

#if defined(__cplusplus)
}
#endif
