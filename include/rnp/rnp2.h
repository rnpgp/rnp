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
* - rnp_result_t
*
* It might be good to consolidate these definitions into one spot, or
* else replicate them here in new enums and make this header freestanding.
*/
#include <rnp/rnp_def.h>

#if defined(__cplusplus)
extern "C" {
#endif

/*
* Opaque structures for key types
*/
typedef struct rnp_keyring_st *rnp_keyring_t;

/**
* Callback used for getting a passphrase.
* @param app_ctx provided by application in rnp_keyring_open
* @param pgp_context a descriptive string for what is being decrypted
* @param pass to which the callback should write the returned
* passphrase, NULL terminated.
* @param pass_len the size of pass buffer
* @return 0 on success, or any other value to stop decryption.
*/
typedef int (*rnp_passphrase_cb)(void *      app_ctx,
                                 const char *pgp_context,
                                 char        buf[],
                                 size_t      buf_len);

/* Operations on key rings */

rnp_result_t rnp_keyring_open(rnp_keyring_t *   keyring,
                              const char *      keyring_format,
                              const char *      pub_path,
                              const char *      sec_path,
                              rnp_passphrase_cb cb,
                              void *            app_ctx);

rnp_result_t rnp_keyring_close(rnp_keyring_t keyring);

/**
* Load a public key into the keyring
* @param key a pointer, on success will be assigned to the new object
* @param key_bits the binary serialized key
* @param key_len length of key_bits in bytes
*/
rnp_result_t rnp_insert_public_key(rnp_keyring_t keyring,
                                   const char *  key_format,
                                   const uint8_t key_bits[],
                                   size_t        key_len);

/**
* Load an armored public key into the keyring
* @param key a pointer, on success will be assigned to the new object
* @param key the PGP armored public key
*/
rnp_result_t rnp_insert_armored_public_key(rnp_keyring_t keyring, const char *key);

/**
* Generate a key and add it to the keyring
*/
rnp_result_t rnp_generate_private_key(rnp_keyring_t keyring,
                                      const char *  userid,
                                      const char *  signature_hash,
                                      const char *  primary_key_algo,
                                      const char *  primary_key_params,
                                      const char *  privkey_passphrase,
                                      uint32_t      primary_expiration,
                                      const char *  subkey_algo,
                                      const char *  subkey_params,
                                      const char *  subkey_passphrase,
                                      uint32_t      subkey_expiration);

/**
* Export a public key from the keyring
*/
rnp_result_t rnp_export_public_key(rnp_keyring_t keyringt, const char *ident, char **output);

/* Signature/verification operations */

/**
* Generate an embedded signature (the output will include the
* message contents)
* @param keyring the keyring
* @param ident the key to sign with
* @param hash_fn the hash function to use
* @param msg the message to sign
* @param msg_len the length of msg in bytes
* @param sig on success, the output signature buffer
* @param sig_len on success, the length of sig in bytes
*/
rnp_result_t rnp_sign(rnp_keyring_t keyring,
                      const char *  ident,
                      const char *  hash_fn,
                      bool          clearsign,
                      bool          armor,
                      const uint8_t msg[],
                      size_t        msg_len,
                      uint8_t **    sig,
                      size_t *      sig_len);

/**
* Generate an embedded signature (the output will include the
* message contents)
* @param keyring the keyring
* @param ident the key to sign with
* @param hash_fn the hash function to use
* @param msg the message to sign
* @param msg_len the length of msg in bytes
* @param sig on success, the output signature buffer
* @param sig_len on success, the length of sig in bytes
*/
rnp_result_t rnp_sign_detached(rnp_keyring_t keyring,
                               const char *  ident,
                               const char *  hash_fn,
                               bool          armor,
                               const uint8_t msg[],
                               size_t        msg_len,
                               uint8_t **    sig,
                               size_t *      sig_len);

/**
* Verify a signature with embedded message
* @param key the keyring
* @param sig the signature
* @param sig_len length of signature in bytes
* @param msg on succes, output buffer to the message
* @param msg_len on success, length of msg in bytes
*/

rnp_result_t rnp_verify(
  rnp_keyring_t keyring, const uint8_t sig[], size_t sig_len, uint8_t **msg, size_t *msg_len);

/**
* Verify a detached signature
* @param key the key to verify with
* @param msg the message bits being verified
* @param msg_len length of msg in bytes
* @parma sig the signature
* @param sig_len length of signature in bytes
* @return RNP_SUCCESS if valid otherwise error
*/
rnp_result_t rnp_verify_detached(rnp_keyring_t keyring,
                                 const uint8_t msg[],
                                 size_t        msg_len,
                                 const uint8_t sig[],
                                 size_t        sig_len);

/**
* Verify a detached signature
* @param key the key to verify with
* @param file_path path to the file to be verified
* @parma sig the signature
* @param sig_len length of signature in bytes
* @return RNP_SUCCESS if valid otherwise error
*/
rnp_result_t rnp_verify_detached_file(rnp_keyring_t keyring,
                                      const char *  file_path,
                                      const uint8_t sig[],
                                      size_t        sig_len);

/* Encryption/decryption operations */

rnp_result_t rnp_encrypt(rnp_keyring_t keyring,
                         const char *  ident,
                         const char *  cipher,
                         const char *  z_alg,
                         size_t        z_level,
                         bool          armored,
                         const uint8_t msg[],
                         size_t        msg_len,
                         uint8_t **    output,
                         size_t *      output_len);

/**
* Decrypt a message
* @param key the private key to attempt decryption with
* @param msg the ciphertext
* @param msg_len length of msg in bytes
* @param output pointer that will be set to a newly allocated
* buffer, length *output_len, free with rnp_buffer_free
* @param output_len will be set to the length of output
*/
rnp_result_t rnp_decrypt(rnp_keyring_t keyring,
                         const uint8_t msg[],
                         size_t        msg_len,
                         uint8_t **    output,
                         size_t *      output_len);

/* TODO define functions for password-based encryption */

/* TODO define functions for encrypt+sign */

/**
* Free a buffer or string previously allocated by a function in this header.
*/
void rnp_buffer_free(void *ptr);

#if defined(__cplusplus)
}
#endif
