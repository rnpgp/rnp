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

#if defined(__cplusplus)
extern "C" {
#endif

/**
* Function return type. 0 == SUCCESS, all other values indicate an error.
*/
typedef uint32_t rnp_result_t;

const char *rnp_result_to_string(rnp_result_t result);

/*
* Opaque structures
*/
typedef struct rnp_keyring_st *rnp_keyring_t;
typedef struct rnp_key_st *    rnp_key_t;

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

/** load keyrings from a home directory
 *
 * @param secring keyring that will hold the secret keys
 *        (from secring.gpg, private-keys-v1.d, etc.)
 * @param pubring keyring that will hold the public keys
 *        (from pubring.gpg, pubring.kbx, etc.)
 * @param format the format of the keyring (GPG or GPG21), or NULL to guess
 * @param path the path to the directory to load from (example: /home/foo/.rnp),
 *        or NULL to determine it automatically based on the current user.
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_keyring_load_homedir(rnp_keyring_t *secring,
                                      rnp_keyring_t *pubring,
                                      const char *   format,
                                      const char *   path);

/** load a keyring
 *
 * @param ring the keyring
 * @param format the format of the keyring (GPG or GPG21), or NULL to guess
 * @param buf
 * @param buf_len
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_keyring_load(rnp_keyring_t *ring,
                              const char *   format,
                              const uint8_t  buf[],
                              size_t         buf_len);

rnp_key_t *rnp_keyring_find_key(rnp_keyring_t ring, const char *identifer);
rnp_result_t rnp_keyring_add_key(rnp_keyring_t ring, rnp_key_t key);

/** save a keyring to a file
 *
 * @param ring the keyring
 * @param path the path to the file to save to, or NULL to use the path this
 *        keyring is already associated with (for homedir)
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_keyring_save_to_file(rnp_keyring_t ring, const char *path);

rnp_result_t rnp_keyring_save_to_mem(rnp_keyring_t ring, uint8_t *buf[], size_t *buf_len);
rnp_result_t rnp_keyring_free(rnp_keyring_t *ring);

/* TODO: keyring iteration */

/** generate a key (or pair of keys)
 *
 * @param primarykey the primary key pointer that will be populated,
 *        must not be NULL
 * @param subkey the subkey key pointer that will be populated,
 *        must not be NULL
 * @param jsondata the JSON string that describes the key generation,
 *        must not be NULL
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_generate_key_json(rnp_key_t * primarykey,
                                   rnp_key_t * subkey,
                                   const char *jsondata);

/* Key operations */

/**
* Export a public key from the keyring
*/
#define RNP_EXPORT_FLAG_ARMORED (1U << 0)
rnp_result_t rnp_export_public_key(rnp_key_t key,
                                   uint32_t  flags,
                                   char **   output,
                                   size_t *  output_len);

/* TODO: export encrypted secret keys */

rnp_result_t rnp_key_get_primary_uid(rnp_key_t key, char **uid);
rnp_result_t rnp_key_get_uid_count(rnp_key_t key, size_t *count);
rnp_result_t rnp_key_get_uid_at(rnp_key_t key, size_t idx, char **uid);

/* The following output hex encoded strings */
rnp_result_t rnp_key_get_fprint(rnp_key_t key, char **fprint);
rnp_result_t rnp_key_get_keyid(rnp_key_t key, char **keyid);
rnp_result_t rnp_key_get_grip(rnp_key_t key, char **grip);

rnp_result_t rnp_key_is_locked(rnp_key_t key, bool *result);
rnp_result_t rnp_key_unlock(rnp_key_t key, rnp_passphrase_cb cb, void *app_ctx);

rnp_result_t rnp_key_is_protected(rnp_key_t key, bool *result);
rnp_result_t rnp_key_protect(rnp_key_t key, rnp_passphrase_cb cb, void *app_ctx);
rnp_result_t rnp_key_unprotect(rnp_key_t key, rnp_passphrase_cb cb, void *app_ctx);

rnp_result_t rnp_key_is_primary_key(rnp_key_t key, bool *result);
rnp_result_t rnp_key_is_subkey(rnp_key_t key, bool *result);
rnp_result_t rnp_key_is_secret(rnp_key_t key, bool *result);
rnp_result_t rnp_key_is_public(rnp_key_t key, bool *result);

/* TODO: function to add a userid to a key */

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
