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
#include <stdio.h>

#if defined(__cplusplus)
extern "C" {
#endif

/**
* Function return type. 0 == SUCCESS, all other values indicate an error.
*/
typedef uint32_t rnp_result_t;

#define RNP_EXPORT_FLAG_ARMORED (1U << 0)

/**
* Return a constant string describing the result code
*/
const char *rnp_result_to_string(rnp_result_t result);

/*
* Opaque structures
*/
typedef struct rnp_keyring_st *    rnp_keyring_t;
typedef struct rnp_key_st *        rnp_key_t;
typedef struct rnp_op_generate_st *rnp_op_generate_t;

/**
* Callback used for getting a passphrase.
* @param app_ctx provided by application
* @param key the key, if any, for which the passphrase is being requested
* @param pgp_context a descriptive string for what is being decrypted
* @param pass to which the callback should write the returned
* passphrase, NULL terminated.
* @param pass_len the size of pass buffer
* @return 0 on success, or any other value to stop decryption.
*/
typedef int (*rnp_passphrase_cb)(
  void *app_ctx, rnp_key_t key, const char *pgp_context, char buf[], size_t buf_len);

/**
* Callback used for getting a key.
* @param app_ctx provided by application in rnp_keyring_open
* @param identifier_type the type of identifier ("userid", "keyid", "fingerprint")
* @param identifier the identifier for locating the key
* @param secret true if a secret key is being requested
* @return the key, or NULL if not found
*/
typedef rnp_key_t (*rnp_get_key_cb)(void *      app_ctx,
                                    const char *identifier_type,
                                    const char *identifier,
                                    bool        secret);

void rnp_set_io(FILE *output_stream, FILE *error_stream, FILE *result_stream);

/* Operations on key rings */

/** retrieve the default homedir (example: /home/user/.rnp)
 *
 * @param homedir pointer where the homedir string will be stored.
 *        The caller should free this with rnp_buffer_free.
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_get_default_homedir(char **homedir);

/** try to detect the formats of the homedir keyrings
 *
 * @param homedir the path to the home directory (example: /home/user/.rnp)
 * @param pub_format pointer where the the format of the public keyring will
 *        be stored. The caller should free this with rnp_buffer_free.
 * @param sec_format pointer where the the format of the secret keyring will
 *        be stored. The caller should free this with rnp_buffer_free.
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_detect_homedir_formats(const char *homedir,
                                        char **     pub_format,
                                        char **     sec_format);

/** try to detect the key format of the provided data
 *
 * @param buf the key data
 * @param pub_format pointer where the the format of the public keyring will
 *        be stored. The caller should free this with rnp_buffer_free.
 * @param sec_format pointer where the the format of the secret keyring will
 *        be stored. The caller should free this with rnp_buffer_free.
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_detect_key_format(const uint8_t buf[], size_t buf_len, char **format);

/** load keyrings from a home directory
 *
 * @param homedir the path to the home directory (example: /home/user/.rnp)
 * @param pub_format the format of the public keyring (example: GPG)
 * @param sec_format the format of the secret keyring (example: GPG)
 * @param pubring keyring that will hold the public keys
 *        (from pubring.gpg, pubring.kbx, etc.)
 * @param secring keyring that will hold the secret keys
 *        (from secring.gpg, private-keys-v1.d, etc.)
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_keyring_load_homedir(const char *   homedir,
                                      const char *   pub_format,
                                      const char *   sec_format,
                                      rnp_keyring_t *pubring,
                                      rnp_keyring_t *secring);

rnp_result_t rnp_keyring_create(rnp_keyring_t *ring, const char *format, const char *path);
rnp_result_t rnp_keyring_destroy(rnp_keyring_t *ring);
rnp_result_t rnp_keyring_get_format(rnp_keyring_t ring, char **format);
rnp_result_t rnp_keyring_get_path(rnp_keyring_t ring, char **path);
rnp_result_t rnp_keyring_get_key_count(rnp_keyring_t ring, size_t *count);
rnp_result_t rnp_keyring_get_key_at(rnp_keyring_t ring, size_t idx, rnp_key_t *key);

/** load a keyring from a data buffer
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

/** find a key in a keyring
 *
 *  @param ring the keyring
 *  @param identifier_type the type of identifier to use for the search.
 *         Example: "userid", "keyid", "grip".
 *         Use NULL to perform a fuzzy userid/keyid search.
 *  @param identifier the identifier to search for
 *  @param key pointer where the found key will be set (if any)
 *  @return 0 on success, or any other value on error
 */
rnp_result_t rnp_keyring_find_key(rnp_keyring_t ring,
                                  const char *  identifier_type,
                                  const char *  identifier,
                                  rnp_key_t *   key);

rnp_result_t rnp_keyring_add_key(rnp_keyring_t ring, rnp_key_t key);

/** save a keyring to a file
 *
 * @param ring the keyring
 * @param path the path to the file to save to, or NULL to use the path this
 *        keyring is already associated with (for homedir)
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_keyring_save_to_file(rnp_keyring_t ring, const char *path);

rnp_result_t rnp_keyring_save_to_mem(rnp_keyring_t ring,
                                     int           flags,
                                     uint8_t *     buf[],
                                     size_t *      buf_len);

rnp_result_t rnp_key_free(rnp_key_t *key);

/* TODO: keyring iteration */

/** generate a key or pair of keys using a JSON description
 *
 * @param pubring the keyring where the generated public keys will
 *        be stored. May be NULL.
 * @param secring the keyring where the generated secret keys will
 *        be stored. May be NULL.
 * @param getkeycb the callback to retrieve keys. This is only used
 *        if the desired key is not already present in the provided
 *        rings, and generally only when adding a subkey to an
 *        already-existant primary. May be NULL.
 * @param getpasscb the callback to retrieve passphrases. This is
 *        generally only used when adding a subkey to an
 *        already-existant primary. May be NULL.
*  @param app_ctx provided by application
*  @param json the json data that describes the key generation.
*         The caller should free this with rnp_buffer_free.
 * @return 0 on success, or any other value on error
 */

rnp_result_t rnp_generate_key_json(rnp_keyring_t     pubring,
                                   rnp_keyring_t     secring,
                                   rnp_get_key_cb    getkeycb,
                                   rnp_passphrase_cb getpasscb,
                                   void *            app_ctx,
                                   const char *      json,
                                   char **           results);

rnp_result_t rnp_generate_private_key(rnp_key_t *   pubkey,
                                      rnp_key_t *   seckey,
                                      rnp_keyring_t pubring,
                                      rnp_keyring_t secring,
                                      const char *  userid,
                                      const char *  passphrase,
                                      const char *  signature_hash);

/* Key operations */

/**
* Export a public key from the keyring
*/
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
rnp_result_t rnp_key_lock(rnp_key_t key);
rnp_result_t rnp_key_unlock(rnp_key_t key, rnp_passphrase_cb cb, void *app_ctx);

rnp_result_t rnp_key_is_protected(rnp_key_t key, bool *result);
rnp_result_t rnp_key_protect(rnp_key_t key, const char *passphrase);
rnp_result_t rnp_key_unprotect(rnp_key_t key, rnp_passphrase_cb cb, void *app_ctx);

rnp_result_t rnp_key_is_primary(rnp_key_t key, bool *result);
rnp_result_t rnp_key_is_sub(rnp_key_t key, bool *result);
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

rnp_result_t rnp_encrypt(rnp_keyring_t     keyring,
                         const char *const recipients[],
                         size_t            recipients_len,
                         const char *      cipher,
                         const char *      z_alg,
                         size_t            z_level,
                         bool              armored,
                         const uint8_t     msg[],
                         size_t            msg_len,
                         uint8_t **        output,
                         size_t *          output_len);

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
