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
typedef struct rnp_ffi_st *       rnp_ffi_t;
typedef struct rnp_keyring_st *   rnp_keyring_t;
typedef struct rnp_key_handle_st *rnp_key_handle_t;
typedef struct rnp_input_st *     rnp_input_t;
typedef struct rnp_output_st *    rnp_output_t;
typedef struct rnp_op_encrypt_st *rnp_op_encrypt_t;

/* Callbacks */
typedef ssize_t rnp_input_reader_t(void *app_ctx, void *buf, size_t len);
typedef void    rnp_input_closer_t(void *app_ctx);
typedef int     rnp_output_writer_t(void *app_ctx, const void *buf, size_t len);
typedef void    rnp_output_closer_t(void *app_ctx, bool discard);

/**
 * Callback used for getting a password.
 * @param app_ctx provided by application
 * @param key the key, if any, for which the password is being requested.
 *        Note: this key handle should not be held by the application,
 *        it is destroyed after the callback. It should only be used to
 *        retrieve information like the userids, grip, etc.
 * @param pgp_context a descriptive string for what is being decrypted
 * @param pass to which the callback should write the returned
 * password, NULL terminated.
 * @param pass_len the size of pass buffer
 * @return 0 on success, or any other value to stop decryption.
 */
typedef int (*rnp_password_cb)(
  void *app_ctx, rnp_key_handle_t key, const char *pgp_context, char buf[], size_t buf_len);

/**
 * Callback used for getting a key.
 * @param app_ctx provided by application in rnp_keyring_open
 * @param identifier_type the type of identifier ("userid", "keyid", "fingerprint")
 * @param identifier the identifier for locating the key
 * @param secret true if a secret key is being requested
 * @return the key, or NULL if not found
 */
typedef int (*rnp_get_key_cb)(void *      app_ctx,
                              const char *identifier_type,
                              const char *identifier,
                              bool        secret,
                              uint8_t **  buf, // TODO: note must be alloc with rnp_buffer_new
                              size_t *    buf_len);

rnp_result_t rnp_ffi_create(rnp_ffi_t *ffi, const char *pub_format, const char *sec_format);

/**
 * TODO: note that this invalidates keyring handles and key handles
 */
rnp_result_t rnp_ffi_destroy(rnp_ffi_t ffi);

rnp_result_t rnp_ffi_get_pubring(rnp_ffi_t ffi, rnp_keyring_t *pubring);
rnp_result_t rnp_ffi_get_secring(rnp_ffi_t ffi, rnp_keyring_t *secring);

rnp_result_t rnp_ffi_set_log_fd(rnp_ffi_t ffi, int fd);

rnp_result_t rnp_ffi_set_key_provider(rnp_ffi_t      ffi,
                                      rnp_get_key_cb getkeycb,
                                      void *         getkeycb_ctx);
rnp_result_t rnp_ffi_set_pass_provider(rnp_ffi_t       ffi,
                                       rnp_password_cb getpasscb,
                                       void *          getpasscb_ctx);

/* Operations on key rings */

/** retrieve the default homedir (example: /home/user/.rnp)
 *
 * @param homedir pointer where the homedir string will be stored.
 *        The caller should free this with rnp_buffer_free.
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_get_default_homedir(char **homedir);

/** try to detect the formats and paths of the homedir keyrings
 *
 * @param homedir the path to the home directory (example: /home/user/.rnp)
 * @param pub_format pointer where the the format of the public keyring will
 *        be stored. The caller should free this with rnp_buffer_free.
 * @param pub_path pointer where the the path to the public keyring will
 *        be stored. The caller should free this with rnp_buffer_free.
 * @param sec_format pointer where the the format of the secret keyring will
 *        be stored. The caller should free this with rnp_buffer_free.
 * @param sec_path pointer where the the path to the secret keyring will
 *        be stored. The caller should free this with rnp_buffer_free.
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_detect_homedir_info(
  const char *homedir, char **pub_format, char **pub_path, char **sec_format, char **sec_path);

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

rnp_result_t rnp_keyring_get_format(rnp_keyring_t ring, char **format);
rnp_result_t rnp_keyring_get_path(rnp_keyring_t ring, char **path);
rnp_result_t rnp_keyring_get_key_count(rnp_keyring_t ring, size_t *count);

/** load keys into a keyring, from a path
 *
 * @param ring the keyring
 * @param path
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_keyring_load_from_path(rnp_keyring_t keyring, const char *path);

// TODO: provide a way to indicate what new keys were loaded
/** load keys into a keyring, from a buffer
 *
 * @param ring the keyring
 * @param buf
 * @param buf_len
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_keyring_load_from_memory(rnp_keyring_t keyring,
                                          const uint8_t buf[],
                                          size_t        buf_len);

/** save a keyring to a path
 *
 * @param ring the keyring
 * @param path the path to save to
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_keyring_save_to_path(rnp_keyring_t ring, const char *path);

/** save a keyring to a buffer
 *
 * @param ring the keyring
 * @param path the path to save to
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_keyring_save_to_memory(rnp_keyring_t ring, uint8_t *buf[], size_t *buf_len);

rnp_result_t rnp_locate_key(rnp_ffi_t         ffi,
                            const char *      identifier_type,
                            const char *      identifier,
                            rnp_key_handle_t *key);

rnp_result_t rnp_key_handle_free(rnp_key_handle_t *key);

/* TODO: keyring iteration */

/** generate a key or pair of keys using a JSON description
 *
 *  Notes:
 *  - When generating a subkey, the  pass provider may be required.
 *
 *  @param ffi
 *  @param json the json data that describes the key generation.
 *         Must not be NULL.
 *  @param results pointer where JSON results will be stored.
 *         Must not be NULL.
 *         The caller should free this with rnp_buffer_free.
 *  @return 0 on success, or any other value on error
 */
rnp_result_t rnp_generate_key_json(rnp_ffi_t ffi, const char *json, char **results);

/* Key operations */

/**
 * Export a public key from the keyring
 */
rnp_result_t rnp_export_public_key(rnp_key_handle_t key,
                                   uint32_t         flags,
                                   char **          output,
                                   size_t *         output_len);

/* TODO: export encrypted secret keys */

rnp_result_t rnp_key_get_primary_uid(rnp_key_handle_t key, char **uid);
rnp_result_t rnp_key_get_uid_count(rnp_key_handle_t key, size_t *count);
rnp_result_t rnp_key_get_uid_at(rnp_key_handle_t key, size_t idx, char **uid);

/* The following output hex encoded strings */
rnp_result_t rnp_key_get_fprint(rnp_key_handle_t key, char **fprint);
rnp_result_t rnp_key_get_keyid(rnp_key_handle_t key, char **keyid);
rnp_result_t rnp_key_get_grip(rnp_key_handle_t key, char **grip);

rnp_result_t rnp_key_is_locked(rnp_key_handle_t key, bool *result);
rnp_result_t rnp_key_lock(rnp_key_handle_t key);
rnp_result_t rnp_key_unlock(rnp_key_handle_t key, const char *password);

rnp_result_t rnp_key_is_protected(rnp_key_handle_t key, bool *result);
rnp_result_t rnp_key_protect(rnp_key_handle_t key, const char *password);
rnp_result_t rnp_key_unprotect(rnp_key_handle_t key, const char *password);

rnp_result_t rnp_key_is_primary(rnp_key_handle_t key, bool *result);
rnp_result_t rnp_key_is_sub(rnp_key_handle_t key, bool *result);
rnp_result_t rnp_key_have_secret(rnp_key_handle_t key, bool *result);
rnp_result_t rnp_key_have_public(rnp_key_handle_t key, bool *result);

/* TODO: function to add a userid to a key */

/* Signature/verification operations */

/* TODO define functions for password-based encryption */

/* TODO define functions for encrypt+sign */

void *rnp_buffer_new(size_t size);

/**
 * Free a buffer or string previously allocated by a function in this header.
 */
void rnp_buffer_free(void *ptr);

rnp_result_t rnp_input_from_file(rnp_input_t *input, const char *path);
rnp_result_t rnp_input_from_memory(rnp_input_t *input, const uint8_t buf[], size_t buf_len);
rnp_result_t rnp_input_from_callback(rnp_input_t *       input,
                                     rnp_input_reader_t *reader,
                                     rnp_input_closer_t *closer,
                                     void *              app_ctx);
rnp_result_t rnp_input_destroy(rnp_input_t input);

rnp_result_t rnp_output_to_file(rnp_output_t *output, const char *path);
rnp_result_t rnp_output_to_callback(rnp_output_t *       output,
                                    rnp_output_writer_t *writer,
                                    rnp_output_closer_t *closer,
                                    void *               app_ctx);
rnp_result_t rnp_output_destroy(rnp_output_t output);

/* encrypt */
rnp_result_t rnp_op_encrypt_create(rnp_op_encrypt_t *op,
                                   rnp_ffi_t         ffi,
                                   rnp_input_t       input,
                                   rnp_output_t      output);

rnp_result_t rnp_op_encrypt_add_recipient(rnp_op_encrypt_t op, rnp_key_handle_t key);

// TODO not implemented
rnp_result_t rnp_op_encrypt_add_signer(
  rnp_op_encrypt_t op,
  const char *     identifier_type,
  const char *     identifier,
  const char *     hash,
  uint32_t         creation_time, /* seconds since Jan 1 1970 UTC */
  uint32_t         expiration_seconds);

rnp_result_t rnp_op_encrypt_add_password(rnp_op_encrypt_t op,
                                         const char *     password,
                                         const char *     s2k_hash,
                                         size_t           iterations,
                                         const char *     s2k_cipher);

rnp_result_t rnp_op_encrypt_set_armor(rnp_op_encrypt_t op, bool armored);
rnp_result_t rnp_op_encrypt_set_cipher(rnp_op_encrypt_t op,
                                       const char *     cipher);
rnp_result_t rnp_op_encrypt_set_compression(rnp_op_encrypt_t op,
                                            const char *     compression,
                                            int              level);
rnp_result_t rnp_op_encrypt_set_file_name(rnp_op_encrypt_t op, const char *filename);
rnp_result_t rnp_op_encrypt_set_file_mtime(rnp_op_encrypt_t op, uint32_t mtime);

rnp_result_t rnp_op_encrypt_execute(rnp_op_encrypt_t op);
rnp_result_t rnp_op_encrypt_destroy(rnp_op_encrypt_t op);

rnp_result_t rnp_decrypt(rnp_ffi_t ffi, rnp_input_t input, rnp_output_t output);

rnp_result_t rnp_public_key_bytes(rnp_key_handle_t handle, uint8_t **buf, size_t *buf_len);
rnp_result_t rnp_secret_key_bytes(rnp_key_handle_t handle, uint8_t **buf, size_t *buf_len);

#if defined(__cplusplus)
}
#endif
