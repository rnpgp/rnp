/*-
 * Copyright (c) 2017,2018 Ribose Inc.
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
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS
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
 * Flags for optional details to include in JSON.
 */
#define RNP_JSON_PUBLIC_MPIS (1U << 0)
#define RNP_JSON_SECRET_MPIS (1U << 1)
#define RNP_JSON_SIGNATURES (1U << 2)
#define RNP_JSON_SIGNATURE_MPIS (1U << 3)

/**
 * Flags for the key loading/saving functions.
 */
#define RNP_LOAD_SAVE_PUBLIC_KEYS (1U << 0)
#define RNP_LOAD_SAVE_SECRET_KEYS (1U << 1)

/**
 * Return a constant string describing the result code
 */
const char *rnp_result_to_string(rnp_result_t result);

/*
 * Opaque structures
 */
typedef struct rnp_ffi_st *                rnp_ffi_t;
typedef struct rnp_key_handle_st *         rnp_key_handle_t;
typedef struct rnp_input_st *              rnp_input_t;
typedef struct rnp_output_st *             rnp_output_t;
typedef struct rnp_op_sign_st *            rnp_op_sign_t;
typedef struct rnp_op_sign_signature_st *  rnp_op_sign_signature_t;
typedef struct rnp_op_verify_st *          rnp_op_verify_t;
typedef struct rnp_op_verify_signature_st *rnp_op_verify_signature_t;
typedef struct rnp_op_encrypt_st *         rnp_op_encrypt_t;
typedef struct rnp_identifier_iterator_st *rnp_identifier_iterator_t;

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
 * @param identifier_type the type of identifier ("userid", "keyid",
 * "fingerprint")
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

/** create the top-level object used for interacting with the library
 *
 *  @param ffi pointer that will be set to the created ffi object
 *  @param pub_format the format of the public keyring
 *  @param sec_format the format of the secret keyring
 *  @return 0 on success, or any other value on error
 */
rnp_result_t rnp_ffi_create(rnp_ffi_t *ffi, const char *pub_format, const char *sec_format);

/** destroy the top-level object used for interacting with the library
 *
 *  Note that this invalidates key handles, keyrings, and any other
 *  objects associated with this particular object.
 *
 *  @param ffi the ffi object
 *  @return 0 on success, or any other value on error
 */
rnp_result_t rnp_ffi_destroy(rnp_ffi_t ffi);

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
 * @param homedir pointer that will be set to the homedir path.
 *        The caller should free this with rnp_buffer_free.
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_get_default_homedir(char **homedir);

/** try to detect the formats and paths of the homedir keyrings
 *
 * @param homedir the path to the home directory (example: /home/user/.rnp)
 * @param pub_format pointer that will be set to the format of the public keyring.
 *        The caller should free this with rnp_buffer_free.
 * @param pub_path pointer that will be set to the path to the public keyring.
 *        The caller should free this with rnp_buffer_free.
 * @param sec_format pointer that will be set to the format of the secret keyring.
 *        The caller should free this with rnp_buffer_free.
 * @param sec_path pointer that will be set to the path to the secret keyring.
 *        The caller should free this with rnp_buffer_free.
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_detect_homedir_info(
  const char *homedir, char **pub_format, char **pub_path, char **sec_format, char **sec_path);

/** try to detect the key format of the provided data
 *
 * @param buf the key data, must not be NULL
 * @param buf_len the size of the buffer, must be > 0
 * @param format pointer that will be set to the format of the keyring.
 *        Must not be NULL. The caller should free this with rnp_buffer_free.
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_detect_key_format(const uint8_t buf[], size_t buf_len, char **format);

/** load keys
 *
 * Note that for G10, the input must be a directory (which must already exist).
 *
 * @param ffi
 * @param format the key format of the data (GPG, KBX, G10). Must not be NULL.
 * @param input source to read from.
 * @param flags the flags. See RNP_LOAD_SAVE_*.
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_load_keys(rnp_ffi_t   ffi,
                           const char *format,
                           rnp_input_t input,
                           uint32_t    flags);

/** save keys
 *
 * Note that for G10, the output must be a directory (which must already exist).
 *
 * @param ffi
 * @param format the key format of the data (GPG, KBX, G10). Must not be NULL.
 * @param output the output destination to write to.
 * @param flags the flags. See RNP_LOAD_SAVE_*.
 * @return 0 on success, or any other value on error
 */
rnp_result_t rnp_save_keys(rnp_ffi_t    ffi,
                           const char * format,
                           rnp_output_t output,
                           uint32_t     flags);

rnp_result_t rnp_get_public_key_count(rnp_ffi_t ffi, size_t *count);
rnp_result_t rnp_get_secret_key_count(rnp_ffi_t ffi, size_t *count);

rnp_result_t rnp_locate_key(rnp_ffi_t         ffi,
                            const char *      identifier_type,
                            const char *      identifier,
                            rnp_key_handle_t *key);

rnp_result_t rnp_key_handle_free(rnp_key_handle_t *key);

/** generate a key or pair of keys using a JSON description
 *
 *  Notes:
 *  - When generating a subkey, the  pass provider may be required.
 *
 *  @param ffi
 *  @param json the json data that describes the key generation.
 *         Must not be NULL.
 *  @param results pointer that will be set to the JSON results.
 *         Must not be NULL. The caller should free this with rnp_buffer_free.
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

/** Add a new user identifier to a key
 *
 *  @param ffi
 *  @param key the key to add - must be a secret key
 *  @param uid the UID to add
 *  @param hash name of the hash function to use for the uid binding
 *         signature (eg "SHA256")
 *  @param expiration time when this user id expires
 *  @param key_flags usage flags, see section 5.2.3.21 of RFC 4880
 *         or just provide zero to indicate no special handling.
 *  @param primary indicates if this is the primary UID
 */
rnp_result_t rnp_key_add_uid(rnp_ffi_t        ffi,
                             rnp_key_handle_t key,
                             const char *     uid,
                             const char *     hash,
                             uint32_t         expiration,
                             uint8_t          key_flags,
                             bool             primary);

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

/* Signing operations */

/** @brief Create signing operation context. This method should be used for embedded
 *         signatures of binary data. For detached and cleartext signing corresponding
 *         function should be used.
 *  @param op pointer to opaque signing context
 *  @param ffi
 *  @param input stream with data to be signed. Could not be NULL.
 *  @param output stream to write results to. Could not be NULL.
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_create(rnp_op_sign_t *op,
                                rnp_ffi_t      ffi,
                                rnp_input_t    input,
                                rnp_output_t   output);

/** @brief Create cleartext signing operation context. Input should be text data. Output will
 *         contain source data with additional headers and armored signature.
 *  @param op pointer to opaque signing context
 *  @param ffi
 *  @param input stream with data to be signed. Could not be NULL.
 *  @param output stream to write results to. Could not be NULL.
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_cleartext_create(rnp_op_sign_t *op,
                                          rnp_ffi_t      ffi,
                                          rnp_input_t    input,
                                          rnp_output_t   output);

/** @brief Create detached signing operation context. Output will contain only signature of the
 *         source data.
 *  @param op pointer to opaque signing context
 *  @param ffi
 *  @param input stream with data to be signed. Could not be NULL.
 *  @param output stream to write results to. Could not be NULL.
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_detached_create(rnp_op_sign_t *op,
                                         rnp_ffi_t      ffi,
                                         rnp_input_t    input,
                                         rnp_output_t   signature);

/** @brief Add information about the signature so it could be calculated later in execute
 *         function call. Multiple signatures could be added.
 *  @param op opaque signing context. Must be successfully initialized with one of the
 *         rnp_op_sign_*_create functions.
 *  @param key handle of the private key. Private key should be capable for signing.
 *  @param sig pointer to opaque structure holding the signature information. May be NULL.
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_add_signature(rnp_op_sign_t            op,
                                       rnp_key_handle_t         key,
                                       rnp_op_sign_signature_t *sig);

/** @brief Set hash algorithm used during signature calculation. Not implemented yet.
 *  @param sig opaque signature context, returned via rnp_op_sign_add_signature
 *  @param hash hash algorithm to be used
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_signature_set_hash(rnp_op_sign_signature_t sig, const char *hash);

/** @brief Set signature creation time. Not implemented yet.
 *  @param sig opaque signature context, returned via rnp_op_sign_add_signature
 *  @param create creation time in seconds since Jan, 1 1970 UTC
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_signature_set_creation_time(rnp_op_sign_signature_t sig,
                                                     uint32_t                create);

/** @brief Set signature expiration time. Not implemented yet.
 *  @param sig opaque signature context, returned via rnp_op_sign_add_signature
 *  @param expire expiration time in seconds since the creation time. 0 value is used to mark
 *         signature as non-expiring (default value)
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_signature_set_expiration_time(rnp_op_sign_signature_t sig,
                                                       uint32_t                expires);

/** @brief Set data compression parameters. Makes sense only for embedded signatures.
 *  @param op opaque signing context. Must be initialized with rnp_op_sign_create function
 *  @param compression compression algorithm (zlib, zip, bzip2)
 *  @param level compression level, 0-9. 0 disables compression.
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_set_compression(rnp_op_sign_t op, const char *compression, int level);

/** @brief Enabled or disable armored (textual) output. Doesn't make sense for cleartext sign.
 *  @param op opaque signing context. Must be initialized with rnp_op_sign_create or
 *         rnp_op_sign_detached_create function.
 *  @param armored true if armoring should be used (it is disabled by default)
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_set_armor(rnp_op_sign_t op, bool armored);

/** @brief Set hash algorithm used during signature calculation. This will set hash function
 *         for all signature. To change it for a single signature use
 *         rnp_op_sign_signature_set_hash function.
 *  @param op opaque signing context. Must be successfully initialized with one of the
 *         rnp_op_sign_*_create functions.
 *  @param hash hash algorithm to be used
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_set_hash(rnp_op_sign_t op, const char *hash);

/** @brief Set signature creation time. By default current time is used.
 *  @param op opaque signing context. Must be successfully initialized with one of the
 *         rnp_op_sign_*_create functions.
 *  @param create creation time in seconds since Jan, 1 1970 UTC
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_set_creation_time(rnp_op_sign_t op, uint32_t create);

/** @brief Set signature expiration time.
 *  @param op opaque signing context. Must be successfully initialized with one of the
 *         rnp_op_sign_*_create functions.
 *  @param expire expiration time in seconds since the creation time. 0 value is used to mark
 *         signature as non-expiring (default value)
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_set_expiration_time(rnp_op_sign_t op, uint32_t expire);

/** @brief Set input's file name. Makes sense only for embedded signature.
 *  @param op opaque signing context. Must be initialized with rnp_op_sign_create function
 *  @param filename source data file name. Special value _CONSOLE may be used to mark message
 *         as 'for your eyes only', i.e. it should not be stored anywhere but only displayed
 *         to the receiver. Default is the empty string.
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_set_file_name(rnp_op_sign_t op, const char *filename);

/** @brief Set input's file modification date. Makes sense only for embedded signature.
 *  @param op opaque signing context. Must be initialized with rnp_op_sign_create function
 *  @param mtime modification time in seconds since Jan, 1 1970 UTC.
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_sign_set_file_mtime(rnp_op_sign_t op, uint32_t mtime);

/** @brief Execute previously initialized signing operation.
 *  @param op opaque signing context. Must be successfully initialized with one of the
 *         rnp_op_sign_*_create functions. At least one signing key should be added.
 *  @return RNP_SUCCESS or error code if failed. On success output stream, passed in the create
 *          function call, will be populated with signed data
 */
rnp_result_t rnp_op_sign_execute(rnp_op_sign_t op);

/** @brief Free resources associated with signing operation.
 *  @param op opaque signing context. Must be successfully initialized with one of the
 *         rnp_op_sign_*_create functions. At least one signing key should be added.
 *  @return RNP_SUCCESS or error code if failed.
 */
rnp_result_t rnp_op_sign_destroy(rnp_op_sign_t op);

/* Verification */

/** @brief Create verification operation context. This method should be used for embedded
 *         signatures or cleartext signed data. For detached verification corresponding
 *         function should be used.
 *  @param op pointer to opaque verification context
 *  @param ffi
 *  @param input stream with signed data. Could not be NULL.
 *  @param output stream to write results to. Could not be NULL, but may be null output stream
 *         if verified data should be discarded.
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_verify_create(rnp_op_verify_t *op,
                                  rnp_ffi_t        ffi,
                                  rnp_input_t      input,
                                  rnp_output_t     output);

/** @brief Create verification operation context for detached signature.
 *  @param op pointer to opaque verification context
 *  @param ffi
 *  @param input stream with raw data. Could not be NULL.
 *  @param signature stream with detached signature data
 *  @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_verify_detached_create(rnp_op_verify_t *op,
                                           rnp_ffi_t        ffi,
                                           rnp_input_t      input,
                                           rnp_input_t      signature);

/** @brief Execute previously initialized verification operation.
 *  @param op opaque verification context. Must be successfully initialized.
 *  @return RNP_SUCCESS if data was processed successfully and all signatures are valid.
 *          Otherwise error code is returned. After rnp_op_verify_execute()
 *          rnp_op_verify_get_* functions may be used to query information about the
 *          signature(s).
 */
rnp_result_t rnp_op_verify_execute(rnp_op_verify_t op);

/** @brief Get number of the signatures for verified data.
 *  @param op opaque verification context. Must be initialized and have execute() called on it.
 *  @param count result will be stored here on success.
 *  @return RNP_SUCCESS if call succeeded.
 */
rnp_result_t rnp_op_verify_get_signature_count(rnp_op_verify_t op, size_t *count);

/** @brief Get single signature information based on it's index.
 *  @param op opaque verification context. Must be initialized and have execute() called on it.
 *  @param sig opaque signature context data will be stored here on success.
 *  @return RNP_SUCCESS if call succeeded.
 */
rnp_result_t rnp_op_verify_get_signature_at(rnp_op_verify_t            op,
                                            size_t                     idx,
                                            rnp_op_verify_signature_t *sig);

/** @brief Get embedded in OpenPGP data file name and modification time. Makes sense only for
 *         embedded signature verification.
 *  @param op opaque verification context. Must be initialized and have execute() called on it.
 *  @param filename pointer to the filename. On success caller is responsible for freeing it
 *                  via the rnp_buffer_free function call. May be NULL if this information is
 *                  not needed.
 *  @param mtime file modification time will be stored here on success. May be NULL.
 *  @return RNP_SUCCESS if call succeeded.
 */
rnp_result_t rnp_op_verify_get_file_info(rnp_op_verify_t op, char **filename, uint32_t *mtime);

/** @brief Free resources allocated in verification context.
 *  @param op opaque verification context. Must be initialized.
 *  @return RNP_SUCCESS if call succeeded.
 */
rnp_result_t rnp_op_verify_destroy(rnp_op_verify_t op);

/** @brief Get signature verification status.
 *  @param sig opaque signature context obtained via rnp_op_verify_get_signature_at call.
 *  @return signature verification status:
 *          RNP_SUCCESS : signature is valid
 *          RNP_ERROR_SIGNATURE_EXPIRED : signature is valid but expired
 *          RNP_ERROR_KEY_NOT_FOUND : public key to verify signature was not available
 *          RNP_ERROR_SIGNATURE_INVALID : data or signature was modified
 */
rnp_result_t rnp_op_verify_signature_get_status(rnp_op_verify_signature_t sig);

/** @brief Get hash function used to calculate signature
 *  @param sig opaque signature context obtained via rnp_op_verify_get_signature_at call.
 *  @param hash pointer to string with hash algorithm name will be put here on success.
 *              Caller is responsible for freeing it with rnp_buffer_free
 *  @return RNP_SUCCESS or error code otherwise
 */
rnp_result_t rnp_op_verify_signature_get_hash(rnp_op_verify_signature_t sig, char **hash);

/** @brief Get key used for signing
 *  @param sig opaque signature context obtained via rnp_op_verify_get_signature_at call.
 *  @param key pointer to opaque key handle structure.
 *  @return RNP_SUCCESS or error code otherwise
 */
rnp_result_t rnp_op_verify_signature_get_key(rnp_op_verify_signature_t sig,
                                             rnp_key_handle_t *        key);

/** @brief Get signature creation and expiration times
 *  @param sig opaque signature context obtained via rnp_op_verify_get_signature_at call.
 *  @param create signature creation time will be put here. It is number of seconds since
 *                Jan, 1 1970 UTC. May be NULL if called doesn't need this data.
 *  @param expires signature expiration time will be stored here. It is number of seconds since
 *                 the creation time or 0 if signature never expires. May be NULL.
 *  @return RNP_SUCCESS or error code otherwise
 */
rnp_result_t rnp_op_verify_signature_get_times(rnp_op_verify_signature_t sig,
                                               uint32_t *                create,
                                               uint32_t *                expires);

/* TODO define functions for encrypt+sign */

/**
 * @brief Allocate and fill with zeroes buffer of the required size.
 *
 * @param size number of bytes to allocate.
 * @return pointer to the buffer or NULL if allocation failed.
 */
void *rnp_buffer_new(size_t size);

/**
 * @brief Free buffer allocated with rnp_buffer_new or any other function in this header.
 *
 * @param ptr previously allocated buffer. May be NULL, then nothing is done.
 */
void rnp_buffer_free(void *ptr);

/**
 * @brief Initialize input struct to read from a path
 *
 * @param input pointer to the input opaque structure
 * @param path path of the file to read from
 * @return RNP_SUCCESS if operation succeeded and input struct is ready to read, or error code
 * otherwise
 */
rnp_result_t rnp_input_from_path(rnp_input_t *input, const char *path);

/**
 * @brief Initialize input struct to read from memory
 *
 * @param input pointer to the input opaque structure
 * @param buf memory buffer. Could not be NULL.
 * @param buf_len number of bytes available to read from buf
 * @param take_ownership copy buffer internally so it could be safely freed
 * @return RNP_SUCCESS if operation succeeded or error code otherwise
 */
rnp_result_t rnp_input_from_memory(rnp_input_t * input,
                                   const uint8_t buf[],
                                   size_t        buf_len,
                                   bool          take_ownership);

/**
 * @brief Initialize input struct to read via callbacks
 *
 * @param input pointer to the input opaque structure
 * @param reader callback used for reading
 * @param closer callback used to close the stream
 * @param app_ctx context to pass as parameter to reader and closer
 * @return RNP_SUCCESS if operation succeeded or error code otherwise
 */
rnp_result_t rnp_input_from_callback(rnp_input_t *       input,
                                     rnp_input_reader_t *reader,
                                     rnp_input_closer_t *closer,
                                     void *              app_ctx);

/**
 * @brief Close previously opened input and free all corresponding resources
 *
 * @param input previously opened input structure
 * @return RNP_SUCCESS if operation succeeded or error code otherwise
 */
rnp_result_t rnp_input_destroy(rnp_input_t input);

/**
 * @brief Initialize output structure to write to a path. If path is a file
 * that already exists then operation will fail.
 *
 * @param output pointer to the opaque output structure.
 * @param path path to the file.
 * @return RNP_SUCCESS if file was opened successfully and ready for writing or error code
 * otherwise.
 */
rnp_result_t rnp_output_to_path(rnp_output_t *output, const char *path);

/**
 * @brief Initialize output structure to write to the memory.
 *
 * @param output pointer to the opaque output structure.
 * @param max_alloc maximum amount of memory to allocate. 0 value means unlimited.
 * @return RNP_SUCCESS if operation succeeded or error code otherwise.
 */
rnp_result_t rnp_output_to_memory(rnp_output_t *output, size_t max_alloc);

/**
 * @brief Get the pointer to the buffer of output, initialized by rnp_output_to_memory
 *
 * @param output output structure, initialized by rnp_output_to_memory and populated with data
 * @param buf pointer to the buffer will be stored here, could not be NULL
 * @param len number of bytes in buffer will be stored here, could not be NULL
 * @param take_ownership take ownership on the data so it must be freed by caller
 * @return RNP_SUCCESS if operation succeeded or error code otherwise.
 */
rnp_result_t rnp_output_memory_get_buf(rnp_output_t output,
                                       uint8_t **   buf,
                                       size_t *     len,
                                       bool         take_ownership);

/**
 * @brief Initialize output structure to write to callbacks.
 *
 * @param output pointer to the opaque output structure.
 * @param writer write callback.
 * @param closer close callback.
 * @param app_ctx context parameter which will be passed to writer and closer.
 * @return RNP_SUCCESS if operation succeeded or error code otherwise.
 */
rnp_result_t rnp_output_to_callback(rnp_output_t *       output,
                                    rnp_output_writer_t *writer,
                                    rnp_output_closer_t *closer,
                                    void *               app_ctx);

/**
 * @brief Initialize output structure which will discard all data
 *
 * @param output pointer to the opaque output structure.
 * @return RNP_SUCCESS if operation succeeded or error code otherwise.
 */
rnp_result_t rnp_output_to_null(rnp_output_t *output);

/**
 * @brief Close previously opened output and free all associated data.
 *
 * @param output previously opened output structure.
 * @return RNP_SUCCESS if operation succeeds or error code otherwise.
 */
rnp_result_t rnp_output_destroy(rnp_output_t output);

/* encrypt */
rnp_result_t rnp_op_encrypt_create(rnp_op_encrypt_t *op,
                                   rnp_ffi_t         ffi,
                                   rnp_input_t       input,
                                   rnp_output_t      output);

rnp_result_t rnp_op_encrypt_add_recipient(rnp_op_encrypt_t op, rnp_key_handle_t key);

/**
 * @brief Add signature to encrypting context, so data will be encrypted and signed.
 *
 * @param op opaque encrypting context. Must be allocated and initialized.
 * @param key private key, used for signing.
 * @param sig pointer to the newly added signature will be stored here. May be NULL.
 * @return RNP_SUCCESS if signature was added or error code otherwise.
 */
rnp_result_t rnp_op_encrypt_add_signature(rnp_op_encrypt_t         op,
                                          rnp_key_handle_t         key,
                                          rnp_op_sign_signature_t *sig);

/**
 * @brief Set hash function used for signature calculation. Makes sense if encrypt-and-sign is
 * used. To set hash function for each signature separately use rnp_op_sign_signature_set_hash.
 *
 * @param op opaque encrypting context. Must be allocated and initialized.
 * @param hash hash algorithm to be used
 * @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_encrypt_set_hash(rnp_op_encrypt_t op, const char *hash);

/**
 * @brief Set signature creation time. By default current time is used.
 *
 * @param op opaque encrypting context. Must be allocated and initialized.
 * @param create creation time in seconds since Jan, 1 1970 UTC
 * @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_encrypt_set_creation_time(rnp_op_encrypt_t op, uint32_t create);

/**
 * @brief Set signature expiration time. By default signatures do not expire.
 *
 * @param op opaque encrypting context. Must be allocated and initialized.
 * @param expire expiration time in seconds since the creation time. 0 value is used to mark
 *        signature as non-expiring
 * @return RNP_SUCCESS or error code if failed
 */
rnp_result_t rnp_op_encrypt_set_expiration_time(rnp_op_encrypt_t op, uint32_t expire);

rnp_result_t rnp_op_encrypt_add_password(rnp_op_encrypt_t op,
                                         const char *     password,
                                         const char *     s2k_hash,
                                         size_t           iterations,
                                         const char *     s2k_cipher);

rnp_result_t rnp_op_encrypt_set_armor(rnp_op_encrypt_t op, bool armored);
rnp_result_t rnp_op_encrypt_set_cipher(rnp_op_encrypt_t op, const char *cipher);
rnp_result_t rnp_op_encrypt_set_compression(rnp_op_encrypt_t op,
                                            const char *     compression,
                                            int              level);
rnp_result_t rnp_op_encrypt_set_file_name(rnp_op_encrypt_t op, const char *filename);
rnp_result_t rnp_op_encrypt_set_file_mtime(rnp_op_encrypt_t op, uint32_t mtime);

rnp_result_t rnp_op_encrypt_execute(rnp_op_encrypt_t op);
rnp_result_t rnp_op_encrypt_destroy(rnp_op_encrypt_t op);

rnp_result_t rnp_decrypt(rnp_ffi_t ffi, rnp_input_t input, rnp_output_t output);

/** retrieve the raw data for a public key
 *
 *  This will always be PGP packets and will never include ASCII armor.
 *
 *  @param handle the key handle
 *  @param buf
 *  @param buf_len
 *  @return 0 on success, or any other value on error
 */
rnp_result_t rnp_get_public_key_data(rnp_key_handle_t handle, uint8_t **buf, size_t *buf_len);

/** retrieve the raw data for a secret key
 *
 *  If this is a G10 key, this will be the s-expr data. Otherwise, it will
 *  be PGP packets.
 *
 *  Note that this result will never include ASCII armor.
 *
 *  @param handle the key handle
 *  @param buf
 *  @param buf_len
 *  @return 0 on success, or any other value on error
 */
rnp_result_t rnp_get_secret_key_data(rnp_key_handle_t handle, uint8_t **buf, size_t *buf_len);

rnp_result_t rnp_key_to_json(rnp_key_handle_t handle, uint32_t flags, char **result);

/** create an identifier iterator
 *
 *  @param ffi
 *  @param it pointer that will be set to the created iterator
 *  @param identifier_type the type of identifier ("userid", "keyid", "grip")
 *  @return 0 on success, or any other value on error
 */
rnp_result_t rnp_identifier_iterator_create(rnp_ffi_t                  ffi,
                                            rnp_identifier_iterator_t *it,
                                            const char *               identifier_type);

/** retrieve the next item from an iterator
 *
 *  @param it the iterator
 *  @param identifier pointer that will be set to the identifier value.
 *         Must not be NULL. This buffer should not be freed by the application.
 *         It will be modified by subsequent calls to this function, and its
 *         life is tied to the iterator.
 *  @return 0 on success, or any other value on error
 */
rnp_result_t rnp_identifier_iterator_next(rnp_identifier_iterator_t it,
                                          const char **             identifier);

/** destroy an identifier iterator
 *
 *  @param it the iterator object
 *  @return 0 on success, or any other value on error
 */
rnp_result_t rnp_identifier_iterator_destroy(rnp_identifier_iterator_t it);

#if defined(__cplusplus)
}
#endif
