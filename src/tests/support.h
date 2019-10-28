/*
 * Copyright (c) 2017-2019 [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <ftw.h>
#include <sys/stat.h>

#include "rnp.h"
#include "../rnp/rnpcli.h"
#include "../rnp/fficli.h"

/* Check if a file exists.
 * Use with assert_true and rnp_assert_false(rstate, .
 */
bool file_exists(const char *path);

/* Check if a file is empty
 * Use with assert_true and rnp_assert_false(rstate, .
 */
bool file_empty(const char *path);

off_t file_size(const char *path);

/* Check if a directory exists */
bool dir_exists(const char *path);

/* Read file contents into the memory */
uint8_t *file_contents(const char *path, ssize_t *size);

/* Read file contents into the std::string */
std::string file_to_str(const std::string &path);

/* Concatenate multiple strings into a full path.
 * A directory separator is added between components.
 * Must be called in between va_start and va_end.
 * Final argument of calling function must be NULL.
 */
void vpaths_concat(char *buffer, size_t buffer_size, const char *first, va_list ap);

/* Concatenate multiple strings into a full path.
 * Final argument must be NULL.
 */
char *paths_concat(char *buffer, size_t buffer_length, const char *first, ...);

/* Concatenate multiple strings into a full path and
 * check that the file exists.
 * Final argument must be NULL.
 */
int path_file_exists(const char *first, ...);

/* Concatenate multiple strings into a full path and
 * create the directory.
 * Final argument must be NULL.
 */
void path_mkdir(mode_t mode, const char *first, ...);

/* Recursively remove a directory.
 * The path must be a full path and must be located in /tmp, for safety.
 */
void delete_recursively(const char *path);

void copy_recursively(const char *src, const char *dst);

/* Creates and returns a temporary directory path.
 * Caller must free the string.
 */
char *make_temp_dir(void);

/** get an absolute directory from a file path
 *
 *  @param file_path the path to the file, which must not be NULL. This can be absolute
 *         or relative (if reldir is supplied)
 *  @param reldir a directory that will be used to construct a full path from a relative
 *         one. Can be NULL if file_path is absolute.
 *  @return if there is no error, it returns an absolute path to the directory.
 *          Otherwise, it returns NULL.
 **/
char *directory_from_file_path(const char *file_path, const char *reldir);

/*
 */
char *hex_encode(const uint8_t v[], size_t len);

/* check whether bin value is equals hex string */
bool bin_eq_hex(uint8_t *data, size_t len, const char *val);

/* check whether key id is equal to hex string */
bool cmp_keyid(uint8_t *id, const char *val);

/* check whether key fp is equal to hex string */
bool cmp_keyfp(pgp_fingerprint_t *fp, const char *val);

/*
 */
int test_value_equal(const char *  what,
                     const char *  expected_value,
                     const uint8_t v[],
                     size_t        v_len);

/*
 */
char *uint_to_string(char *buff, const int buffsize, unsigned int num, int base);

bool write_pass_to_pipe(int fd, size_t count);
/* Setup readable pipe with default password inside */
bool setupPasswordfd(int *pipefd);

/* Common initialization of rnp structure : home path, keystore format and pointer to store
 * password fd */
bool setup_rnp_common(rnp_t *rnp, const char *ks_format, const char *homedir, int *pipefd);
bool setup_cli_rnp_common(cli_rnp_t * rnp,
                          const char *ks_format,
                          const char *homedir,
                          int *       pipefd);

/* Initialize key generation params with default values and specified hash algorithm */
void cli_set_default_rsa_key_desc(rnp_cfg_t *cfg, const char *hash);

// this is a password callback that will always fail
bool failing_password_callback(const pgp_password_ctx_t *ctx,
                               char *                    password,
                               size_t                    password_size,
                               void *                    userdata);

bool ffi_failing_password_provider(rnp_ffi_t        ffi,
                                   void *           app_ctx,
                                   rnp_key_handle_t key,
                                   const char *     pgp_context,
                                   char *           buf,
                                   size_t           buf_len);

// this is a password callback that should never be called
bool asserting_password_callback(const pgp_password_ctx_t *ctx,
                                 char *                    password,
                                 size_t                    password_size,
                                 void *                    userdata);

bool ffi_asserting_password_provider(rnp_ffi_t        ffi,
                                     void *           app_ctx,
                                     rnp_key_handle_t key,
                                     const char *     pgp_context,
                                     char *           buf,
                                     size_t           buf_len);

// this is a password callback that just copies the string in userdata to
// the password buffer
bool string_copy_password_callback(const pgp_password_ctx_t *ctx,
                                   char *                    password,
                                   size_t                    password_size,
                                   void *                    userdata);

bool ffi_string_password_provider(rnp_ffi_t        ffi,
                                  void *           app_ctx,
                                  rnp_key_handle_t key,
                                  const char *     pgp_context,
                                  char *           buf,
                                  size_t           buf_len);

bool starts_with(const std::string &data, const std::string &match);
bool ends_with(const std::string &data, const std::string &match);

std::string fmt(const char *format, ...);
std::string strip_eol(const std::string &str);

bool check_json_field_str(json_object *      obj,
                          const std::string &field,
                          const std::string &value);
bool check_json_field_int(json_object *obj, const std::string &field, int value);
bool check_json_field_bool(json_object *obj, const std::string &field, bool value);
