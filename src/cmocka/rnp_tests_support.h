/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
#include <cmocka.h>
#include <rnp.h>

/* Check if a file exists.
 * Use with assert_true and rnp_assert_false(rstate, .
 */
int file_exists(const char *path);

/* Check if a file is empty
 * Use with assert_true and rnp_assert_false(rstate, .
 */
int file_empty(const char *path);

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

int remove_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);

/* Recursively remove a directory.
 * The path must be a full path and must be located in /tmp, for safety.
 */
void delete_recursively(const char *path);

/* Creates and returns a temporary directory path.
 * Caller must free the string.
 */
char *make_temp_dir();

/*
 */
char *hex_encode(const uint8_t v[], size_t len);

/*
 */
int test_value_equal(const char *  what,
                     const char *  expected_value,
                     const uint8_t v[],
                     size_t        v_len);

/*
 */
char *uint_to_string(char *buff, const int buffsize, unsigned int num, int base);

/* Setup readable pipe with default passphrase inside */
int setupPassphrasefd(int *pipefd);

/* Common initialization of rnp structure : home path, keystore format and pointer to store
 * passphrase fd */
int setup_rnp_common(rnp_t *                 rnp,
                      enum key_store_format_t ks_format,
                      const char *            homedir,
                      int *                   pipefd);

/* Initialize key generation params with default values and specified hash algorithm */
void set_default_rsa_key_desc(rnp_keygen_desc_t *key_desc, pgp_hash_alg_t hashalg);
