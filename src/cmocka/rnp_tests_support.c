/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 *modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *OF
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

#include <cmocka.h>

#include <crypto.h>
#include <key_store_pgp.h>
#include <packet.h>
#include <packet-key.h>
#include <bn.h>

#include <rnp.h>
#include <sys/stat.h>

/* Check if a file exists.
 * Use with assert_true and assert_false.
 */
int file_exists(const char *path) {
  struct stat st = { 0 };
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Check if a file is empty
 * Use with assert_true and assert_false.
 */
int file_empty(const char *path) {
  struct stat st = { 0 };
  return stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 0;
}

/* Concatenate multiple strings into a full path.
 * A directory separator is added between components.
 * Must be called in between va_start and va_end.
 * Final argument of calling function must be NULL.
 */
void vpaths_concat(char *buffer, size_t buffer_size, const char *first,
                   va_list ap) {
  size_t length = strlen(first);
  const char *s;

  assert_true(length < buffer_size);

  memset(buffer, 0, buffer_size);

  strncpy(buffer, first, buffer_size - 1);
  while ((s = va_arg(ap, const char *))) {
    length += strlen(s) + 1;
    assert_true(length < buffer_size);
    strncat(buffer, "/", buffer_size - 1);
    strncat(buffer, s, buffer_size - 1);
  }
}

/* Concatenate multiple strings into a full path.
 * Final argument must be NULL.
 */
char *paths_concat(char *buffer, size_t buffer_length, const char *first, ...) {
  va_list ap;

  va_start(ap, first);
  vpaths_concat(buffer, buffer_length, first, ap);
  va_end(ap);
  return buffer;
}

/* Concatenate multiple strings into a full path and
 * check that the file exists.
 * Final argument must be NULL.
 */
int path_file_exists(const char *first, ...) {
  va_list ap;
  char buffer[512] = { 0 };

  va_start(ap, first);
  vpaths_concat(buffer, sizeof(buffer), first, ap);
  va_end(ap);
  return file_exists(buffer);
}

/* Concatenate multiple strings into a full path and
 * create the directory.
 * Final argument must be NULL.
 */
void path_mkdir(mode_t mode, const char *first, ...) {
  va_list ap;
  char buffer[512];

  /* sanity check - should always be an absolute path */
  assert_true(first[0] == '/');

  va_start(ap, first);
  vpaths_concat(buffer, sizeof(buffer), first, ap);
  va_end(ap);

  assert_int_equal(0, mkdir(buffer, mode));
}

int remove_cb(const char *fpath, const struct stat *sb, int typeflag,
              struct FTW *ftwbuf) {
  int ret = remove(fpath);
  if (ret)
    perror(fpath);

  return ret;
}

/* Recursively remove a directory.
 * The path must be a full path and must be located in /tmp, for safety.
 */
void delete_recursively(const char *path) {
  /* sanity check, we should only be purging things from /tmp/ */
  assert_int_equal(strncmp(path, "/tmp/", 5), 0);
  assert_true(strlen(path) > 5);

  nftw(path, remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

/* Creates and returns a temporary directory path.
 * Caller must free the string.
 */
char *make_temp_dir() {
  const char *template = "/tmp/rnp-cmocka-XXXXXX";
  char *buffer = calloc(1, strlen(template) + 1);
  strncpy(buffer, template, strlen(template));
  return mkdtemp(buffer);
}

// returns new string containing hex value
char *hex_encode(const uint8_t v[], size_t len) {
  char *s;
  size_t i;

  s = malloc(2 * len + 1);
  if (s == NULL)
    return NULL;

  char hex_chars[] = "0123456789ABCDEF";

  for (i = 0; i < len; ++i) {
    uint8_t b0 = 0x0F & (v[i] >> 4);
    uint8_t b1 = 0x0F & (v[i]);
    const char c1 = hex_chars[b0];
    const char c2 = hex_chars[b1];
    s[2 * i] = c1;
    s[2 * i + 1] = c2;
  }
  s[2 * len] = 0;

  return s;
}

int test_value_equal(const char *what, const char *expected_value,
                     const uint8_t v[], size_t v_len) {
  assert_int_equal(strlen(expected_value), v_len * 2);

  char *produced = hex_encode(v, v_len);

  // fixme - expects expected_value is also uppercase
  assert_string_equal(produced, expected_value);

  free(produced);
  return 0;
}

char *uint_to_string(char *buff, const int buffsize, unsigned int num,
                     int base) {
  char *ptr;
  ptr = &buff[buffsize - 1];
  *ptr = '\0';

  do {
    *--ptr = "0123456789abcdef"[num % base];
    num /= base;
  } while (num != 0);

  return ptr;
}

int setupPassphrasefd(int *pipefd) {
  if (pipe(pipefd) == -1) {
    perror("pipe");
    return 0;
  }

  /*Write and close fd*/
  const char *password = "passwordforkeygeneration\0";
  assert_int_equal(write(pipefd[1], password, strlen(password)),
                   strlen(password));
  close(pipefd[1]);
  return 1;
}
