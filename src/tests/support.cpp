/*
 * Copyright (c) 2017-2018 [Ribose Inc](https://www.ribose.com).
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

#include "support.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <ftw.h>
#include <fcntl.h>

#include <crypto.h>
#include <pgp-key.h>

extern rng_t global_rng;

/* Check if a file exists.
 * Use with assert_true and rnp_assert_false(rstate, .
 */
bool
file_exists(const char *path)
{
    struct stat st = {0};
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Check if a directory exists */
bool
dir_exists(const char *path)
{
    struct stat st = {0};
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Check if a file is empty
 * Use with assert_true and rnp_assert_false(rstate, .
 */
bool
file_empty(const char *path)
{
    struct stat st = {0};
    return stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 0;
}

uint8_t *
file_contents(const char *path, ssize_t *size)
{
    int         fd;
    struct stat st;
    uint8_t *   mem;

    *size = -1;
    if ((stat(path, &st) != 0) || (st.st_size == 0)) {
        return NULL;
    }

#ifdef O_BINARY
    fd = open(path, O_RDONLY | O_BINARY);
#else
    fd = open(path, O_RDONLY);
#endif
    if (fd < 0) {
        return NULL;
    }
    if ((mem = (uint8_t *) malloc(st.st_size))) {
        *size = read(fd, mem, st.st_size);
    }
    close(fd);
    return mem;
}

off_t
file_size(const char *path)
{
    struct stat path_stat;
    if (stat(path, &path_stat) != -1) {
        if (S_ISDIR(path_stat.st_mode)) {
            return -1;
        }
        return path_stat.st_size;
    }
    return -1;
}

/* Concatenate multiple strings into a full path.
 * A directory separator is added between components.
 * Must be called in between va_start and va_end.
 * Final argument of calling function must be NULL.
 */
void
vpaths_concat(char *buffer, size_t buffer_size, const char *first, va_list ap)
{
    size_t      length = strlen(first);
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
char *
paths_concat(char *buffer, size_t buffer_length, const char *first, ...)
{
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
int
path_file_exists(const char *first, ...)
{
    va_list ap;
    char    buffer[512] = {0};

    va_start(ap, first);
    vpaths_concat(buffer, sizeof(buffer), first, ap);
    va_end(ap);
    return file_exists(buffer);
}

/* Concatenate multiple strings into a full path and
 * create the directory.
 * Final argument must be NULL.
 */
void
path_mkdir(mode_t mode, const char *first, ...)
{
    va_list ap;
    char    buffer[512];

    /* sanity check - should always be an absolute path */
    assert_true(first[0] == '/');

    va_start(ap, first);
    vpaths_concat(buffer, sizeof(buffer), first, ap);
    va_end(ap);

    assert_int_equal(0, mkdir(buffer, mode));
}

static int
remove_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    int ret = remove(fpath);
    if (ret)
        perror(fpath);

    return ret;
}

/* Recursively remove a directory.
 * The path must be a full path and must be located in /tmp, for safety.
 */
void
delete_recursively(const char *path)
{
    /* sanity check, we should only be purging things from /tmp/ */
    assert_int_equal(strncmp(path, "/tmp/", 5), 0);
    assert_true(strlen(path) > 5);

    nftw(path, remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

void
copy_recursively(const char *src, const char *dst)
{
    /* sanity check, we should only be copying things to /tmp/ */
    assert_int_equal(strncmp(dst, "/tmp/", 5), 0);
    assert_true(strlen(dst) > 5);

    // TODO: maybe use fts or something less hacky
    char buf[2048];
    snprintf(buf, sizeof(buf), "/bin/cp -a '%s' '%s'", src, dst);
    assert_int_equal(0, system(buf));
}

/* Creates and returns a temporary directory path.
 * Caller must free the string.
 */
char *
make_temp_dir()
{
    const char *tmplate = "/tmp/rnp-cmocka-XXXXXX";
    char *      buffer = (char *) calloc(1, strlen(tmplate) + 1);
    if (buffer == NULL) {
        return NULL;
    }
    strncpy(buffer, tmplate, strlen(tmplate));
    return mkdtemp(buffer);
}

static char *
directory_from_absolute_file_path(const char *file_path)
{
    const char *last_sep = strrchr(file_path, '/');
    if (!last_sep) {
        return NULL;
    }

    size_t file_path_len = (last_sep - file_path);
    size_t dir_len = file_path_len + 1;
    char * dir = (char *) calloc(1, dir_len);
    if (!dir) {
        return NULL;
    }
    strncpy(dir, file_path, file_path_len);

    char *full_dir = realpath(dir, NULL);
    free(dir);
    dir = NULL;
    return full_dir;
}

static char *
directory_from_relative_file_path(const char *file_path, const char *reldir)
{
    const char *last_sep = strrchr(file_path, '/');
    if (!last_sep) {
        return NULL;
    }

    size_t file_path_len = (last_sep - file_path);
    size_t dir_len = strlen(reldir) + 1 + file_path_len + 1;
    char * dir = (char *) calloc(1, dir_len);
    if (!dir) {
        return NULL;
    }

    strncpy(dir, reldir, dir_len);
    strncat(dir, "/", dir_len);
    strncat(dir, file_path, file_path_len);

    char *full_dir = realpath(dir, NULL);
    free(dir);
    dir = NULL;
    return full_dir;
}

char *
directory_from_file_path(const char *file_path, const char *reldir)
{
    if (!file_path) {
        return NULL;
    }
    if (*file_path == '/') {
        return directory_from_absolute_file_path(file_path);
    }
    return directory_from_relative_file_path(file_path, reldir);
}

// returns new string containing hex value
char *
hex_encode(const uint8_t v[], size_t len)
{
    char * s;
    size_t i;

    s = (char *) malloc(2 * len + 1);
    if (s == NULL)
        return NULL;

    char hex_chars[] = "0123456789ABCDEF";

    for (i = 0; i < len; ++i) {
        uint8_t    b0 = 0x0F & (v[i] >> 4);
        uint8_t    b1 = 0x0F & (v[i]);
        const char c1 = hex_chars[b0];
        const char c2 = hex_chars[b1];
        s[2 * i] = c1;
        s[2 * i + 1] = c2;
    }
    s[2 * len] = 0;

    return s;
}

bool
bin_eq_hex(uint8_t *data, size_t len, const char *val)
{
    uint8_t *dec;
    size_t   stlen = strlen(val);
    if (stlen != len * 2) {
        return false;
    }

    assert_non_null(dec = (uint8_t *) malloc(len));
    assert_true(rnp_hex_decode(val, dec, len));
    bool res = !memcmp(data, dec, len);
    free(dec);
    return res;
}

bool
cmp_keyid(uint8_t *id, const char *val)
{
    return bin_eq_hex(id, PGP_KEY_ID_SIZE, val);
}

bool
cmp_keyfp(pgp_fingerprint_t *fp, const char *val)
{
    return bin_eq_hex(fp->fingerprint, fp->length, val);
}

int
test_value_equal(const char *what, const char *expected_value, const uint8_t v[], size_t v_len)
{
    assert_int_equal(strlen(expected_value), v_len * 2);

    char *produced = hex_encode(v, v_len);
    if (produced == NULL) {
        return -1;
    }

    // fixme - expects expected_value is also uppercase
    assert_string_equal(produced, expected_value);

    free(produced);
    return 0;
}

char *
uint_to_string(char *buff, const int buffsize, unsigned int num, int base)
{
    char *ptr;
    ptr = &buff[buffsize - 1];
    *ptr = '\0';

    do {
        *--ptr = "0123456789abcdef"[num % base];
        num /= base;
    } while (num != 0);

    return ptr;
}

bool
write_pass_to_pipe(int fd, size_t count)
{
    const char *const password = "passwordforkeygeneration\n";
    for (size_t i = 0; i < count; i++) {
        const char *p = password;
        ssize_t     remaining = strlen(p);

        do {
            ssize_t written = write(fd, p, remaining);
            if (written <= 0) {
                perror("write");
                return false;
            }
            p += written;
            remaining -= written;
        } while (remaining);
    }
    return true;
}

bool
setupPasswordfd(int *pipefd)
{
    bool ok = false;

    if (pipe(pipefd) == -1) {
        perror("pipe");
        goto end;
    }
    // write it twice for normal keygen (primary+sub)
    if (!write_pass_to_pipe(pipefd[1], 2)) {
        close(pipefd[1]);
        goto end;
    }
    ok = true;

end:
    close(pipefd[1]);
    return ok;
}

bool
setup_rnp_common(rnp_t *rnp, const char *ks_format, const char *homedir, int *pipefd)
{
    int       res;
    char      pubpath[MAXPATHLEN];
    char      secpath[MAXPATHLEN];
    char      homepath[MAXPATHLEN];
    rnp_cfg_t cfg = {};

    rnp_cfg_init(&cfg);

    /* set password fd if any */
    if (pipefd) {
        if ((res = setupPasswordfd(pipefd)) != 1) {
            return res;
        }
        rnp_cfg_setint(&cfg, CFG_PASSFD, pipefd[0]);
    }
    /* setup keyring pathes */
    if (homedir == NULL) {
        /* if we use default homedir then we append '.rnp' and create directory as well */
        homedir = getenv("HOME");
        paths_concat(homepath, sizeof(homepath), homedir, ".rnp", NULL);
        if (!dir_exists(homepath)) {
            path_mkdir(0700, homepath, NULL);
        }
        homedir = homepath;
    }

    if (homedir == NULL) {
        return false;
    }

    rnp_cfg_setstr(&cfg, CFG_KR_PUB_FORMAT, ks_format);
    rnp_cfg_setstr(&cfg, CFG_KR_SEC_FORMAT, ks_format);

    if (strcmp(ks_format, RNP_KEYSTORE_GPG) == 0) {
        paths_concat(pubpath, MAXPATHLEN, homedir, PUBRING_GPG, NULL);
        paths_concat(secpath, MAXPATHLEN, homedir, SECRING_GPG, NULL);
    } else if (strcmp(ks_format, RNP_KEYSTORE_KBX) == 0) {
        paths_concat(pubpath, MAXPATHLEN, homedir, PUBRING_KBX, NULL);
        paths_concat(secpath, MAXPATHLEN, homedir, SECRING_KBX, NULL);
    } else if (strcmp(ks_format, RNP_KEYSTORE_G10) == 0) {
        paths_concat(pubpath, MAXPATHLEN, homedir, PUBRING_G10, NULL);
        paths_concat(secpath, MAXPATHLEN, homedir, SECRING_G10, NULL);
    } else if (strcmp(ks_format, RNP_KEYSTORE_GPG21) == 0) {
        paths_concat(pubpath, MAXPATHLEN, homedir, PUBRING_KBX, NULL);
        paths_concat(secpath, MAXPATHLEN, homedir, SECRING_G10, NULL);
        rnp_cfg_setstr(&cfg, CFG_KR_PUB_FORMAT, RNP_KEYSTORE_KBX);
        rnp_cfg_setstr(&cfg, CFG_KR_SEC_FORMAT, RNP_KEYSTORE_G10);
    } else {
        return false;
    }

    rnp_cfg_setstr(&cfg, CFG_KR_PUB_PATH, pubpath);
    rnp_cfg_setstr(&cfg, CFG_KR_SEC_PATH, secpath);

    /*initialize the basic RNP structure. */
    memset(rnp, '\0', sizeof(*rnp));
    if (rnp_init(rnp, &cfg) != RNP_SUCCESS) {
        return false;
    }
    rnp_cfg_free(&cfg);
    return true;
}

void
set_default_rsa_key_desc(rnp_action_keygen_t *action, pgp_hash_alg_t hashalg)
{
    rnp_keygen_primary_desc_t *primary = &action->primary.keygen;
    rnp_keygen_subkey_desc_t * subkey = &action->subkey.keygen;

    primary->crypto.key_alg = PGP_PKA_RSA;
    primary->crypto.rsa.modulus_bit_len = 1024;
    primary->crypto.hash_alg = hashalg;
    primary->crypto.rng = &global_rng;

    action->primary.protection.iterations = 1;
    action->subkey.protection.iterations = 1;

    subkey->crypto.key_alg = PGP_PKA_RSA;
    subkey->crypto.rsa.modulus_bit_len = 1024;
    subkey->crypto.hash_alg = hashalg;
    subkey->crypto.rng = &global_rng;
}

// this is a password callback that will always fail
bool
failing_password_callback(const pgp_password_ctx_t *ctx,
                          char *                    password,
                          size_t                    password_size,
                          void *                    userdata)
{
    return false;
}

// this is a password callback that should never be called
bool
asserting_password_callback(const pgp_password_ctx_t *ctx,
                            char *                    password,
                            size_t                    password_size,
                            void *                    userdata)
{
    assert_false(true);
    return false;
}

// this is a password callback that just copies the string in userdata to
// the password buffer
bool
string_copy_password_callback(const pgp_password_ctx_t *ctx,
                              char *                    password,
                              size_t                    password_size,
                              void *                    userdata)
{
    const char *str = (const char *) userdata;
    strncpy(password, str, password_size - 1);
    return true;
}

bool
starts_with(const std::string &data, const std::string &match)
{
    return data.find(match) == 0;
}

bool
ends_with(const std::string &data, const std::string &match)
{
    return data.size() >= match.size() &&
           data.substr(data.size() - match.size(), match.size()) == match;
}

std::string
fmt(const char *format, ...)
{
    int     size;
    va_list ap;

    va_start(ap, format);
    size = vsnprintf(NULL, 0, format, ap);
    va_end(ap);

    // +1 for terminating null
    std::string buf(size + 1, '\0');

    va_start(ap, format);
    size = vsnprintf(&buf[0], buf.size(), format, ap);
    va_end(ap);

    // drop terminating null
    buf.resize(size);
    return buf;
}
