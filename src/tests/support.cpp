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

#include "support.h"
#include "rnp_tests.h"
#include "utils.h"

#include <sys/types.h>
#include <sys/param.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include <crypto.h>
#include <pgp-key.h>
#include <fstream>

extern rng_t global_rng;

#ifdef _WIN32
int
setenv(const char *name, const char *value, int overwrite)
{
    if (getenv(name) && !overwrite) {
        return 0;
    }
    char varbuf[512] = {0};
    snprintf(varbuf, sizeof(varbuf) - 1, "%s=%s", name, value);
    return _putenv(varbuf);
}
#endif

#ifndef HAVE_MKDTEMP
char *
mkdtemp(char *templ)
{
    char *dirpath = mktemp(templ);
    if (!dirpath) {
        return NULL;
    }
    return !RNP_MKDIR(dirpath, S_IRWXU) ? dirpath : NULL;
}
#endif


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

std::string
file_to_str(const std::string &path)
{
    std::ifstream infile(path);
    return std::string(std::istreambuf_iterator<char>(infile), std::istreambuf_iterator<char>());
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

    va_start(ap, first);
    vpaths_concat(buffer, sizeof(buffer), first, ap);
    va_end(ap);

    assert_int_equal(0, RNP_MKDIR(buffer, mode));
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
 * The path must be located in /tmp, for safety.
 */
void
delete_recursively(const char *path)
{
    char *fullpath = const_cast<char *>(path);
    if (*path != '/') {
        char *cwd = getcwd(NULL, 0);
        fullpath = rnp_compose_path(cwd, path, NULL);
        free(cwd);
    }
    /* sanity check, we should only be purging things from /tmp/ */
    assert_true(!strncmp(fullpath, "/tmp/", 5) || !strncmp(fullpath, "/private/tmp/", 13));

    nftw(path, remove_cb, 64, FTW_DEPTH | FTW_PHYS);
    if (*path != '/') {
        free(fullpath);
    }
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
    const char *tmplate = "/tmp/rnp-gtest-XXXXXX";
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

static bool
setup_rnp_cfg(rnp_cfg_t *cfg, const char *ks_format, const char *homedir, int *pipefd)
{
    bool res;
    char pubpath[MAXPATHLEN];
    char secpath[MAXPATHLEN];
    char homepath[MAXPATHLEN];

    rnp_cfg_init(cfg);

    /* set password fd if any */
    if (pipefd) {
        if (!(res = setupPasswordfd(pipefd))) {
            return res;
        }
        rnp_cfg_setint(cfg, CFG_PASSFD, pipefd[0]);
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

    rnp_cfg_setstr(cfg, CFG_KR_PUB_FORMAT, ks_format);
    rnp_cfg_setstr(cfg, CFG_KR_SEC_FORMAT, ks_format);

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
        rnp_cfg_setstr(cfg, CFG_KR_PUB_FORMAT, RNP_KEYSTORE_KBX);
        rnp_cfg_setstr(cfg, CFG_KR_SEC_FORMAT, RNP_KEYSTORE_G10);
    } else {
        return false;
    }

    rnp_cfg_setstr(cfg, CFG_KR_PUB_PATH, pubpath);
    rnp_cfg_setstr(cfg, CFG_KR_SEC_PATH, secpath);
    return true;
}

bool
setup_cli_rnp_common(cli_rnp_t *rnp, const char *ks_format, const char *homedir, int *pipefd)
{
    rnp_cfg_t cfg = {};

    if (!setup_rnp_cfg(&cfg, ks_format, homedir, pipefd)) {
        return false;
    }

    /*initialize the basic RNP structure. */
    memset(rnp, '\0', sizeof(*rnp));
    bool res = cli_rnp_init(rnp, &cfg);
    rnp_cfg_free(&cfg);
    return res;
}

void
cli_set_default_rsa_key_desc(rnp_cfg_t *cfg, const char *hashalg)
{
    rnp_cfg_setint(cfg, CFG_NUMBITS, 1024);
    rnp_cfg_setstr(cfg, CFG_HASH, hashalg);
    rnp_cfg_setint(cfg, CFG_S2K_ITER, 1);
    cli_rnp_set_generate_params(cfg);
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

bool
ffi_failing_password_provider(rnp_ffi_t ffi, void *app_ctx, rnp_key_handle_t key, const char *pgp_context, char *buf, size_t buf_len)
{
    return false;
}

bool
ffi_asserting_password_provider(rnp_ffi_t ffi, void *app_ctx, rnp_key_handle_t key, const char *pgp_context, char *buf, size_t buf_len)
{
    assert_false(true);
    return false;
}

bool
ffi_string_password_provider(rnp_ffi_t ffi, void *app_ctx, rnp_key_handle_t key, const char *pgp_context, char *buf, size_t buf_len)
{
    const char *str = (const char *) app_ctx;
    strncpy(buf, str, buf_len - 1);
    return true;
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

std::string
strip_eol(const std::string &str)
{
    size_t endpos = str.find_last_not_of("\r\n");
    if (endpos != std::string::npos) {
        return str.substr(0, endpos + 1);
    }
    return str;
}

static bool
jso_get_field(json_object *obj, json_object **fld, const std::string &name)
{
    if (!obj || !json_object_is_type(obj, json_type_object)) {
      return false;
    }
    return json_object_object_get_ex(obj, name.c_str(), fld);
}

bool
check_json_field_str(json_object *obj, const std::string &field, const std::string &value)
{
    json_object *fld = NULL;
    if (!jso_get_field(obj, &fld, field)) {
        return false;
    }
    if (!json_object_is_type(fld, json_type_string)) {
        return false;
    }
    const char *jsoval = json_object_get_string(fld);
    return jsoval && (value == jsoval);
}

bool
check_json_field_int(json_object *obj, const std::string &field, int value)
{
    json_object *fld = NULL;
    if (!jso_get_field(obj, &fld, field)) {
        return false;
    }
    if (!json_object_is_type(fld, json_type_int)) {
        return false;
    }
    return json_object_get_int(fld) == value;
}

bool
check_json_field_bool(json_object *obj, const std::string &field, bool value)
{
    json_object *fld = NULL;
    if (!jso_get_field(obj, &fld, field)) {
        return false;
    }
    if (!json_object_is_type(fld, json_type_boolean)) {
        return false;
    }
    return json_object_get_boolean(fld) == value;
}

pgp_key_t*
rnp_tests_get_key_by_id(const rnp_key_store_t* keyring, const std::string& keyid, pgp_key_t* after)
{
    pgp_key_t *key = NULL;
    std::vector<uint8_t> keyid_bin(PGP_KEY_ID_SIZE, 0);
    size_t binlen = 0;

    if (!keyring || keyid.empty()) {
        return NULL;
    }
    assert(!after || list_is_member(keyring->keys, (list_item *) after));

    if (ishex(keyid.c_str(), keyid.size()) && hex2bin(keyid.c_str(), keyid.size(), keyid_bin.data(), keyid_bin.size(), &binlen)) {
        if (binlen <= PGP_KEY_ID_SIZE) {
            key = rnp_key_store_get_key_by_id(keyring, keyid_bin.data(), after);
        }
    }
    return key;
}

pgp_key_t*
rnp_tests_get_key_by_fpr(const rnp_key_store_t* keyring, const std::string& keyid)
{
    pgp_key_t *key = NULL;
    std::vector<uint8_t> keyid_bin(PGP_FINGERPRINT_SIZE, 0);
    size_t binlen = 0;

    if (!keyring || keyid.empty()) {
        return NULL;
    }

    if (ishex(keyid.c_str(), keyid.size()) && hex2bin(keyid.c_str(), keyid.size(), keyid_bin.data(), keyid_bin.size(), &binlen)) {
        if (binlen <= PGP_FINGERPRINT_SIZE) {
            pgp_fingerprint_t fp = { {}, static_cast<unsigned>(binlen) };
            memcpy(fp.fingerprint, keyid_bin.data(), binlen);
            key = rnp_key_store_get_key_by_fpr(keyring, &fp);
        } 
    }
    return key;
}

pgp_key_t*
rnp_tests_key_search(const rnp_key_store_t* keyring, const std::string& keyid)
{
    if (!keyring || keyid.empty()) {
        return NULL;
    }

    pgp_key_search_t srch_userid = { PGP_KEY_SEARCH_USERID };
    strncpy(srch_userid.by.userid, keyid.c_str(), sizeof(srch_userid.by.userid));
    return rnp_key_store_search(keyring, &srch_userid, NULL);
}
