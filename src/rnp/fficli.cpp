/*
 * Copyright (c) 2019, [Ribose Inc](https://www.ribose.com).
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <ctype.h>
#include <unistd.h>

#ifndef _WIN32
#include <termios.h>
#include <sys/resource.h>
#endif

#include <time.h>
#include "config.h"
#include "fficli.h"

// must be placed after include "utils.h"
#ifndef RNP_USE_STD_REGEX
#include <regex.h>
#else
#include <regex>
#endif

#define RNP_KEYSTORE_GPG ("GPG") /* GPG keystore format */
#define RNP_KEYSTORE_KBX ("KBX") /* KBX keystore format */
#define RNP_KEYSTORE_G10 ("G10") /* G10 keystore format */

// combinated keystores
#define RNP_KEYSTORE_GPG21 ("GPG21") /* KBX + G10 keystore format */

#ifdef HAVE_SYS_RESOURCE_H
/* When system resource consumption limit controls are available this
 * can be used to attempt to disable core dumps which may leak
 * sensitive data.
 *
 * Returns false if disabling core dumps failed, returns true if disabling
 * core dumps succeeded. errno will be set to the result from setrlimit in
 * the event of failure.
 */
static bool
disable_core_dumps(void)
{
    struct rlimit limit;
    int           error;

    errno = 0;
    memset(&limit, 0, sizeof(limit));
    error = setrlimit(RLIMIT_CORE, &limit);

    if (error == 0) {
        error = getrlimit(RLIMIT_CORE, &limit);
        if (error) {
            ERR_MSG("Warning - cannot turn off core dumps");
            return false;
        } else if (limit.rlim_cur == 0) {
            return true; // disabling core dumps ok
        } else {
            return false; // failed for some reason?
        }
    }
    return false;
}
#endif

static bool
set_pass_fd(FILE **file, int passfd)
{
    if (!file) {
        return false;
    }
    *file = fdopen(passfd, "r");
    if (!*file) {
        ERR_MSG("cannot open fd %d for reading", passfd);
        return false;
    }
    return true;
}

static char *
ptimestr(char *dest, size_t size, time_t t)
{
    struct tm *tm;

    tm = gmtime(&t);
    (void) snprintf(
      dest, size, "%04d-%02d-%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    return dest;
}

/** @brief checks whether file exists already and asks user for the new filename
 *  @param path output file name with path. May be NULL, then user is asked for it.
 *  @param newpath preallocated pointer which will store the result on success
 *  @param maxlen maximum number of chars in newfile, including the trailing \0
 *  @param overwrite whether it is allowed to overwrite output file by default
 *  @return true on success, or false otherwise (user cancels the operation)
 **/

static bool
rnp_get_output_filename(const char *path, char *newpath, size_t maxlen, bool overwrite)
{
    char reply[10];

    if (!path || !path[0]) {
        fprintf(stdout, "Please enter the output filename: ");
        if (fgets(newpath, maxlen, stdin) == NULL) {
            return false;
        }
        rnp_strip_eol(newpath);
    } else {
        strncpy(newpath, path, maxlen - 1);
        newpath[maxlen - 1] = '\0';
    }

    while (true) {
        if (rnp_file_exists(newpath)) {
            if (overwrite) {
                unlink(newpath);
                return true;
            }

            fprintf(stdout,
                    "File '%s' already exists. Would you like to overwrite it (y/N)?",
                    newpath);

            if (fgets(reply, sizeof(reply), stdin) == NULL) {
                return false;
            }
            if (strlen(reply) > 0 && toupper(reply[0]) == 'Y') {
                unlink(newpath);
                return true;
            }

            fprintf(stdout, "Please enter the new filename: ");
            if (fgets(newpath, maxlen, stdin) == NULL) {
                return false;
            }

            rnp_strip_eol(newpath);

            if (strlen(newpath) == 0) {
                return false;
            }
        } else {
            return true;
        }
    }
}

static bool
stdin_getpass(const char *prompt, char *buffer, size_t size)
{
#ifndef _WIN32
    struct termios saved_flags, noecho_flags;
    bool           restore_ttyflags = false;
#endif
    bool  ok = false;
    FILE *in = NULL;
    FILE *out = NULL;

    // validate args
    if (!buffer) {
        goto end;
    }
    // doesn't hurt
    *buffer = '\0';

#ifndef _WIN32
    in = fopen("/dev/tty", "w+ce");
#endif
    if (!in) {
        in = stdin;
        out = stderr;
    } else {
        out = in;
    }

    // TODO: Implement alternative for hiding password entry on Windows
    // TODO: avoid duplicate termios code with pass-provider.cpp
#ifndef _WIN32
    // save the original termios
    if (tcgetattr(fileno(in), &saved_flags) == 0) {
        noecho_flags = saved_flags;
        // disable echo in the local modes
        noecho_flags.c_lflag = (noecho_flags.c_lflag & ~ECHO) | ECHONL | ISIG;
        restore_ttyflags = (tcsetattr(fileno(in), TCSANOW, &noecho_flags) == 0);
    }
#endif
    if (prompt) {
        fputs(prompt, out);
    }
    if (fgets(buffer, size, in) == NULL) {
        goto end;
    }

    rnp_strip_eol(buffer);
    ok = true;
end:
#ifndef _WIN32
    if (restore_ttyflags) {
        tcsetattr(fileno(in), TCSAFLUSH, &saved_flags);
    }
#endif
    if (in != stdin) {
        fclose(in);
    }
    return ok;
}

static bool
ffi_pass_callback_stdin(rnp_ffi_t        ffi,
                        void *           app_ctx,
                        rnp_key_handle_t key,
                        const char *     pgp_context,
                        char             buf[],
                        size_t           buf_len)
{
    char *keyid = NULL;
    char  target[64] = {0};
    char  prompt[128] = {0};
    char  buffer[MAX_PASSWORD_LENGTH];
    bool  ok = false;

    if (!ffi || !pgp_context) {
        goto done;
    }

    if (strcmp(pgp_context, "decrypt (symmetric)") &&
        strcmp(pgp_context, "encrypt (symmetric)")) {
        rnp_key_get_keyid(key, &keyid);
        snprintf(target, sizeof(target), "key 0x%s", keyid);
        rnp_buffer_destroy(keyid);
    }
start:
    if (!strcmp(pgp_context, "decrypt (symmetric)")) {
        snprintf(prompt, sizeof(prompt), "Enter password to decrypt data: ");
    } else if (!strcmp(pgp_context, "encrypt (symmetric)")) {
        snprintf(prompt, sizeof(prompt), "Enter password to encrypt data: ");
    } else {
        snprintf(prompt, sizeof(prompt), "Enter password for %s: ", target);
    }

    if (!stdin_getpass(prompt, buf, buf_len)) {
        goto done;
    }
    if (!strcmp(pgp_context, "protect") || !strcmp(pgp_context, "encrypt (symmetric)")) {
        if (!strcmp(pgp_context, "protect")) {
            snprintf(prompt, sizeof(prompt), "Repeat password for %s: ", target);
        } else {
            snprintf(prompt, sizeof(prompt), "Repeat password: ");
        }

        if (!stdin_getpass(prompt, buffer, sizeof(buffer))) {
            goto done;
        }
        if (strcmp(buf, buffer) != 0) {
            puts("\nPasswords do not match!");
            // currently will loop forever
            goto start;
        }
    }
    ok = true;
done:
    puts("");
    pgp_forget(buffer, sizeof(buffer));
    return ok;
}

static bool
ffi_pass_callback_file(rnp_ffi_t        ffi,
                       void *           app_ctx,
                       rnp_key_handle_t key,
                       const char *     pgp_context,
                       char             buf[],
                       size_t           buf_len)
{
    if (!app_ctx || !buf || !buf_len) {
        return false;
    }

    FILE *fp = (FILE *) app_ctx;
    if (!fgets(buf, buf_len, fp)) {
        return false;
    }
    rnp_strip_eol(buf);
    return true;
}

static bool
ffi_pass_callback_string(rnp_ffi_t        ffi,
                         void *           app_ctx,
                         rnp_key_handle_t key,
                         const char *     pgp_context,
                         char             buf[],
                         size_t           buf_len)
{
    if (!app_ctx || !buf || !buf_len) {
        return false;
    }

    const char *pswd = (const char *) app_ctx;
    if (strlen(pswd) >= buf_len) {
        return false;
    }

    strncpy(buf, pswd, buf_len);
    return true;
}

bool
cli_rnp_init(cli_rnp_t *rnp, rnp_cfg_t *cfg)
{
    bool coredumps = true;

    /* If system resource constraints are in effect then attempt to
     * disable core dumps.
     */
    if (!rnp_cfg_getbool(cfg, CFG_COREDUMPS)) {
#ifdef HAVE_SYS_RESOURCE_H
        coredumps = !disable_core_dumps();
#endif
    }

    if (coredumps) {
        ERR_MSG(
          "rnp: warning: core dumps may be enabled, sensitive data may be leaked to disk");
    }

    /* Configure the results stream. */
    const char *ress = rnp_cfg_getstr(cfg, CFG_IO_RESS);
    if (!ress || !strcmp(ress, "<stderr>")) {
        rnp->resfp = stderr;
    } else if (strcmp(ress, "<stdout>") == 0) {
        rnp->resfp = stdout;
    } else if (!(rnp->resfp = fopen(ress, "w"))) {
        ERR_MSG("cannot open results %s for writing", ress);
        return false;
    }

    bool        res = false;
    const char *format = rnp_cfg_getstr(cfg, CFG_KR_PUB_FORMAT);
    if (!format || !(rnp->pubformat = strdup(format))) {
        return false;
    }
    format = rnp_cfg_getstr(cfg, CFG_KR_SEC_FORMAT);
    if (!format || !(rnp->secformat = strdup(format))) {
        return false;
    }
    if (rnp_ffi_create(&rnp->ffi, rnp->pubformat, rnp->secformat)) {
        ERR_MSG("failed to initialize FFI");
        return false;
    }

    // by default use stdin password provider
    if (rnp_ffi_set_pass_provider(rnp->ffi, ffi_pass_callback_stdin, NULL)) {
        goto done;
    }

    // setup file/pipe password input if requested
    if (rnp_cfg_getint_default(cfg, CFG_PASSFD, -1) >= 0) {
        if (!set_pass_fd(&rnp->passfp, rnp_cfg_getint(cfg, CFG_PASSFD))) {
            goto done;
        }
        if (rnp_ffi_set_pass_provider(rnp->ffi, ffi_pass_callback_file, rnp->passfp)) {
            goto done;
        }
    }

    rnp->pswdtries = MAX_PASSWORD_ATTEMPTS;

    if (rnp_cfg_getstr(cfg, CFG_KR_PUB_PATH)) {
        rnp->pubpath = strdup(rnp_cfg_getstr(cfg, CFG_KR_PUB_PATH));
        if (!rnp->pubpath) {
            ERR_MSG("allocation failed");
            goto done;
        }
    }
    if (rnp_cfg_getstr(cfg, CFG_KR_SEC_PATH)) {
        rnp->secpath = strdup(rnp_cfg_getstr(cfg, CFG_KR_SEC_PATH));
        if (!rnp->secpath) {
            ERR_MSG("allocation failed");
            goto done;
        }
    }
    res = true;
done:
    if (!res) {
        rnp_ffi_destroy(rnp->ffi);
        rnp->ffi = NULL;
    }
    return res;
}

void
cli_rnp_end(cli_rnp_t *rnp)
{
    free(rnp->pubpath);
    free(rnp->pubformat);
    free(rnp->secpath);
    free(rnp->secformat);

    if (rnp->defkey) {
        free(rnp->defkey);
        rnp->defkey = NULL;
    }
    if (rnp->passfp) {
        fclose(rnp->passfp);
        rnp->passfp = NULL;
    }
    if (rnp->resfp && (rnp->resfp != stderr) && (rnp->resfp != stdout)) {
        fclose(rnp->resfp);
        rnp->resfp = NULL;
    }
    rnp_ffi_destroy(rnp->ffi);
    memset(rnp, 0, sizeof(*rnp));
}

bool
cli_rnp_load_keyrings(cli_rnp_t *rnp, bool loadsecret)
{
    rnp_input_t keyin = NULL;
    size_t      keycount = 0;
    bool        res = false;

    if (rnp_unload_keys(rnp->ffi, RNP_KEY_UNLOAD_PUBLIC)) {
        ERR_MSG("failed to clear public keyring");
        goto done;
    }

    if (rnp_input_from_path(&keyin, rnp->pubpath)) {
        ERR_MSG("wrong pubring path");
        goto done;
    }

    if (rnp_load_keys(rnp->ffi, rnp->pubformat, keyin, RNP_LOAD_SAVE_PUBLIC_KEYS)) {
        ERR_MSG("cannot read pub keyring");
        goto done;
    }

    rnp_input_destroy(keyin);
    keyin = NULL;

    if (rnp_get_public_key_count(rnp->ffi, &keycount)) {
        goto done;
    }

    if (keycount < 1) {
        ERR_MSG("pub keyring '%s' is empty", rnp->pubpath);
        goto done;
    }

    /* Only read secret keys if we need to */
    if (loadsecret) {
        if (rnp_unload_keys(rnp->ffi, RNP_KEY_UNLOAD_SECRET)) {
            ERR_MSG("failed to clear secret keyring");
            goto done;
        }

        if (rnp_input_from_path(&keyin, rnp->secpath)) {
            ERR_MSG("wrong secring path");
            goto done;
        }

        if (rnp_load_keys(rnp->ffi, rnp->secformat, keyin, RNP_LOAD_SAVE_SECRET_KEYS)) {
            ERR_MSG("cannot read sec keyring");
            goto done;
        }

        rnp_input_destroy(keyin);
        keyin = NULL;

        if (rnp_get_secret_key_count(rnp->ffi, &keycount)) {
            goto done;
        }

        if (keycount < 1) {
            ERR_MSG("sec keyring '%s' is empty", rnp->secpath);
            goto done;
        }
    }
    if (!rnp->defkey) {
        cli_rnp_set_default_key(rnp);
    }
    res = true;
done:
    rnp_input_destroy(keyin);
    return res;
}

void
cli_rnp_set_default_key(cli_rnp_t *rnp)
{
    rnp_identifier_iterator_t it = NULL;
    rnp_key_handle_t          handle = NULL;
    const char *              grip = NULL;

    free(rnp->defkey);
    rnp->defkey = NULL;

    if (rnp_identifier_iterator_create(rnp->ffi, &it, "grip")) {
        ERR_MSG("failed to create key iterator");
        return;
    }

    while (!rnp_identifier_iterator_next(it, &grip)) {
        bool is_subkey = false;
        bool is_secret = false;

        if (!grip) {
            break;
        }
        if (rnp_locate_key(rnp->ffi, "grip", grip, &handle)) {
            ERR_MSG("failed to locate key");
            continue;
        }
        if (rnp_key_is_sub(handle, &is_subkey) || is_subkey) {
            goto next;
        }
        if (rnp_key_have_secret(handle, &is_secret)) {
            goto next;
        }
        if (!rnp->defkey || is_secret) {
            free(rnp->defkey);
            rnp->defkey = strdup(grip);
            if (!rnp->defkey) {
                ERR_MSG("allocation failed");
                goto done;
            }
        }
        /* if we have secret primary key then use it as default */
        if (is_secret) {
            goto done;
        }

    next:
        rnp_key_handle_destroy(handle);
        handle = NULL;
    }

done:
    rnp_key_handle_destroy(handle);
    rnp_identifier_iterator_destroy(it);
}

const char *
json_obj_get_str(json_object *obj, const char *key)
{
    json_object *fld = NULL;
    if (!json_object_object_get_ex(obj, key, &fld)) {
        return NULL;
    }
    return json_object_get_string(fld);
}

int64_t
json_obj_get_int64(json_object *obj, const char *key)
{
    json_object *fld = NULL;
    if (!json_object_object_get_ex(obj, key, &fld)) {
        return 0;
    }
    return json_object_get_int64(fld);
}

bool
rnp_casecmp(const std::string &str1, const std::string &str2)
{
    if (str1.size() != str2.size()) {
        return false;
    }

    for (size_t i = 0; i < str1.size(); i++) {
        if (tolower(str1[i]) != tolower(str2[i])) {
            return false;
        }
    }
    return true;
}

static char *
cli_key_usage_str(rnp_key_handle_t key, char *buf)
{
    char *orig = buf;
    bool  allow = false;

    if (!rnp_key_allows_usage(key, "encrypt", &allow) && allow) {
        *buf++ = 'E';
    }
    allow = false;
    if (!rnp_key_allows_usage(key, "sign", &allow) && allow) {
        *buf++ = 'S';
    }
    allow = false;
    if (!rnp_key_allows_usage(key, "certify", &allow) && allow) {
        *buf++ = 'C';
    }
    allow = false;
    if (!rnp_key_allows_usage(key, "authenticate", &allow) && allow) {
        *buf++ = 'A';
    }
    *buf = '\0';
    return orig;
}

void
cli_rnp_print_key_info(FILE *fp, rnp_ffi_t ffi, rnp_key_handle_t key, bool psecret, bool psigs)
{
    char         buf[64] = {0};
    const char * header = NULL;
    bool         secret = false;
    bool         primary = false;
    uint32_t     bits = 0;
    int64_t      create = 0;
    uint32_t     expiry = 0;
    size_t       uids = 0;
    char *       json = NULL;
    json_object *pkts = NULL;
    json_object *keypkt = NULL;

    /* header */
    if (rnp_key_have_secret(key, &secret) || rnp_key_is_primary(key, &primary) ||
        rnp_key_packets_to_json(key, false, RNP_JSON_DUMP_GRIP, &json)) {
        fprintf(fp, "Key error.\n");
        return;
    }
    if (!(pkts = json_tokener_parse(json))) {
        fprintf(fp, "Key JSON error");
        goto done;
    }
    if (!(keypkt = json_object_array_get_idx(pkts, 0))) {
        fprintf(fp, "Key JSON error");
        goto done;
    }

    if (psecret && secret) {
        header = primary ? "sec" : "ssb";
    } else {
        header = primary ? "pub" : "sub";
    }
    if (primary) {
        fprintf(fp, "\n");
    }
    fprintf(fp, "%s   ", header);

    /* key bits */
    rnp_key_get_bits(key, &bits);
    fprintf(fp, "%d/", (int) bits);
    /* key algorithm */
    fprintf(fp, "%s ", json_obj_get_str(keypkt, "algorithm.str"));
    /* key id */
    fprintf(fp, "%s", json_obj_get_str(keypkt, "keyid"));
    /* key creation time */
    create = json_obj_get_int64(keypkt, "creation time");
    fprintf(fp, " %s", ptimestr(buf, sizeof(buf), create));
    /* key usage */
    fprintf(fp, " [%s]", cli_key_usage_str(key, buf));
    /* key expiration */
    (void) rnp_key_get_expiration(key, &expiry);
    if (expiry > 0) {
        time_t now = time(NULL);
        time_t expire_time = create + expiry;
        ptimestr(buf, sizeof(buf), expire_time);
        fprintf(fp, " [%s %s]", expire_time <= now ? "EXPIRED" : "EXPIRES", buf);
    }
    /* fingerprint */
    fprintf(fp, "\n      %s\n", json_obj_get_str(keypkt, "fingerprint"));
    /* user ids */
    (void) rnp_key_get_uid_count(key, &uids);
    for (size_t i = 0; i < uids; i++) {
        rnp_uid_handle_t uid = NULL;
        bool             revoked = false;
        char *           uid_str = NULL;
        size_t           sigs = 0;

        if (rnp_key_get_uid_handle_at(key, i, &uid)) {
            continue;
        }
        (void) rnp_uid_is_revoked(uid, &revoked);
        (void) rnp_key_get_uid_at(key, i, &uid_str);

        /* userid itself with revocation status */
        fprintf(fp, "uid           %s", uid_str);
        fprintf(fp, "%s\n", revoked ? "[REVOKED]" : "");
        rnp_buffer_destroy(uid_str);

        /* print signatures only if requested */
        if (!psigs) {
            (void) rnp_uid_handle_destroy(uid);
            continue;
        }

        (void) rnp_uid_get_signature_count(uid, &sigs);
        for (size_t j = 0; j < sigs; j++) {
            rnp_signature_handle_t sig = NULL;
            rnp_key_handle_t       signer = NULL;
            char *                 keyid = NULL;
            uint32_t               creation = 0;
            char *                 signer_uid = NULL;

            if (rnp_uid_get_signature_at(uid, j, &sig)) {
                continue;
            }
            if (rnp_signature_get_creation(sig, &creation)) {
                goto next;
            }
            if (rnp_signature_get_keyid(sig, &keyid)) {
                goto next;
            }
            /* lowercase key id */
            for (char *idptr = keyid; *idptr; ++idptr) {
                *idptr = tolower(*idptr);
            }
            /* signer primary uid */
            if (rnp_locate_key(ffi, "keyid", keyid, &signer)) {
                goto next;
            }
            if (signer) {
                (void) rnp_key_get_primary_uid(signer, &signer_uid);
            }

            /* signer key id */
            fprintf(fp, "sig           %s ", keyid ? keyid : "[no key id]");
            /* signature creation time */
            fprintf(fp, "%s", ptimestr(buf, sizeof(buf), creation));
            /* signer's userid */
            fprintf(fp, " %s\n", signer_uid ? signer_uid : "[unknown]");
        next:
            (void) rnp_signature_handle_destroy(sig);
            (void) rnp_key_handle_destroy(signer);
            rnp_buffer_destroy(keyid);
            rnp_buffer_destroy(signer_uid);
        }
        (void) rnp_uid_handle_destroy(uid);
    }

done:
    rnp_buffer_destroy(json);
    json_object_put(pkts);
}

bool
cli_rnp_save_keyrings(cli_rnp_t *rnp)
{
    rnp_output_t output = NULL;
    rnp_result_t pub_ret = 0;
    rnp_result_t sec_ret = 0;

    // check whether we have G10 secret keyring - then need to create directory
    if (!strcmp(rnp->secformat, "G10")) {
        struct stat path_stat;
        if (stat(rnp->secpath, &path_stat) != -1) {
            if (!S_ISDIR(path_stat.st_mode)) {
                ERR_MSG("G10 keystore should be a directory: %s", rnp->secpath);
                return false;
            }
        } else {
            if (errno != ENOENT) {
                ERR_MSG("stat(%s): %s", rnp->secpath, strerror(errno));
                return false;
            }
            if (RNP_MKDIR(rnp->secpath, S_IRWXU) != 0) {
                ERR_MSG("mkdir(%s, S_IRWXU): %s", rnp->secpath, strerror(errno));
                return false;
            }
        }
    }

    // public keyring
    if (!(pub_ret = rnp_output_to_path(&output, rnp->pubpath))) {
        pub_ret = rnp_save_keys(rnp->ffi, rnp->pubformat, output, RNP_LOAD_SAVE_PUBLIC_KEYS);
        rnp_output_destroy(output);
    }
    if (pub_ret) {
        ERR_MSG("failed to write pubring to path '%s'", rnp->pubpath);
    }

    // secret keyring
    if (!(sec_ret = rnp_output_to_path(&output, rnp->secpath))) {
        sec_ret = rnp_save_keys(rnp->ffi, rnp->secformat, output, RNP_LOAD_SAVE_SECRET_KEYS);
        rnp_output_destroy(output);
    }
    if (sec_ret) {
        ERR_MSG("failed to write secring to path '%s'\n", rnp->secpath);
    }

    return !pub_ret && !sec_ret;
}

bool
cli_rnp_generate_key(rnp_cfg_t *cfg, cli_rnp_t *rnp, const char *username)
{
    /* set key generation parameters to rnp_cfg_t */
    if (!cli_rnp_set_generate_params(cfg)) {
        (void) fprintf(stderr, "Key generation setup failed.\n");
        return false;
    }
    /* generate the primary key */
    rnp_op_generate_t genkey = NULL;
    rnp_key_handle_t  primary = NULL;
    rnp_key_handle_t  subkey = NULL;
    bool              res = false;

    if (rnp_op_generate_create(&genkey, rnp->ffi, rnp_cfg_getstr(cfg, CFG_KG_PRIMARY_ALG))) {
        (void) fprintf(stderr, "Failed to initialize key generation.\n");
        return false;
    }
    if (username && rnp_op_generate_set_userid(genkey, username)) {
        (void) fprintf(stderr, "Failed to set userid.\n");
        goto done;
    }
    if (rnp_cfg_hasval(cfg, CFG_KG_PRIMARY_BITS) &&
        rnp_op_generate_set_bits(genkey, rnp_cfg_getint(cfg, CFG_KG_PRIMARY_BITS))) {
        (void) fprintf(stderr, "Failed to set key bits.\n");
        goto done;
    }
    if (rnp_cfg_hasval(cfg, CFG_KG_PRIMARY_CURVE) &&
        rnp_op_generate_set_curve(genkey, rnp_cfg_getstr(cfg, CFG_KG_PRIMARY_CURVE))) {
        (void) fprintf(stderr, "Failed to set key curve.\n");
        goto done;
    }
    // TODO : set DSA qbits
    if (rnp_op_generate_set_hash(genkey, rnp_cfg_getstr(cfg, CFG_KG_HASH))) {
        (void) fprintf(stderr, "Failed to set hash algorithm.\n");
        goto done;
    }
    if (rnp_op_generate_set_protection_cipher(genkey, rnp_cfg_getstr(cfg, CFG_KG_PROT_ALG))) {
        (void) fprintf(stderr, "Failed to set protection algorithm.\n");
        goto done;
    }
    if (rnp_op_generate_set_protection_hash(genkey, rnp_cfg_getstr(cfg, CFG_KG_PROT_HASH))) {
        (void) fprintf(stderr, "Failed to set protection hash algorithm.\n");
        goto done;
    }
    if (rnp_op_generate_set_protection_iterations(
          genkey, rnp_cfg_getint(cfg, CFG_KG_PROT_ITERATIONS))) {
        (void) fprintf(stderr, "Failed to set protection iterations.\n");
        goto done;
    }

    fprintf(stdout, "Generating a new key...\n");
    if (rnp_op_generate_execute(genkey) || rnp_op_generate_get_key(genkey, &primary)) {
        (void) fprintf(stderr, "Primary key generation failed.\n");
        goto done;
    }

    if (!rnp_cfg_getstr(cfg, CFG_KG_SUBKEY_ALG)) {
        res = true;
        goto done;
    }

    rnp_op_generate_destroy(genkey);
    genkey = NULL;
    if (rnp_op_generate_subkey_create(
          &genkey, rnp->ffi, primary, rnp_cfg_getstr(cfg, CFG_KG_SUBKEY_ALG))) {
        (void) fprintf(stderr, "Failed to initialize subkey generation.\n");
        goto done;
    }
    if (rnp_cfg_hasval(cfg, CFG_KG_SUBKEY_BITS) &&
        rnp_op_generate_set_bits(genkey, rnp_cfg_getint(cfg, CFG_KG_SUBKEY_BITS))) {
        (void) fprintf(stderr, "Failed to set subkey bits.\n");
        goto done;
    }
    if (rnp_cfg_hasval(cfg, CFG_KG_SUBKEY_CURVE) &&
        rnp_op_generate_set_curve(genkey, rnp_cfg_getstr(cfg, CFG_KG_SUBKEY_CURVE))) {
        (void) fprintf(stderr, "Failed to set subkey curve.\n");
        goto done;
    }
    // TODO : set DSA qbits
    if (rnp_op_generate_set_hash(genkey, rnp_cfg_getstr(cfg, CFG_KG_HASH))) {
        (void) fprintf(stderr, "Failed to set hash algorithm.\n");
        goto done;
    }
    if (rnp_op_generate_set_protection_cipher(genkey, rnp_cfg_getstr(cfg, CFG_KG_PROT_ALG))) {
        (void) fprintf(stderr, "Failed to set protection algorithm.\n");
        goto done;
    }
    if (rnp_op_generate_set_protection_hash(genkey, rnp_cfg_getstr(cfg, CFG_KG_PROT_HASH))) {
        (void) fprintf(stderr, "Failed to set protection hash algorithm.\n");
        goto done;
    }
    if (rnp_op_generate_set_protection_iterations(
          genkey, rnp_cfg_getint(cfg, CFG_KG_PROT_ITERATIONS))) {
        (void) fprintf(stderr, "Failed to set protection iterations.\n");
        goto done;
    }
    if (rnp_op_generate_execute(genkey) || rnp_op_generate_get_key(genkey, &subkey)) {
        (void) fprintf(stderr, "Subkey generation failed.\n");
        goto done;
    }

    res = cli_rnp_save_keyrings(rnp);
done:
    if (res) {
        cli_rnp_print_key_info(stdout, rnp->ffi, primary, true, false);
        if (subkey) {
            cli_rnp_print_key_info(stdout, rnp->ffi, subkey, true, false);
        }
    }
    rnp_op_generate_destroy(genkey);
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(subkey);
    return res;
}

static bool
str_is_hex(const char *hexid, size_t hexlen)
{
    /* todo: this function duplicates ishex from rnp_sdk.h. Should we add it to FFI? */
    if ((hexlen >= 2) && (hexid[0] == '0') && ((hexid[1] == 'x') || (hexid[1] == 'X'))) {
        hexid += 2;
        hexlen -= 2;
    }

    for (size_t i = 0; i < hexlen; i++) {
        if ((hexid[i] >= '0') && (hexid[i] <= '9')) {
            continue;
        }
        if ((hexid[i] >= 'a') && (hexid[i] <= 'f')) {
            continue;
        }
        if ((hexid[i] >= 'A') && (hexid[i] <= 'F')) {
            continue;
        }
        if ((hexid[i] == ' ') || (hexid[i] == '\t')) {
            continue;
        }
        return false;
    }
    return true;
}

static bool
key_matches_string(rnp_key_handle_t handle, const char *str, bool secret)
{
    bool   matches = false;
    char * id = NULL;
    size_t idlen = 0;
    size_t len = str ? strlen(str) : 0;
#ifndef RNP_USE_STD_REGEX
    regex_t r = {};
#else
    std::regex re;
#endif
    size_t uid_count = 0;
    bool   boolres = false;

    if (rnp_key_have_secret(handle, &boolres)) {
        goto done;
    }

    if (secret && !boolres) {
        goto done;
    }

    if (!str) {
        matches = true;
        goto done;
    }

    if (str_is_hex(str, len) && (len >= RNP_KEYID_SIZE)) {
        const char *hexstr = str;

        if ((str[0] == '0') && ((str[1] == 'x') || (str[1] == 'X'))) {
            hexstr += 2;
            len -= 2;
        }

        /* check whether it's key id */
        if ((len == RNP_KEYID_SIZE * 2) || (len == RNP_KEYID_SIZE)) {
            if (rnp_key_get_keyid(handle, &id)) {
                goto done;
            }

            if ((idlen = strlen(id)) < len) {
                goto done;
            }

            if (strncasecmp(hexstr, id + idlen - len, len) == 0) {
                matches = true;
                goto done;
            }
            rnp_buffer_destroy(id);
            id = NULL;
        }

        /* check fingerprint */
        if (len == RNP_FP_SIZE * 2) {
            if (rnp_key_get_fprint(handle, &id)) {
                goto done;
            }

            if (strlen(id) != len) {
                goto done;
            }

            if (strncasecmp(hexstr, id, len) == 0) {
                matches = true;
                goto done;
            }
            rnp_buffer_destroy(id);
            id = NULL;
        }

        /* check grip */
        if (len == RNP_GRIP_SIZE * 2) {
            if (rnp_key_get_grip(handle, &id)) {
                goto done;
            }

            if (strlen(id) != len) {
                goto done;
            }

            if (strncasecmp(hexstr, id, len) == 0) {
                matches = true;
                goto done;
            }
            rnp_buffer_destroy(id);
            id = NULL;
        }
        /* let then search for hex userid */
    }

    /* no need to check for userid over the subkey */
    if (rnp_key_is_sub(handle, &boolres) || boolres) {
        goto done;
    }

    if (rnp_key_get_uid_count(handle, &uid_count) || (uid_count == 0)) {
        goto done;
    }

#ifndef RNP_USE_STD_REGEX
    /* match on full name or email address as a NOSUB, ICASE regexp */
    if (regcomp(&r, str, REG_EXTENDED | REG_ICASE) != 0) {
        goto done;
    }
#else
    re.assign(str, std::regex_constants::extended | std::regex_constants::icase);
#endif

    for (size_t idx = 0; idx < uid_count; idx++) {
        if (rnp_key_get_uid_at(handle, idx, &id)) {
            goto regdone;
        }

#ifndef RNP_USE_STD_REGEX
        if (regexec(&r, id, 0, NULL, 0) == 0) {
            matches = true;
            goto regdone;
        }
#else
        if (std::regex_search(id, re)) {
            matches = true;
            goto regdone;
        }
#endif

        rnp_buffer_destroy(id);
        id = NULL;
    }

regdone:
#ifndef RNP_USE_STD_REGEX
    regfree(&r);
#endif
done:
    rnp_buffer_destroy(id);
    return matches;
}

void
cli_rnp_keylist_destroy(list *keys)
{
    for (list_item *kh = list_front(*keys); kh; kh = list_next(kh)) {
        rnp_key_handle_destroy(*((rnp_key_handle_t *) kh));
    }
    list_destroy(keys);
}

static rnp_key_handle_t
key_matching_string(cli_rnp_t *rnp, const std::string &str, bool secret)
{
    rnp_identifier_iterator_t it = NULL;
    rnp_key_handle_t          handle = NULL;
    const char *              grip = NULL;
    rnp_ffi_t                 ffi = rnp->ffi;

    // TODO: optimize this to get key by id/fingerprint if one is specified
    if (rnp_identifier_iterator_create(ffi, &it, "grip")) {
        return NULL;
    }

    while (!rnp_identifier_iterator_next(it, &grip)) {
        if (!grip) {
            goto done;
        }
        if (rnp_locate_key(ffi, "grip", grip, &handle)) {
            goto done;
        }
        if (key_matches_string(handle, str.c_str(), secret)) {
            goto done;
        }
        rnp_key_handle_destroy(handle);
        handle = NULL;
    }
done:
    rnp_identifier_iterator_destroy(it);
    return handle;
}

list
cli_rnp_get_keylist(cli_rnp_t *rnp, const char *filter, bool secret)
{
    list                      result = NULL;
    rnp_identifier_iterator_t it = NULL;
    rnp_key_handle_t          handle = NULL;
    const char *              grip = NULL;
    rnp_ffi_t                 ffi = rnp->ffi;

    if (rnp_identifier_iterator_create(ffi, &it, "grip")) {
        return NULL;
    }

    while (!rnp_identifier_iterator_next(it, &grip)) {
        size_t sub_count = 0;
        bool   is_subkey = false;
        char * primary_grip = NULL;

        if (!grip) {
            goto done;
        }

        if (rnp_locate_key(ffi, "grip", grip, &handle)) {
            goto error;
        }
        if (!key_matches_string(handle, filter, secret)) {
            rnp_key_handle_destroy(handle);
            continue;
        }
        /* check whether key is subkey */
        if (rnp_key_is_sub(handle, &is_subkey)) {
            rnp_key_handle_destroy(handle);
            goto error;
        }
        if (is_subkey && rnp_key_get_primary_grip(handle, &primary_grip)) {
            rnp_key_handle_destroy(handle);
            goto error;
        }
        /* if we have primary key then subkey will be printed together with primary */
        if (is_subkey && primary_grip) {
            rnp_buffer_destroy(primary_grip);
            rnp_key_handle_destroy(handle);
            continue;
        }

        if (!list_append(&result, &handle, sizeof(handle))) {
            rnp_key_handle_destroy(handle);
            goto error;
        }

        /* add subkeys as well, if key is primary */
        if (is_subkey) {
            continue;
        }
        if (rnp_key_get_subkey_count(handle, &sub_count)) {
            goto error;
        }
        for (size_t i = 0; i < sub_count; i++) {
            rnp_key_handle_t sub_handle = NULL;
            if (rnp_key_get_subkey_at(handle, i, &sub_handle)) {
                goto error;
            }
            if (!list_append(&result, &sub_handle, sizeof(sub_handle))) {
                rnp_key_handle_destroy(sub_handle);
                goto error;
            }
        }
    }

error:
    cli_rnp_keylist_destroy(&result);
done:
    rnp_identifier_iterator_destroy(it);
    return result;
}

/** @brief compose path from dir, subdir and filename, and store it in the res
 *  @param dir [in] null-terminated directory path, cannot be NULL
 *  @param subddir [in] null-terminated subdirectory to add to the path, can be NULL
 *  @param filename [in] null-terminated filename (or path/filename), cannot be NULL
 *  @param res [out] preallocated buffer
 *  @param res_size [in] size of output res buffer
 *
 *  @return true if path constructed successfully, or false otherwise
 **/
static bool
rnp_path_compose(
  const char *dir, const char *subdir, const char *filename, char *res, size_t res_size)
{
    int pos;

    /* checking input parameters for conrrectness */
    if (!dir || !filename || !res) {
        return false;
    }

    /* concatenating dir, subdir and filename */
    if (strlen(dir) > res_size - 1) {
        return false;
    }

    strcpy(res, dir);
    pos = strlen(dir);

    if (subdir) {
        if ((pos > 0) && (res[pos - 1] != '/')) {
            res[pos++] = '/';
        }

        if (strlen(subdir) + pos > res_size - 1) {
            return false;
        }

        strcpy(res + pos, subdir);
        pos += strlen(subdir);
    }

    if ((pos > 0) && (res[pos - 1] != '/')) {
        res[pos++] = '/';
    }

    if (strlen(filename) + pos > res_size - 1) {
        return false;
    }

    strcpy(res + pos, filename);

    return true;
}

/* helper function : get key storage subdir in case when user didn't specify homedir */
static const char *
rnp_cfg_get_ks_subdir(rnp_cfg_t *cfg, int defhomedir)
{
    const char *subdir;

    if (!defhomedir) {
        subdir = NULL;
    } else {
        if ((subdir = rnp_cfg_getstr(cfg, CFG_SUBDIRGPG)) == NULL) {
            subdir = SUBDIRECTORY_RNP;
        }
    }

    return subdir;
}

static bool
rnp_cfg_set_ks_info(rnp_cfg_t *cfg)
{
    bool        defhomedir = false;
    const char *homedir;
    const char *subdir;
    const char *ks_format;
    char        pubpath[MAXPATHLEN] = {0};
    char        secpath[MAXPATHLEN] = {0};
    struct stat st;

    /* getting path to keyrings. If it is specified by user in 'homedir' param then it is
     * considered as the final path */
    if (rnp_cfg_getint_default(cfg, CFG_KEYSTORE_DISABLED, 0)) {
        return rnp_cfg_setstr(cfg, CFG_KR_PUB_PATH, "") &&
               rnp_cfg_setstr(cfg, CFG_KR_SEC_PATH, "") &&
               rnp_cfg_setstr(cfg, CFG_KR_PUB_FORMAT, RNP_KEYSTORE_GPG) &&
               rnp_cfg_setstr(cfg, CFG_KR_SEC_FORMAT, RNP_KEYSTORE_GPG);
    }

    if (!(homedir = rnp_cfg_getstr(cfg, CFG_HOMEDIR))) {
        homedir = getenv("HOME");
        defhomedir = true;
    }

    /* detecting key storage format */
    if (!(ks_format = rnp_cfg_getstr(cfg, CFG_KEYSTOREFMT))) {
        if (!(subdir = rnp_cfg_getstr(cfg, CFG_SUBDIRGPG))) {
            subdir = SUBDIRECTORY_RNP;
        }
        if (!rnp_path_compose(
              homedir, defhomedir ? subdir : NULL, PUBRING_KBX, pubpath, sizeof(pubpath))) {
            return false;
        }
        if (!rnp_path_compose(
              homedir, defhomedir ? subdir : NULL, SECRING_G10, secpath, sizeof(secpath))) {
            return false;
        }

        bool pubpath_exists = stat(pubpath, &st) == 0;
        bool secpath_exists = stat(secpath, &st) == 0;

        if (pubpath_exists && secpath_exists) {
            ks_format = RNP_KEYSTORE_GPG21;
        } else if (secpath_exists) {
            ks_format = RNP_KEYSTORE_G10;
        } else if (pubpath_exists) {
            ks_format = RNP_KEYSTORE_KBX;
        } else {
            ks_format = RNP_KEYSTORE_GPG;
        }
    }

    /* building pubring/secring pathes */
    subdir = rnp_cfg_get_ks_subdir(cfg, defhomedir);

    /* creating home dir if needed */
    if (defhomedir && subdir) {
        if (!rnp_path_compose(homedir, NULL, subdir, pubpath, sizeof(pubpath))) {
            return false;
        }
        if (RNP_MKDIR(pubpath, 0700) == -1 && errno != EEXIST) {
            ERR_MSG("cannot mkdir '%s' errno = %d", pubpath, errno);
            return false;
        }
    }

    const char *pub_format = RNP_KEYSTORE_GPG;
    const char *sec_format = RNP_KEYSTORE_GPG;

    if (strcmp(ks_format, RNP_KEYSTORE_GPG) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_GPG, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_GPG, secpath, sizeof(secpath))) {
            return false;
        }
        pub_format = RNP_KEYSTORE_GPG;
        sec_format = RNP_KEYSTORE_GPG;
    } else if (strcmp(ks_format, RNP_KEYSTORE_GPG21) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_KBX, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_G10, secpath, sizeof(secpath))) {
            return false;
        }
        pub_format = RNP_KEYSTORE_KBX;
        sec_format = RNP_KEYSTORE_G10;
    } else if (strcmp(ks_format, RNP_KEYSTORE_KBX) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_KBX, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_KBX, secpath, sizeof(secpath))) {
            return false;
        }
        pub_format = RNP_KEYSTORE_KBX;
        sec_format = RNP_KEYSTORE_KBX;
    } else if (strcmp(ks_format, RNP_KEYSTORE_G10) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_G10, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_G10, secpath, sizeof(secpath))) {
            return false;
        }
        pub_format = RNP_KEYSTORE_G10;
        sec_format = RNP_KEYSTORE_G10;
    } else {
        ERR_MSG("unsupported keystore format: \"%s\"", ks_format);
        return false;
    }

    return rnp_cfg_setstr(cfg, CFG_KR_PUB_PATH, pubpath) &&
           rnp_cfg_setstr(cfg, CFG_KR_SEC_PATH, secpath) &&
           rnp_cfg_setstr(cfg, CFG_KR_PUB_FORMAT, pub_format) &&
           rnp_cfg_setstr(cfg, CFG_KR_SEC_FORMAT, sec_format);
}

/* read any gpg config file */
static bool
conffile(const char *homedir, char *userid, size_t length)
{
    char  buf[BUFSIZ];
    FILE *fp;

#ifndef RNP_USE_STD_REGEX
    regmatch_t matchv[10];
    regex_t    keyre;
#else
    static std::regex keyre("^[ \t]*default-key[ \t]+([0-9a-zA-F]+)",
                            std::regex_constants::extended);
#endif

    (void) snprintf(buf, sizeof(buf), "%s/.gnupg/gpg.conf", homedir);
    if ((fp = fopen(buf, "r")) == NULL) {
        return false;
    }
#ifndef RNP_USE_STD_REGEX
    (void) memset(&keyre, 0x0, sizeof(keyre));
    if (regcomp(&keyre, "^[ \t]*default-key[ \t]+([0-9a-zA-F]+)", REG_EXTENDED) != 0) {
        ERR_MSG("failed to compile regular expression");
        fclose(fp);
        return false;
    }
#endif
    while (fgets(buf, (int) sizeof(buf), fp) != NULL) {
#ifndef RNP_USE_STD_REGEX
        if (regexec(&keyre, buf, 10, matchv, 0) == 0) {
            (void) memcpy(userid,
                          &buf[(int) matchv[1].rm_so],
                          MIN((unsigned) (matchv[1].rm_eo - matchv[1].rm_so), length));

            (void) fprintf(stderr,
                           "rnp: default key set to \"%.*s\"\n",
                           (int) (matchv[1].rm_eo - matchv[1].rm_so),
                           &buf[(int) matchv[1].rm_so]);
        }
#else
        std::smatch result;
        std::string input = buf;
        if (std::regex_search(input, result, keyre)) {
            (void) strncpy(userid, result[1].str().c_str(), length);
            userid[length - 1] = '\0';

            (void) fprintf(stderr, "rnp: default key set to \"%s\"\n", userid);
        }
#endif
    }
    (void) fclose(fp);
#ifndef RNP_USE_STD_REGEX
    regfree(&keyre);
#endif
    return true;
}

static void
rnp_cfg_set_defkey(rnp_cfg_t *cfg)
{
    char        id[MAX_ID_LENGTH];
    const char *userid;
    const char *homedir;
    bool        defhomedir = false;

    if ((homedir = rnp_cfg_getstr(cfg, CFG_HOMEDIR)) == NULL) {
        homedir = getenv("HOME");
        defhomedir = true;
    }

    /* If a userid has been given, we'll use it. */
    userid = NULL;
    std::string uis = rnp_cfg_getlist_string(cfg, CFG_USERID, 0);
    if (!uis.empty()) {
        userid = uis.c_str();
    }
    if (!userid) {
        /* also search in config file for default id */

        if (defhomedir) {
            memset(id, 0, sizeof(id));
            conffile(homedir, id, sizeof(id));
            if (id[0] != 0x0) {
                rnp_cfg_unset(cfg, CFG_USERID);
                rnp_cfg_addstr(cfg, CFG_USERID, id);
                rnp_cfg_setstr(cfg, CFG_KR_DEF_KEY, id);
            }
        }
    } else {
        rnp_cfg_setstr(cfg, CFG_KR_DEF_KEY, userid);
    }
}

bool
cli_cfg_set_keystore_info(rnp_cfg_t *cfg)
{
    /* detecting keystore pathes and format */
    if (!rnp_cfg_set_ks_info(cfg)) {
        ERR_MSG("cannot obtain keystore path(es)");
        return false;
    }

    /* default key/userid */
    rnp_cfg_set_defkey(cfg);

    return true;
}

static ssize_t
stdin_reader(void *app_ctx, void *buf, size_t len)
{
    return read(STDIN_FILENO, buf, len);
}

static bool
stdout_writer(void *app_ctx, const void *buf, size_t len)
{
    ssize_t wlen = write(STDOUT_FILENO, buf, len);
    return (wlen >= 0) && (size_t) wlen == len;
}

bool
cli_rnp_export_keys(rnp_cfg_t *cfg, cli_rnp_t *rnp, const char *filter)
{
    bool secret = rnp_cfg_getbool(cfg, CFG_SECRET);
    list keys = cli_rnp_get_keylist(rnp, filter, secret);
    if (!keys) {
        fprintf(stdout, "Key(s) matching '%s' not found.\n", filter);
        return false;
    }

    rnp_output_t output = NULL;
    rnp_output_t armor = NULL;
    const char * file = rnp_cfg_getstr(cfg, CFG_OUTFILE);
    rnp_result_t ret;
    uint32_t     base_flags = secret ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC;
    bool         result = false;

    if (file) {
        uint32_t flags = rnp_cfg_getbool(cfg, CFG_FORCE) ? RNP_OUTPUT_FILE_OVERWRITE : 0;
        ret = rnp_output_to_file(&output, file, flags);
    } else {
        ret = rnp_output_to_callback(&output, stdout_writer, NULL, NULL);
    }
    if (ret) {
        goto done;
    }

    if (rnp_output_to_armor(output, &armor, secret ? "secret key" : "public key")) {
        goto done;
    }

    for (list_item *ki = list_front(keys); ki; ki = list_next(ki)) {
        uint32_t         flags = base_flags;
        rnp_key_handle_t key = *((rnp_key_handle_t *) ki);
        bool             primary = false;
        char *           grip = NULL;

        if (rnp_key_is_primary(key, &primary)) {
            goto done;
        }

        /* skip subkeys which have primary key */
        if (!primary && !rnp_key_get_primary_grip(key, &grip)) {
            if (grip) {
                rnp_buffer_destroy(grip);
                continue;
            }
        }

        if (primary) {
            flags = flags | RNP_KEY_EXPORT_SUBKEYS;
        }

        if (rnp_key_export(key, armor, flags)) {
            goto done;
        }
    }
    result = !rnp_output_finish(armor);
done:
    rnp_output_destroy(armor);
    rnp_output_destroy(output);
    cli_rnp_keylist_destroy(&keys);
    return result;
}

bool
cli_rnp_add_key(const rnp_cfg_t *cfg, cli_rnp_t *rnp)
{
    std::string path = rnp_cfg_getstring(cfg, CFG_KEYFILE);
    if (path.empty()) {
        return false;
    }

    rnp_input_t input = NULL;
    if (rnp_input_from_path(&input, path.c_str())) {
        ERR_MSG("failed to open key file %s", path.c_str());
        return false;
    }

    bool res = !rnp_import_keys(
      rnp->ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS, NULL);
    rnp_input_destroy(input);

    // set default key if we didn't have one
    if (res && !rnp->defkey) {
        cli_rnp_set_default_key(rnp);
    }

    return res;
}

static bool
strip_extension(std::string &src)
{
    size_t dpos = src.find_last_of('.');
    if (dpos == std::string::npos) {
        return false;
    }
    src.resize(dpos);
    return true;
}

static bool
has_extension(const std::string &path, const std::string &ext)
{
    if (path.length() < ext.length()) {
        return false;
    }
    return path.compare(path.length() - ext.length(), ext.length(), ext) == 0;
}

static std::string
output_extension(const rnp_cfg_t *cfg, const std::string &op)
{
    if (op == "encrypt_sign") {
        bool armor = rnp_cfg_getbool(cfg, CFG_ARMOR);
        if (rnp_cfg_getbool(cfg, CFG_DETACHED)) {
            return armor ? EXT_ASC : EXT_SIG;
        }
        if (rnp_cfg_getbool(cfg, CFG_CLEARTEXT)) {
            return EXT_ASC;
        }
        return armor ? EXT_ASC : EXT_PGP;
    }
    if (op == "armor") {
        return EXT_ASC;
    }
    return "";
}

static std::string
extract_filename(const std::string path)
{
    size_t lpos = path.find_last_of("/\\");
    if (lpos == std::string::npos) {
        return path;
    }
    return path.substr(lpos + 1);
}

/* TODO: replace temporary stub with C++ function */
static bool
adjust_output_path(std::string &path, bool overwrite)
{
    char pathbuf[PATH_MAX] = {0};

    if (!rnp_get_output_filename(path.c_str(), pathbuf, sizeof(pathbuf), overwrite)) {
        return false;
    }

    path = pathbuf;
    return true;
}

static bool
cli_rnp_init_io(const rnp_cfg_t *  cfg,
                const std::string &op,
                rnp_input_t *      input,
                rnp_output_t *     output)
{
    std::string in = rnp_cfg_getstring(cfg, CFG_INFILE);
    bool        is_stdin = in.empty() || (in == "-");
    if (input) {
        rnp_result_t res = is_stdin ?
                             rnp_input_from_callback(input, stdin_reader, NULL, NULL) :
                             rnp_input_from_path(input, in.c_str());

        if (res) {
            return false;
        }
    }

    if (!output) {
        return true;
    }
    std::string out = rnp_cfg_getstring(cfg, CFG_OUTFILE);
    bool        is_stdout = out.empty() || (out == "-");
    bool discard = (op == "verify") && out.empty() && rnp_cfg_getbool(cfg, CFG_NO_OUTPUT);

    if (is_stdout && !is_stdin && !discard) {
        std::string ext = output_extension(cfg, op);
        if (!ext.empty()) {
            out = in + ext;
            is_stdout = false;
        }
    }

    rnp_result_t res = RNP_ERROR_GENERIC;
    if (discard) {
        res = rnp_output_to_null(output);
    } else if (is_stdout) {
        res = rnp_output_to_callback(output, stdout_writer, NULL, NULL);
    } else if (!adjust_output_path(out, rnp_cfg_getbool(cfg, CFG_OVERWRITE))) {
        ERR_MSG("Operation failed: file '%s' already exists.", out.c_str());
        res = RNP_ERROR_BAD_PARAMETERS;
    } else {
        res = rnp_output_to_file(output, out.c_str(), RNP_OUTPUT_FILE_OVERWRITE);
    }

    if (res && input) {
        rnp_input_destroy(*input);
    }
    return !res;
}

bool
cli_rnp_dump_file(const rnp_cfg_t *cfg)
{
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;
    uint32_t     flags = 0;
    uint32_t     jflags = 0;

    if (rnp_cfg_getbool(cfg, CFG_GRIPS)) {
        flags |= RNP_DUMP_GRIP;
        jflags |= RNP_JSON_DUMP_GRIP;
    }
    if (rnp_cfg_getbool(cfg, CFG_MPIS)) {
        flags |= RNP_DUMP_MPI;
        jflags |= RNP_JSON_DUMP_MPI;
    }
    if (rnp_cfg_getbool(cfg, CFG_RAW)) {
        flags |= RNP_DUMP_RAW;
        jflags |= RNP_JSON_DUMP_RAW;
    }

    if (!cli_rnp_init_io(cfg, "dump", &input, &output)) {
        ERR_MSG("failed to open source or create output");
        return false;
    }

    rnp_result_t ret;
    if (rnp_cfg_getbool(cfg, CFG_JSON)) {
        char *json = NULL;
        ret = rnp_dump_packets_to_json(input, jflags, &json);
        if (!ret) {
            size_t len = strlen(json);
            size_t written = 0;
            ret = rnp_output_write(output, json, len, &written);
            if (written < len) {
                ret = RNP_ERROR_WRITE;
            }
            // add trailing empty line
            if (!ret) {
                ret = rnp_output_write(output, "\n", 1, &written);
            }
            if (written < 1) {
                ret = RNP_ERROR_WRITE;
            }
            rnp_buffer_destroy(json);
        }
    } else {
        ret = rnp_dump_packets_to_output(input, output, flags);
    }
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    return !ret;
}

bool
cli_rnp_armor_file(const rnp_cfg_t *cfg)
{
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    if (!cli_rnp_init_io(cfg, "armor", &input, &output)) {
        ERR_MSG("failed to open source or create output");
        return false;
    }

    rnp_result_t ret = rnp_enarmor(input, output, rnp_cfg_getstr(cfg, CFG_ARMOR_DATA_TYPE));

    rnp_input_destroy(input);
    rnp_output_destroy(output);
    return !ret;
}

bool
cli_rnp_dearmor_file(const rnp_cfg_t *cfg)
{
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    if (!cli_rnp_init_io(cfg, "dearmor", &input, &output)) {
        ERR_MSG("failed to open source or create output");
        return false;
    }

    rnp_result_t ret = rnp_dearmor(input, output);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    return !ret;
}

static bool
cli_rnp_search_keys(cli_rnp_t *                     rnp,
                    const std::vector<std::string> &names,
                    std::vector<rnp_key_handle_t> & keys,
                    bool                            secret,
                    bool                            usedef)
{
    bool res = false;

    keys.clear();
    for (const std::string &str : names) {
        rnp_key_handle_t key = key_matching_string(rnp, str, secret);
        if (!key) {
            ERR_MSG("Cannot find key matching \"%s\"", str.c_str());
            goto done;
        }
        try {
            keys.push_back(key);
        } catch (...) {
            ERR_MSG("allocation failed");
            goto done;
        }
    }
    if (keys.empty() && usedef) {
        rnp_key_handle_t key = NULL;
        if (!rnp->defkey) {
            ERR_MSG("No userid or default key for operation");
            goto done;
        }
        key = key_matching_string(rnp, rnp->defkey, secret);
        if (!key) {
            ERR_MSG("Default key not found");
            goto done;
        }
        try {
            keys.push_back(key);
        } catch (...) {
            ERR_MSG("allocation failed");
            goto done;
        }
    }
    res = !keys.empty();
done:
    if (!res) {
        keys.clear();
    }
    return res;
}

static bool
cli_rnp_sign(const rnp_cfg_t *cfg, cli_rnp_t *rnp, rnp_input_t input, rnp_output_t output)
{
    rnp_op_sign_t op = NULL;
    rnp_result_t  ret = RNP_ERROR_GENERIC;
    bool          cleartext = rnp_cfg_getbool(cfg, CFG_CLEARTEXT);
    bool          detached = rnp_cfg_getbool(cfg, CFG_DETACHED);

    if (cleartext) {
        ret = rnp_op_sign_cleartext_create(&op, rnp->ffi, input, output);
    } else if (detached) {
        ret = rnp_op_sign_detached_create(&op, rnp->ffi, input, output);
    } else {
        ret = rnp_op_sign_create(&op, rnp->ffi, input, output);
    }

    if (ret) {
        ERR_MSG("failed to initialize signing");
        return false;
    }

    /* setup sign operation via cfg */
    bool                          res = false;
    std::vector<std::string>      signers;
    std::vector<rnp_key_handle_t> signkeys;

    if (!cleartext) {
        rnp_op_sign_set_armor(op, rnp_cfg_getbool(cfg, CFG_ARMOR));
    }

    if (!cleartext && !detached) {
        std::string fname = rnp_cfg_getstring(cfg, CFG_INFILE);
        if (!fname.empty()) {
            if (rnp_op_sign_set_file_name(op, extract_filename(fname).c_str())) {
                goto done;
            }
            rnp_op_sign_set_file_mtime(op, rnp_filemtime(fname.c_str()));
        }
        if (rnp_op_sign_set_compression(
              op, rnp_cfg_getstr(cfg, CFG_ZALG), rnp_cfg_getint(cfg, CFG_ZLEVEL))) {
            goto done;
        }
    }

    if (rnp_op_sign_set_hash(op, rnp_cfg_gethashalg(cfg))) {
        goto done;
    }
    rnp_op_sign_set_creation_time(op, get_creation(rnp_cfg_getstr(cfg, CFG_CREATION)));
    rnp_op_sign_set_expiration_time(op, get_expiration(rnp_cfg_getstr(cfg, CFG_EXPIRATION)));

    /* signing keys */
    if (!rnp_cfg_copylist_string(cfg, signers, CFG_SIGNERS)) {
        ERR_MSG("Failed to copy signers list");
        goto done;
    }
    if (!cli_rnp_search_keys(rnp, signers, signkeys, true, true)) {
        ERR_MSG("Failed to build signing keys list");
        goto done;
    }
    for (rnp_key_handle_t key : signkeys) {
        if (rnp_op_sign_add_signature(op, key, NULL)) {
            ERR_MSG("Failed to add signature");
            goto done;
        }
    }

    /* execute sign operation */
    res = !rnp_op_sign_execute(op);
done:
    for (auto &value : signkeys) {
        rnp_key_handle_destroy(value);
    }
    rnp_op_sign_destroy(op);
    return res;
}

static bool
cli_rnp_encrypt_and_sign(const rnp_cfg_t *cfg,
                         cli_rnp_t *      rnp,
                         rnp_input_t      input,
                         rnp_output_t     output)
{
    rnp_op_encrypt_t op = NULL;

    if (rnp_op_encrypt_create(&op, rnp->ffi, input, output)) {
        ERR_MSG("failed to initialize encryption");
        return false;
    }

    std::string                   fname;
    std::string                   aalg;
    std::vector<rnp_key_handle_t> enckeys;
    std::vector<rnp_key_handle_t> signkeys;
    bool                          res = false;

    rnp_op_encrypt_set_armor(op, rnp_cfg_getbool(cfg, CFG_ARMOR));

    fname = rnp_cfg_getstring(cfg, CFG_INFILE);
    if (!fname.empty()) {
        if (rnp_op_encrypt_set_file_name(op, extract_filename(fname).c_str())) {
            goto done;
        }
        rnp_op_encrypt_set_file_mtime(op, rnp_filemtime(fname.c_str()));
    }
    if (rnp_op_encrypt_set_compression(
          op, rnp_cfg_getstr(cfg, CFG_ZALG), rnp_cfg_getint(cfg, CFG_ZLEVEL))) {
        goto done;
    }
    if (rnp_op_encrypt_set_cipher(op, rnp_cfg_getstr(cfg, CFG_CIPHER))) {
        goto done;
    }
    if (rnp_op_encrypt_set_hash(op, rnp_cfg_gethashalg(cfg))) {
        goto done;
    }
    aalg = rnp_cfg_hasval(cfg, CFG_AEAD) ? rnp_cfg_getstring(cfg, CFG_AEAD) : "None";
    if (rnp_op_encrypt_set_aead(op, aalg.c_str())) {
        goto done;
    }
    if (rnp_cfg_hasval(cfg, CFG_AEAD_CHUNK) &&
        rnp_op_encrypt_set_aead_bits(op, rnp_cfg_getint(cfg, CFG_AEAD_CHUNK))) {
        goto done;
    }

    /* adding passwords if password-based encryption is used */
    if (rnp_cfg_getbool(cfg, CFG_ENCRYPT_SK)) {
        std::string halg = rnp_cfg_gethashalg(cfg);
        std::string ealg = rnp_cfg_getstring(cfg, CFG_CIPHER);

        for (int i = 0; i < rnp_cfg_getint_default(cfg, CFG_PASSWORDC, 1); i++) {
            if (rnp_op_encrypt_add_password(op, NULL, halg.c_str(), 0, ealg.c_str())) {
                ERR_MSG("Failed to add encrypting password");
                goto done;
            }
        }
    }

    /* adding encrypting keys if pk-encryption is used */
    if (rnp_cfg_getbool(cfg, CFG_ENCRYPT_PK)) {
        std::vector<std::string> keynames;
        if (!rnp_cfg_copylist_string(cfg, keynames, CFG_RECIPIENTS)) {
            ERR_MSG("Failed to copy recipients list");
            goto done;
        }
        if (!cli_rnp_search_keys(rnp, keynames, enckeys, false, true)) {
            ERR_MSG("Failed to build recipients key list");
            goto done;
        }
        for (rnp_key_handle_t key : enckeys) {
            if (rnp_op_encrypt_add_recipient(op, key)) {
                ERR_MSG("Failed to add recipient");
                goto done;
            }
        }
    }

    /* adding signatures if encrypt-and-sign is used */
    if (rnp_cfg_getbool(cfg, CFG_SIGN_NEEDED)) {
        rnp_op_encrypt_set_creation_time(op, get_creation(rnp_cfg_getstr(cfg, CFG_CREATION)));
        rnp_op_encrypt_set_expiration_time(
          op, get_expiration(rnp_cfg_getstr(cfg, CFG_EXPIRATION)));

        /* signing keys */
        std::vector<std::string> keynames;
        if (!rnp_cfg_copylist_string(cfg, keynames, CFG_SIGNERS)) {
            ERR_MSG("Failed to copy signers list");
            goto done;
        }
        if (!cli_rnp_search_keys(rnp, keynames, signkeys, true, true)) {
            ERR_MSG("Failed to build signing keys list");
            goto done;
        }
        for (rnp_key_handle_t key : signkeys) {
            if (rnp_op_encrypt_add_signature(op, key, NULL)) {
                ERR_MSG("Failed to add signature");
                goto done;
            }
        }
    }

    /* execute encrypt or encrypt-and-sign operation */
    res = !rnp_op_encrypt_execute(op);
done:
    for (auto &value : signkeys) {
        rnp_key_handle_destroy(value);
    }
    for (auto &value : enckeys) {
        rnp_key_handle_destroy(value);
    }
    rnp_op_encrypt_destroy(op);
    return res;
}

bool
cli_rnp_setup(const rnp_cfg_t *cfg, cli_rnp_t *rnp)
{
    if (rnp_cfg_getstr(cfg, CFG_PASSWD) &&
        rnp_ffi_set_pass_provider(
          rnp->ffi, ffi_pass_callback_string, (void *) rnp_cfg_getstr(cfg, CFG_PASSWD))) {
        return false;
    }

    rnp->pswdtries = rnp_cfg_get_pswdtries(cfg);
    return true;
}

bool
cli_rnp_protect_file(const rnp_cfg_t *cfg, cli_rnp_t *rnp)
{
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    if (!cli_rnp_init_io(cfg, "encrypt_sign", &input, &output)) {
        ERR_MSG("failed to open source or create output");
        return false;
    }

    bool res = false;
    bool sign = rnp_cfg_getbool(cfg, CFG_SIGN_NEEDED);
    bool encrypt =
      rnp_cfg_getbool(cfg, CFG_ENCRYPT_PK) || rnp_cfg_getbool(cfg, CFG_ENCRYPT_SK);
    if (sign && !encrypt) {
        res = cli_rnp_sign(cfg, rnp, input, output);
    } else if (encrypt) {
        res = cli_rnp_encrypt_and_sign(cfg, rnp, input, output);
    } else {
        ERR_MSG("No operation specified");
    }

    rnp_input_destroy(input);
    rnp_output_destroy(output);
    return res;
}

/* helper function which prints something like 'using RSA (Sign-Only) key 0x0102030405060708 */
static void
cli_rnp_print_sig_key_info(FILE *resfp, rnp_signature_handle_t sig)
{
    char *      keyid = NULL;
    const char *alg = "Unknown";

    if (!rnp_signature_get_keyid(sig, &keyid)) {
        for (char *idptr = keyid; *idptr; ++idptr) {
            *idptr = tolower(*idptr);
        }
    }

    char *       json = NULL;
    json_object *pkts = NULL;
    json_object *sigpkt = NULL;

    if (rnp_signature_packet_to_json(sig, RNP_JSON_DUMP_GRIP, &json)) {
        ERR_MSG("Signature error.");
        goto done;
    }
    if (!(pkts = json_tokener_parse(json))) {
        ERR_MSG("Signature JSON error");
        goto done;
    }
    if (!(sigpkt = json_object_array_get_idx(pkts, 0))) {
        ERR_MSG("Signature JSON error");
        goto done;
    }
    alg = json_obj_get_str(sigpkt, "algorithm.str");
done:
    fprintf(resfp, "using %s key %s\n", alg, keyid ? keyid : "0000000000000000");
    rnp_buffer_destroy(keyid);
    rnp_buffer_destroy(json);
    json_object_put(pkts);
}

static void
cli_rnp_print_signatures(cli_rnp_t *rnp, const std::vector<rnp_op_verify_signature_t> &sigs)
{
    unsigned    invalidc = 0;
    unsigned    unknownc = 0;
    unsigned    validc = 0;
    std::string title = "UNKNOWN signature";
    FILE *      resfp = rnp->resfp;

    for (auto sig : sigs) {
        rnp_result_t status = rnp_op_verify_signature_get_status(sig);
        switch (status) {
        case RNP_SUCCESS:
            title = "Good signature";
            validc++;
            break;
        case RNP_ERROR_SIGNATURE_EXPIRED:
            title = "EXPIRED signature";
            invalidc++;
            break;
        case RNP_ERROR_SIGNATURE_INVALID:
            title = "BAD signature";
            invalidc++;
            break;
        case RNP_ERROR_KEY_NOT_FOUND:
            title = "NO PUBLIC KEY for signature";
            unknownc++;
            break;
        default:
            title = "UKNOWN signature";
            break;
        }

        uint32_t create = 0;
        uint32_t expiry = 0;
        rnp_op_verify_signature_get_times(sig, &create, &expiry);

        if (create > 0) {
            time_t crtime = create;
            fprintf(resfp, "%s made %s", title.c_str(), ctime(&crtime));
            if (expiry > 0) {
                crtime += expiry;
                fprintf(resfp, "Valid until %s\n", ctime(&crtime));
            }
        } else {
            fprintf(resfp, "%s\n", title.c_str());
        }

        rnp_signature_handle_t handle = NULL;
        if (rnp_op_verify_signature_get_handle(sig, &handle)) {
            ERR_MSG("Failed to obtain signature handle.");
            continue;
        }

        cli_rnp_print_sig_key_info(resfp, handle);
        rnp_key_handle_t key = NULL;

        if ((status != RNP_ERROR_KEY_NOT_FOUND) && !rnp_signature_get_signer(handle, &key)) {
            cli_rnp_print_key_info(resfp, rnp->ffi, key, false, false);
            rnp_key_handle_destroy(key);
        }
        rnp_signature_handle_destroy(handle);
    }

    if (sigs.size() == 0) {
        ERR_MSG("No signature(s) found - is this a signed file?");
    } else if (invalidc > 0 || unknownc > 0) {
        ERR_MSG(
          "Signature verification failure: %u invalid signature(s), %u unknown signature(s)",
          invalidc,
          unknownc);
    } else {
        ERR_MSG("Signature(s) verified successfully");
    }
}

bool
cli_rnp_process_file(const rnp_cfg_t *cfg, cli_rnp_t *rnp)
{
    rnp_input_t input = NULL;
    if (!cli_rnp_init_io(cfg, "verify", &input, NULL)) {
        ERR_MSG("failed to open source");
        return false;
    }

    char *contents = NULL;
    if (rnp_guess_contents(input, &contents)) {
        ERR_MSG("failed to check source contents");
        return false;
    }

    /* source data for detached signature verification */
    rnp_input_t                            source = NULL;
    rnp_output_t                           output = NULL;
    rnp_op_verify_t                        verify = NULL;
    rnp_result_t                           ret = RNP_ERROR_GENERIC;
    bool                                   res = false;
    std::vector<rnp_op_verify_signature_t> sigs;
    size_t                                 scount = 0;

    if (rnp_casecmp(contents, "signature")) {
        /* detached signature */
        std::string in = rnp_cfg_getstring(cfg, CFG_INFILE);
        if (in.empty() || in == "-") {
            ERR_MSG("Cannot verify detached signature from stdin.");
            goto done;
        }
        if (!has_extension(in, EXT_SIG) && !has_extension(in, EXT_ASC)) {
            ERR_MSG("Unsupported detached signature extension.");
            goto done;
        }
        if (!strip_extension(in) || rnp_input_from_path(&source, in.c_str())) {
            ERR_MSG("Failed to open source for detached signature verification.");
            goto done;
        }

        ret = rnp_op_verify_detached_create(&verify, rnp->ffi, source, input);
    } else {
        if (!cli_rnp_init_io(cfg, "verify", NULL, &output)) {
            ERR_MSG("Failed to create output stream.");
            goto done;
        }
        ret = rnp_op_verify_create(&verify, rnp->ffi, input, output);
    }
    if (ret) {
        ERR_MSG("Failed to initialize verification/decryption operation.");
        goto done;
    }

    res = !rnp_op_verify_execute(verify);

    rnp_op_verify_get_signature_count(verify, &scount);
    if (!scount) {
        goto done;
    }

    for (size_t i = 0; i < scount; i++) {
        rnp_op_verify_signature_t sig = NULL;
        if (rnp_op_verify_get_signature_at(verify, i, &sig)) {
            ERR_MSG("Failed to obtain signature info.");
            res = false;
            goto done;
        }
        try {
            sigs.push_back(sig);
        } catch (...) {
            ERR_MSG("allocation failed");
            res = false;
            goto done;
        }
    }
    cli_rnp_print_signatures(rnp, sigs);
done:
    rnp_buffer_destroy(contents);
    rnp_input_destroy(input);
    rnp_input_destroy(source);
    rnp_output_destroy(output);
    rnp_op_verify_destroy(verify);
    return res;
}
