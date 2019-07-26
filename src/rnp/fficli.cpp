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
#include <ctype.h>
#include <unistd.h>

#ifndef _WIN32
#include <termios.h>
#endif

#include <time.h>
#include "config.h"
#include "fficli.h"
#include "utils.h"

// must be placed after include "utils.h"
#ifndef RNP_USE_STD_REGEX
#include <regex.h>
#else
#include <regex>
#endif

static bool
stdin_getpass(const char *prompt, char *buffer, size_t size)
{
#ifndef _WIN32
    struct termios saved_flags, noecho_flags;
    bool           restore_ttyflags = false;
#endif
    bool           ok = false;
    FILE *         in = NULL;
    FILE *         out = NULL;

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

bool
cli_rnp_init(cli_rnp_t *rnp, rnp_cfg_t *cfg)
{
    bool coredumps = true;

    /* If system resource constraints are in effect then attempt to
     * disable core dumps.
     */
    if (!rnp_cfg_getbool(cfg, CFG_COREDUMPS)) {
#ifdef HAVE_SYS_RESOURCE_H
        coredumps = disable_core_dumps() != RNP_SUCCESS;
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
    const char *              defkey = NULL;

    if (rnp_identifier_iterator_create(rnp->ffi, &it, "grip")) {
        return;
    }
    if (rnp_identifier_iterator_next(it, &defkey) == RNP_SUCCESS) {
        rnp->defkey = strdup(defkey);
    }
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
    bool    matches = false;
    char *  id = NULL;
    size_t  idlen = 0;
    size_t  len = str ? strlen(str) : 0;
#ifndef RNP_USE_STD_REGEX
    regex_t r = {};
#else
    std::regex re;
#endif
    size_t  uid_count = 0;
    bool    boolres = false;

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

    while (rnp_identifier_iterator_next(it, &grip) == RNP_SUCCESS) {
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

static bool
stdout_write(void *app_ctx, const void *buf, size_t len)
{
    return write(STDOUT_FILENO, buf, len) >= 0;
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
    uint32_t base_flags = secret ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC;
    bool     result = false;

    if (file) {
        uint32_t flags = rnp_cfg_getbool(cfg, CFG_FORCE) ? RNP_OUTPUT_FILE_OVERWRITE : 0;
        ret = rnp_output_to_file(&output, file, flags);
    } else {
        ret = rnp_output_to_callback(&output, stdout_write, NULL, NULL);
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
