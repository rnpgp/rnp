/*
 * Copyright (c) 2019-2021, [Ribose Inc](https://www.ribose.com).
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

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <iterator>
#include <cassert>
#include <ctype.h>
#ifdef _MSC_VER
#include "uniwin.h"
#else
#include <sys/param.h>
#include <unistd.h>
#endif

#ifndef _WIN32
#include <termios.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#endif

#include "config.h"
#include "fficli.h"
#include "str-utils.h"
#include "file-utils.h"
#include "time-utils.h"
#include "defaults.h"

#ifndef RNP_USE_STD_REGEX
#include <regex.h>
#else
#include <regex>
#endif

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

#ifdef _WIN32
#include "str-utils.h"
#include <windows.h>
#include <vector>
#include <stdexcept>

static std::vector<std::string>
get_utf8_args()
{
    int       arg_nb;
    wchar_t **arg_w;

    arg_w = CommandLineToArgvW(GetCommandLineW(), &arg_nb);
    if (!arg_w) {
        throw std::runtime_error("CommandLineToArgvW failed");
    }

    try {
        std::vector<std::string> result;
        result.reserve(arg_nb);
        for (int i = 0; i < arg_nb; i++) {
            auto utf8 = wstr_to_utf8(arg_w[i]);
            result.push_back(utf8);
        }
        LocalFree(arg_w);
        return result;
    } catch (...) {
        LocalFree(arg_w);
        throw;
    }
}

void
rnp_win_clear_args(int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        if (argv[i]) {
            free(argv[i]);
        }
    }
    delete argv;
}

bool
rnp_win_substitute_cmdline_args(int *argc, char ***argv)
{
    int    argc_utf8 = 0;
    char **argv_utf8_cstrs = NULL;
    try {
        auto argv_utf8_strings = get_utf8_args();
        argc_utf8 = argv_utf8_strings.size();
        *argc = argc_utf8;
        argv_utf8_cstrs = new (std::nothrow) char *[argc_utf8]();
        if (!argv_utf8_cstrs) {
            throw std::bad_alloc();
        }
        for (int i = 0; i < argc_utf8; i++) {
            auto arg_utf8 = strdup(argv_utf8_strings[i].c_str());
            if (!arg_utf8) {
                throw std::bad_alloc();
            }
            argv_utf8_cstrs[i] = arg_utf8;
        }
    } catch (...) {
        if (argv_utf8_cstrs) {
            rnp_win_clear_args(argc_utf8, argv_utf8_cstrs);
        }
        throw;
    }
    *argc = argc_utf8;
    *argv = argv_utf8_cstrs;
    return true;
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

    tm = rnp_gmtime(t);
    (void) snprintf(dest,
                    size,
                    "%s%04d-%02d-%02d",
                    rnp_y2k38_warning(t) ? ">=" : "",
                    tm->tm_year + 1900,
                    tm->tm_mon + 1,
                    tm->tm_mday);
    return dest;
}

static bool
cli_rnp_get_confirmation(const cli_rnp_t *rnp, const char *msg, ...)
{
    char    reply[10];
    va_list ap;

    while (true) {
        va_start(ap, msg);
        vfprintf(rnp->userio_out, msg, ap);
        va_end(ap);
        fprintf(rnp->userio_out, " (y/N) ");
        fflush(rnp->userio_out);

        if (fgets(reply, sizeof(reply), rnp->userio_in) == NULL) {
            return false;
        }

        rnp::strip_eol(reply);

        if (strlen(reply) > 0) {
            if (toupper(reply[0]) == 'Y') {
                return true;
            } else if (toupper(reply[0]) == 'N') {
                return false;
            }

            fprintf(rnp->userio_out, "Sorry, response '%s' not understood.\n", reply);
        } else {
            return false;
        }
    }

    return false;
}

static bool
rnp_ask_filename(const std::string &msg, std::string &res, cli_rnp_t &rnp)
{
    fprintf(rnp.userio_out, "%s", msg.c_str());
    fflush(rnp.userio_out);
    char        fname[128] = {0};
    std::string path;
    do {
        if (!fgets(fname, sizeof(fname), rnp.userio_in)) {
            return false;
        }
        path = path + std::string(fname);
        if (rnp::strip_eol(path)) {
            res = path;
            return true;
        }
        if (path.size() >= 2048) {
            fprintf(rnp.userio_out, "%s", "Too long filename, aborting.");
            fflush(rnp.userio_out);
            return false;
        }
    } while (1);
}

/** @brief checks whether file exists already and asks user for the new filename
 *  @param path output file name with path. May be an empty string, then user is asked for it.
 *  @param res resulting output path will be stored here.
 *  @param rnp initialized cli_rnp_t structure with additional data
 *  @return true on success, or false otherwise (user cancels the operation)
 **/

static bool
rnp_get_output_filename(const std::string &path, std::string &res, cli_rnp_t &rnp)
{
    std::string newpath = path;
    if (newpath.empty() &&
        !rnp_ask_filename("Please enter the output filename: ", newpath, rnp)) {
        return false;
    }

    while (true) {
        if (!rnp_file_exists(newpath.c_str())) {
            res = newpath;
            return true;
        }
        if (rnp.cfg().get_bool(CFG_OVERWRITE) ||
            cli_rnp_get_confirmation(
              &rnp,
              "File '%s' already exists. Would you like to overwrite it?",
              newpath.c_str())) {
            rnp_unlink(newpath.c_str());
            res = newpath;
            return true;
        }

        if (!rnp_ask_filename("Please enter the new filename: ", newpath, rnp)) {
            return false;
        }
        if (newpath.empty()) {
            return false;
        }
    }
}

static bool
stdin_getpass(const char *prompt, char *buffer, size_t size, cli_rnp_t *rnp)
{
#ifndef _WIN32
    struct termios saved_flags, noecho_flags;
    bool           restore_ttyflags = false;
#endif
    bool  ok = false;
    FILE *in = NULL;
    FILE *out = NULL;
    FILE *userio_in = (rnp && rnp->userio_in) ? rnp->userio_in : stdin;

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
        in = userio_in;
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

    rnp::strip_eol(buffer);
    ok = true;
end:
#ifndef _WIN32
    if (restore_ttyflags) {
        tcsetattr(fileno(in), TCSAFLUSH, &saved_flags);
    }
#endif
    if (in && (in != userio_in)) {
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
    char *     keyid = NULL;
    char       target[64] = {0};
    char       prompt[128] = {0};
    char *     buffer = NULL;
    bool       ok = false;
    cli_rnp_t *rnp = static_cast<cli_rnp_t *>(app_ctx);

    if (!ffi || !pgp_context) {
        goto done;
    }

    if (strcmp(pgp_context, "decrypt (symmetric)") &&
        strcmp(pgp_context, "encrypt (symmetric)")) {
        rnp_key_get_keyid(key, &keyid);
        snprintf(target, sizeof(target), "key 0x%s", keyid);
        rnp_buffer_destroy(keyid);
    }
    buffer = (char *) calloc(1, buf_len);
    if (!buffer) {
        return false;
    }
start:
    if (!strcmp(pgp_context, "decrypt (symmetric)")) {
        snprintf(prompt, sizeof(prompt), "Enter password to decrypt data: ");
    } else if (!strcmp(pgp_context, "encrypt (symmetric)")) {
        snprintf(prompt, sizeof(prompt), "Enter password to encrypt data: ");
    } else {
        snprintf(prompt, sizeof(prompt), "Enter password for %s: ", target);
    }

    if (!stdin_getpass(prompt, buf, buf_len, rnp)) {
        goto done;
    }
    if (!strcmp(pgp_context, "protect") || !strcmp(pgp_context, "encrypt (symmetric)")) {
        if (!strcmp(pgp_context, "protect")) {
            snprintf(prompt, sizeof(prompt), "Repeat password for %s: ", target);
        } else {
            snprintf(prompt, sizeof(prompt), "Repeat password: ");
        }

        if (!stdin_getpass(prompt, buffer, buf_len, rnp)) {
            goto done;
        }
        if (strcmp(buf, buffer) != 0) {
            fputs("\nPasswords do not match!", rnp->userio_out);
            // currently will loop forever
            goto start;
        }
    }
    ok = true;
done:
    fputs("", rnp->userio_out);
    rnp_buffer_clear(buffer, buf_len);
    free(buffer);
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
    rnp::strip_eol(buf);
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
cli_rnp_t::init(const rnp_cfg &cfg)
{
    cfg_.copy(cfg);

    /* Configure user's io streams. */
    if (!cfg_.get_bool(CFG_NOTTY)) {
        userio_in = (isatty(fileno(stdin)) ? stdin : fopen("/dev/tty", "r"));
        userio_in = (userio_in ? userio_in : stdin);
        userio_out = (isatty(fileno(stdout)) ? stdout : fopen("/dev/tty", "a+"));
        userio_out = (userio_out ? userio_out : stdout);
    } else {
        userio_in = stdin;
        userio_out = stdout;
    }

#ifndef _WIN32
    /* If system resource constraints are in effect then attempt to
     * disable core dumps.
     */
    bool coredumps = true;
    if (!cfg_.get_bool(CFG_COREDUMPS)) {
#ifdef HAVE_SYS_RESOURCE_H
        coredumps = !disable_core_dumps();
#endif
    }

    if (coredumps) {
        ERR_MSG("warning: core dumps may be enabled, sensitive data may be leaked to disk");
    }
#endif

    /* Configure the results stream. */
    // TODO: UTF8?
    const std::string &ress = cfg_.get_str(CFG_IO_RESS);
    if (ress.empty() || (ress == "<stderr>")) {
        resfp = stderr;
    } else if (ress == "<stdout>") {
        resfp = stdout;
    } else if (!(resfp = rnp_fopen(ress.c_str(), "w"))) {
        ERR_MSG("cannot open results %s for writing", ress.c_str());
        return false;
    }

    bool              res = false;
    const std::string pformat = pubformat();
    const std::string sformat = secformat();
    if (pformat.empty() || sformat.empty()) {
        ERR_MSG("Unknown public or secret keyring format");
        return false;
    }
    if (rnp_ffi_create(&ffi, pformat.c_str(), sformat.c_str())) {
        ERR_MSG("failed to initialize FFI");
        return false;
    }

    // by default use stdin password provider
    if (rnp_ffi_set_pass_provider(ffi, ffi_pass_callback_stdin, this)) {
        goto done;
    }

    // setup file/pipe password input if requested
    if (cfg_.get_int(CFG_PASSFD, -1) >= 0) {
        if (!set_pass_fd(&passfp, cfg_.get_int(CFG_PASSFD))) {
            goto done;
        }
        if (rnp_ffi_set_pass_provider(ffi, ffi_pass_callback_file, passfp)) {
            goto done;
        }
    }
    pswdtries = MAX_PASSWORD_ATTEMPTS;
    res = true;
done:
    if (!res) {
        rnp_ffi_destroy(ffi);
        ffi = NULL;
    }
    return res;
}

void
cli_rnp_t::end()
{
    if (passfp) {
        fclose(passfp);
        passfp = NULL;
    }
    if (resfp && (resfp != stderr) && (resfp != stdout)) {
        fclose(resfp);
        resfp = NULL;
    }
    if (userio_in && userio_in != stdin) {
        fclose(userio_in);
    }
    userio_in = NULL;
    if (userio_out && userio_out != stdout) {
        fclose(userio_out);
    }
    userio_out = NULL;
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    cfg_.clear();
}

bool
cli_rnp_t::load_keyring(bool secret)
{
    const char *path = secret ? secpath().c_str() : pubpath().c_str();
    bool        dir = secret && (secformat() == RNP_KEYSTORE_G10);
    if (dir && !rnp_dir_exists(path)) {
        ERR_MSG("warning: keyring directory at '%s' doesn't exist.", path);
        return true;
    }
    if (!dir && !rnp_file_exists(path)) {
        ERR_MSG("warning: keyring at path '%s' doesn't exist.", path);
        return true;
    }

    rnp_input_t keyin = NULL;
    if (rnp_input_from_path(&keyin, path)) {
        ERR_MSG("warning: failed to open keyring at path '%s' for reading.", path);
        return true;
    }

    const char * format = secret ? secformat().c_str() : pubformat().c_str();
    uint32_t     flags = secret ? RNP_LOAD_SAVE_SECRET_KEYS : RNP_LOAD_SAVE_PUBLIC_KEYS;
    rnp_result_t ret = rnp_load_keys(ffi, format, keyin, flags);
    if (ret) {
        ERR_MSG("error: failed to load keyring from '%s'", path);
    }
    rnp_input_destroy(keyin);

    if (ret) {
        return false;
    }

    size_t keycount = 0;
    if (secret) {
        (void) rnp_get_secret_key_count(ffi, &keycount);
    } else {
        (void) rnp_get_public_key_count(ffi, &keycount);
    }
    if (!keycount) {
        ERR_MSG("warning: no keys were loaded from the keyring '%s'.", path);
    }
    return true;
}

bool
cli_rnp_t::load_keyrings(bool loadsecret)
{
    /* Read public keys */
    if (rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC)) {
        ERR_MSG("failed to clear public keyring");
        return false;
    }

    if (!load_keyring(false)) {
        return false;
    }

    /* Only read secret keys if we need to */
    if (loadsecret) {
        if (rnp_unload_keys(ffi, RNP_KEY_UNLOAD_SECRET)) {
            ERR_MSG("failed to clear secret keyring");
            return false;
        }

        if (!load_keyring(true)) {
            return false;
        }
    }
    if (defkey().empty()) {
        set_defkey();
    }
    return true;
}

void
cli_rnp_t::set_defkey()
{
    rnp_identifier_iterator_t it = NULL;
    rnp_key_handle_t          handle = NULL;
    const char *              grip = NULL;

    cfg_.unset(CFG_KR_DEF_KEY);
    if (rnp_identifier_iterator_create(ffi, &it, "grip")) {
        ERR_MSG("failed to create key iterator");
        return;
    }

    while (!rnp_identifier_iterator_next(it, &grip)) {
        bool is_subkey = false;
        bool is_secret = false;

        if (!grip) {
            break;
        }
        if (rnp_locate_key(ffi, "grip", grip, &handle)) {
            ERR_MSG("failed to locate key");
            continue;
        }
        if (rnp_key_is_sub(handle, &is_subkey) || is_subkey) {
            goto next;
        }
        if (rnp_key_have_secret(handle, &is_secret)) {
            goto next;
        }
        if (!cfg_.has(CFG_KR_DEF_KEY) || is_secret) {
            cfg_.set_str(CFG_KR_DEF_KEY, grip);
            /* if we have secret primary key then use it as default */
            if (is_secret) {
                break;
            }
        }
    next:
        rnp_key_handle_destroy(handle);
        handle = NULL;
    }
    rnp_key_handle_destroy(handle);
    rnp_identifier_iterator_destroy(it);
}

bool
cli_rnp_t::is_cv25519_subkey(rnp_key_handle_t handle)
{
    bool primary = false;
    if (rnp_key_is_primary(handle, &primary)) {
        ERR_MSG("Error: failed to check for subkey.");
        return false;
    }
    if (primary) {
        return false;
    }
    char *alg = NULL;
    if (rnp_key_get_alg(handle, &alg)) {
        ERR_MSG("Error: failed to check key's alg.");
        return false;
    }
    bool ecdh = !strcmp(alg, RNP_ALGNAME_ECDH);
    rnp_buffer_destroy(alg);
    if (!ecdh) {
        return false;
    }
    char *curve = NULL;
    if (rnp_key_get_curve(handle, &curve)) {
        ERR_MSG("Error: failed to check key's curve.");
        return false;
    }
    bool cv25519 = !strcmp(curve, "Curve25519");
    rnp_buffer_destroy(curve);
    return cv25519;
}

bool
cli_rnp_t::get_protection(rnp_key_handle_t handle,
                          std::string &    hash,
                          std::string &    cipher,
                          size_t &         iterations)
{
    bool prot = false;
    if (rnp_key_is_protected(handle, &prot)) {
        ERR_MSG("Error: failed to check key's protection.");
        return false;
    }
    if (!prot) {
        hash = "";
        cipher = "";
        iterations = 0;
        return true;
    }

    char *val = NULL;
    try {
        if (rnp_key_get_protection_hash(handle, &val)) {
            ERR_MSG("Error: failed to retrieve key's protection hash.");
            return false;
        }
        hash = val;
        rnp_buffer_destroy(val);
        if (rnp_key_get_protection_cipher(handle, &val)) {
            ERR_MSG("Error: failed to retrieve key's protection cipher.");
            return false;
        }
        cipher = val;
        rnp_buffer_destroy(val);
        if (rnp_key_get_protection_iterations(handle, &iterations)) {
            ERR_MSG("Error: failed to retrieve key's protection iterations.");
            return false;
        }
        return true;
    } catch (const std::exception &e) {
        ERR_MSG("Error: failed to retrieve key's properties: %s", e.what());
        rnp_buffer_destroy(val);
        return false;
    }
}

bool
cli_rnp_t::check_cv25519_bits(rnp_key_handle_t key, char *prot_password, bool &tweaked)
{
    /* unlock key first to check whether bits are tweaked */
    if (prot_password && rnp_key_unlock(key, prot_password)) {
        ERR_MSG("Error: failed to unlock key. Did you specify valid password?");
        return false;
    }
    rnp_result_t ret = rnp_key_25519_bits_tweaked(key, &tweaked);
    if (ret) {
        ERR_MSG("Error: failed to check whether key's bits are tweaked.");
    }
    if (prot_password) {
        rnp_key_lock(key);
    }
    return !ret;
}

bool
cli_rnp_t::fix_cv25519_subkey(const std::string &key, bool checkonly)
{
    std::vector<rnp_key_handle_t> keys;
    if (!cli_rnp_keys_matching_string(
          this, keys, key, CLI_SEARCH_SECRET | CLI_SEARCH_SUBKEYS)) {
        ERR_MSG("Secret keys matching '%s' not found.", key.c_str());
        return false;
    }
    bool        res = false;
    std::string prot_hash;
    std::string prot_cipher;
    size_t      prot_iterations;
    char *      prot_password = NULL;
    bool        tweaked = false;

    if (keys.size() > 1) {
        ERR_MSG(
          "Ambiguous input: too many keys found for '%s'. Did you use keyid or fingerprint?",
          key.c_str());
        goto done;
    }
    cli_rnp_print_key_info(userio_out, ffi, keys[0], true, false);
    if (!is_cv25519_subkey(keys[0])) {
        ERR_MSG("Error: specified key is not Curve25519 ECDH subkey.");
        goto done;
    }

    if (!get_protection(keys[0], prot_hash, prot_cipher, prot_iterations)) {
        goto done;
    }

    if (!prot_hash.empty() &&
        (rnp_request_password(ffi, keys[0], "unprotect", &prot_password) || !prot_password)) {
        ERR_MSG("Error: failed to obtain protection password.");
        goto done;
    }

    if (!check_cv25519_bits(keys[0], prot_password, tweaked)) {
        goto done;
    }

    if (checkonly) {
        fprintf(userio_out,
                tweaked ? "Cv25519 key bits are set correctly and do not require fixing.\n" :
                          "Warning: Cv25519 key bits need fixing.\n");
        res = tweaked;
        goto done;
    }

    if (tweaked) {
        ERR_MSG("Warning: key's bits are fixed already, no action is required.");
        res = true;
        goto done;
    }

    /* now unprotect so we can tweak bits */
    if (!prot_hash.empty()) {
        if (rnp_key_unprotect(keys[0], prot_password)) {
            ERR_MSG("Error: failed to unprotect key. Did you specify valid password?");
            goto done;
        }
        if (rnp_key_unlock(keys[0], NULL)) {
            ERR_MSG("Error: failed to unlock key.");
            goto done;
        }
    }

    /* tweak key bits and protect back */
    if (rnp_key_25519_bits_tweak(keys[0])) {
        ERR_MSG("Error: failed to tweak key's bits.");
        goto done;
    }

    if (!prot_hash.empty() && rnp_key_protect(keys[0],
                                              prot_password,
                                              prot_cipher.c_str(),
                                              NULL,
                                              prot_hash.c_str(),
                                              prot_iterations)) {
        ERR_MSG("Error: failed to protect key back.");
        goto done;
    }

    res = cli_rnp_save_keyrings(this);
done:
    clear_key_handles(keys);
    if (prot_password) {
        rnp_buffer_clear(prot_password, strlen(prot_password) + 1);
        rnp_buffer_destroy(prot_password);
    }
    return res;
}

bool
cli_rnp_t::edit_key(const std::string &key)
{
    if (cfg().get_bool(CFG_CHK_25519_BITS)) {
        return fix_cv25519_subkey(key, true);
    }
    if (cfg().get_bool(CFG_FIX_25519_BITS)) {
        return fix_cv25519_subkey(key, false);
    }

    /* more options, like --passwd, --unprotect, --expiration are to come */
    ERR_MSG("You should specify at least one editing option for --edit-key.");
    return false;
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

std::string
cli_rnp_escape_string(const std::string &src)
{
    static const int   SPECIAL_CHARS_COUNT = 0x20;
    static const char *escape_map[SPECIAL_CHARS_COUNT + 1] = {
      "\\x00", "\\x01", "\\x02", "\\x03", "\\x04", "\\x05", "\\x06", "\\x07",
      "\\b",   "\\x09", "\\n",   "\\v",   "\\f",   "\\r",   "\\x0e", "\\x0f",
      "\\x10", "\\x11", "\\x12", "\\x13", "\\x14", "\\x15", "\\x16", "\\x17",
      "\\x18", "\\x19", "\\x1a", "\\x1b", "\\x1c", "\\x1d", "\\x1e", "\\x1f",
      "\\x20" // space should not be auto-replaced
    };
    std::string result;
    // we want to replace leading and trailing spaces with escape codes to make them visible
    auto        original_len = src.length();
    std::string rtrimmed = src;
    bool        leading_space = true;
    rtrimmed.erase(rtrimmed.find_last_not_of(0x20) + 1);
    result.reserve(original_len);
    for (char const &c : rtrimmed) {
        leading_space &= c == 0x20;
        if (leading_space || (c >= 0 && c < SPECIAL_CHARS_COUNT)) {
            result.append(escape_map[(int) c]);
        } else {
            result.push_back(c);
        }
    }
    // printing trailing spaces
    for (auto pos = rtrimmed.length(); pos < original_len; pos++) {
        result.append(escape_map[0x20]);
    }
    return result;
}

static const std::string alg_aliases[] = {
  "3DES",         "TRIPLEDES",   "3-DES",        "TRIPLEDES",   "CAST-5",       "CAST5",
  "AES",          "AES128",      "AES-128",      "AES128",      "AES-192",      "AES192",
  "AES-256",      "AES256",      "CAMELLIA-128", "CAMELLIA128", "CAMELLIA-192", "CAMELLIA192",
  "CAMELLIA-256", "CAMELLIA256", "SHA",          "SHA1",        "SHA-1",        "SHA1",
  "SHA-224",      "SHA224",      "SHA-256",      "SHA256",      "SHA-384",      "SHA384",
  "SHA-512",      "SHA512",      "RIPEMD-160",   "RIPEMD160"};

const std::string
cli_rnp_alg_to_ffi(const std::string alg)
{
    size_t count = sizeof(alg_aliases) / sizeof(alg_aliases[0]);
    assert((count % 2) == 0);
    for (size_t idx = 0; idx < count; idx += 2) {
        if (rnp_casecmp(alg, alg_aliases[idx])) {
            return alg_aliases[idx + 1];
        }
    }
    return alg;
}

#ifndef RNP_USE_STD_REGEX
static std::string
cli_rnp_unescape_for_regcomp(const std::string &src)
{
    std::string result;
    result.reserve(src.length());
    regex_t    r = {};
    regmatch_t matches[1];
    if (regcomp(&r, "\\\\x[0-9a-f]([0-9a-f])?", REG_EXTENDED | REG_ICASE) != 0)
        return src;

    int offset = 0;
    while (regexec(&r, src.c_str() + offset, 1, matches, 0) == 0) {
        result.append(src, offset, matches[0].rm_so);
        int         hexoff = matches[0].rm_so + 2;
        std::string hex;
        hex.push_back(src[offset + hexoff]);
        if (hexoff + 1 < matches[0].rm_eo) {
            hex.push_back(src[offset + hexoff + 1]);
        }
        char decoded = stoi(hex, 0, 16);
        if ((decoded >= 0x7B && decoded <= 0x7D) || (decoded >= 0x24 && decoded <= 0x2E) ||
            decoded == 0x5C || decoded == 0x5E) {
            result.push_back('\\');
            result.push_back(decoded);
        } else if ((decoded == '[' || decoded == ']') &&
                   /* not enclosed in [] */ (result.empty() || result.back() != '[')) {
            result.push_back('[');
            result.push_back(decoded);
            result.push_back(']');
        } else {
            result.push_back(decoded);
        }
        offset += matches[0].rm_eo;
    }

    result.append(src.begin() + offset, src.end());

    return result;
}
#endif

void
cli_rnp_print_key_info(FILE *fp, rnp_ffi_t ffi, rnp_key_handle_t key, bool psecret, bool psigs)
{
    char         buf[64] = {0};
    const char * header = NULL;
    bool         secret = false;
    bool         primary = false;
    bool         revoked = false;
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
        fprintf(fp, "Key JSON error.\n");
        goto done;
    }
    if (!(keypkt = json_object_array_get_idx(pkts, 0))) {
        fprintf(fp, "Key JSON error.\n");
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
        uint32_t now = time(NULL);
        auto     expire_time = create + expiry;
        ptimestr(buf, sizeof(buf), expire_time);
        fprintf(fp, " [%s %s]", expire_time <= now ? "EXPIRED" : "EXPIRES", buf);
    }
    /* key is revoked */
    (void) rnp_key_is_revoked(key, &revoked);
    if (revoked) {
        fprintf(fp, " [REVOKED]");
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
        fprintf(fp, "uid           %s", cli_rnp_escape_string(uid_str).c_str());
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
            if (keyid) {
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
    rnp_output_t       output = NULL;
    rnp_result_t       pub_ret = 0;
    rnp_result_t       sec_ret = 0;
    const std::string &ppath = rnp->pubpath();
    const std::string &spath = rnp->secpath();

    // check whether we have G10 secret keyring - then need to create directory
    if (rnp->secformat() == "G10") {
        struct stat path_stat;
        if (rnp_stat(spath.c_str(), &path_stat) != -1) {
            if (!S_ISDIR(path_stat.st_mode)) {
                ERR_MSG("G10 keystore should be a directory: %s", spath.c_str());
                return false;
            }
        } else {
            if (errno != ENOENT) {
                ERR_MSG("stat(%s): %s", spath.c_str(), strerror(errno));
                return false;
            }
            if (RNP_MKDIR(spath.c_str(), S_IRWXU) != 0) {
                ERR_MSG("mkdir(%s, S_IRWXU): %s", spath.c_str(), strerror(errno));
                return false;
            }
        }
    }

    // public keyring
    if (!(pub_ret = rnp_output_to_path(&output, ppath.c_str()))) {
        pub_ret =
          rnp_save_keys(rnp->ffi, rnp->pubformat().c_str(), output, RNP_LOAD_SAVE_PUBLIC_KEYS);
        rnp_output_destroy(output);
    }
    if (pub_ret) {
        ERR_MSG("failed to write pubring to path '%s'", ppath.c_str());
    }

    // secret keyring
    if (!(sec_ret = rnp_output_to_path(&output, spath.c_str()))) {
        sec_ret =
          rnp_save_keys(rnp->ffi, rnp->secformat().c_str(), output, RNP_LOAD_SAVE_SECRET_KEYS);
        rnp_output_destroy(output);
    }
    if (sec_ret) {
        ERR_MSG("failed to write secring to path '%s'", spath.c_str());
    }

    return !pub_ret && !sec_ret;
}

bool
cli_rnp_generate_key(cli_rnp_t *rnp, const char *username)
{
    /* set key generation parameters to rnp_cfg_t */
    rnp_cfg &cfg = rnp->cfg();
    if (!cli_rnp_set_generate_params(cfg)) {
        ERR_MSG("Key generation setup failed.");
        return false;
    }
    /* generate the primary key */
    rnp_op_generate_t genkey = NULL;
    rnp_key_handle_t  primary = NULL;
    rnp_key_handle_t  subkey = NULL;
    bool              res = false;

    if (rnp_op_generate_create(&genkey, rnp->ffi, cfg.get_cstr(CFG_KG_PRIMARY_ALG))) {
        ERR_MSG("Failed to initialize key generation.");
        return false;
    }
    if (username && rnp_op_generate_set_userid(genkey, username)) {
        ERR_MSG("Failed to set userid.");
        goto done;
    }
    if (cfg.has(CFG_KG_PRIMARY_BITS) &&
        rnp_op_generate_set_bits(genkey, cfg.get_int(CFG_KG_PRIMARY_BITS))) {
        ERR_MSG("Failed to set key bits.");
        goto done;
    }
    if (cfg.has(CFG_KG_PRIMARY_CURVE) &&
        rnp_op_generate_set_curve(genkey, cfg.get_cstr(CFG_KG_PRIMARY_CURVE))) {
        ERR_MSG("Failed to set key curve.");
        goto done;
    }
    if (cfg.has(CFG_KG_PRIMARY_EXPIRATION)) {
        uint32_t expiration = 0;
        if (!cfg.get_expiration(CFG_KG_PRIMARY_EXPIRATION, expiration) ||
            rnp_op_generate_set_expiration(genkey, expiration)) {
            ERR_MSG("Failed to set primary key expiration.");
            goto done;
        }
    }
    // TODO : set DSA qbits
    if (rnp_op_generate_set_hash(genkey, cfg.get_cstr(CFG_KG_HASH))) {
        ERR_MSG("Failed to set hash algorithm.");
        goto done;
    }

    fprintf(rnp->userio_out, "Generating a new key...\n");
    if (rnp_op_generate_execute(genkey) || rnp_op_generate_get_key(genkey, &primary)) {
        ERR_MSG("Primary key generation failed.");
        goto done;
    }

    if (!cfg.has(CFG_KG_SUBKEY_ALG)) {
        res = true;
        goto done;
    }

    rnp_op_generate_destroy(genkey);
    genkey = NULL;
    if (rnp_op_generate_subkey_create(
          &genkey, rnp->ffi, primary, cfg.get_cstr(CFG_KG_SUBKEY_ALG))) {
        ERR_MSG("Failed to initialize subkey generation.");
        goto done;
    }
    if (cfg.has(CFG_KG_SUBKEY_BITS) &&
        rnp_op_generate_set_bits(genkey, cfg.get_int(CFG_KG_SUBKEY_BITS))) {
        ERR_MSG("Failed to set subkey bits.");
        goto done;
    }
    if (cfg.has(CFG_KG_SUBKEY_CURVE) &&
        rnp_op_generate_set_curve(genkey, cfg.get_cstr(CFG_KG_SUBKEY_CURVE))) {
        ERR_MSG("Failed to set subkey curve.");
        goto done;
    }
    if (cfg.has(CFG_KG_SUBKEY_EXPIRATION)) {
        uint32_t expiration = 0;
        if (!cfg.get_expiration(CFG_KG_SUBKEY_EXPIRATION, expiration) ||
            rnp_op_generate_set_expiration(genkey, expiration)) {
            ERR_MSG("Failed to set subkey expiration.");
            goto done;
        }
    }
    // TODO : set DSA qbits
    if (rnp_op_generate_set_hash(genkey, cfg.get_cstr(CFG_KG_HASH))) {
        ERR_MSG("Failed to set hash algorithm.");
        goto done;
    }
    if (rnp_op_generate_execute(genkey) || rnp_op_generate_get_key(genkey, &subkey)) {
        ERR_MSG("Subkey generation failed.");
        goto done;
    }

    // protect
    for (auto key : {primary, subkey}) {
        char *password = NULL;
        if (rnp_request_password(rnp->ffi, key, "protect", &password)) {
            ERR_MSG("Failed to obtain protection password.");
            goto done;
        }
        if (*password) {
            rnp_result_t ret = rnp_key_protect(key,
                                               password,
                                               cfg.get_cstr(CFG_KG_PROT_ALG),
                                               NULL,
                                               cfg.get_cstr(CFG_KG_PROT_HASH),
                                               cfg.get_int(CFG_KG_PROT_ITERATIONS));
            rnp_buffer_clear(password, strlen(password) + 1);
            rnp_buffer_destroy(password);
            if (ret) {
                ERR_MSG("Failed to protect key.");
                goto done;
            }
        } else {
            rnp_buffer_destroy(password);
        }
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

static size_t
hex_prefix_len(const std::string &str)
{
    if ((str.length() >= 2) && (str[0] == '0') && ((str[1] == 'x') || (str[1] == 'X'))) {
        return 2;
    }
    return 0;
}

static bool
str_is_hex(const std::string &hexid)
{
    for (size_t i = hex_prefix_len(hexid); i < hexid.length(); i++) {
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

static std::string
strip_hex_str(const std::string &str)
{
    std::string res = "";
    for (size_t idx = hex_prefix_len(str); idx < str.length(); idx++) {
        char ch = str[idx];
        if ((ch == ' ') || (ch == '\t')) {
            continue;
        }
        res.push_back(ch);
    }
    return res;
}

static bool
key_matches_string(rnp_key_handle_t handle, const std::string &str)
{
    bool   matches = false;
    char * id = NULL;
    size_t idlen = 0;
    size_t len = str.length();
#ifndef RNP_USE_STD_REGEX
    regex_t r = {};
#else
    std::regex re;
#endif
    size_t uid_count = 0;
    bool   boolres = false;

    if (str.empty()) {
        matches = true;
        goto done;
    }
    if (str_is_hex(str) && (len >= RNP_KEYID_SIZE)) {
        std::string hexstr = strip_hex_str(str);

        /* check whether it's key id */
        if ((len == RNP_KEYID_SIZE * 2) || (len == RNP_KEYID_SIZE)) {
            if (rnp_key_get_keyid(handle, &id)) {
                goto done;
            }
            if ((idlen = strlen(id)) < len) {
                goto done;
            }
            if (strncasecmp(hexstr.c_str(), id + idlen - len, len) == 0) {
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
            if (strncasecmp(hexstr.c_str(), id, len) == 0) {
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
            if (strncasecmp(hexstr.c_str(), id, len) == 0) {
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
    if (regcomp(&r, cli_rnp_unescape_for_regcomp(str).c_str(), REG_EXTENDED | REG_ICASE) !=
        0) {
        goto done;
    }
#else
    try {
        re.assign(str, std::regex_constants::ECMAScript | std::regex_constants::icase);
    } catch (const std::exception &e) {
        ERR_MSG("Invalid regular expression : %s, error %s.", str.c_str(), e.what());
        goto done;
    }
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

static bool
key_matches_flags(rnp_key_handle_t key, int flags)
{
    /* check whether secret key search is requested */
    bool secret = false;
    if (rnp_key_have_secret(key, &secret)) {
        return false;
    }
    if ((flags & CLI_SEARCH_SECRET) && !secret) {
        return false;
    }
    /* check whether no subkeys allowed */
    bool subkey = false;
    if (rnp_key_is_sub(key, &subkey)) {
        return false;
    }
    if (!subkey) {
        return true;
    }
    if (!(flags & CLI_SEARCH_SUBKEYS)) {
        return false;
    }
    /* check whether subkeys should be put after primary (if it is available) */
    if ((flags & CLI_SEARCH_SUBKEYS_AFTER) != CLI_SEARCH_SUBKEYS_AFTER) {
        return true;
    }

    char *grip = NULL;
    if (rnp_key_get_primary_grip(key, &grip)) {
        return false;
    }
    if (!grip) {
        return true;
    }
    rnp_buffer_destroy(grip);
    return false;
}

void
clear_key_handles(std::vector<rnp_key_handle_t> &keys)
{
    for (auto handle : keys) {
        rnp_key_handle_destroy(handle);
    }
    keys.clear();
}

static bool
add_key_to_array(rnp_ffi_t                      ffi,
                 std::vector<rnp_key_handle_t> &keys,
                 rnp_key_handle_t               key,
                 int                            flags)
{
    bool subkey = false;
    bool subkeys = (flags & CLI_SEARCH_SUBKEYS_AFTER) == CLI_SEARCH_SUBKEYS_AFTER;
    if (rnp_key_is_sub(key, &subkey)) {
        return false;
    }

    try {
        keys.push_back(key);
    } catch (const std::exception &e) {
        ERR_MSG("%s", e.what());
        return false;
    }
    if (!subkeys || subkey) {
        return true;
    }

    std::vector<rnp_key_handle_t> subs;
    size_t                        sub_count = 0;
    if (rnp_key_get_subkey_count(key, &sub_count)) {
        goto error;
    }

    try {
        for (size_t i = 0; i < sub_count; i++) {
            rnp_key_handle_t sub_handle = NULL;
            if (rnp_key_get_subkey_at(key, i, &sub_handle)) {
                goto error;
            }
            subs.push_back(sub_handle);
        }
        std::move(subs.begin(), subs.end(), std::back_inserter(keys));
    } catch (const std::exception &e) {
        ERR_MSG("%s", e.what());
        goto error;
    }
    return true;
error:
    keys.pop_back();
    clear_key_handles(subs);
    return false;
}

bool
cli_rnp_keys_matching_string(cli_rnp_t *                    rnp,
                             std::vector<rnp_key_handle_t> &keys,
                             const std::string &            str,
                             int                            flags)
{
    bool                      res = false;
    rnp_identifier_iterator_t it = NULL;
    rnp_key_handle_t          handle = NULL;
    const char *              fp = NULL;

    /* iterate through the keys */
    if (rnp_identifier_iterator_create(rnp->ffi, &it, "fingerprint")) {
        return false;
    }

    while (!rnp_identifier_iterator_next(it, &fp)) {
        if (!fp) {
            break;
        }
        if (rnp_locate_key(rnp->ffi, "fingerprint", fp, &handle) || !handle) {
            goto done;
        }
        if (!key_matches_flags(handle, flags) || !key_matches_string(handle, str.c_str())) {
            rnp_key_handle_destroy(handle);
            continue;
        }
        if (!add_key_to_array(rnp->ffi, keys, handle, flags)) {
            rnp_key_handle_destroy(handle);
            goto done;
        }
        if (flags & CLI_SEARCH_FIRST_ONLY) {
            res = true;
            goto done;
        }
    }
    res = !keys.empty();
done:
    rnp_identifier_iterator_destroy(it);
    return res;
}

bool
cli_rnp_keys_matching_strings(cli_rnp_t *                     rnp,
                              std::vector<rnp_key_handle_t> & keys,
                              const std::vector<std::string> &strs,
                              int                             flags)
{
    bool res = false;
    clear_key_handles(keys);

    for (const std::string &str : strs) {
        if (!cli_rnp_keys_matching_string(rnp, keys, str, flags & ~CLI_SEARCH_DEFAULT)) {
            ERR_MSG("Cannot find key matching \"%s\"", str.c_str());
            goto done;
        }
    }

    /* search for default key */
    if (keys.empty() && (flags & CLI_SEARCH_DEFAULT)) {
        if (rnp->defkey().empty()) {
            ERR_MSG("No userid or default key for operation");
            goto done;
        }
        cli_rnp_keys_matching_string(rnp, keys, rnp->defkey(), flags & ~CLI_SEARCH_DEFAULT);
        if (keys.empty()) {
            ERR_MSG("Default key not found");
        }
    }
    res = !keys.empty();
done:
    if (!res) {
        clear_key_handles(keys);
    }
    return res;
}

/** @brief compose path from dir, subdir and filename, and return it.
 *  @param dir [in] directory path
 *  @param subddir [in] subdirectory to add to the path, can be empty
 *  @param filename [in] filename (or path/filename)
 *
 *  @return constructed path
 **/
static std::string
rnp_path_compose(const std::string &dir,
                 const std::string &subdir,
                 const std::string &filename)
{
    std::string res = dir;
    if (!subdir.empty()) {
        if (!res.empty() && (res.back() != '/')) {
            res.push_back('/');
        }
        res.append(subdir);
    }

    if (!res.empty() && (res.back() != '/')) {
        res.push_back('/');
    }

    res.append(filename);
    return res;
}

static bool
rnp_cfg_set_ks_info(rnp_cfg &cfg)
{
    if (cfg.get_bool(CFG_KEYSTORE_DISABLED)) {
        cfg.set_str(CFG_KR_PUB_PATH, "");
        cfg.set_str(CFG_KR_SEC_PATH, "");
        cfg.set_str(CFG_KR_PUB_FORMAT, RNP_KEYSTORE_GPG);
        cfg.set_str(CFG_KR_SEC_FORMAT, RNP_KEYSTORE_GPG);
        return true;
    }

    /* getting path to keyrings. If it is specified by user in 'homedir' param then it is
     * considered as the final path */
    bool        defhomedir = false;
    std::string homedir = cfg.get_str(CFG_HOMEDIR);
    if (homedir.empty()) {
        const char *home = getenv("HOME");
        homedir = home ? home : "";
        defhomedir = true;
    }

    struct stat st;

    if (rnp_stat(homedir.c_str(), &st) || rnp_access(homedir.c_str(), R_OK | W_OK)) {
        ERR_MSG("Home directory '%s' does not exist or is not writable!", homedir.c_str());
        return false;
    }

    /* detecting key storage format */
    std::string subdir = defhomedir ? SUBDIRECTORY_RNP : "";
    std::string pubpath;
    std::string secpath;
    std::string ks_format = cfg.get_str(CFG_KEYSTOREFMT);

    if (ks_format.empty()) {
        pubpath = rnp_path_compose(homedir, subdir, PUBRING_KBX);
        secpath = rnp_path_compose(homedir, subdir, SECRING_G10);

        bool pubpath_exists = !rnp_stat(pubpath.c_str(), &st);
        bool secpath_exists = !rnp_stat(secpath.c_str(), &st);

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

    /* creating home dir if needed */
    if (!subdir.empty()) {
        pubpath = rnp_path_compose(homedir, "", subdir);
        if (RNP_MKDIR(pubpath.c_str(), 0700) == -1 && errno != EEXIST) {
            ERR_MSG("cannot mkdir '%s' errno = %d", pubpath.c_str(), errno);
            return false;
        }
    }

    std::string pub_format = RNP_KEYSTORE_GPG;
    std::string sec_format = RNP_KEYSTORE_GPG;

    if (ks_format == RNP_KEYSTORE_GPG) {
        pubpath = rnp_path_compose(homedir, subdir, PUBRING_GPG);
        secpath = rnp_path_compose(homedir, subdir, SECRING_GPG);
        pub_format = RNP_KEYSTORE_GPG;
        sec_format = RNP_KEYSTORE_GPG;
    } else if (ks_format == RNP_KEYSTORE_GPG21) {
        pubpath = rnp_path_compose(homedir, subdir, PUBRING_KBX);
        secpath = rnp_path_compose(homedir, subdir, SECRING_G10);
        pub_format = RNP_KEYSTORE_KBX;
        sec_format = RNP_KEYSTORE_G10;
    } else if (ks_format == RNP_KEYSTORE_KBX) {
        pubpath = rnp_path_compose(homedir, subdir, PUBRING_KBX);
        secpath = rnp_path_compose(homedir, subdir, SECRING_KBX);
        pub_format = RNP_KEYSTORE_KBX;
        sec_format = RNP_KEYSTORE_KBX;
    } else if (ks_format == RNP_KEYSTORE_G10) {
        pubpath = rnp_path_compose(homedir, subdir, PUBRING_G10);
        secpath = rnp_path_compose(homedir, subdir, SECRING_G10);
        pub_format = RNP_KEYSTORE_G10;
        sec_format = RNP_KEYSTORE_G10;
    } else {
        ERR_MSG("unsupported keystore format: \"%s\"", ks_format.c_str());
        return false;
    }

    cfg.set_str(CFG_KR_PUB_PATH, pubpath);
    cfg.set_str(CFG_KR_SEC_PATH, secpath);
    cfg.set_str(CFG_KR_PUB_FORMAT, pub_format);
    cfg.set_str(CFG_KR_SEC_FORMAT, sec_format);
    return true;
}

/* read any gpg config file */
static bool
conffile(const std::string &homedir, std::string &userid)
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
    (void) snprintf(buf, sizeof(buf), "%s/.gnupg/gpg.conf", homedir.c_str());
    if ((fp = rnp_fopen(buf, "r")) == NULL) {
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
            userid =
              std::string(&buf[(int) matchv[1].rm_so], matchv[1].rm_eo - matchv[1].rm_so);
            ERR_MSG("rnp: default key set to \"%s\"", userid.c_str());
        }
#else
        std::smatch result;
        std::string input = buf;
        if (std::regex_search(input, result, keyre)) {
            userid = result[1].str();
            ERR_MSG("rnp: default key set to \"%s\"", userid.c_str());
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
rnp_cfg_set_defkey(rnp_cfg &cfg)
{
    bool        defhomedir = false;
    std::string homedir = cfg.get_str(CFG_HOMEDIR);
    if (homedir.empty()) {
        const char *home = getenv("HOME");
        homedir = home ? home : "";
        defhomedir = true;
    }

    /* If a userid has been given, we'll use it. */
    std::string userid = cfg.get_count(CFG_USERID) ? cfg.get_str(CFG_USERID, 0) : "";
    if (!userid.empty()) {
        cfg.set_str(CFG_KR_DEF_KEY, userid);
        return;
    }
    /* also search in config file for default id */
    if (defhomedir) {
        std::string id;
        if (conffile(homedir, id) && !id.empty()) {
            cfg.unset(CFG_USERID);
            cfg.add_str(CFG_USERID, id);
            cfg.set_str(CFG_KR_DEF_KEY, id);
        }
    }
}

bool
cli_cfg_set_keystore_info(rnp_cfg &cfg)
{
    /* detecting keystore paths and format */
    if (!rnp_cfg_set_ks_info(cfg)) {
        ERR_MSG("cannot obtain keystore path(s)");
        return false;
    }

    /* default key/userid */
    rnp_cfg_set_defkey(cfg);
    return true;
}

static bool
stdin_reader(void *app_ctx, void *buf, size_t len, size_t *readres)
{
    ssize_t res = read(STDIN_FILENO, buf, len);
    if (res < 0) {
        return false;
    }
    *readres = res;
    return true;
}

/* This produces
   runtime error: call to function stdout_writer(void*, void const*, unsigned long) through
   pointer to incorrect function type 'bool (*)(void *, const void *, unsigned long)' */
#if defined(__clang__)
__attribute__((no_sanitize("undefined")))
#endif
static bool
stdout_writer(void *app_ctx, const void *buf, size_t len)
{
    ssize_t wlen = write(STDOUT_FILENO, buf, len);
    return (wlen >= 0) && (size_t) wlen == len;
}

rnp_input_t
cli_rnp_input_from_specifier(cli_rnp_t &rnp, const std::string &spec, bool *is_path)
{
    rnp_input_t  input = NULL;
    rnp_result_t res = RNP_ERROR_GENERIC;
    bool         path = false;
    if (spec.empty() || (spec == "-")) {
        /* input from stdin */
        res = rnp_input_from_callback(&input, stdin_reader, NULL, NULL);
    } else if ((spec.size() > 4) && (spec.compare(0, 4, "env:") == 0)) {
        /* input from an environment variable */
        const char *envval = getenv(spec.c_str() + 4);
        if (!envval) {
            ERR_MSG("Failed to get value of the environment variable '%s'.", spec.c_str() + 4);
            return NULL;
        }
        res = rnp_input_from_memory(&input, (const uint8_t *) envval, strlen(envval), true);
    } else {
        /* input from path */
        res = rnp_input_from_path(&input, spec.c_str());
        path = true;
    }

    if (res) {
        return NULL;
    }
    if (is_path) {
        *is_path = path;
    }
    return input;
}

rnp_output_t
cli_rnp_output_to_specifier(cli_rnp_t &rnp, const std::string &spec, bool discard)
{
    rnp_output_t output = NULL;
    rnp_result_t res = RNP_ERROR_GENERIC;
    std::string  path = spec;
    if (discard) {
        res = rnp_output_to_null(&output);
    } else if (spec.empty() || (spec == "-")) {
        res = rnp_output_to_callback(&output, stdout_writer, NULL, NULL);
    } else if (!rnp_get_output_filename(spec, path, rnp)) {
        ERR_MSG("Operation failed: file '%s' already exists.", spec.c_str());
        res = RNP_ERROR_BAD_PARAMETERS;
    } else {
        res = rnp_output_to_file(&output, path.c_str(), RNP_OUTPUT_FILE_OVERWRITE);
    }
    return res ? NULL : output;
}

bool
cli_rnp_export_keys(cli_rnp_t *rnp, const char *filter)
{
    bool                          secret = rnp->cfg().get_bool(CFG_SECRET);
    int                           flags = secret ? CLI_SEARCH_SECRET : 0;
    std::vector<rnp_key_handle_t> keys;

    if (!cli_rnp_keys_matching_string(rnp, keys, filter, flags)) {
        ERR_MSG("Key(s) matching '%s' not found.", filter);
        return false;
    }

    rnp_output_t output = NULL;
    rnp_output_t armor = NULL;
    uint32_t     base_flags = secret ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC;
    bool         result = false;

    output = cli_rnp_output_to_specifier(*rnp, rnp->cfg().get_str(CFG_OUTFILE));
    if (!output) {
        goto done;
    }

    /* We need single armored stream for all of the keys */
    if (rnp_output_to_armor(output, &armor, secret ? "secret key" : "public key")) {
        goto done;
    }

    for (auto key : keys) {
        uint32_t flags = base_flags;
        bool     primary = false;

        if (rnp_key_is_primary(key, &primary)) {
            goto done;
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
    clear_key_handles(keys);
    return result;
}

bool
cli_rnp_export_revocation(cli_rnp_t *rnp, const char *key)
{
    std::vector<rnp_key_handle_t> keys;
    if (!cli_rnp_keys_matching_string(rnp, keys, key, 0)) {
        ERR_MSG("Key matching '%s' not found.", key);
        return false;
    }
    if (keys.size() > 1) {
        ERR_MSG("Ambiguous input: too many keys found for '%s'.", key);
        clear_key_handles(keys);
        return false;
    }
    rnp_output_t output = NULL;
    rnp_output_t armored = NULL;
    bool         result = false;

    output = cli_rnp_output_to_specifier(*rnp, rnp->cfg().get_str(CFG_OUTFILE));
    if (!output) {
        goto done;
    }

    /* export it armored by default */
    if (rnp_output_to_armor(output, &armored, "public key")) {
        goto done;
    }

    result = !rnp_key_export_revocation(keys[0],
                                        armored,
                                        0,
                                        rnp->cfg().get_cstr(CFG_HASH),
                                        rnp->cfg().get_cstr(CFG_REV_TYPE),
                                        rnp->cfg().get_cstr(CFG_REV_REASON));
done:
    rnp_output_destroy(armored);
    rnp_output_destroy(output);
    clear_key_handles(keys);
    return result;
}

bool
cli_rnp_revoke_key(cli_rnp_t *rnp, const char *key)
{
    std::vector<rnp_key_handle_t> keys;
    if (!cli_rnp_keys_matching_string(rnp, keys, key, CLI_SEARCH_SUBKEYS)) {
        ERR_MSG("Key matching '%s' not found.", key);
        return false;
    }
    bool         res = false;
    bool         revoked = false;
    rnp_result_t ret = 0;

    if (keys.size() > 1) {
        ERR_MSG("Ambiguous input: too many keys found for '%s'.", key);
        goto done;
    }
    if (rnp_key_is_revoked(keys[0], &revoked)) {
        ERR_MSG("Error getting key revocation status.");
        goto done;
    }
    if (revoked && !rnp->cfg().get_bool(CFG_FORCE)) {
        ERR_MSG("Error: key '%s' is revoked already. Use --force to generate another "
                "revocation signature.",
                key);
        goto done;
    }

    ret = rnp_key_revoke(keys[0],
                         0,
                         rnp->cfg().get_cstr(CFG_HASH),
                         rnp->cfg().get_cstr(CFG_REV_TYPE),
                         rnp->cfg().get_cstr(CFG_REV_REASON));
    if (ret) {
        ERR_MSG("Failed to revoke a key: error %d", (int) ret);
        goto done;
    }
    res = cli_rnp_save_keyrings(rnp);
    /* print info about the revoked key */
    if (res) {
        bool  subkey = false;
        char *grip = NULL;
        if (rnp_key_is_sub(keys[0], &subkey)) {
            ERR_MSG("Failed to get key info");
            goto done;
        }
        ret =
          subkey ? rnp_key_get_primary_grip(keys[0], &grip) : rnp_key_get_grip(keys[0], &grip);
        if (ret || !grip) {
            ERR_MSG("Failed to get primary key grip.");
            goto done;
        }
        clear_key_handles(keys);
        if (!cli_rnp_keys_matching_string(rnp, keys, grip, CLI_SEARCH_SUBKEYS_AFTER)) {
            ERR_MSG("Failed to search for revoked key.");
            rnp_buffer_destroy(grip);
            goto done;
        }
        rnp_buffer_destroy(grip);
        for (auto handle : keys) {
            cli_rnp_print_key_info(rnp->userio_out, rnp->ffi, handle, false, false);
        }
    }
done:
    clear_key_handles(keys);
    return res;
}

bool
cli_rnp_remove_key(cli_rnp_t *rnp, const char *key)
{
    std::vector<rnp_key_handle_t> keys;
    if (!cli_rnp_keys_matching_string(rnp, keys, key, CLI_SEARCH_SUBKEYS)) {
        ERR_MSG("Key matching '%s' not found.", key);
        return false;
    }
    bool         res = false;
    bool         secret = false;
    bool         primary = false;
    uint32_t     flags = RNP_KEY_REMOVE_PUBLIC;
    rnp_result_t ret = 0;

    if (keys.size() > 1) {
        ERR_MSG("Ambiguous input: too many keys found for '%s'.", key);
        goto done;
    }
    if (rnp_key_have_secret(keys[0], &secret)) {
        ERR_MSG("Error getting secret key presence.");
        goto done;
    }
    if (rnp_key_is_primary(keys[0], &primary)) {
        ERR_MSG("Key error.");
        goto done;
    }

    if (secret) {
        flags |= RNP_KEY_REMOVE_SECRET;
    }
    if (primary) {
        flags |= RNP_KEY_REMOVE_SUBKEYS;
    }

    if (secret && !rnp->cfg().get_bool(CFG_FORCE)) {
        if (!cli_rnp_get_confirmation(
              rnp,
              "Key '%s' has corresponding secret key. Do you really want to delete it?",
              key)) {
            goto done;
        }
    }

    ret = rnp_key_remove(keys[0], flags);

    if (ret) {
        ERR_MSG("Failed to remove the key: error %d", (int) ret);
        goto done;
    }
    res = cli_rnp_save_keyrings(rnp);
done:
    clear_key_handles(keys);
    return res;
}

bool
cli_rnp_add_key(cli_rnp_t *rnp)
{
    const std::string &path = rnp->cfg().get_str(CFG_KEYFILE);
    if (path.empty()) {
        return false;
    }

    rnp_input_t input = cli_rnp_input_from_specifier(*rnp, path, NULL);
    if (!input) {
        ERR_MSG("failed to open key from %s", path.c_str());
        return false;
    }

    bool res = !rnp_import_keys(
      rnp->ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS, NULL);
    rnp_input_destroy(input);

    // set default key if we didn't have one
    if (res && rnp->defkey().empty()) {
        rnp->set_defkey();
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
output_extension(const rnp_cfg &cfg, const std::string &op)
{
    if (op == "encrypt_sign") {
        bool armor = cfg.get_bool(CFG_ARMOR);
        if (cfg.get_bool(CFG_DETACHED)) {
            return armor ? EXT_ASC : EXT_SIG;
        }
        if (cfg.get_bool(CFG_CLEARTEXT)) {
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

static bool
cli_rnp_init_io(const std::string &op,
                rnp_input_t *      input,
                rnp_output_t *     output,
                cli_rnp_t *        rnp)
{
    const std::string &in = rnp->cfg().get_str(CFG_INFILE);
    bool               is_pathin = true;
    if (input) {
        *input = cli_rnp_input_from_specifier(*rnp, in, &is_pathin);
        if (!*input) {
            return false;
        }
    }

    if (!output) {
        return true;
    }
    std::string out = rnp->cfg().get_str(CFG_OUTFILE);
    bool discard = (op == "verify") && out.empty() && rnp->cfg().get_bool(CFG_NO_OUTPUT);

    if (out.empty() && is_pathin && !discard) {
        std::string ext = output_extension(rnp->cfg(), op);
        if (!ext.empty()) {
            out = in + ext;
        }
    }

    *output = cli_rnp_output_to_specifier(*rnp, out, discard);
    if (!*output && input) {
        rnp_input_destroy(*input);
        *input = NULL;
    }
    return *output;
}

bool
cli_rnp_dump_file(cli_rnp_t *rnp)
{
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;
    uint32_t     flags = 0;
    uint32_t     jflags = 0;

    if (rnp->cfg().get_bool(CFG_GRIPS)) {
        flags |= RNP_DUMP_GRIP;
        jflags |= RNP_JSON_DUMP_GRIP;
    }
    if (rnp->cfg().get_bool(CFG_MPIS)) {
        flags |= RNP_DUMP_MPI;
        jflags |= RNP_JSON_DUMP_MPI;
    }
    if (rnp->cfg().get_bool(CFG_RAW)) {
        flags |= RNP_DUMP_RAW;
        jflags |= RNP_JSON_DUMP_RAW;
    }

    rnp_result_t ret = 0;
    if (!cli_rnp_init_io("dump", &input, &output, rnp)) {
        ERR_MSG("failed to open source or create output");
        ret = 1;
        goto done;
    }

    if (rnp->cfg().get_bool(CFG_JSON)) {
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
done:
    return !ret;
}

bool
cli_rnp_armor_file(cli_rnp_t *rnp)
{
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    if (!cli_rnp_init_io("armor", &input, &output, rnp)) {
        ERR_MSG("failed to open source or create output");
        return false;
    }
    rnp_result_t ret = rnp_enarmor(input, output, rnp->cfg().get_cstr(CFG_ARMOR_DATA_TYPE));
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    return !ret;
}

bool
cli_rnp_dearmor_file(cli_rnp_t *rnp)
{
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    if (!cli_rnp_init_io("dearmor", &input, &output, rnp)) {
        ERR_MSG("failed to open source or create output");
        return false;
    }

    rnp_result_t ret = rnp_dearmor(input, output);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    return !ret;
}

static bool
cli_rnp_sign(const rnp_cfg &cfg, cli_rnp_t *rnp, rnp_input_t input, rnp_output_t output)
{
    rnp_op_sign_t op = NULL;
    rnp_result_t  ret = RNP_ERROR_GENERIC;
    bool          cleartext = cfg.get_bool(CFG_CLEARTEXT);
    bool          detached = cfg.get_bool(CFG_DETACHED);

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
        rnp_op_sign_set_armor(op, cfg.get_bool(CFG_ARMOR));
    }

    if (!cleartext && !detached) {
        const std::string &fname = cfg.get_str(CFG_INFILE);
        if (!fname.empty()) {
            if (rnp_op_sign_set_file_name(op, extract_filename(fname).c_str())) {
                goto done;
            }
            rnp_op_sign_set_file_mtime(op, rnp_filemtime(fname.c_str()));
        }
        if (rnp_op_sign_set_compression(op, cfg.get_cstr(CFG_ZALG), cfg.get_int(CFG_ZLEVEL))) {
            goto done;
        }
    }

    if (rnp_op_sign_set_hash(op, cfg.get_hashalg().c_str())) {
        goto done;
    }
    rnp_op_sign_set_creation_time(op, cfg.get_sig_creation());
    {
        uint32_t expiration = 0;
        if (cfg.get_expiration(CFG_EXPIRATION, expiration)) {
            rnp_op_sign_set_expiration_time(op, expiration);
        }
    }

    /* signing keys */
    signers = cfg.get_list(CFG_SIGNERS);
    if (!cli_rnp_keys_matching_strings(rnp,
                                       signkeys,
                                       signers,
                                       CLI_SEARCH_SECRET | CLI_SEARCH_DEFAULT |
                                         CLI_SEARCH_SUBKEYS | CLI_SEARCH_FIRST_ONLY)) {
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
    clear_key_handles(signkeys);
    rnp_op_sign_destroy(op);
    return res;
}

static bool
cli_rnp_encrypt_and_sign(const rnp_cfg &cfg,
                         cli_rnp_t *    rnp,
                         rnp_input_t    input,
                         rnp_output_t   output)
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
    rnp_result_t                  ret;

    rnp_op_encrypt_set_armor(op, cfg.get_bool(CFG_ARMOR));

    fname = cfg.get_str(CFG_INFILE);
    if (!fname.empty()) {
        if (rnp_op_encrypt_set_file_name(op, extract_filename(fname).c_str())) {
            goto done;
        }
        rnp_op_encrypt_set_file_mtime(op, rnp_filemtime(fname.c_str()));
    }
    if (rnp_op_encrypt_set_compression(op, cfg.get_cstr(CFG_ZALG), cfg.get_int(CFG_ZLEVEL))) {
        goto done;
    }
    if (rnp_op_encrypt_set_cipher(op, cfg.get_cstr(CFG_CIPHER))) {
        goto done;
    }
    if (rnp_op_encrypt_set_hash(op, cfg.get_hashalg().c_str())) {
        goto done;
    }
    aalg = cfg.has(CFG_AEAD) ? cfg.get_str(CFG_AEAD) : "None";
    if (rnp_op_encrypt_set_aead(op, aalg.c_str())) {
        goto done;
    }
    if (cfg.has(CFG_AEAD_CHUNK) &&
        rnp_op_encrypt_set_aead_bits(op, cfg.get_int(CFG_AEAD_CHUNK))) {
        goto done;
    }

    /* adding passwords if password-based encryption is used */
    if (cfg.get_bool(CFG_ENCRYPT_SK)) {
        std::string halg = cfg.get_hashalg();
        std::string ealg = cfg.get_str(CFG_CIPHER);

        for (int i = 0; i < cfg.get_int(CFG_PASSWORDC, 1); i++) {
            if (rnp_op_encrypt_add_password(op, NULL, halg.c_str(), 0, ealg.c_str())) {
                ERR_MSG("Failed to add encrypting password");
                goto done;
            }
        }
    }

    /* adding encrypting keys if pk-encryption is used */
    if (cfg.get_bool(CFG_ENCRYPT_PK)) {
        std::vector<std::string> keynames = cfg.get_list(CFG_RECIPIENTS);
        if (!cli_rnp_keys_matching_strings(rnp,
                                           enckeys,
                                           keynames,
                                           CLI_SEARCH_DEFAULT | CLI_SEARCH_SUBKEYS |
                                             CLI_SEARCH_FIRST_ONLY)) {
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
    if (cfg.get_bool(CFG_SIGN_NEEDED)) {
        rnp_op_encrypt_set_creation_time(op, cfg.get_sig_creation());
        uint32_t expiration;
        if (cfg.get_expiration(CFG_EXPIRATION, expiration)) {
            rnp_op_encrypt_set_expiration_time(op, expiration);
        }

        /* signing keys */
        std::vector<std::string> keynames = cfg.get_list(CFG_SIGNERS);
        if (!cli_rnp_keys_matching_strings(rnp,
                                           signkeys,
                                           keynames,
                                           CLI_SEARCH_SECRET | CLI_SEARCH_DEFAULT |
                                             CLI_SEARCH_SUBKEYS | CLI_SEARCH_FIRST_ONLY)) {
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
    ret = rnp_op_encrypt_execute(op);
    res = (ret == RNP_SUCCESS);
    if (ret != RNP_SUCCESS) {
        ERR_MSG("Operation failed: %s", rnp_result_to_string(ret));
    }
done:
    clear_key_handles(signkeys);
    clear_key_handles(enckeys);
    rnp_op_encrypt_destroy(op);
    return res;
}

bool
cli_rnp_setup(cli_rnp_t *rnp)
{
    /* unset CFG_PASSWD and empty CFG_PASSWD are different cases */
    if (rnp->cfg().has(CFG_PASSWD)) {
        const std::string &passwd = rnp->cfg().get_str(CFG_PASSWD);
        if (rnp_ffi_set_pass_provider(
              rnp->ffi, ffi_pass_callback_string, (void *) passwd.c_str())) {
            return false;
        }
    }
    rnp->pswdtries = rnp->cfg().get_pswdtries();
    return true;
}

bool
cli_rnp_protect_file(cli_rnp_t *rnp)
{
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    if (!cli_rnp_init_io("encrypt_sign", &input, &output, rnp)) {
        ERR_MSG("failed to open source or create output");
        return false;
    }

    bool res = false;
    bool sign = rnp->cfg().get_bool(CFG_SIGN_NEEDED);
    bool encrypt = rnp->cfg().get_bool(CFG_ENCRYPT_PK) || rnp->cfg().get_bool(CFG_ENCRYPT_SK);
    if (sign && !encrypt) {
        res = cli_rnp_sign(rnp->cfg(), rnp, input, output);
    } else if (encrypt) {
        res = cli_rnp_encrypt_and_sign(rnp->cfg(), rnp, input, output);
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
            title = "UNKNOWN signature";
            break;
        }

        uint32_t create = 0;
        uint32_t expiry = 0;
        rnp_op_verify_signature_get_times(sig, &create, &expiry);

        if (create > 0) {
            time_t crtime = create;
            fprintf(resfp,
                    "%s made %s%s",
                    title.c_str(),
                    rnp_y2k38_warning(crtime) ? ">=" : "",
                    rnp_ctime(crtime));
            if (expiry > 0) {
                crtime = rnp_timeadd(crtime, expiry);
                fprintf(resfp,
                        "Valid until %s%s\n",
                        rnp_y2k38_warning(crtime) ? ">=" : "",
                        rnp_ctime(crtime));
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
cli_rnp_process_file(cli_rnp_t *rnp)
{
    rnp_input_t input = NULL;
    if (!cli_rnp_init_io("verify", &input, NULL, rnp)) {
        ERR_MSG("failed to open source");
        return false;
    }

    char *contents = NULL;
    if (rnp_guess_contents(input, &contents)) {
        ERR_MSG("failed to check source contents");
        rnp_input_destroy(input);
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
        std::string in = rnp->cfg().get_str(CFG_INFILE);
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
        if (!cli_rnp_init_io("verify", NULL, &output, rnp)) {
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
        } catch (const std::exception &e) {
            ERR_MSG("%s", e.what());
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

void
cli_rnp_print_praise(void)
{
    printf("%s\n%s\n", PACKAGE_STRING, PACKAGE_BUGREPORT);
    printf("Backend: %s\n", rnp_backend_string());
    printf("Backend version: %s\n", rnp_backend_version());
    printf("Supported algorithms:\n");
    cli_rnp_print_feature(stdout, RNP_FEATURE_PK_ALG, "Public key");
    cli_rnp_print_feature(stdout, RNP_FEATURE_SYMM_ALG, "Encryption");
    cli_rnp_print_feature(stdout, RNP_FEATURE_AEAD_ALG, "AEAD");
    cli_rnp_print_feature(stdout, RNP_FEATURE_PROT_MODE, "Key protection");
    cli_rnp_print_feature(stdout, RNP_FEATURE_HASH_ALG, "Hash");
    cli_rnp_print_feature(stdout, RNP_FEATURE_COMP_ALG, "Compression");
    cli_rnp_print_feature(stdout, RNP_FEATURE_CURVE, "Curves");
    printf("Please report security issues at (https://www.rnpgp.org/feedback) and\n"
           "general bugs at https://github.com/rnpgp/rnp/issues.\n");
}

void
cli_rnp_print_feature(FILE *fp, const char *type, const char *printed_type)
{
    char * result = NULL;
    size_t count;
    if (rnp_supported_features(type, &result) != RNP_SUCCESS) {
        ERR_MSG("Failed to list supported features: %s", type);
        return;
    }
    json_object *jso = json_tokener_parse(result);
    if (!jso) {
        ERR_MSG("Failed to parse JSON with features: %s", type);
        goto done;
    }
    fprintf(fp, "%s: ", printed_type);
    count = json_object_array_length(jso);
    for (size_t idx = 0; idx < count; idx++) {
        json_object *val = json_object_array_get_idx(jso, idx);
        fprintf(fp, " %s%s", json_object_get_string(val), idx < count - 1 ? "," : "");
    }
    fputs("\n", fp);
    fflush(fp);
    json_object_put(jso);
done:
    rnp_buffer_destroy(result);
}
