/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
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
/* Command line program to perform rnp operations */

#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include "../rnp/rnpcfg.h"
#include "../rnp/fficli.h"
#include "rnpkeys.h"
#include "config.h"

// must be placed after include "utils.h"
#ifndef RNP_USE_STD_REGEX
#include <regex.h>
#else
#include <regex>
#endif

extern const char *rnp_keys_progname;

const char *usage = "--help OR\n"
                    "\t--export-key [options] OR\n"
                    "\t--generate-key [options] OR\n"
                    "\t--import-key [options] OR\n"
                    "\t--list-keys [options] OR\n"
                    "\t--version\n"
                    "where options are:\n"
                    "\t[--cipher=<cipher name>] AND/OR\n"
                    "\t[--coredumps] AND/OR\n"
                    "\t[--expert] AND/OR\n"
                    "\t[--with-sigs] AND/OR\n"
                    "\t[--force] AND/OR\n"
                    "\t[--hash=<hash alg>] AND/OR\n"
                    "\t[--homedir=<homedir>] AND/OR\n"
                    "\t[--keyring=<keyring>] AND/OR\n"
                    "\t[--output=file] file OR\n"
                    "\t[--keystore-format=<format>] AND/OR\n"
                    "\t[--userid=<userid>] AND/OR\n"
                    "\t[--verbose]\n";

struct option options[] = {
  /* key-management commands */
  {"list-keys", no_argument, NULL, CMD_LIST_KEYS},
  {"export", no_argument, NULL, CMD_EXPORT_KEY},
  {"export-key", optional_argument, NULL, CMD_EXPORT_KEY},
  {"import", no_argument, NULL, CMD_IMPORT_KEY},
  {"import-key", no_argument, NULL, CMD_IMPORT_KEY},
  {"gen", optional_argument, NULL, CMD_GENERATE_KEY},
  {"gen-key", optional_argument, NULL, CMD_GENERATE_KEY},
  {"generate", optional_argument, NULL, CMD_GENERATE_KEY},
  {"generate-key", optional_argument, NULL, CMD_GENERATE_KEY},
  /* debugging commands */
  {"help", no_argument, NULL, CMD_HELP},
  {"version", no_argument, NULL, CMD_VERSION},
  {"debug", required_argument, NULL, OPT_DEBUG},
  /* options */
  {"coredumps", no_argument, NULL, OPT_COREDUMPS},
  {"keystore-format", required_argument, NULL, OPT_KEY_STORE_FORMAT},
  {"userid", required_argument, NULL, OPT_USERID},
  {"format", required_argument, NULL, OPT_FORMAT},
  {"with-sigs", no_argument, NULL, OPT_WITH_SIGS},
  {"hash-alg", required_argument, NULL, OPT_HASH_ALG},
  {"hash", required_argument, NULL, OPT_HASH_ALG},
  {"algorithm", required_argument, NULL, OPT_HASH_ALG},
  {"home", required_argument, NULL, OPT_HOMEDIR},
  {"homedir", required_argument, NULL, OPT_HOMEDIR},
  {"numbits", required_argument, NULL, OPT_NUMBITS},
  {"s2k-iterations", required_argument, NULL, OPT_S2K_ITER},
  {"s2k-msec", required_argument, NULL, OPT_S2K_MSEC},
  {"verbose", no_argument, NULL, OPT_VERBOSE},
  {"pass-fd", required_argument, NULL, OPT_PASSWDFD},
  {"results", required_argument, NULL, OPT_RESULTS},
  {"cipher", required_argument, NULL, OPT_CIPHER},
  {"expert", no_argument, NULL, OPT_EXPERT},
  {"output", required_argument, NULL, OPT_OUTPUT},
  {"force", no_argument, NULL, OPT_FORCE},
  {"secret", no_argument, NULL, OPT_SECRET},
  {NULL, 0, NULL, 0},
};

/* list keys */
static bool
print_keys_info(rnp_cfg_t *cfg, cli_rnp_t *rnp, FILE *fp, const char *filter)
{
    list keys = NULL;
    int  keyc;
    bool psecret = rnp_cfg_getbool(cfg, CFG_SECRET);

    keys = cli_rnp_get_keylist(rnp, filter, psecret);
    if (!keys) {
        fprintf(fp, "Key(s) not found.\n");
        return false;
    }

    keyc = list_length(keys);
    fprintf(fp, "%d key%s found\n", keyc, (keyc == 1) ? "" : "s");

    for (list_item *ki = list_front(keys); ki; ki = list_next(ki)) {
        rnp_key_handle_t key = *((rnp_key_handle_t *) ki);
        cli_rnp_print_key_info(
          fp, rnp->ffi, key, psecret, rnp_cfg_getbool(cfg, CFG_WITH_SIGS));
    }

    fprintf(fp, "\n");
    /* clean up */
    cli_rnp_keylist_destroy(&keys);
    return true;
}

static bool
imported_key_changed(json_object *key)
{
    const char *pub = json_obj_get_str(key, "public");
    const char *sec = json_obj_get_str(key, "secret");

    if (pub && (!strcmp(pub, "updated") || !strcmp(pub, "new"))) {
        return true;
    }
    return sec && (!strcmp(pub, "updated") || !strcmp(pub, "new"));
}

static bool
import_keys(rnp_cfg_t *cfg, cli_rnp_t *rnp, const char *file)
{
    rnp_input_t input = NULL;
    bool        res = false;

    if (rnp_input_from_path(&input, file)) {
        (void) fprintf(stderr, "failed to open file %s\n", file);
        return false;
    }

    uint32_t     flags = RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS;
    char *       results = NULL;
    json_object *jso = NULL;
    json_object *keys = NULL;

    if (rnp_import_keys(rnp->ffi, input, flags, &results)) {
        (void) fprintf(stderr, "failed to import keys from file %s\n", file);
        goto done;
    }
    // print information about imported key(s)
    jso = json_tokener_parse(results);
    if (!jso || !json_object_object_get_ex(jso, "keys", &keys)) {
        (void) fprintf(stderr, "invalid key import result\n");
        goto done;
    }

    for (size_t idx = 0; idx < (size_t) json_object_array_length(keys); idx++) {
        json_object *    keyinfo = json_object_array_get_idx(keys, idx);
        rnp_key_handle_t key = NULL;
        if (!keyinfo || !imported_key_changed(keyinfo)) {
            continue;
        }
        const char *fphex = json_obj_get_str(keyinfo, "fingerprint");
        if (rnp_locate_key(rnp->ffi, "fingerprint", fphex, &key) || !key) {
            (void) fprintf(stderr, "failed to locate key with fingerprint %s\n", fphex);
            continue;
        }
        cli_rnp_print_key_info(stdout, rnp->ffi, key, true, false);
        rnp_key_handle_destroy(key);
    }

    // set default key if we didn't have one
    if (!rnp->defkey) {
        cli_rnp_set_default_key(rnp);
    }

    // save public and secret keyrings
    if (!cli_rnp_save_keyrings(rnp)) {
        (void) fprintf(stderr, "failed to save keyrings\n");
        goto done;
    }
    res = true;
done:
    json_object_put(jso);
    rnp_buffer_destroy(results);
    rnp_input_destroy(input);
    return res;
}

void
print_praise(void)
{
    (void) fprintf(stderr,
                   "%s\nAll bug reports, praise and chocolate, please, to:\n%s\n",
                   PACKAGE_STRING,
                   PACKAGE_BUGREPORT);
}

/* print a usage message */
void
print_usage(const char *usagemsg)
{
    print_praise();
    (void) fprintf(stderr, "Usage: %s %s", rnp_keys_progname, usagemsg);
}

/* do a command once for a specified file 'f' */
bool
rnp_cmd(rnp_cfg_t *cfg, cli_rnp_t *rnp, optdefs_t cmd, const char *f)
{
    const char *key;
    std::string fs;

    switch (cmd) {
    case CMD_LIST_KEYS:
        if (!f) {
            list *ids = NULL;
            if ((ids = rnp_cfg_getlist(cfg, CFG_USERID)) && list_length(*ids) > 0) {
                f = (fs = rnp_cfg_getlist_string(cfg, CFG_USERID, 0)).c_str();
            }
        }
        return print_keys_info(cfg, rnp, stdout, f);
    case CMD_EXPORT_KEY: {
        key = f;
        if (!key) {
            list *ids = NULL;
            if ((ids = rnp_cfg_getlist(cfg, CFG_USERID)) && list_length(*ids) > 0) {
                f = (fs = rnp_cfg_getlist_string(cfg, CFG_USERID, 0)).c_str();
            }
        }
        if (!key) {
            (void) fprintf(stderr, "key '%s' not found\n", f);
            return 0;
        }
        return cli_rnp_export_keys(cfg, rnp, key);
    }
    case CMD_IMPORT_KEY:
        if (f == NULL) {
            (void) fprintf(stderr, "import file isn't specified\n");
            return false;
        }
        return import_keys(cfg, rnp, f);
    case CMD_GENERATE_KEY: {
        if (f == NULL) {
            list *ids = NULL;
            if ((ids = rnp_cfg_getlist(cfg, CFG_USERID)) && list_length(*ids) > 0) {
                if (list_length(*ids) == 1) {
                    f = (fs = rnp_cfg_getlist_string(cfg, CFG_USERID, 0)).c_str();
                } else {
                    fprintf(stderr, "Only single userid is supported for generated keys\n");
                    return false;
                }
            }
        }
        return cli_rnp_generate_key(cfg, rnp, f);
    }
    case CMD_VERSION:
        print_praise();
        return true;
    case CMD_HELP:
    default:
        print_usage(usage);
        return false;
    }
}

/* set the option */
bool
setoption(rnp_cfg_t *cfg, optdefs_t *cmd, int val, const char *arg)
{
    bool ret = false;

    switch (val) {
    case OPT_COREDUMPS:
        ret = rnp_cfg_setbool(cfg, CFG_COREDUMPS, true);
        break;
    case CMD_GENERATE_KEY:
        ret = rnp_cfg_setbool(cfg, CFG_NEEDSSECKEY, true);
        *cmd = (optdefs_t) val;
        break;
    case OPT_EXPERT:
        ret = rnp_cfg_setbool(cfg, CFG_EXPERT, true);
        break;
    case CMD_LIST_KEYS:
    case CMD_EXPORT_KEY:
    case CMD_IMPORT_KEY:
    case CMD_HELP:
    case CMD_VERSION:
        *cmd = (optdefs_t) val;
        ret = true;
        break;
    /* options */
    case OPT_KEY_STORE_FORMAT:
        if (arg == NULL) {
            (void) fprintf(stderr, "No keyring format argument provided\n");
            break;
        }
        ret = rnp_cfg_setstr(cfg, CFG_KEYSTOREFMT, arg);
        break;
    case OPT_USERID:
        if (arg == NULL) {
            (void) fprintf(stderr, "no userid argument provided\n");
            break;
        }
        ret = rnp_cfg_addstr(cfg, CFG_USERID, arg);
        break;
    case OPT_VERBOSE:
        ret = rnp_cfg_setint(cfg, CFG_VERBOSE, rnp_cfg_getint(cfg, CFG_VERBOSE) + 1);
        break;
    case OPT_HOMEDIR:
        if (arg == NULL) {
            (void) fprintf(stderr, "no home directory argument provided\n");
            break;
        }
        ret = rnp_cfg_setstr(cfg, CFG_HOMEDIR, arg);
        break;
    case OPT_NUMBITS: {
        if (arg == NULL) {
            (void) fprintf(stderr, "no number of bits argument provided\n");
            break;
        }
        int bits = atoi(arg);
        if ((bits < 1024) || (bits > 16384)) {
            (void) fprintf(stderr, "wrong bits value: %s\n", arg);
            break;
        }
        ret = rnp_cfg_setint(cfg, CFG_NUMBITS, bits);
        break;
    }
    case OPT_HASH_ALG: {
        if (arg == NULL) {
            (void) fprintf(stderr, "No hash algorithm argument provided\n");
            break;
        }
        bool supported = false;
        if (rnp_supports_feature("hash algorithm", arg, &supported) || !supported) {
            (void) fprintf(stderr, "Unsupported hash algorithm: %s\n", arg);
            break;
        }
        ret = rnp_cfg_setstr(cfg, CFG_HASH, arg);
        break;
    }
    case OPT_S2K_ITER: {
        if (arg == NULL) {
            (void) fprintf(stderr, "No s2k iteration argument provided\n");
            break;
        }
        int iterations = atoi(arg);
        if (!iterations) {
            (void) fprintf(stderr, "Wrong iterations value: %s\n", arg);
            break;
        }
        ret = rnp_cfg_setint(cfg, CFG_S2K_ITER, iterations);
        break;
    }
    case OPT_S2K_MSEC: {
        if (arg == NULL) {
            (void) fprintf(stderr, "No s2k msec argument provided\n");
            break;
        }
        int msec = atoi(arg);
        if (!msec) {
            (void) fprintf(stderr, "Invalid s2k msec value: %s\n", arg);
            break;
        }
        ret = rnp_cfg_setint(cfg, CFG_S2K_MSEC, atoi(arg));
        break;
    }
    case OPT_PASSWDFD:
        if (arg == NULL) {
            (void) fprintf(stderr, "no pass-fd argument provided\n");
            break;
        }
        ret = rnp_cfg_setstr(cfg, CFG_PASSFD, arg);
        break;
    case OPT_RESULTS:
        if (arg == NULL) {
            (void) fprintf(stderr, "No output filename argument provided\n");
            break;
        }
        ret = rnp_cfg_setstr(cfg, CFG_IO_RESS, arg);
        break;
    case OPT_FORMAT:
        ret = rnp_cfg_setstr(cfg, CFG_KEYFORMAT, arg);
        break;
    case OPT_CIPHER: {
        bool supported = false;
        if (rnp_supports_feature("symmetric algorithm", arg, &supported) || !supported) {
            (void) fprintf(stderr, "Unsupported symmetric algorithm: %s\n", arg);
            break;
        }
        ret = rnp_cfg_setstr(cfg, CFG_CIPHER, arg);
        break;
    }
    case OPT_DEBUG:
        ret = !rnp_enable_debug(arg);
        break;
    case OPT_OUTPUT:
        if (arg == NULL) {
            (void) fprintf(stderr, "No output filename argument provided\n");
            break;
        }
        ret = rnp_cfg_setstr(cfg, CFG_OUTFILE, arg);
        break;
    case OPT_FORCE:
        ret = rnp_cfg_setbool(cfg, CFG_FORCE, true);
        break;
    case OPT_SECRET:
        ret = rnp_cfg_setbool(cfg, CFG_SECRET, true);
        break;
    case OPT_WITH_SIGS:
        ret = rnp_cfg_setbool(cfg, CFG_WITH_SIGS, true);
        break;
    default:
        *cmd = CMD_HELP;
        ret = true;
        break;
    }
    return ret;
}

/* we have -o option=value -- parse, and process */
bool
parse_option(rnp_cfg_t *cfg, optdefs_t *cmd, const char *s)
{
#ifndef RNP_USE_STD_REGEX
    static regex_t opt;
    struct option *op;
    static int     compiled;
    regmatch_t     matches[10];
    char           option[128];
    char           value[128];

    if (!compiled) {
        compiled = 1;
        if (regcomp(&opt, "([^=]{1,128})(=(.*))?", REG_EXTENDED) != 0) {
            fprintf(stderr, "Can't compile regex\n");
            return false;
        }
    }
    if (regexec(&opt, s, 10, matches, 0) == 0) {
        (void) snprintf(option,
                        sizeof(option),
                        "%.*s",
                        (int) (matches[1].rm_eo - matches[1].rm_so),
                        &s[matches[1].rm_so]);
        if (matches[2].rm_so > 0) {
            (void) snprintf(value,
                            sizeof(value),
                            "%.*s",
                            (int) (matches[3].rm_eo - matches[3].rm_so),
                            &s[matches[3].rm_so]);
        } else {
            value[0] = 0x0;
        }
        for (op = options; op->name; op++) {
            if (strcmp(op->name, option) == 0) {
                return setoption(cfg, cmd, op->val, value);
            }
        }
    }
#else
    static std::regex re("([^=]{1,128})(=(.*))?", std::regex_constants::extended);
    std::string       input = s;
    std::smatch       result;

    if (std::regex_match(input, result, re)) {
        std::string option = result[1];
        std::string value;
        if (result.size() >= 4) {
            value = result[3];
        }
        for (struct option *op = options; op->name; op++) {
            if (strcmp(op->name, option.c_str()) == 0) {
                return setoption(cfg, cmd, op->val, value.c_str());
            }
        }
    }
#endif
    return false;
}

bool
rnpkeys_init(rnp_cfg_t *      cfg,
             cli_rnp_t *      rnp,
             const rnp_cfg_t *override_cfg,
             bool             is_generate_key)
{
    bool ret = true;

    rnp_cfg_init(cfg);

    rnp_cfg_load_defaults(cfg);
    rnp_cfg_setint(cfg, CFG_NUMBITS, DEFAULT_RSA_NUMBITS);
    rnp_cfg_setstr(cfg, CFG_IO_RESS, "<stdout>");
    rnp_cfg_setstr(cfg, CFG_KEYFORMAT, "human");
    rnp_cfg_copy(cfg, override_cfg);

    memset(rnp, '\0', sizeof(*rnp));

    if (!cli_cfg_set_keystore_info(cfg)) {
        ERR_MSG("fatal: cannot set keystore info");
        ret = false;
        goto end;
    }

    if (!cli_rnp_init(rnp, cfg)) {
        ERR_MSG("fatal: failed to initialize rnpkeys");
        ret = false;
        goto end;
    }

    if (!cli_rnp_load_keyrings(rnp, true) && !is_generate_key) {
        /* Keys mightn't loaded if this is a key generation step. */
        ERR_MSG("fatal: failed to load keys");
        ret = false;
        goto end;
    }

end:
    if (!ret) {
        rnp_cfg_free(cfg);
        cli_rnp_end(rnp);
    }
    return ret;
}
