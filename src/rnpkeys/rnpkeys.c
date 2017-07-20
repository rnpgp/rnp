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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
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
#include <regex.h>
#include <string.h>
#include "rnp.h"
#include "crypto.h"
#include "rnp_defs.h"
#include "../rnp/rnpcfg.h"
#include "rnpkeys.h"

extern char *__progname;

const char *usage = "--help OR\n"
                    "\t--export-key [options] OR\n"
                    "\t--find-key [options] OR\n"
                    "\t--generate-key [options] OR\n"
                    "\t--import-key [options] OR\n"
                    "\t--list-keys [options] OR\n"
                    "\t--list-sigs [options] OR\n"
                    "\t--trusted-keys [options] OR\n"
                    "\t--get-key keyid [options] OR\n"
                    "\t--version\n"
                    "where options are:\n"
                    "\t[--cipher=<cipher name>] AND/OR\n"
                    "\t[--coredumps] AND/OR\n"
                    "\t[--expert] AND/OR\n"
                    "\t[--hash=<hash alg>] AND/OR\n"
                    "\t[--homedir=<homedir>] AND/OR\n"
                    "\t[--keyring=<keyring>] AND/OR\n"
                    "\t[--keystore-format=<format>] AND/OR\n"
                    "\t[--userid=<userid>] AND/OR\n"
                    "\t[--verbose]\n";

struct option options[] = {
  /* key-management commands */
  {"list-keys", no_argument, NULL, CMD_LIST_KEYS},
  {"list-sigs", no_argument, NULL, CMD_LIST_SIGS},
  {"find-key", optional_argument, NULL, CMD_FIND_KEY},
  {"export", no_argument, NULL, CMD_EXPORT_KEY},
  {"export-key", no_argument, NULL, CMD_EXPORT_KEY},
  {"import", no_argument, NULL, CMD_IMPORT_KEY},
  {"import-key", no_argument, NULL, CMD_IMPORT_KEY},
  {"gen", optional_argument, NULL, CMD_GENERATE_KEY},
  {"gen-key", optional_argument, NULL, CMD_GENERATE_KEY},
  {"generate", optional_argument, NULL, CMD_GENERATE_KEY},
  {"generate-key", optional_argument, NULL, CMD_GENERATE_KEY},
  {"get-key", no_argument, NULL, CMD_GET_KEY},
  {"trusted-keys", optional_argument, NULL, CMD_TRUSTED_KEYS},
  {"trusted", optional_argument, NULL, CMD_TRUSTED_KEYS},
  /* debugging commands */
  {"help", no_argument, NULL, CMD_HELP},
  {"version", no_argument, NULL, CMD_VERSION},
  {"debug", required_argument, NULL, OPT_DEBUG},
  /* options */
  {"coredumps", no_argument, NULL, OPT_COREDUMPS},
  {"keyring", required_argument, NULL, OPT_KEYRING},
  {"keystore-format", required_argument, NULL, OPT_KEY_STORE_FORMAT},
  {"userid", required_argument, NULL, OPT_USERID},
  {"format", required_argument, NULL, OPT_FORMAT},
  {"hash-alg", required_argument, NULL, OPT_HASH_ALG},
  {"hash", required_argument, NULL, OPT_HASH_ALG},
  {"algorithm", required_argument, NULL, OPT_HASH_ALG},
  {"home", required_argument, NULL, OPT_HOMEDIR},
  {"homedir", required_argument, NULL, OPT_HOMEDIR},
  {"numbits", required_argument, NULL, OPT_NUMBITS},
  {"ssh", no_argument, NULL, OPT_SSHKEYS},
  {"ssh-keys", no_argument, NULL, OPT_SSHKEYS},
  {"sshkeyfile", required_argument, NULL, OPT_SSHKEYFILE},
  {"verbose", no_argument, NULL, OPT_VERBOSE},
  {"pass-fd", required_argument, NULL, OPT_PASSWDFD},
  {"results", required_argument, NULL, OPT_RESULTS},
  {"cipher", required_argument, NULL, OPT_CIPHER},
  {"expert", no_argument, NULL, OPT_EXPERT},
  {NULL, 0, NULL, 0},
};

/* match keys, decoding from json if we do find any */
static int
match_keys(rnp_cfg_t *cfg, rnp_t *rnp, FILE *fp, char *f, const int psigs)
{
    char *json = NULL;
    int   idc;

    if (f == NULL) {
        if (!rnp_list_keys_json(rnp, &json, psigs)) {
            return 0;
        }
    } else {
        if (rnp_match_keys_json(rnp, &json, f, rnp_cfg_get(cfg, CFG_KEYFORMAT), psigs) == 0) {
            return 0;
        }
    }
    idc = rnp_format_json(fp, json, psigs);
    /* clean up */
    free(json);
    return idc;
}

void
print_praise(void)
{
    (void) fprintf(stderr,
                   "%s\nAll bug reports, praise and chocolate, please, to:\n%s\n",
                   rnp_get_info("version"),
                   rnp_get_info("maintainer"));
}

/* print a usage message */
void
print_usage(const char *usagemsg)
{
    print_praise();
    (void) fprintf(stderr, "Usage: %s %s", __progname, usagemsg);
}

/* do a command once for a specified file 'f' */
bool
rnp_cmd(rnp_cfg_t *cfg, rnp_t *rnp, optdefs_t cmd, char *f)
{
    const char *key;
    char *      s;

    switch (cmd) {
    case CMD_LIST_KEYS:
    case CMD_LIST_SIGS:
        return match_keys(cfg, rnp, stdout, f, cmd == CMD_LIST_SIGS);
    case CMD_FIND_KEY:
        if ((key = f) == NULL) {
            key = rnp_cfg_get(cfg, CFG_USERID);
        }
        return rnp_find_key(rnp, key);
    case CMD_EXPORT_KEY:
        if ((key = f) == NULL) {
            key = rnp_cfg_get(cfg, CFG_USERID);
        }
        if (key) {
            if ((s = rnp_export_key(rnp, key)) != NULL) {
                printf("%s", s);
                return true;
            }
        }
        (void) fprintf(stderr, "key '%s' not found\n", f);
        return 0;
    case CMD_IMPORT_KEY:
        if (f == NULL) {
            (void) fprintf(stderr, "import file isn't specified\n");
            return false;
        }
        return rnp_import_key(rnp, f);
    case CMD_GENERATE_KEY:
        key = f ? f : rnp_cfg_get(cfg, CFG_USERID);
        rnp_keygen_desc_t *key_desc = &rnp->action.generate_key_ctx;
        key_desc->hash_alg = pgp_str_to_hash_alg(rnp_cfg_get(cfg, CFG_HASH));
        key_desc->sym_alg = pgp_str_to_cipher(rnp_cfg_get(cfg, CFG_CIPHER));

        if (!rnp_cfg_getbool(cfg, CFG_EXPERT)) {
            key_desc->key_alg = PGP_PKA_RSA;
            key_desc->rsa.modulus_bit_len = rnp_cfg_getint(cfg, CFG_NUMBITS);
        } else if (rnp_generate_key_expert_mode(rnp) != PGP_E_OK) {
            RNP_LOG("Critical error: Key generation failed");
            return false;
        }
        return rnp_generate_key(rnp, key);
    case CMD_GET_KEY:
        key = rnp_get_key(rnp, f, rnp_cfg_get(cfg, CFG_KEYFORMAT));
        if (key) {
            printf("%s", key);
            return true;
        }
        (void) fprintf(stderr, "key '%s' not found\n", f);
        return false;
    case CMD_TRUSTED_KEYS:
        return rnp_match_pubkeys(rnp, f, stdout);
    case CMD_HELP:
    default:
        print_usage(usage);
        return false;
    }
}

/* set the option */
int
setoption(rnp_cfg_t *cfg, optdefs_t *cmd, int val, char *arg)
{
    switch (val) {
    case OPT_COREDUMPS:
        rnp_cfg_setbool(cfg, CFG_COREDUMPS, true);
        break;
    case CMD_GENERATE_KEY:
        rnp_cfg_setbool(cfg, CFG_NEEDSSECKEY, true);
        *cmd = val;
        break;
    case OPT_EXPERT:
        rnp_cfg_setbool(cfg, CFG_EXPERT, true);
        break;
    case CMD_LIST_KEYS:
    case CMD_LIST_SIGS:
    case CMD_FIND_KEY:
    case CMD_EXPORT_KEY:
    case CMD_IMPORT_KEY:
    case CMD_GET_KEY:
    case CMD_TRUSTED_KEYS:
    case CMD_HELP:
        *cmd = val;
        break;
    case CMD_VERSION:
        print_praise();
        exit(EXIT_SUCCESS);
    /* options */
    case OPT_SSHKEYS:
        rnp_cfg_set(cfg, CFG_KEYSTOREFMT, CFG_KEYSTORE_SSH);
        break;
    case OPT_KEYRING:
        if (arg == NULL) {
            (void) fprintf(stderr, "No keyring argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_KEYRING, arg);
        break;
    case OPT_KEY_STORE_FORMAT:
        if (arg == NULL) {
            (void) fprintf(stderr, "No keyring format argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_KEYSTOREFMT, arg);
        break;
    case OPT_USERID:
        if (arg == NULL) {
            (void) fprintf(stderr, "no userid argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_USERID, arg);
        break;
    case OPT_VERBOSE:
        rnp_cfg_setint(cfg, CFG_VERBOSE, rnp_cfg_getint(cfg, CFG_VERBOSE) + 1);
        break;
    case OPT_HOMEDIR:
        if (arg == NULL) {
            (void) fprintf(stderr, "no home directory argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_HOMEDIR, arg);
        break;
    case OPT_NUMBITS:
        if (arg == NULL) {
            (void) fprintf(stderr, "no number of bits argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_setint(cfg, CFG_NUMBITS, atoi(arg));
        break;
    case OPT_HASH_ALG:
        if (arg == NULL) {
            (void) fprintf(stderr, "No hash algorithm argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_HASH, arg);
        break;
    case OPT_PASSWDFD:
        if (arg == NULL) {
            (void) fprintf(stderr, "no pass-fd argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_PASSFD, arg);
        break;
    case OPT_RESULTS:
        if (arg == NULL) {
            (void) fprintf(stderr, "No output filename argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_IO_RESS, arg);
        break;
    case OPT_SSHKEYFILE:
        rnp_cfg_set(cfg, CFG_KEYSTOREFMT, CFG_KEYSTORE_SSH);
        rnp_cfg_set(cfg, CFG_SSHKEYFILE, arg);
        break;
    case OPT_FORMAT:
        rnp_cfg_set(cfg, CFG_KEYFORMAT, arg);
        break;
    case OPT_CIPHER:
        rnp_cfg_set(cfg, CFG_CIPHER, arg);
        break;
    case OPT_DEBUG:
        rnp_set_debug(arg);
        break;
    default:
        *cmd = CMD_HELP;
        break;
    }
    return true;
}

/* we have -o option=value -- parse, and process */
int
parse_option(rnp_cfg_t *cfg, optdefs_t *cmd, const char *s)
{
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
            return 0;
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
    return 0;
}

bool
rnpkeys_init(rnp_cfg_t *cfg, rnp_t *rnp, const rnp_cfg_t *override_cfg, bool is_generate_key)
{
    bool         ret = true;
    rnp_params_t rnp_params;

    rnp_params_init(&rnp_params);
    rnp_cfg_init(cfg);

    rnp_cfg_load_defaults(cfg);
    rnp_cfg_setint(cfg, CFG_NUMBITS, DEFAULT_RSA_NUMBITS);
    rnp_cfg_set(cfg, CFG_IO_RESS, "<stdout>");
    rnp_cfg_set(cfg, CFG_KEYFORMAT, "human");
    rnp_cfg_copy(cfg, override_cfg);

    if (!rnp_cfg_apply(cfg, &rnp_params)) {
        fputs("fatal: cannot apply configuration\n", stderr);
        ret = false;
        goto end;
    }

    memset(rnp, '\0', sizeof(rnp_t));
    if (!rnp_init(rnp, &rnp_params)) {
        fputs("fatal: failed to initialize rnpkeys\n", stderr);
        ret = false;
        goto end;
    }

    if (!rnp_key_store_load_keys(rnp, 1) && !is_generate_key) {
        /* Keys mightn't loaded if this is a key generation step. */
        fputs("fatal: failed to load keys\n", stderr);
        ret = false;
        goto end;
    }

end:
    rnp_params_free(&rnp_params);
    if (!ret) {
        rnp_cfg_free(cfg);
        rnp_end(rnp);
    }
    return ret;
}