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
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <getopt.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rnp.h>
#include <crypto.h>

#include "../common/constants.h"
#include "../rnp/rnpcfg.h"

#define DEFAULT_RSA_NUMBITS 2048
#define DEFAULT_HASH_ALG "SHA256"

extern char *__progname;

static const char *usage = "--help OR\n"
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

enum optdefs {
    /* commands */
    CMD_LIST_KEYS = 260,
    CMD_LIST_SIGS,
    CMD_FIND_KEY,
    CMD_EXPORT_KEY,
    CMD_IMPORT_KEY,
    CMD_GENERATE_KEY,
    CMD_VERSION,
    CMD_HELP,
    CMD_GET_KEY,
    CMD_TRUSTED_KEYS,

    /* options */
    OPT_SSHKEYS,
    OPT_KEYRING,
    OPT_KEY_STORE_FORMAT,
    OPT_USERID,
    OPT_HOMEDIR,
    OPT_NUMBITS,
    OPT_HASH_ALG,
    OPT_VERBOSE,
    OPT_COREDUMPS,
    OPT_PASSWDFD,
    OPT_RESULTS,
    OPT_SSHKEYFILE,
    OPT_CIPHER,
    OPT_FORMAT,
    OPT_EXPERT,

    /* debug */
    OPT_DEBUG
};

#define EXIT_ERROR 2

static struct option options[] = {
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

static void
adjust_key_params(rnp_keygen_desc_t *key_desc, const char *hash_str, const char *symalg_str)
{
    switch (key_desc->key_alg) {
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
        key_desc->hash_alg = hash_str ? pgp_str_to_hash_alg(hash_str) :
                                        (key_desc->ecc.curve == PGP_CURVE_NIST_P_256) ?
                                        PGP_HASH_SHA256 :
                                        (key_desc->ecc.curve == PGP_CURVE_NIST_P_384) ?
                                        PGP_HASH_SHA384 :
                                        /*PGP_CURVE_NIST_P_521*/ PGP_HASH_SHA512;
        break;
    default:
        key_desc->hash_alg = hash_str ? pgp_str_to_hash_alg(hash_str) : PGP_HASH_SHA1;
    }

    key_desc->sym_alg = pgp_str_to_cipher(symalg_str);
}

pgp_errcode_t rnp_generate_key_expert_mode(rnp_t *rnp);

/* gather up program variables into one struct */
typedef struct prog_t {
    char keyring[MAXPATHLEN + 1]; /* name of keyring */
    int  numbits;                 /* # of bits */
    int  cmd;                     /* rnpkeys command */
} prog_t;

static void
print_praise(void)
{
    (void) fprintf(stderr,
                   "%s\nAll bug reports, praise and chocolate, please, to:\n%s\n",
                   rnp_get_info("version"),
                   rnp_get_info("maintainer"));
}

/* print a usage message */
static void
print_usage(const char *usagemsg)
{
    print_praise();
    (void) fprintf(stderr, "Usage: %s %s", __progname, usagemsg);
}

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

/* do a command once for a specified file 'f' */
static int
rnp_cmd(rnp_cfg_t *cfg, rnp_t *rnp, int cmd, char *f)
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
                return 1;
            }
        }
        (void) fprintf(stderr, "key '%s' not found\n", f);
        return 0;
    case CMD_IMPORT_KEY:
        if (f == NULL) {
            (void) fprintf(stderr, "import file isn't specified\n");
            return 0;
        }
        return rnp_import_key(rnp, f);
    case CMD_GENERATE_KEY:
        key = f ? f : rnp_cfg_get(cfg, CFG_USERID);
        rnp_keygen_desc_t *key_desc = &rnp->action.generate_key_ctx;
        if (rnp_cfg_getint(cfg, CFG_EXPERT)) {
            (void) rnp_generate_key_expert_mode(rnp);
        } else {
            key_desc->key_alg = PGP_PKA_RSA;
            key_desc->rsa.modulus_bit_len = rnp_cfg_getint(cfg, CFG_NUMBITS);
        }
        adjust_key_params(key_desc, rnp_cfg_get(cfg, CFG_HASH), rnp_cfg_get(cfg, CFG_CIPHER));
        return rnp_generate_key(rnp, key);
    case CMD_GET_KEY:
        key = rnp_get_key(rnp, f, rnp_cfg_get(cfg, CFG_KEYFORMAT));
        if (key) {
            printf("%s", key);
            return 1;
        }
        (void) fprintf(stderr, "key '%s' not found\n", f);
        return 0;
    case CMD_TRUSTED_KEYS:
        return rnp_match_pubkeys(rnp, f, stdout);
    case CMD_HELP:
    default:
        print_usage(usage);
        exit(EXIT_SUCCESS);
    }
}

/* set the option */
static int
setoption(rnp_cfg_t *cfg, int *cmd, int val, char *arg)
{
    switch (val) {
    case OPT_COREDUMPS:
        rnp_cfg_setint(cfg, CFG_COREDUMPS, 1);
        break;
    case CMD_GENERATE_KEY:
        rnp_cfg_setint(cfg, CFG_NEEDSSECKEY, 1);
        *cmd = val;
        break;
    case OPT_EXPERT:
        rnp_cfg_setint(cfg, CFG_EXPERT, 1);
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
    return 1;
}

/* we have -o option=value -- parse, and process */
static int
parse_option(rnp_cfg_t *cfg, int *cmd, const char *s)
{
    static regex_t opt;
    struct option *op;
    static int     compiled;
    regmatch_t     matches[10];
    char           option[128];
    char           value[128];

    if (!compiled) {
        compiled = 1;
        (void) regcomp(&opt, "([^=]{1,128})(=(.*))?", REG_EXTENDED);
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

int
main(int argc, char **argv)
{
    rnp_t        rnp;
    rnp_cfg_t    cfg;
    rnp_params_t rnp_params;
    int          cmd;
    int          optindex;
    int          ret;
    int          ch;
    int          i;

    if (argc < 2) {
        print_usage(usage);
        exit(EXIT_ERROR);
    }

    memset(&rnp, '\0', sizeof(rnp));
    memset(&rnp_params, '\0', sizeof(rnp_params));

    if (!rnp_cfg_init(&cfg)) {
        fputs("fatal: cannot initialise cfg\n", stderr);
        return EXIT_ERROR;
    }

    rnp_cfg_load_defaults(&cfg);
    rnp_cfg_setint(&cfg, CFG_NUMBITS, DEFAULT_RSA_NUMBITS);
    rnp_cfg_set(&cfg, CFG_IO_RESS, "<stdout>");
    rnp_cfg_set(&cfg, CFG_KEYFORMAT, "human");

    optindex = 0;

    while ((ch = getopt_long(argc, argv, "S:Vglo:s", options, &optindex)) != -1) {
        if (ch >= CMD_LIST_KEYS) {
            /* getopt_long returns 0 for long options */
            if (!setoption(&cfg, &cmd, options[optindex].val, optarg))
                fprintf(stderr, "Bad setoption result %d\n", ch);
        } else {
            switch (ch) {
            case 'S':
                rnp_cfg_set(&cfg, CFG_KEYSTOREFMT, CFG_KEYSTORE_SSH);
                rnp_cfg_set(&cfg, CFG_SSHKEYFILE, optarg);
                break;
            case 'V':
                print_praise();
                exit(EXIT_SUCCESS);
            case 'g':
                cmd = CMD_GENERATE_KEY;
                break;
            case 'l':
                cmd = CMD_LIST_KEYS;
                break;
            case 'o':
                if (!parse_option(&cfg, &cmd, optarg)) {
                    (void) fprintf(stderr, "Bad parse_option\n");
                }
                break;
            case 's':
                cmd = CMD_LIST_SIGS;
                break;
            default:
                cmd = CMD_HELP;
                break;
            }
        }
    }

    rnp_params_init(&rnp_params);
    if (!rnp_cfg_apply(&cfg, &rnp_params)) {
        fputs("fatal: cannot apply configuration\n", stderr);
        return EXIT_ERROR;
    }

    if (!rnp_init(&rnp, &rnp_params)) {
        fputs("fatal: failed to initialize rnpkeys\n", stderr);
        return EXIT_ERROR;
    }

    rnp_params_free(&rnp_params);

    if (!rnp_key_store_load_keys(&rnp, 1)) {
        /* Keys mightn't loaded if this is a key generation step. */
        if (cmd != CMD_GENERATE_KEY) {
            fputs("fatal: failed to load keys\n", stderr);
            return EXIT_ERROR;
        }
    }

    /* now do the required action for each of the command line args */
    ret = EXIT_SUCCESS;
    if (optind == argc) {
        if (!rnp_cmd(&cfg, &rnp, cmd, NULL))
            ret = EXIT_FAILURE;
    } else {
        for (i = optind; i < argc; i++) {
            if (!rnp_cmd(&cfg, &rnp, cmd, argv[i]))
                ret = EXIT_FAILURE;
        }
    }
    rnp_end(&rnp);

    return ret;
}
