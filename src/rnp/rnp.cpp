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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#ifdef _MSC_VER
#include "uniwin.h"
#else
#include <sys/param.h>
#include <unistd.h>
#include <getopt.h>
#endif
#include <fcntl.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <errno.h>

#include "fficli.h"
#include "logging.h"

#ifndef RNP_USE_STD_REGEX
#include <regex.h>
#else
#include <regex>
#endif

static const char *rnp_prog_name = NULL;

static const char *usage = "-h, --help OR\n"
                           "\t--encrypt [--output=file] [options] files... OR\n"
                           "\t-c, --symmetric [--output=file] [options] files...OR\n"
                           "\t--decrypt [--output=file] [options] files... OR\n"
                           "\t--sign [--detach] [--hash=alg] [--output=file]\n"
                           "\t\t[options] files... OR\n"
                           "\t--verify [options] files... OR\n"
                           "\t--cat [--output=file] [options] files... OR\n"
                           "\t--clearsign [--output=file] [options] files... OR\n"
                           "\t--list-packets [options] OR\n"
                           "\t--dearmor [--output=file] file OR\n"
                           "\t--enarmor=<msg|pubkey|seckey|sign> OR\n"
                           "\t--list-packets [--json] [--grips] [--mpi] [--raw] OR\n"
                           "\t\t[--output=file] file OR\n"
                           "\t--version\n"
                           "where options are:\n"
                           "\t[-r, --recipient] AND/OR\n"
                           "\t[--passwords] AND/OR\n"
                           "\t[--armor] AND/OR\n"
                           "\t[--cipher=<ciphername>] AND/OR\n"
                           "\t[--zip, --zlib, --bzip, -z 0..9] AND/OR\n"
                           "\t[--aead[=EAX, OCB]] AND/OR\n"
                           "\t[--aead-chunk-bits=0..56] AND/OR\n"
                           "\t[--coredumps] AND/OR\n"
                           "\t[--homedir=<homedir>] AND/OR\n"
                           "\t[-f, --keyfile=<path to key] AND/OR\n"
                           "\t[--keyring=<keyring>] AND/OR\n"
                           "\t[--keystore-format=<format>] AND/OR\n"
                           "\t[--numtries=<attempts>] AND/OR\n"
                           "\t[-u, --userid=<userid>] AND/OR\n"
                           "\t[--maxmemalloc=<number of bytes>] AND/OR\n"
                           "\t[--verbose]\n";

enum optdefs {
    /* Commands as they are get via CLI */
    CMD_ENCRYPT = 260,
    CMD_DECRYPT,
    CMD_SIGN,
    CMD_CLEARSIGN,
    CMD_VERIFY,
    CMD_VERIFY_CAT,
    CMD_SYM_ENCRYPT,
    CMD_DEARMOR,
    CMD_ENARMOR,
    CMD_LIST_PACKETS,
    CMD_VERSION,
    CMD_HELP,

    /* OpenPGP data processing commands. Sign/Encrypt/Decrypt mapped to these */
    CMD_PROTECT,
    CMD_PROCESS,

    /* Options */
    OPT_KEY_STORE_FORMAT,
    OPT_USERID,
    OPT_RECIPIENT,
    OPT_ARMOR,
    OPT_HOMEDIR,
    OPT_DETACHED,
    OPT_HASH_ALG,
    OPT_OUTPUT,
    OPT_RESULTS,
    OPT_VERBOSE,
    OPT_COREDUMPS,
    OPT_PASSWDFD,
    OPT_PASSWD,
    OPT_PASSWORDS,
    OPT_EXPIRATION,
    OPT_CREATION,
    OPT_CIPHER,
    OPT_NUMTRIES,
    OPT_ZALG_ZIP,
    OPT_ZALG_ZLIB,
    OPT_ZALG_BZIP,
    OPT_ZLEVEL,
    OPT_OVERWRITE,
    OPT_AEAD,
    OPT_AEAD_CHUNK,
    OPT_KEYFILE,
    OPT_JSON,
    OPT_GRIPS,
    OPT_MPIS,
    OPT_RAW,

    /* debug */
    OPT_DEBUG
};

#define EXIT_ERROR 2

static struct option options[] = {
  /* file manipulation commands */
  {"encrypt", no_argument, NULL, CMD_ENCRYPT},
  {"decrypt", no_argument, NULL, CMD_DECRYPT},
  {"sign", no_argument, NULL, CMD_SIGN},
  {"clearsign", no_argument, NULL, CMD_CLEARSIGN},
  {"verify", no_argument, NULL, CMD_VERIFY},
  {"cat", no_argument, NULL, CMD_VERIFY_CAT},
  {"vericat", no_argument, NULL, CMD_VERIFY_CAT},
  {"verify-cat", no_argument, NULL, CMD_VERIFY_CAT},
  {"verify-show", no_argument, NULL, CMD_VERIFY_CAT},
  {"verifyshow", no_argument, NULL, CMD_VERIFY_CAT},
  {"symmetric", no_argument, NULL, CMD_SYM_ENCRYPT},
  {"dearmor", no_argument, NULL, CMD_DEARMOR},
  {"enarmor", required_argument, NULL, CMD_ENARMOR},
  /* file listing commands */
  {"list-packets", no_argument, NULL, CMD_LIST_PACKETS},
  /* debugging commands */
  {"help", no_argument, NULL, CMD_HELP},
  {"version", no_argument, NULL, CMD_VERSION},
  {"debug", required_argument, NULL, OPT_DEBUG},
  /* options */
  {"coredumps", no_argument, NULL, OPT_COREDUMPS},
  {"keystore-format", required_argument, NULL, OPT_KEY_STORE_FORMAT},
  {"userid", required_argument, NULL, OPT_USERID},
  {"recipient", required_argument, NULL, OPT_RECIPIENT},
  {"home", required_argument, NULL, OPT_HOMEDIR},
  {"homedir", required_argument, NULL, OPT_HOMEDIR},
  {"keyfile", required_argument, NULL, OPT_KEYFILE},
  {"ascii", no_argument, NULL, OPT_ARMOR},
  {"armor", no_argument, NULL, OPT_ARMOR},
  {"armour", no_argument, NULL, OPT_ARMOR},
  {"detach", no_argument, NULL, OPT_DETACHED},
  {"detached", no_argument, NULL, OPT_DETACHED},
  {"hash-alg", required_argument, NULL, OPT_HASH_ALG},
  {"hash", required_argument, NULL, OPT_HASH_ALG},
  {"algorithm", required_argument, NULL, OPT_HASH_ALG},
  {"verbose", no_argument, NULL, OPT_VERBOSE},
  {"pass-fd", required_argument, NULL, OPT_PASSWDFD},
  {"password", required_argument, NULL, OPT_PASSWD},
  {"passwords", required_argument, NULL, OPT_PASSWORDS},
  {"output", required_argument, NULL, OPT_OUTPUT},
  {"results", required_argument, NULL, OPT_RESULTS},
  {"creation", required_argument, NULL, OPT_CREATION},
  {"expiration", required_argument, NULL, OPT_EXPIRATION},
  {"expiry", required_argument, NULL, OPT_EXPIRATION},
  {"cipher", required_argument, NULL, OPT_CIPHER},
  {"num-tries", required_argument, NULL, OPT_NUMTRIES},
  {"numtries", required_argument, NULL, OPT_NUMTRIES},
  {"attempts", required_argument, NULL, OPT_NUMTRIES},
  {"zip", no_argument, NULL, OPT_ZALG_ZIP},
  {"zlib", no_argument, NULL, OPT_ZALG_ZLIB},
  {"bzip", no_argument, NULL, OPT_ZALG_BZIP},
  {"bzip2", no_argument, NULL, OPT_ZALG_BZIP},
  {"overwrite", no_argument, NULL, OPT_OVERWRITE},
  {"aead", optional_argument, NULL, OPT_AEAD},
  {"aead-chunk-bits", required_argument, NULL, OPT_AEAD_CHUNK},
  {"json", no_argument, NULL, OPT_JSON},
  {"grips", no_argument, NULL, OPT_GRIPS},
  {"mpi", no_argument, NULL, OPT_MPIS},
  {"raw", no_argument, NULL, OPT_RAW},

  {NULL, 0, NULL, 0},
};

static void
print_praise(void)
{
    ERR_MSG("%s\nAll bug reports, praise and chocolate, please, to:\n%s",
            PACKAGE_STRING,
            PACKAGE_BUGREPORT);
}

/* print a usage message */
static void
print_usage(const char *usagemsg)
{
    print_praise();
    ERR_MSG("Usage: %s %s", rnp_prog_name, usagemsg);
}

/* do a command once for a specified config */
static bool
rnp_cmd(cli_rnp_t *rnp)
{
    bool ret = false;

    switch (cli_rnp_cfg(*rnp).get_int(CFG_COMMAND)) {
    case CMD_PROTECT:
        ret = cli_rnp_protect_file(rnp);
        break;
    case CMD_PROCESS:
        ret = cli_rnp_process_file(rnp);
        break;
    case CMD_LIST_PACKETS:
        ret = cli_rnp_dump_file(rnp);
        break;
    case CMD_DEARMOR:
        ret = cli_rnp_dearmor_file(rnp);
        break;
    case CMD_ENARMOR:
        ret = cli_rnp_armor_file(rnp);
        break;
    case CMD_VERSION:
        print_praise();
        ret = true;
        break;
    default:
        print_usage(usage);
        ret = true;
    }

    return ret;
}

static bool
setcmd(rnp_cfg &cfg, int cmd, const char *arg)
{
    int newcmd = cmd;

    /* set file processing command to one of PROTECT or PROCESS */
    switch (cmd) {
    case CMD_ENCRYPT:
        cfg.set_bool(CFG_ENCRYPT_PK, true);
        if (cfg.get_bool(CFG_ENCRYPT_SK)) {
            cfg.set_bool(CFG_KEYSTORE_DISABLED, false);
        }
        newcmd = CMD_PROTECT;
        break;
    case CMD_SYM_ENCRYPT:
        cfg.set_bool(CFG_ENCRYPT_SK, true);
        if (!cfg.get_bool(CFG_ENCRYPT_PK) && !cfg.get_bool(CFG_SIGN_NEEDED)) {
            cfg.set_bool(CFG_KEYSTORE_DISABLED, true);
        }
        newcmd = CMD_PROTECT;
        break;
    case CMD_CLEARSIGN:
        cfg.set_bool(CFG_CLEARTEXT, true);
    /* FALLTHROUGH */
    case CMD_SIGN:
        cfg.set_bool(CFG_NEEDSSECKEY, true);
        cfg.set_bool(CFG_SIGN_NEEDED, true);
        if (cfg.get_bool(CFG_ENCRYPT_SK)) {
            cfg.set_bool(CFG_KEYSTORE_DISABLED, false);
        }
        newcmd = CMD_PROTECT;
        break;
    case CMD_DECRYPT:
        /* for decryption, we probably need a seckey */
        cfg.set_bool(CFG_NEEDSSECKEY, true);
        newcmd = CMD_PROCESS;
        break;
    case CMD_VERIFY:
        /* single verify will discard output, decrypt will not */
        cfg.set_bool(CFG_NO_OUTPUT, true);
    /* FALLTHROUGH */
    case CMD_VERIFY_CAT:
        newcmd = CMD_PROCESS;
        break;
    case CMD_LIST_PACKETS:
        cfg.set_bool(CFG_KEYSTORE_DISABLED, true);
        break;
    case CMD_DEARMOR:
        cfg.set_bool(CFG_KEYSTORE_DISABLED, true);
        break;
    case CMD_ENARMOR: {
        std::string msgt = "";

        if (arg) {
            msgt = arg;
            if (msgt == "msg") {
                msgt = "message";
            } else if (msgt == "pubkey") {
                msgt = "public key";
            } else if (msgt == "seckey") {
                msgt = "secret key";
            } else if (msgt == "sign") {
                msgt = "signature";
            } else {
                ERR_MSG("Wrong enarmor argument: %s", arg);
                return false;
            }
        }

        if (!msgt.empty()) {
            cfg.set_str(CFG_ARMOR_DATA_TYPE, msgt);
        }
        cfg.set_bool(CFG_KEYSTORE_DISABLED, true);
        break;
    }
    case CMD_HELP:
    case CMD_VERSION:
        break;
    default:
        newcmd = CMD_HELP;
        break;
    }

    cfg.set_int(CFG_COMMAND, newcmd);
    return true;
}

/* set an option */
static bool
setoption(rnp_cfg &cfg, int val, const char *arg)
{
    switch (val) {
    /* redirect commands to setcmd */
    case CMD_ENCRYPT:
    case CMD_SIGN:
    case CMD_CLEARSIGN:
    case CMD_DECRYPT:
    case CMD_SYM_ENCRYPT:
    case CMD_VERIFY:
    case CMD_VERIFY_CAT:
    case CMD_LIST_PACKETS:
    case CMD_DEARMOR:
    case CMD_ENARMOR:
    case CMD_HELP:
    case CMD_VERSION:
        return setcmd(cfg, val, arg);
    /* options */
    case OPT_COREDUMPS:
        cfg.set_bool(CFG_COREDUMPS, true);
        return true;
    case OPT_KEY_STORE_FORMAT:
        if (!arg) {
            ERR_MSG("No keyring format argument provided");
            return false;
        }
        cfg.set_str(CFG_KEYSTOREFMT, arg);
        return true;
    case OPT_USERID:
        if (!arg) {
            ERR_MSG("No userid argument provided");
            return false;
        }
        cfg.add_str(CFG_SIGNERS, arg);
        return true;
    case OPT_RECIPIENT:
        if (!arg) {
            ERR_MSG("No recipient argument provided");
            return false;
        }
        cfg.add_str(CFG_RECIPIENTS, arg);
        return true;
    case OPT_ARMOR:
        cfg.set_bool(CFG_ARMOR, true);
        return true;
    case OPT_DETACHED:
        cfg.set_bool(CFG_DETACHED, true);
        return true;
    case OPT_VERBOSE:
        cfg.set_int(CFG_VERBOSE, cfg.get_int(CFG_VERBOSE) + 1);
        return true;
    case OPT_HOMEDIR:
        if (!arg) {
            ERR_MSG("No home directory argument provided");
            return false;
        }
        cfg.set_str(CFG_HOMEDIR, arg);
        return true;
    case OPT_KEYFILE:
        if (!arg) {
            ERR_MSG("No keyfile argument provided");
            return false;
        }
        cfg.set_str(CFG_KEYFILE, arg);
        cfg.set_bool(CFG_KEYSTORE_DISABLED, true);
        return true;
    case OPT_HASH_ALG: {
        if (!arg) {
            ERR_MSG("No hash algorithm argument provided");
            return false;
        }
        bool supported = false;
        if (rnp_supports_feature(RNP_FEATURE_HASH_ALG, arg, &supported) || !supported) {
            ERR_MSG("Unsupported hash algorithm: %s", arg);
            return false;
        }
        cfg.set_str(CFG_HASH, arg);
        return true;
    }
    case OPT_PASSWDFD:
        if (!arg) {
            ERR_MSG("No pass-fd argument provided");
            return false;
        }
        cfg.set_str(CFG_PASSFD, arg);
        return true;
    case OPT_PASSWD:
        if (!arg) {
            ERR_MSG("No password argument provided");
            return false;
        }
        cfg.set_str(CFG_PASSWD, arg);
        return true;
    case OPT_PASSWORDS: {
        if (!arg) {
            ERR_MSG("You must provide a number with --passwords option");
            return false;
        }
        int count = atoi(arg);
        if (count <= 0) {
            ERR_MSG("Incorrect value for --passwords option: %s", arg);
            return false;
        }

        cfg.set_int(CFG_PASSWORDC, count);
        cfg.set_bool(CFG_ENCRYPT_SK, true);
        return true;
    }
    case OPT_OUTPUT:
        if (!arg) {
            ERR_MSG("No output filename argument provided");
            return false;
        }
        cfg.set_str(CFG_OUTFILE, arg);
        return true;
    case OPT_RESULTS:
        if (!arg) {
            ERR_MSG("No output filename argument provided");
            return false;
        }
        cfg.set_str(CFG_RESULTS, arg);
        return true;
    case OPT_EXPIRATION:
        cfg.set_str(CFG_EXPIRATION, arg);
        return true;
    case OPT_CREATION:
        cfg.set_str(CFG_CREATION, arg);
        return true;
    case OPT_CIPHER: {
        if (!arg) {
            ERR_MSG("No encryption algorithm argument provided");
            return false;
        }
        bool supported = false;
        if (rnp_supports_feature(RNP_FEATURE_SYMM_ALG, arg, &supported) || !supported) {
            ERR_MSG("Warning, unsupported encryption algorithm: %s", arg);
            arg = DEFAULT_SYMM_ALG;
        }
        cfg.set_str(CFG_CIPHER, arg);
        return true;
    }
    case OPT_NUMTRIES:
        cfg.set_str(CFG_NUMTRIES, arg);
        return true;
    case OPT_ZALG_ZIP:
        cfg.set_str(CFG_ZALG, "ZIP");
        return true;
    case OPT_ZALG_ZLIB:
        cfg.set_str(CFG_ZALG, "ZLib");
        return true;
    case OPT_ZALG_BZIP:
        cfg.set_str(CFG_ZALG, "BZip2");
        return true;
    case OPT_AEAD: {
        const char *alg = NULL;
        std::string argstr = arg ? arg : "";
        if (argstr.empty() || (argstr == "1") || rnp_casecmp(argstr, "eax")) {
            alg = "EAX";
        } else if ((argstr == "2") || rnp_casecmp(argstr, "ocb")) {
            alg = "OCB";
        } else {
            ERR_MSG("Wrong AEAD algorithm: %s", arg);
            return false;
        }
        cfg.set_str(CFG_AEAD, alg);
        return true;
    }
    case OPT_AEAD_CHUNK: {
        if (!arg) {
            ERR_MSG("Option aead-chunk-bits requires parameter");
            return false;
        }

        int bits = atoi(arg);
        if ((bits < 0) || (bits > 56)) {
            ERR_MSG("Wrong argument value %s for aead-chunk-bits", arg);
            return false;
        }
        cfg.set_int(CFG_AEAD_CHUNK, bits);
        return true;
    }
    case OPT_OVERWRITE:
        cfg.set_bool(CFG_OVERWRITE, true);
        return true;
    case OPT_JSON:
        cfg.set_bool(CFG_JSON, true);
        return true;
    case OPT_GRIPS:
        cfg.set_bool(CFG_GRIPS, true);
        return true;
    case OPT_MPIS:
        cfg.set_bool(CFG_MPIS, true);
        return true;
    case OPT_RAW:
        cfg.set_bool(CFG_RAW, true);
        return true;
    case OPT_DEBUG:
        return rnp_enable_debug(arg);
    default:
        return setcmd(cfg, CMD_HELP, arg);
    }

    return false;
}

/* we have -o option=value -- parse, and process */
static bool
parse_option(rnp_cfg &cfg, const char *s)
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
            ERR_MSG("Can't compile regex");
            return 0;
        }
    }
    if (regexec(&opt, s, 10, matches, 0) == 0) {
        snprintf(option,
                 sizeof(option),
                 "%.*s",
                 (int) (matches[1].rm_eo - matches[1].rm_so),
                 &s[matches[1].rm_so]);
        if (matches[2].rm_so > 0) {
            snprintf(value,
                     sizeof(value),
                     "%.*s",
                     (int) (matches[3].rm_eo - matches[3].rm_so),
                     &s[matches[3].rm_so]);
        } else {
            value[0] = 0x0;
        }
        for (op = options; op->name; op++) {
            if (strcmp(op->name, option) == 0)
                return setoption(cfg, op->val, value);
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
            if (strcmp(op->name, option.c_str()) == 0)
                return setoption(cfg, op->val, value.c_str());
        }
    }
#endif
    return 0;
}

#ifndef RNP_RUN_TESTS
int
main(int argc, char **argv)
#else
int rnp_main(int argc, char **argv);
int
rnp_main(int argc, char **argv)
#endif
{
    cli_rnp_t rnp = {};
    rnp_cfg   cfg;
    int       optindex;
    int       ret = EXIT_ERROR;
    int       ch;
    bool      disable_ks = false;

    rnp_prog_name = argv[0];

    if (argc < 2) {
        print_usage(usage);
        return EXIT_ERROR;
    }

#if !defined(RNP_RUN_TESTS) && defined(_WIN32)
    bool args_are_substituted = false;
    try {
        args_are_substituted = rnp_win_substitute_cmdline_args(&argc, &argv);
    } catch (std::exception &ex) {
        RNP_LOG("Error converting arguments ('%s')", ex.what());
        return EXIT_ERROR;
    }
#endif

    cfg.load_defaults();
    optindex = 0;

    /* TODO: These options should be set after initialising the context. */
    while ((ch = getopt_long(argc, argv, "S:Vdeco:r:su:vz:f:", options, &optindex)) != -1) {
        if (ch >= CMD_ENCRYPT) {
            /* getopt_long returns 0 for long options */
            if (!setoption(cfg, options[optindex].val, optarg)) {
                goto finish;
            }
        } else {
            int cmd = 0;
            switch (ch) {
            case 'V':
                cmd = CMD_VERSION;
                break;
            case 'd':
                cmd = CMD_DECRYPT;
                break;
            case 'e':
                cmd = CMD_ENCRYPT;
                break;
            case 'c':
                cmd = CMD_SYM_ENCRYPT;
                break;
            case 's':
                cmd = CMD_SIGN;
                break;
            case 'v':
                cmd = CMD_VERIFY;
                break;
            case 'o':
                if (!parse_option(cfg, optarg)) {
                    ERR_MSG("Bad option");
                    goto finish;
                }
                break;
            case 'r':
                if (strlen(optarg) < 1) {
                    ERR_MSG("Recipient should not be empty");
                } else {
                    cfg.add_str(CFG_RECIPIENTS, optarg);
                }
                break;
            case 'u':
                if (!optarg) {
                    ERR_MSG("No userid argument provided");
                    goto finish;
                }
                cfg.add_str(CFG_SIGNERS, optarg);
                break;
            case 'z':
                if ((strlen(optarg) != 1) || (optarg[0] < '0') || (optarg[0] > '9')) {
                    ERR_MSG("Bad compression level: %s. Should be 0..9", optarg);
                } else {
                    cfg.set_int(CFG_ZLEVEL, optarg[0] - '0');
                }
                break;
            case 'f':
                if (!optarg) {
                    ERR_MSG("No keyfile argument provided");
                    goto finish;
                }
                cfg.set_str(CFG_KEYFILE, optarg);
                cfg.set_bool(CFG_KEYSTORE_DISABLED, true);
                break;
            default:
                cmd = CMD_HELP;
                break;
            }

            if (cmd && !setcmd(cfg, cmd, optarg)) {
                goto finish;
            }
        }
    }

    switch (cfg.get_int(CFG_COMMAND)) {
    case CMD_HELP:
        print_usage(usage);
        ret = EXIT_SUCCESS;
        goto finish;
    case CMD_VERSION:
        print_praise();
        ret = EXIT_SUCCESS;
        goto finish;
    default:;
    }

    if (!cli_cfg_set_keystore_info(cfg)) {
        ERR_MSG("fatal: cannot set keystore info");
        goto finish;
    }

    if (!cli_rnp_init(&rnp, cfg)) {
        ERR_MSG("fatal: cannot initialise");
        goto finish;
    }

    disable_ks = cli_rnp_cfg(rnp).get_bool(CFG_KEYSTORE_DISABLED);
    if (!disable_ks &&
        !cli_rnp_load_keyrings(&rnp, cli_rnp_cfg(rnp).get_bool(CFG_NEEDSSECKEY))) {
        ERR_MSG("fatal: failed to load keys");
        goto finish;
    }

    /* load the keyfile if any */
    if (disable_ks && !cli_rnp_cfg(rnp).get_str(CFG_KEYFILE).empty() &&
        !cli_rnp_add_key(&rnp)) {
        ERR_MSG("fatal: failed to load key(s) from the file");
        goto finish;
    }

    if (!cli_rnp_setup(&rnp)) {
        goto finish;
    }

    /* now do the required action for each of the command line args */
    ret = EXIT_SUCCESS;
    if (optind == argc) {
        if (!rnp_cmd(&rnp))
            ret = EXIT_FAILURE;
    } else {
        for (int i = optind; i < argc; i++) {
            cli_rnp_cfg(rnp).set_str(CFG_INFILE, argv[i]);
            if (!rnp_cmd(&rnp)) {
                ret = EXIT_FAILURE;
            }
        }
    }
finish:
    cli_rnp_end(&rnp);
#if !defined(RNP_RUN_TESTS) && defined(_WIN32)
    if (args_are_substituted) {
        rnp_win_clear_args(argc, argv);
    }
#endif
    return ret;
}
