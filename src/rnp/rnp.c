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
#include <sys/param.h>
#include <sys/stat.h>

#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <regex.h>
#include <rnp/rnp.h>
#include <rnp/rnp_sdk.h>
#include "rnpcfg.h"
#include "symmetric.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <rnp/rnp_obsolete_defs.h>
#include "rnpcfg.h"
#include <rekey/rnp_key_store.h>
#include <repgp/repgp.h>
#include <librepgp/stream-armor.h>

#include "hash.h"

extern char *__progname;

static const char *usage = "--help OR\n"
                           "\t--encrypt [--output=file] [options] files... OR\n"
                           "\t--decrypt [--output=file] [options] files... OR\n"
                           "\t--sign [--detach] [--hash=alg] [--output=file]\n"
                           "\t\t[options] files... OR\n"
                           "\t--verify [options] files... OR\n"
                           "\t--cat [--output=file] [options] files... OR\n"
                           "\t--clearsign [--output=file] [options] files... OR\n"
                           "\t--list-packets [options] OR\n"
                           "\t--dearmor [--output=file] file OR\n"
                           "\t--enarmor=<msg|pubkey|seckey|sign> \n"
                           "\t\t[--output=file] file OR\n"
                           "\t--version\n"
                           "where options are:\n"
                           "\t[--armor] AND/OR\n"
                           "\t[--cipher=<ciphername>] AND/OR\n"
                           "\t[--zip, --zlib, --bzip, -z 0..9] AND/OR\n"
                           "\t[--coredumps] AND/OR\n"
                           "\t[--homedir=<homedir>] AND/OR\n"
                           "\t[--keyring=<keyring>] AND/OR\n"
                           "\t[--keystore-format=<format>] AND/OR\n"
                           "\t[--numtries=<attempts>] AND/OR\n"
                           "\t[--userid=<userid>] AND/OR\n"
                           "\t[--maxmemalloc=<number of bytes>] AND/OR\n"
                           "\t[--verbose]\n";

enum optdefs {
    /* commands */
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
    CMD_SHOW_KEYS,
    CMD_VERSION,
    CMD_HELP,

    /* options */
    OPT_SSHKEYS,
    OPT_KEYRING,
    OPT_KEY_STORE_FORMAT,
    OPT_USERID,
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
    OPT_SSHKEYFILE,
    OPT_MAX_MEM_ALLOC,
    OPT_DURATION,
    OPT_BIRTHTIME,
    OPT_CIPHER,
    OPT_NUMTRIES,
    OPT_ZALG_ZIP,
    OPT_ZALG_ZLIB,
    OPT_ZALG_BZIP,
    OPT_ZLEVEL,
    OPT_OVERWRITE,

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
  {"show-keys", no_argument, NULL, CMD_SHOW_KEYS},
  {"showkeys", no_argument, NULL, CMD_SHOW_KEYS},
  /* options */
  {"ssh", no_argument, NULL, OPT_SSHKEYS},
  {"ssh-keys", no_argument, NULL, OPT_SSHKEYS},
  {"sshkeyfile", required_argument, NULL, OPT_SSHKEYFILE},
  {"coredumps", no_argument, NULL, OPT_COREDUMPS},
  {"keyring", required_argument, NULL, OPT_KEYRING},
  {"keystore-format", required_argument, NULL, OPT_KEY_STORE_FORMAT},
  {"userid", required_argument, NULL, OPT_USERID},
  {"home", required_argument, NULL, OPT_HOMEDIR},
  {"homedir", required_argument, NULL, OPT_HOMEDIR},
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
  {"password", required_argument, NULL, OPT_PASSWD},
  {"output", required_argument, NULL, OPT_OUTPUT},
  {"results", required_argument, NULL, OPT_RESULTS},
  {"maxmemalloc", required_argument, NULL, OPT_MAX_MEM_ALLOC},
  {"max-mem", required_argument, NULL, OPT_MAX_MEM_ALLOC},
  {"max-alloc", required_argument, NULL, OPT_MAX_MEM_ALLOC},
  {"from", required_argument, NULL, OPT_BIRTHTIME},
  {"birth", required_argument, NULL, OPT_BIRTHTIME},
  {"birthtime", required_argument, NULL, OPT_BIRTHTIME},
  {"creation", required_argument, NULL, OPT_BIRTHTIME},
  {"duration", required_argument, NULL, OPT_DURATION},
  {"expiry", required_argument, NULL, OPT_DURATION},
  {"cipher", required_argument, NULL, OPT_CIPHER},
  {"num-tries", required_argument, NULL, OPT_NUMTRIES},
  {"numtries", required_argument, NULL, OPT_NUMTRIES},
  {"attempts", required_argument, NULL, OPT_NUMTRIES},
  {"zip", no_argument, NULL, OPT_ZALG_ZIP},
  {"zlib", no_argument, NULL, OPT_ZALG_ZLIB},
  {"bzip", no_argument, NULL, OPT_ZALG_BZIP},
  {"bzip2", no_argument, NULL, OPT_ZALG_BZIP},
  {"overwrite", no_argument, NULL, OPT_OVERWRITE},

  {NULL, 0, NULL, 0},
};

static void
print_praise(void)
{
    fprintf(stderr,
            "%s\nAll bug reports, praise and chocolate, please, to:\n%s\n",
            rnp_get_info("version"),
            rnp_get_info("maintainer"));
}

/* print a usage message */
static void
print_usage(const char *usagemsg)
{
    print_praise();
    fprintf(stderr, "Usage: %s %s", __progname, usagemsg);
}

/* read all of stdin into memory */
static int
stdin_to_mem(rnp_cfg_t *cfg, char **temp, char **out, unsigned *maxsize)
{
    unsigned newsize;
    unsigned size;
    char     buf[BUFSIZ * 8];
    char *   loc;
    int      n;

    if (cfg) {
        *maxsize = (unsigned) rnp_cfg_getint(cfg, CFG_MAXALLOC);
    }

    size = 0;
    *temp = NULL;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        /* round up the allocation */
        newsize = size + ((n / BUFSIZ) + 1) * BUFSIZ;
        if (newsize > *maxsize) {
            fputs("bounds check\n", stderr);
            return size;
        }
        loc = realloc(*temp, newsize);
        if (loc == NULL) {
            fputs("short read\n", stderr);
            return size;
        }
        *temp = loc;
        memcpy(&(*temp)[size], buf, n);
        size += n;
    }
    if ((*out = calloc(1, *maxsize)) == NULL) {
        fputs("Bad alloc\n", stderr);
        return 0;
    }
    return (int) size;
}

/* output the text to stdout */
static bool
show_output(rnp_cfg_t *cfg, char *out, int size, const char *header)
{
    int         cc;
    int         n;
    int         flags;
    const char *outfile;
    int         fd = STDOUT_FILENO;

    if (size <= 0) {
        fprintf(stderr, "%s\n", header);
        return false;
    }

    if ((outfile = rnp_cfg_get(cfg, CFG_OUTFILE))) {
        flags = O_WRONLY | O_CREAT;
        if (rnp_cfg_getbool(cfg, CFG_OVERWRITE)) {
            flags |= O_TRUNC;
        } else {
            flags |= O_EXCL;
        }

        fd = open(outfile, flags, 0600);
        if (fd < 0) {
            fprintf(stderr, "Failed to write to the %s : %s.\n", outfile, strerror(errno));
            return RNP_FAIL;
        }
    }

    for (cc = 0; cc < size; cc += n) {
        if ((n = write(fd, &out[cc], size - cc)) <= 0) {
            if (n < 0) {
                fprintf(stderr, "Write failed: %s.\n", strerror(errno));
            }

            break;
        }
    }

    if (fd != STDOUT_FILENO) {
        close(fd);
    }

    if (cc < size) {
        fputs("Short write\n", stderr);
        return false;
    }
    return cc == size;
}

/* do a command once for a specified file 'f' */
static bool
rnp_cmd(rnp_cfg_t *cfg, rnp_t *rnp, int cmd, char *f)
{
    unsigned    maxsize;
    char *      out = NULL;
    char *      in = NULL;
    const char *userid = NULL;
    bool        ret = false;
    int         cc;
    int         sz;
    bool        clearsign = (cmd == CMD_CLEARSIGN);
    rnp_ctx_t   ctx = {0};
    // TODO: Probably something smarter should be done here
    repgp_io_t *io = repgp_create_io();

    if (io == NULL) {
        RNP_LOG("Allocation failed");
        return false;
    }

    /* checking userid for the upcoming operation */
    if (rnp_cfg_getbool(cfg, CFG_NEEDSUSERID)) {
        userid = rnp_cfg_get(cfg, CFG_USERID);

        if (!userid && rnp->defkey) {
            userid = rnp->defkey;
        }

        if (!userid) {
            fprintf(stderr, "user/key id is not available but required\n");
            ret = false;
            goto done;
        }
    }

    if (rnp_cfg_get(cfg, CFG_PASSWD)) {
        rnp->password_provider.callback = rnp_password_provider_string;
        rnp->password_provider.userdata = (void *) rnp_cfg_get(cfg, CFG_PASSWD);
    }

    /* operation context initialization: writing all additional parameters */
    rnp_ctx_init(&ctx, rnp);
    ctx.armor = rnp_cfg_getint(cfg, CFG_ARMOR);
    ctx.overwrite = rnp_cfg_getbool(cfg, CFG_OVERWRITE);
    if (f) {
        ctx.filename = strdup(rnp_filename(f));
        ctx.filemtime = rnp_filemtime(f);
    }
    if (userid) {
        list_append(&ctx.recipients, userid, strlen(userid) + 1);
    }
    rnp->pswdtries = rnp_cfg_get_pswdtries(cfg);

    switch (cmd) {
    case CMD_CLEARSIGN:
    case CMD_SIGN:
        ctx.halg = pgp_str_to_hash_alg(rnp_cfg_get(cfg, CFG_HASH));

        if (ctx.halg == PGP_HASH_UNKNOWN) {
            fprintf(stderr, "Unknown hash algorithm: %s\n", rnp_cfg_get(cfg, CFG_HASH));
            ret = false;
            break;
        }

        ctx.zalg = rnp_cfg_getint(cfg, CFG_ZALG);
        ctx.zlevel = rnp_cfg_getint(cfg, CFG_ZLEVEL);

        ctx.sigcreate = get_birthtime(rnp_cfg_get(cfg, CFG_BIRTHTIME));
        ctx.sigexpire = get_duration(rnp_cfg_get(cfg, CFG_DURATION));

        clearsign = (cmd == CMD_CLEARSIGN) ? true : false;

        if (f == NULL) {
            cc = stdin_to_mem(cfg, &in, &out, &maxsize);
            sz = rnp_sign_memory(&ctx, userid, in, cc, out, maxsize, clearsign);
            ret = show_output(cfg, out, sz, "Bad memory signature");
        } else {
            ret = rnp_sign_file(&ctx,
                                userid,
                                f,
                                rnp_cfg_get(cfg, CFG_OUTFILE),
                                clearsign,
                                rnp_cfg_getbool(cfg, CFG_DETACHED)) == RNP_OK;
        }
        break;
    case CMD_DECRYPT:
        ret = rnp_process_stream(&ctx, f, rnp_cfg_get(cfg, CFG_OUTFILE)) == RNP_SUCCESS;
        break;
    case CMD_SYM_ENCRYPT:
        ctx.ealg = pgp_str_to_cipher(rnp_cfg_get(cfg, CFG_CIPHER));
        ctx.halg = pgp_str_to_hash_alg(rnp_cfg_get(cfg, CFG_HASH));
        ret = rnp_encrypt_add_password(&ctx);
        if (ret) {
            RNP_LOG("Failed to add password");
            goto done;
        }
    /* FALLTHROUGH */
    case CMD_ENCRYPT: {
        ctx.ealg = pgp_str_to_cipher(rnp_cfg_get(cfg, CFG_CIPHER));
        ctx.zalg = rnp_cfg_getint(cfg, CFG_ZALG);
        ctx.zlevel = rnp_cfg_getint(cfg, CFG_ZLEVEL);
        ret = rnp_encrypt_stream(&ctx, f, rnp_cfg_get(cfg, CFG_OUTFILE)) == RNP_SUCCESS;
        break;
    }
    case CMD_VERIFY:
        ctx.discard = true;
        ret = rnp_process_stream(&ctx, f, NULL) == RNP_SUCCESS;
        break;
    case CMD_VERIFY_CAT:
        ret = rnp_process_stream(&ctx, f, rnp_cfg_get(cfg, CFG_OUTFILE)) == RNP_SUCCESS;
        break;
    case CMD_LIST_PACKETS: {
        repgp_handle_t *input = create_filepath_handle(f);
        if (input == NULL) {
            RNP_LOG("%s: No filename provided", __progname);
            ret = false;
            break;
        }
        ret = (RNP_SUCCESS == repgp_list_packets(&ctx, input, true));
        repgp_destroy_handle(input);
        break;
    }
    case CMD_DEARMOR:
        ret = rnp_armor_stream(&ctx, false, f, rnp_cfg_get(cfg, CFG_OUTFILE)) == RNP_SUCCESS;
        break;
    case CMD_ENARMOR:
        ctx.armortype = rnp_cfg_getint_default(cfg, CFG_ARMOR_DATA_TYPE, PGP_ARMORED_UNKNOWN);
        ret = rnp_armor_stream(&ctx, true, f, rnp_cfg_get(cfg, CFG_OUTFILE)) == RNP_SUCCESS;
        break;
    case CMD_SHOW_KEYS:
        ret = (repgp_validate_pubkeys_signatures(&ctx) == RNP_SUCCESS);
        break;
    default:
        print_usage(usage);
        exit(EXIT_SUCCESS);
    }

done:
    repgp_destroy_io(io);
    free(in);
    free(out);
    rnp_ctx_free(&ctx);

    return ret;
}

/* set an option */
static int
setoption(rnp_cfg_t *cfg, int *cmd, int val, char *arg)
{
    switch (val) {
    case OPT_COREDUMPS:
        rnp_cfg_setbool(cfg, CFG_COREDUMPS, true);
        break;
    case CMD_ENCRYPT:
        /* for encryption, we need a userid */
        rnp_cfg_setbool(cfg, CFG_NEEDSUSERID, true);
        *cmd = val;
        break;
    case CMD_SIGN:
    case CMD_CLEARSIGN:
        /* for signing, we need a userid and a seckey */
        rnp_cfg_setbool(cfg, CFG_NEEDSUSERID, true);
        rnp_cfg_setbool(cfg, CFG_NEEDSSECKEY, true);
        *cmd = val;
        break;
    case CMD_DECRYPT:
        /* for decryption, we need a seckey */
        rnp_cfg_setbool(cfg, CFG_NEEDSSECKEY, true);
        *cmd = val;
        break;
    case CMD_SYM_ENCRYPT:
    case CMD_VERIFY:
    case CMD_VERIFY_CAT:
    case CMD_LIST_PACKETS:
    case CMD_SHOW_KEYS:
        *cmd = val;
        break;
    case CMD_DEARMOR:
        *cmd = val;
        rnp_cfg_setint(cfg, CFG_KEYSTORE_DISABLED, 1);
        break;
    case CMD_ENARMOR: {
        pgp_armored_msg_t msgt = PGP_ARMORED_UNKNOWN;
        *cmd = val;

        if (arg) {
            if (!strncmp("msg", arg, strlen(arg))) {
                msgt = PGP_ARMORED_MESSAGE;
            } else if (!strncmp("pubkey", arg, strlen(arg))) {
                msgt = PGP_ARMORED_PUBLIC_KEY;
            } else if (!strncmp("seckey", arg, strlen(arg))) {
                msgt = PGP_ARMORED_SECRET_KEY;
            } else if (!strncmp("sign", arg, strlen(arg))) {
                msgt = PGP_ARMORED_SIGNATURE;
            } else {
                fprintf(stderr, "Wrong enarmor argument: %s\n", arg);
                exit(EXIT_ERROR);
            }
        }

        rnp_cfg_setint(cfg, CFG_ARMOR_DATA_TYPE, msgt);
        rnp_cfg_setint(cfg, CFG_KEYSTORE_DISABLED, 1);
        break;
    }
    case CMD_HELP:
        print_usage(usage);
        exit(EXIT_SUCCESS);
    case CMD_VERSION:
        print_praise();
        exit(EXIT_SUCCESS);
    /* options */
    case OPT_SSHKEYS:
        rnp_cfg_set(cfg, CFG_KEYSTOREFMT, RNP_KEYSTORE_SSH);
        break;
    case OPT_KEYRING:
        if (arg == NULL) {
            fputs("No keyring argument provided\n", stderr);
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
            fputs("No userid argument provided\n", stderr);
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_USERID, arg);
        break;
    case OPT_ARMOR:
        rnp_cfg_setint(cfg, CFG_ARMOR, 1);
        break;
    case OPT_DETACHED:
        rnp_cfg_setbool(cfg, CFG_DETACHED, true);
        break;
    case OPT_VERBOSE:
        rnp_cfg_setint(cfg, CFG_VERBOSE, rnp_cfg_getint(cfg, CFG_VERBOSE) + 1);
        break;
    case OPT_HOMEDIR:
        if (arg == NULL) {
            (void) fprintf(stderr, "No home directory argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_HOMEDIR, arg);

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
            (void) fprintf(stderr, "No pass-fd argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_PASSFD, arg);
        break;
    case OPT_PASSWD:
        if (arg == NULL) {
            (void) fprintf(stderr, "No password argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_PASSWD, arg);
        break;
    case OPT_OUTPUT:
        if (arg == NULL) {
            (void) fprintf(stderr, "No output filename argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_OUTFILE, arg);
        break;
    case OPT_RESULTS:
        if (arg == NULL) {
            (void) fprintf(stderr, "No output filename argument provided\n");
            exit(EXIT_ERROR);
        }
        rnp_cfg_set(cfg, CFG_RESULTS, arg);
        break;
    case OPT_SSHKEYFILE:
        rnp_cfg_set(cfg, CFG_KEYSTOREFMT, RNP_KEYSTORE_SSH);
        rnp_cfg_set(cfg, CFG_SSHKEYFILE, arg);
        break;
    case OPT_MAX_MEM_ALLOC:
        rnp_cfg_set(cfg, CFG_MAXALLOC, arg);
        break;
    case OPT_DURATION:
        rnp_cfg_set(cfg, CFG_DURATION, arg);
        break;
    case OPT_BIRTHTIME:
        rnp_cfg_set(cfg, CFG_BIRTHTIME, arg);
        break;
    case OPT_CIPHER:
        rnp_cfg_set(cfg, CFG_CIPHER, arg);
        break;
    case OPT_NUMTRIES:
        rnp_cfg_set(cfg, CFG_NUMTRIES, arg);
        break;
    case OPT_ZALG_ZIP:
        rnp_cfg_setint(cfg, CFG_ZALG, PGP_C_ZIP);
        break;
    case OPT_ZALG_ZLIB:
        rnp_cfg_setint(cfg, CFG_ZALG, PGP_C_ZLIB);
        break;
    case OPT_ZALG_BZIP:
        rnp_cfg_setint(cfg, CFG_ZALG, PGP_C_BZIP2);
        break;
    case OPT_OVERWRITE:
        rnp_cfg_setbool(cfg, CFG_OVERWRITE, true);
        break;
    case OPT_DEBUG:
        rnp_set_debug(arg);
        break;
    default:
        *cmd = CMD_HELP;
        break;
    }

    return RNP_OK;
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
        if (regcomp(&opt, "([^=]{1,128})(=(.*))?", REG_EXTENDED) != 0) {
            fprintf(stderr, "Can't compile regex\n");
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
                return setoption(cfg, cmd, op->val, value);
        }
    }
    return 0;
}

int
main(int argc, char **argv)
{
    rnp_params_t rnp_params = {0};
    rnp_t        rnp = {0};
    rnp_cfg_t    cfg;
    int          optindex;
    int          ret;
    int          cmd = 0;
    int          ch;
    int          i;

    if (argc < 2) {
        print_usage(usage);
        exit(EXIT_ERROR);
    }

    rnp_cfg_init(&cfg);
    rnp_cfg_load_defaults(&cfg);
    optindex = 0;

    /* TODO: These options should be set after initialising the context. */
    while ((ch = getopt_long(argc, argv, "S:Vdeco:svz:", options, &optindex)) != -1) {
        if (ch >= CMD_ENCRYPT) {
            /* getopt_long returns 0 for long options */
            if (!setoption(&cfg, &cmd, options[optindex].val, optarg)) {
                (void) fprintf(stderr, "Bad option\n");
            }
        } else {
            switch (ch) {
            case 'S':
                rnp_cfg_set(&cfg, CFG_KEYSTOREFMT, RNP_KEYSTORE_SSH);
                rnp_cfg_set(&cfg, CFG_SSHKEYFILE, optarg);
                break;
            case 'V':
                print_praise();
                exit(EXIT_SUCCESS);
            case 'd':
                /* for decryption, we need the seckey */
                rnp_cfg_setbool(&cfg, CFG_NEEDSSECKEY, true);
                cmd = CMD_DECRYPT;
                break;
            case 'e':
                /* for encryption, we need a userid */
                rnp_cfg_setbool(&cfg, CFG_NEEDSUSERID, true);
                cmd = CMD_ENCRYPT;
                break;
            case 'c':
                cmd = CMD_SYM_ENCRYPT;
                break;
            case 'o':
                if (!parse_option(&cfg, &cmd, optarg)) {
                    (void) fprintf(stderr, "Bad option\n");
                }
                break;
            case 's':
                /* for signing, we need a userid and a seckey */
                rnp_cfg_setbool(&cfg, CFG_NEEDSSECKEY, true);
                rnp_cfg_setbool(&cfg, CFG_NEEDSUSERID, true);
                cmd = CMD_SIGN;
                break;
            case 'v':
                cmd = CMD_VERIFY;
                break;
            case 'z':
                if ((strlen(optarg) != 1) || (optarg[0] < '0') || (optarg[0] > '9')) {
                    fprintf(stderr, "Bad compression level: %s. Should be 0..9\n", optarg);
                } else {
                    rnp_cfg_setint(&cfg, CFG_ZLEVEL, (int) (optarg[0] - '0'));
                }
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
        ret = EXIT_ERROR;
        goto finish;
    }

    if (rnp_init(&rnp, &rnp_params) != RNP_SUCCESS) {
        fputs("fatal: cannot initialise\n", stderr);
        ret = EXIT_ERROR;
        goto finish;
    }

    if (!rnp_params.keystore_disabled &&
        !rnp_key_store_load_keys(&rnp, rnp_cfg_getbool(&cfg, CFG_NEEDSSECKEY))) {
        fputs("fatal: failed to load keys\n", stderr);
        ret = EXIT_ERROR;
        goto finish;
    }

    /* now do the required action for each of the command line args */
    ret = EXIT_SUCCESS;
    if (optind == argc) {
        if (!rnp_cmd(&cfg, &rnp, cmd, NULL))
            ret = EXIT_FAILURE;
    } else {
        for (i = optind; i < argc; i++) {
            if (!rnp_cmd(&cfg, &rnp, cmd, argv[i])) {
                ret = EXIT_FAILURE;
            }
        }
    }

finish:
    rnp_params_free(&rnp_params);
    rnp_cfg_free(&cfg);
    rnp_end(&rnp);

    return ret;
}
