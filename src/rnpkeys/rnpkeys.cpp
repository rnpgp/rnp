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
#include <regex.h>
#include <string.h>
#include <stdarg.h>
#include <rnp/rnp.h>
#include "crypto.h"
#include <rnp/rnp_def.h>
#include "pgp-key.h"
#include "../rnp/rnpcfg.h"
#include "rnpkeys.h"
#include <librepgp/stream-common.h>
#include <librepgp/stream-sig.h>
#include <librepgp/packet-show.h>
#include "utils.h"

extern char *__progname;

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

static list
rnp_get_keylist(rnp_key_store_t *keyring, const char *filter)
{
    list       result = NULL;
    pgp_key_t *key = NULL;

    if (!filter) {
        for (list_item *key = list_front(rnp_key_store_get_keys(keyring)); key;
             key = list_next(key)) {
            if (!list_append(&result, &key, sizeof(pgp_key_t *))) {
                goto error;
            }
        }

        return result;
    }

    while ((key = rnp_key_store_get_key_by_name(keyring, filter, key))) {
        if (!list_append(&result, &key, sizeof(pgp_key_t *))) {
            goto error;
        }
        if (pgp_key_is_subkey(key)) {
            continue;
        }
        /* add primary key's subkeys as well */
        for (size_t i = 0; i < pgp_key_get_subkey_count(key); i++) {
            const uint8_t *grip = pgp_key_get_subkey_grip(key, i);
            pgp_key_t *    subkey = grip ? rnp_key_store_get_key_by_grip(keyring, grip) : NULL;
            if (subkey && !list_append(&result, &subkey, sizeof(pgp_key_t *))) {
                goto error;
            }
        }
    }

    return result;
error:
    list_destroy(&result);
    return NULL;
}

/* list keys */
static bool
print_keys_info(rnp_cfg_t *cfg, rnp_t *rnp, FILE *fp, const char *filter)
{
    list             keys = NULL;
    int              keyc;
    rnp_key_store_t *keyring;

    keyring = rnp_cfg_getbool(cfg, CFG_SECRET) ? rnp->secring : rnp->pubring;
    keys = rnp_get_keylist(keyring, filter);
    if (!keys) {
        fprintf(fp, "Key(s) not found.\n");
        return false;
    }

    keyc = list_length(keys);
    fprintf(fp, "%d key%s found\n", keyc, (keyc == 1) ? "" : "s");

    for (list_item *ki = list_front(keys); ki; ki = list_next(ki)) {
        pgp_key_t *key = *((pgp_key_t **) ki);
        rnp_print_key_info(fp, keyring, key, rnp_cfg_getbool(cfg, CFG_WITH_SIGS));
    }

    fprintf(fp, "\n");
    /* clean up */
    list_destroy(&keys);
    return true;
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
rnp_cmd(rnp_cfg_t *cfg, rnp_t *rnp, optdefs_t cmd, const char *f)
{
    const char *key;
    char *      s;

    switch (cmd) {
    case CMD_LIST_KEYS:
        if (!f) {
            f = rnp_cfg_getstr(cfg, CFG_USERID);
        }
        return print_keys_info(cfg, rnp, stdout, f);
    case CMD_EXPORT_KEY: {
        pgp_dest_t   dst;
        rnp_result_t ret;

        if ((key = f) == NULL) {
            key = rnp_cfg_getstr(cfg, CFG_USERID);
        }

        if (!key) {
            RNP_LOG("key '%s' not found\n", f);
            return 0;
        }

        s = rnp_export_key(rnp, key, rnp_cfg_getbool(cfg, CFG_SECRET));
        if (!s) {
            return false;
        }

        const char *file = rnp_cfg_getstr(cfg, CFG_OUTFILE);
        bool        force = rnp_cfg_getbool(cfg, CFG_FORCE);
        ret = file ? init_file_dest(&dst, file, force) : init_stdout_dest(&dst);
        if (ret) {
            free(s);
            return false;
        }

        dst_write(&dst, s, strlen(s));
        dst_close(&dst, false);
        free(s);
        return true;
    }
    case CMD_IMPORT_KEY:
        if (f == NULL) {
            (void) fprintf(stderr, "import file isn't specified\n");
            return false;
        }
        return rnp_import_key(rnp, f);
    case CMD_GENERATE_KEY: {
        key = f ? f : rnp_cfg_getstr(cfg, CFG_USERID);
        rnp_action_keygen_t *        action = &rnp->action.generate_key_ctx;
        rnp_keygen_primary_desc_t *  primary_desc = &action->primary.keygen;
        rnp_key_protection_params_t *protection = &action->primary.protection;
        pgp_key_t *                  primary_key = NULL;
        pgp_key_t *                  subkey = NULL;

        memset(action, 0, sizeof(*action));
        /* setup key generation and key protection parameters */
        if (key) {
            strcpy((char *) primary_desc->cert.userid, key);
        }
        primary_desc->crypto.hash_alg = pgp_str_to_hash_alg(rnp_cfg_gethashalg(cfg));

        if (primary_desc->crypto.hash_alg == PGP_HASH_UNKNOWN) {
            fprintf(stderr, "Unknown hash algorithm: %s\n", rnp_cfg_getstr(cfg, CFG_HASH));
            return false;
        }

        primary_desc->crypto.rng = &rnp->rng;
        protection->hash_alg = primary_desc->crypto.hash_alg;
        protection->symm_alg = pgp_str_to_cipher(rnp_cfg_getstr(cfg, CFG_CIPHER));
        protection->iterations = rnp_cfg_getint(cfg, CFG_S2K_ITER);

        if (protection->iterations == 0) {
            protection->iterations = pgp_s2k_compute_iters(
              protection->hash_alg, rnp_cfg_getint(cfg, CFG_S2K_MSEC), 10);
        }

        action->subkey.keygen.crypto.rng = &rnp->rng;

        if (!rnp_cfg_getbool(cfg, CFG_EXPERT)) {
            primary_desc->crypto.key_alg = PGP_PKA_RSA;
            primary_desc->crypto.rsa.modulus_bit_len = rnp_cfg_getint(cfg, CFG_NUMBITS);
            // copy keygen crypto and protection from primary to subkey
            action->subkey.keygen.crypto = primary_desc->crypto;
            action->subkey.protection = *protection;
        } else if (rnp_generate_key_expert_mode(rnp, cfg) != RNP_SUCCESS) {
            RNP_LOG("Critical error: Key generation failed");
            return false;
        }

        /* generate key with/without subkey */
        RNP_MSG("Generating a new key...\n");
        if (!(primary_key = rnp_generate_key(rnp))) {
            return false;
        }
        /* show the primary key, use public key part */
        primary_key = rnp_key_store_get_key_by_fpr(rnp->pubring, pgp_key_get_fp(primary_key));
        if (!primary_key) {
            RNP_LOG("Cannot get public key part");
            return false;
        }
        rnp_print_key_info(stdout, rnp->pubring, primary_key, false);

        /* show the subkey if any */
        if (pgp_key_get_subkey_count(primary_key)) {
            subkey = pgp_key_get_subkey(primary_key, rnp->pubring, 0);
            if (!subkey) {
                RNP_LOG("Cannot find generated subkey");
                return false;
            }
            rnp_print_key_info(stdout, rnp->pubring, subkey, false);
        }
        return true;
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
setoption(rnp_cfg_t *cfg, optdefs_t *cmd, int val, char *arg)
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
        ret = rnp_cfg_setstr(cfg, CFG_USERID, arg);
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
    case OPT_NUMBITS:
        if (arg == NULL) {
            (void) fprintf(stderr, "no number of bits argument provided\n");
            break;
        }
        ret = rnp_cfg_setint(cfg, CFG_NUMBITS, atoi(arg));
        break;
    case OPT_HASH_ALG:
        if (arg == NULL) {
            (void) fprintf(stderr, "No hash algorithm argument provided\n");
            break;
        }
        ret = rnp_cfg_setstr(cfg, CFG_HASH, arg);
        break;
    case OPT_S2K_ITER:
        if (arg == NULL) {
            (void) fprintf(stderr, "No s2k iteration argument provided\n");
            break;
        }
        ret = rnp_cfg_setint(cfg, CFG_S2K_ITER, atoi(arg));
        break;
    case OPT_S2K_MSEC:
        if (arg == NULL) {
            (void) fprintf(stderr, "No s2k msec argument provided\n");
            break;
        }
        ret = rnp_cfg_setint(cfg, CFG_S2K_MSEC, atoi(arg));
        break;
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
    case OPT_CIPHER:
        ret = rnp_cfg_setstr(cfg, CFG_CIPHER, arg);
        break;
    case OPT_DEBUG:
        ret = rnp_set_debug(arg);
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
    return false;
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
    rnp_cfg_setstr(cfg, CFG_IO_RESS, "<stdout>");
    rnp_cfg_setstr(cfg, CFG_KEYFORMAT, "human");
    rnp_cfg_copy(cfg, override_cfg);

    memset(rnp, '\0', sizeof(rnp_t));

    if (!rnp_cfg_apply(cfg, &rnp_params)) {
        fputs("fatal: cannot apply configuration\n", stderr);
        ret = false;
        goto end;
    }

    if (rnp_init(rnp, &rnp_params) != RNP_SUCCESS) {
        fputs("fatal: failed to initialize rnpkeys\n", stderr);
        ret = false;
        goto end;
    }

    if (!rnp_load_keyrings(rnp, 1) && !is_generate_key) {
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
