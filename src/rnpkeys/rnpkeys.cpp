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
#include "utils.h"

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
  {"list-sigs", no_argument, NULL, CMD_LIST_SIGS},
  {"find-key", optional_argument, NULL, CMD_FIND_KEY},
  {"export", no_argument, NULL, CMD_EXPORT_KEY},
  {"export-key", optional_argument, NULL, CMD_EXPORT_KEY},
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

/* vararg print function */
static void
p(FILE *fp, const char *s, ...)
{
    va_list args;

    va_start(args, s);
    while (s != NULL) {
        (void) fprintf(fp, "%s", s);
        s = va_arg(args, char *);
    }
    va_end(args);
}

/* print a JSON object to the FILE stream */
static void
pobj(FILE *fp, json_object *obj, int depth)
{
    unsigned i;

    if (obj == NULL) {
        RNP_LOG("No object found");
        return;
    }
    for (i = 0; i < (unsigned) depth; i++) {
        p(fp, " ", NULL);
    }
    switch (json_object_get_type(obj)) {
    case json_type_null:
        p(fp, "null", NULL);
    case json_type_boolean:
        p(fp, json_object_get_boolean(obj) ? "true" : "false", NULL);
        break;
    case json_type_int:
        fprintf(fp, "%d", json_object_get_int(obj));
        break;
    case json_type_string:
        fprintf(fp, "%s", json_object_get_string(obj));
        break;
    case json_type_array: {
        int arrsize = json_object_array_length(obj);
        int i;
        for (i = 0; i < arrsize; i++) {
            json_object *item = json_object_array_get_idx(obj, i);
            pobj(fp, item, depth + 1);
            if (i < arrsize - 1) {
                (void) fprintf(fp, ", ");
            }
        }
        (void) fprintf(fp, "\n");
        break;
    }
    case json_type_object: {
        json_object_object_foreach(obj, key, val)
        {
            printf("key: \"%s\"\n", key);
            pobj(fp, val, depth + 1);
        }
        p(fp, "\n", NULL);
        break;
    }
    default:
        break;
    }
}

/* return the time as a string */
static char *
ptimestr(char *dest, size_t size, time_t t)
{
    struct tm *tm;

    tm = gmtime(&t);
    (void) snprintf(
      dest, size, "%04d-%02d-%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    return dest;
}

/* format a JSON object */
static void
format_json_key(FILE *fp, json_object *obj, const int psigs)
{
    int64_t creation;
    int64_t expiration;
    time_t  now;
    char    tbuf[32];

    RNP_DLOG("json is '%s'", json_object_to_json_string(obj));
#if 0 //?
    if (obj->c == 2 && obj->value.v[1].type == MJ_STRING &&
        strcmp(obj->value.v[1].value.s, "[REVOKED]") == 0) {
        /* whole key has been rovoked - just return */
        return;
    }
#endif
    json_object *tmp;
    if (json_object_object_get_ex(obj, "header", &tmp)) {
        if (strcmp(json_object_get_string(tmp), "sub") != 0) {
            p(fp, "\n", NULL);
        }
        pobj(fp, tmp, 0);
        p(fp, "   ", NULL);
    }

    if (json_object_object_get_ex(obj, "key bits", &tmp)) {
        pobj(fp, tmp, 0);
        p(fp, "/", NULL);
    }

    if (json_object_object_get_ex(obj, "pka", &tmp)) {
        pobj(fp, tmp, 0);
        p(fp, " ", NULL);
    }

    if (json_object_object_get_ex(obj, "key id", &tmp)) {
        pobj(fp, tmp, 0);
    }

    if (json_object_object_get_ex(obj, "creation time", &tmp)) {
        creation = (int64_t) strtoll(json_object_get_string(tmp), NULL, 10);
        p(fp, " ", ptimestr(tbuf, sizeof(tbuf), creation), NULL);

        if (json_object_object_get_ex(obj, "usage", &tmp)) {
            p(fp, " [", NULL);
            int count = json_object_array_length(tmp);
            for (int i = 0; i < count; i++) {
                json_object *str = json_object_array_get_idx(tmp, i);
                char         buff[2] = {0};
                buff[0] = toupper(*json_object_get_string(str));
                p(fp, buff, NULL);
            }
            p(fp, "]", NULL);
        }

        if (json_object_object_get_ex(obj, "expiration", &tmp)) {
            expiration = (int64_t) strtoll(json_object_get_string(tmp), NULL, 10);
            if (expiration > 0) {
                now = time(NULL);
                p(fp,
                  " ",
                  (creation + expiration < now) ? "[EXPIRED " : "[EXPIRES ",
                  ptimestr(tbuf, sizeof(tbuf), creation + expiration),
                  "]",
                  NULL);
            }
        }
    }

    if (json_object_object_get_ex(obj, "fingerprint", &tmp)) {
        p(fp, "\n", "      ", NULL);
        pobj(fp, tmp, 0);
        p(fp, "\n", NULL);
    }

    if (json_object_object_get_ex(obj, "user ids", &tmp) &&
        !json_object_is_type(tmp, json_type_null)) {
        int count = json_object_array_length(tmp);
        for (int i = 0; i < count; i++) {
            json_object *uidobj = json_object_array_get_idx(tmp, i);
            json_object *userid = NULL;

            json_object_object_get_ex(uidobj, "user id", &userid);
            p(fp, "uid", NULL);
            pobj(fp, userid, 11); /* human name */
            json_object *revoked = NULL;
            json_object_object_get_ex(uidobj, "revoked", &revoked);
            p(fp, json_object_get_boolean(revoked) ? "[REVOKED]" : "", NULL);
            p(fp, "\n", NULL);

            json_object *sig = NULL;
            json_object_object_get_ex(uidobj, "signature", &sig);
            if (sig && psigs) {
                json_object *signer_id = NULL;
                json_object *creation_time = NULL;
                json_object_object_get_ex(sig, "signer id", &signer_id);
                json_object_object_get_ex(sig, "creation time", &creation_time);
                json_object_object_get_ex(sig, "user id", &userid);
                if (signer_id && creation_time && userid) {
                    p(fp, "sig", NULL);
                    pobj(fp, signer_id, 11);
                    p(fp,
                      " ",
                      ptimestr(tbuf, sizeof(tbuf), json_object_get_int(creation_time)),
                      " ",
                      NULL);
                    pobj(fp, userid, 0);
                    p(fp, "\n", NULL);
                }
            }
        }
    }
}

/* print the json out on 'fp' */
static int
rnp_format_json(void *vp, const char *json, const int psigs)
{
    json_object *ids;
    FILE *       fp;
    int          idc;
    int          i;

    if ((fp = (FILE *) vp) == NULL || json == NULL) {
        return 0;
    }
    /* convert from string into a json structure */
    ids = json_tokener_parse(json);
    //    /* ids is an array of strings, each containing 1 entry */
    idc = json_object_array_length(ids);
    (void) fprintf(fp, "%d key%s found\n", idc, (idc == 1) ? "" : "s");
    for (i = 0; i < idc; i++) {
        json_object *item = json_object_array_get_idx(ids, i);
        ;
        format_json_key(fp, item, psigs);
    }
    fprintf(fp, "\n");
    /* clean up */
    json_object_put(ids);
    return idc;
}

static bool
rnp_key_store_json(const rnp_key_store_t *keyring, json_object *obj, const int psigs)
{
    for (list_item *key_item = list_front(rnp_key_store_get_keys(keyring)); key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *  key = (pgp_key_t *) key_item;
        json_object *jso = json_object_new_object();
        const char * header = NULL;
        if (pgp_key_is_secret(key)) { /* secret key is always shown as "sec" */
            header = "sec";
        } else if (pgp_key_is_primary_key(key)) { /* top-level public key */
            header = "pub";
        } else {
            header = "sub"; /* subkey */
        }
        repgp_sprint_json(keyring, key, jso, header, psigs);
        json_object_array_add(obj, jso);
    }
    return true;
}

/* list the keys in a keyring, returning a JSON encoded string */
static bool
rnp_list_keys_json(rnp_t *rnp, char **json, const int psigs)
{
    json_object *obj = json_object_new_array();

    if (!obj) {
        return false;
    }
    if (rnp->pubring == NULL) {
        RNP_LOG("No keyring");
        return false;
    }
    if (!rnp_key_store_json(rnp->pubring, obj, psigs)) {
        RNP_LOG("No keys in keyring");
        return false;
    }
    const char *j = json_object_to_json_string(obj);
    if (!j) {
        json_object_put(obj);
        return false;
    }
    *json = strdup(j);
    json_object_put(obj);
    return *json != NULL;
}

#ifndef HKP_VERSION
#define HKP_VERSION 1
#endif

/* find and list some keys in a keyring - return JSON string */
static int
rnp_match_keys_json(rnp_t *rnp, char **json, char *name, const char *fmt, const int psigs)
{
    int          ret = 1;
    pgp_key_t *  key = NULL;
    json_object *id_array = json_object_new_array();
    char *       newkey;
    // remove 0x prefix, if any
    if (name[0] == '0' && name[1] == 'x') {
        name += 2;
    }
    printf("%s,%d, NAME: %s\n", __FILE__, __LINE__, name);
    *json = NULL;
    do {
        key = rnp_key_store_get_key_by_name(rnp->pubring, name, key);
        if (!key) {
            return 0;
        }
        if (key != NULL) {
            if (strcmp(fmt, "mr") == 0) {
                pgp_hkp_sprint_key(rnp->pubring, key, &newkey, 0);
                if (newkey) {
                    printf("%s\n", newkey);
                    free(newkey);
                    newkey = NULL;
                }
            } else {
                json_object *obj = json_object_new_object();
                repgp_sprint_json(
                  rnp->pubring, key, obj, pgp_key_is_primary_key(key) ? "pub" : "sub", psigs);
                json_object_array_add(id_array, obj);
            }
        }
    } while (key != NULL);
    const char *j = json_object_to_json_string(id_array);
    *json = strdup(j);
    ret = strlen(j);
    json_object_put(id_array);
    return ret;
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
        if (rnp_match_keys_json(rnp, &json, f, rnp_cfg_getstr(cfg, CFG_KEYFORMAT), psigs) ==
            0) {
            return 0;
        }
    }
    idc = rnp_format_json(fp, json, psigs);
    /* clean up */
    free(json);
    return idc;
}

/* find and list some public keys in a keyring */
static int
rnp_match_pubkeys(rnp_t *rnp, char *name, void *vp)
{
    pgp_key_t *key = NULL;
    unsigned   k = 0;
    ssize_t    cc;
    char       out[1024 * 64];
    FILE *     fp = (FILE *) vp;

    do {
        key = rnp_key_store_get_key_by_name(rnp->pubring, name, key);
        if (!key) {
            return 0;
        }
        if (key != NULL) {
            cc = pgp_sprint_pubkey(key, out, sizeof(out));
            (void) fprintf(fp, "%.*s", (int) cc, out);
            k += 1;
        }
    } while (key != NULL);
    return k;
}

/* get a key in a keyring */
static char *
rnp_get_key(rnp_t *rnp, const char *name, const char *fmt)
{
    const pgp_key_t *key;
    char *           newkey;

    if ((key = resolve_userid(rnp, rnp->pubring, name)) == NULL) {
        return NULL;
    }
    if (strcmp(fmt, "mr") == 0) {
        return (pgp_hkp_sprint_key(rnp->pubring, key, &newkey, 0) > 0) ? newkey : NULL;
    }
    return (pgp_sprint_key(rnp->pubring, key, &newkey, "signature", 0) > 0) ? newkey : NULL;
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
            key = rnp_cfg_getstr(cfg, CFG_USERID);
        }
        return rnp_find_key(rnp, key);
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
        char *                       key_info = NULL;

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
        pgp_sprint_key(NULL, primary_key, &key_info, "pub", 0);
        (void) fprintf(stdout, "%s", key_info);
        free(key_info);

        /* show the subkey if any */
        if (pgp_key_get_subkey_count(primary_key)) {
            subkey = pgp_key_get_subkey(primary_key, rnp->pubring, 0);
            if (!subkey) {
                RNP_LOG("Cannot find generated subkey");
                return false;
            }
            pgp_sprint_key(NULL, subkey, &key_info, "sub", 0);
            (void) fprintf(stdout, "%s", key_info);
            free(key_info);
        }

        return true;
    }
    case CMD_GET_KEY: {
        char *keydesc = rnp_get_key(rnp, f, rnp_cfg_getstr(cfg, CFG_KEYFORMAT));
        if (keydesc) {
            printf("%s", keydesc);
            free(keydesc);
            return true;
        }
        (void) fprintf(stderr, "key '%s' not found\n", f);
        return false;
    }
    case CMD_TRUSTED_KEYS:
        return rnp_match_pubkeys(rnp, f, stdout);
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
    case CMD_LIST_SIGS:
    case CMD_FIND_KEY:
    case CMD_EXPORT_KEY:
    case CMD_IMPORT_KEY:
    case CMD_GET_KEY:
    case CMD_TRUSTED_KEYS:
    case CMD_HELP:
    case CMD_VERSION:
        *cmd = (optdefs_t) val;
        ret = true;
        break;
    /* options */
    case OPT_KEYRING:
        if (arg == NULL) {
            (void) fprintf(stderr, "No keyring argument provided\n");
            break;
        }
        ret = rnp_cfg_setstr(cfg, CFG_KEYRING, arg);
        break;
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
