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
#include "config.h"
#include <assert.h>

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: rnp.c,v 1.98 2016/06/28 16:34:40 christos Exp $");
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <stdbool.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include <rnp/rnp.h>
#include <rnp/rnp_def.h>
#include <rnp/rnp_sdk.h>
#include <rekey/rnp_key_store.h>

#include "pass-provider.h"
#include <repgp/repgp.h>
#include <librepgp/packet-print.h>
#include <librepgp/packet-show.h>
#include <librepgp/validate.h>
#include "errors.h"
#include "packet-create.h"
#include "memory.h"
#include "signature.h"
#include "readerwriter.h"
#include "utils.h"
#include "crypto.h"
#include "crypto/bn.h"
#include "defs.h"
#include <rnp/rnp_def.h>
#include "pgp-key.h"
#include "list.h"
#include <librepgp/stream-armour.h>
#include <librepgp/stream-parse.h>
#include <librepgp/stream-write.h>

#include "rnp/rnp_obsolete_defs.h"
#include <json.h>
#include <rnp.h>

/* small function to pretty print an 8-character raw userid */
static char *
userid_to_id(const uint8_t *userid, char *id)
{
    static const char *hexes = "0123456789abcdef";
    int                i;

    for (i = 0; i < 8; i++) {
        id[i * 2] = hexes[(unsigned) (userid[i] & 0xf0) >> 4];
        id[(i * 2) + 1] = hexes[userid[i] & 0xf];
    }
    id[8 * 2] = 0x0;
    return id;
}

/* print out the successful signature information */
static void
resultp(pgp_io_t *io, const char *f, pgp_validation_t *res, rnp_key_store_t *ring)
{
    const pgp_key_t *key;
    pgp_pubkey_t *   sigkey;
    unsigned         from;
    unsigned         i;
    time_t           t;
    char             id[MAX_ID_LENGTH + 1];

    for (i = 0; i < res->validc; i++) {
        (void) fprintf(io->res,
                       "Good signature for %s made %s",
                       (f) ? f : "<stdin>",
                       ctime(&res->valid_sigs[i].birthtime));
        if (res->duration > 0) {
            t = res->birthtime + res->duration;
            (void) fprintf(io->res, "Valid until %s", ctime(&t));
        }
        (void) fprintf(io->res,
                       "using %s key %s\n",
                       pgp_show_pka(res->valid_sigs[i].key_alg),
                       userid_to_id(res->valid_sigs[i].signer_id, id));
        from = 0;
        key = rnp_key_store_get_key_by_id(
          io, ring, (const uint8_t *) res->valid_sigs[i].signer_id, &from, &sigkey);
        repgp_print_key(io, ring, key, "signature ", &key->key.pubkey, 0);
    }
}

/* TODO: Make these const; currently their consumers don't preserve const. */

static bool
use_ssh_keys(rnp_t *rnp)
{
    return ((rnp_key_store_t *) rnp->secring)->format == SSH_KEY_STORE;
}

/* resolve the userid */
static pgp_key_t *
resolve_userid(rnp_t *rnp, const rnp_key_store_t *keyring, const char *userid)
{
    pgp_key_t *key;
    pgp_io_t * io;

    if (userid == NULL) {
        return NULL;
    } else if ((strlen(userid) > 1) && userid[0] == '0' && userid[1] == 'x') {
        userid += 2;
    }
    io = rnp->io;
    if (rnp_key_store_get_key_by_name(io, keyring, userid, &key) != RNP_OK) {
        (void) fprintf(io->errs, "cannot find key '%s'\n", userid);
    }
    return key;
}

/* return 1 if the file contains ascii-armoured text */
static int
isarmoured(const char *f, const void *memory, const char *text)
{
    regmatch_t matches[10];
    unsigned   armoured;
    regex_t    r;
    FILE *     fp;
    char       buf[BUFSIZ];

    armoured = 0;
    if (regcomp(&r, text, REG_EXTENDED) != 0) {
        RNP_LOG("Can't compile regex");
        return -1;
    }
    if (f) {
        if ((fp = fopen(f, "r")) == NULL) {
            RNP_LOG("isarmoured: cannot open '%s'", f);
            regfree(&r);
            return 0;
        }
        if (fgets(buf, (int) sizeof(buf), fp) != NULL) {
            if (regexec(&r, buf, 10, matches, 0) == 0) {
                armoured = 1;
            }
        }
        (void) fclose(fp);
    } else {
        if (memory && regexec(&r, memory, 10, matches, 0) == 0) {
            armoured = 1;
        }
    }
    regfree(&r);
    return armoured;
}

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
        (void) fprintf(stderr, "No object found\n");
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
    case json_type_array:;
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
    case json_type_object:;
        json_object_object_foreach(obj, key, val)
        {
            printf("key: \"%s\"\n", key);
            pobj(fp, val, depth + 1);
        }
        p(fp, "\n", NULL);
        break;
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
    int64_t birthtime;
    int64_t duration;
    time_t  now;
    char    tbuf[32];

    if (rnp_get_debug(__FILE__)) {
        (void) fprintf(stderr, "formatobj: json is '%s'\n", json_object_to_json_string(obj));
    }
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
        birthtime = (int64_t) strtoll(json_object_get_string(tmp), NULL, 10);
        p(fp, " ", ptimestr(tbuf, sizeof(tbuf), birthtime), NULL);

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

        if (json_object_object_get_ex(obj, "duration", &tmp)) {
            duration = (int64_t) strtoll(json_object_get_string(tmp), NULL, 10);
            if (duration > 0) {
                now = time(NULL);
                p(fp,
                  " ",
                  (birthtime + duration < now) ? "[EXPIRED " : "[EXPIRES ",
                  ptimestr(tbuf, sizeof(tbuf), birthtime + duration),
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

/* save a pgp pubkey to a temp file */
static bool
savepubkey(char *res, char *f, size_t size)
{
    size_t len;
    int    cc;
    int    wc;
    int    fd;

    (void) snprintf(f, size, "/tmp/pgp2ssh.XXXXXXX");
    if ((fd = mkstemp(f)) < 0) {
        (void) fprintf(stderr, "cannot create temp file '%s'\n", f);
        return false;
    }
    len = strlen(res);
    for (cc = 0; (wc = (int) write(fd, &res[cc], len - (size_t) cc)) > 0; cc += wc) {
    }
    (void) close(fd);
    return true;
}

/* format a uint32_t */
static int
formatu32(uint8_t *buffer, uint32_t value)
{
    buffer[0] = (uint8_t)(value >> 24) & 0xff;
    buffer[1] = (uint8_t)(value >> 16) & 0xff;
    buffer[2] = (uint8_t)(value >> 8) & 0xff;
    buffer[3] = (uint8_t) value & 0xff;
    return sizeof(uint32_t);
}

/* format a string as (len, string) */
static int
formatstring(char *buffer, const uint8_t *s, size_t len)
{
    int cc;

    cc = formatu32((uint8_t *) buffer, (uint32_t) len);
    (void) memcpy(&buffer[cc], s, len);
    return cc + (int) len;
}

/* format a bignum, checking for "interesting" high bit values */
static int
formatbignum(char *buffer, BIGNUM *bn)
{
    size_t   len;
    uint8_t *cp;
    int      cc;

    len = (size_t) BN_num_bytes(bn);
    if ((cp = calloc(1, len + 1)) == NULL) {
        (void) fprintf(stderr, "calloc failure in formatbignum\n");
        return 0;
    }
    (void) BN_bn2bin(bn, cp + 1);
    cp[0] = 0x0;
    cc =
      (cp[1] & 0x80) ? formatstring(buffer, cp, len + 1) : formatstring(buffer, &cp[1], len);
    free(cp);
    return cc;
}

/* find a subkey that includes any of the desired key flags */
static pgp_key_t *
find_suitable_subkey(const pgp_key_t *primary, uint8_t desired_usage)
{
    if (!primary || DYNARRAY_IS_EMPTY(primary, subkey)) {
        return NULL;
    }
    // search in reverse with the assumption that the last
    // in the list would be the newest created subkey, for now
    for (unsigned i = primary->subkeyc; i-- > 0;) {
        pgp_key_t *subkey = primary->subkeys[i];
        if (subkey->key_flags & desired_usage) {
            return subkey;
        }
    }
    return NULL;
}

#ifdef HAVE_SYS_RESOURCE_H

/* When system resource consumption limit controls are available this
 * can be used to attempt to disable core dumps which may leak
 * sensitive data.
 *
 * Returns 0 if disabling core dumps failed, returns 1 if disabling
 * core dumps succeeded, and returns -1 if an error occurred. errno
 * will be set to the result from setrlimit in the event of
 * failure.
 */
static int
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
            return -1;
        } else if (limit.rlim_cur == 0) {
            return RNP_OK; // disabling core dumps ok
        } else {
            return RNP_FAIL; // failed for some reason?
        }
    } else {
        return -1;
    }
}

#endif

static bool
set_pass_fd(rnp_t *rnp, int passfd)
{
    rnp->passfp = fdopen(passfd, "r");
    if (!rnp->passfp) {
        fprintf(rnp->io->errs, "cannot open fd %d for reading\n", passfd);
        return false;
    }
    return true;
}

/* Initialize a RNP context's io stream handles with a user-supplied
 * io struct. Returns 1 on success and 0 on failure. It is the caller's
 * responsibility to de-allocate a dynamically allocated io struct
 * upon failure.
 */
static bool
init_io(rnp_t *rnp, pgp_io_t *io, const char *outs, const char *errs, const char *ress)
{
    /* TODO: I think refactoring can go even further here. */

    /* Configure the output stream. */
    io->outs = stdout;
    if (outs && strcmp(outs, "<stderr>") == 0) {
        io->outs = stderr;
    }

    /* Configure the error stream. */
    io->errs = stderr;
    if (errs && strcmp(errs, "<stdout>") == 0) {
        io->errs = stdout;
    }

    /* Configure the results stream. */
    if (ress == NULL) {
        io->res = io->errs;
    } else if (strcmp(ress, "<stdout>") == 0) {
        io->res = stdout;
    } else if (strcmp(ress, "<stderr>") == 0) {
        io->res = stderr;
    } else {
        if ((io->res = fopen(ress, "w")) == NULL) {
            fprintf(io->errs, "cannot open results %s for writing\n", ress);
            return false;
        }
    }

    rnp->io = io;
    return true;
}

/* Allocate a new io struct and initialize a rnp context with it.
 * Returns 1 on success and 0 on failure.
 *
 * TODO: Set errno with a suitable error code.
 */
static bool
init_new_io(rnp_t *rnp, const char *outs, const char *errs, const char *ress)
{
    pgp_io_t *io = (pgp_io_t *) calloc(1, sizeof(*io));

    if (io != NULL) {
        if (init_io(rnp, io, outs, errs, ress))
            return true;
        free((void *) io);
    }

    return false;
}

/*************************************************************************/
/* exported functions start here                                         */
/*************************************************************************/

/* Initialize a rnp_t structure */
rnp_result_t
rnp_init(rnp_t *rnp, const rnp_params_t *params)
{
    int       coredumps = -1; /* -1 : cannot disable, 1 : disabled, 0 : enabled */
    pgp_io_t *io;

    /* If system resource constraints are in effect then attempt to
     * disable core dumps.
    */
    if (!params->enable_coredumps) {
#ifdef HAVE_SYS_RESOURCE_H
        coredumps = disable_core_dumps();
#endif
    } else {
        coredumps = 0;
    }

    if (coredumps == -1) {
        fputs("rnp: warning - cannot turn off core dumps\n", stderr);
    }
    if (coredumps != 1) {
        fputs("rnp: warning: core dumps enabled, sensitive data may be leaked to disk\n",
              stderr);
    }

    /* Initialize the context's io streams apparatus. */
    if (!init_new_io(rnp, params->outs, params->errs, params->ress)) {
        return RNP_ERROR_GENERIC;
    }
    io = rnp->io;

    // set the default passphrase provider
    rnp->passphrase_provider.callback = rnp_passphrase_provider_stdin;
    rnp->passphrase_provider.userdata = NULL;

    // setup file/pipe password input if requested
    if (params->passfd >= 0) {
        if (!set_pass_fd(rnp, params->passfd)) {
            return RNP_ERROR_GENERIC;
        }
        rnp->passphrase_provider.callback = rnp_passphrase_provider_file;
        rnp->passphrase_provider.userdata = rnp->passfp;
    }

    if (params->passphrase_provider.callback) {
        rnp->passphrase_provider = params->passphrase_provider;
    }

    if (params->userinputfd >= 0) {
        rnp->user_input_fp = fdopen(params->userinputfd, "r");
        if (!rnp->user_input_fp) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }

    rnp->pswdtries = MAX_PASSPHRASE_ATTEMPTS;

    /* set keystore type and pathes */
    rnp->pubring = rnp_key_store_new(params->ks_pub_format, params->pubpath);
    if (rnp->pubring == NULL) {
        fputs("rnp: can't create empty pubring keystore\n", io->errs);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp->secring = rnp_key_store_new(params->ks_sec_format, params->secpath);
    if (rnp->secring == NULL) {
        fputs("rnp: can't create empty secring keystore\n", io->errs);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    return RNP_SUCCESS;
}

/* finish off with the rnp_t struct */
void
rnp_end(rnp_t *rnp)
{
    if (rnp->pubring != NULL) {
        rnp_key_store_free(rnp->pubring);
        rnp->pubring = NULL;
    }
    if (rnp->secring != NULL) {
        rnp_key_store_free(rnp->secring);
        rnp->secring = NULL;
    }
    if (rnp->defkey) {
        free(rnp->defkey);
        rnp->defkey = NULL;
    }
    free(rnp->io);
}

/* rnp_params_t : initialize and free internals */
void
rnp_params_init(rnp_params_t *params)
{
    memset(params, '\0', sizeof(*params));
    params->passfd = -1;
    params->userinputfd = -1;
}

void
rnp_params_free(rnp_params_t *params)
{
    if (params->pubpath != NULL) {
        free(params->pubpath);
    }
    if (params->secpath != NULL) {
        free(params->secpath);
    }
    if (params->defkey != NULL) {
        free(params->defkey);
    }
}

/* rnp_ctx_t : init, reset, free internal pointers */
rnp_result_t
rnp_ctx_init(rnp_ctx_t *ctx, rnp_t *rnp)
{
    if (rnp == NULL) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    memset(ctx, '\0', sizeof(*ctx));
    ctx->rnp = rnp;
    return RNP_SUCCESS;
}

void
rnp_ctx_reset(rnp_ctx_t *ctx)
{
    rnp_ctx_free(ctx);
    memset(ctx, '\0', sizeof(*ctx));
}

/* free operation context */
void
rnp_ctx_free(rnp_ctx_t *ctx)
{
    free(ctx->filename);
}

/* list the keys in a keyring */
int
rnp_list_keys(rnp_t *rnp, const int psigs)
{
    if (rnp->pubring == NULL) {
        (void) fprintf(stderr, "No keyring\n");
        return RNP_FAIL;
    }
    return rnp_key_store_list(rnp->io, rnp->pubring, psigs);
}

/* list the keys in a keyring, returning a JSON encoded string */
int
rnp_list_keys_json(rnp_t *rnp, char **json, const int psigs)
{
    json_object *obj = json_object_new_array();
    int          ret;
    if (rnp->pubring == NULL) {
        (void) fprintf(stderr, "No keyring\n");
        return RNP_FAIL;
    }
    if (!rnp_key_store_json(rnp->io, rnp->pubring, obj, psigs)) {
        (void) fprintf(stderr, "No keys in keyring\n");
        return RNP_FAIL;
    }
    const char *j = json_object_to_json_string(obj);
    ret = j != NULL;
    *json = strdup(j);
    return ret ? RNP_OK : RNP_FAIL;
}

DEFINE_ARRAY(strings_t, char *);

#ifndef HKP_VERSION
#define HKP_VERSION 1
#endif

/* find and list some keys in a keyring */
int
rnp_match_keys(rnp_t *rnp, char *name, const char *fmt, void *vp, const int psigs)
{
    pgp_key_t *key;
    unsigned   k;
    strings_t  pubs;
    FILE *     fp = (FILE *) vp;

    if (name[0] == '0' && name[1] == 'x') {
        name += 2;
    }
    (void) memset(&pubs, 0x0, sizeof(pubs));
    k = 0;
    do {
        if (rnp_key_store_get_next_key_by_name(rnp->io, rnp->pubring, name, &k, &key) !=
            RNP_OK) {
            return 0;
        }
        if (key != NULL) {
            ALLOC(char *, pubs.v, pubs.size, pubs.c, 10, 10, "rnp_match_keys", return 0);
            if (strcmp(fmt, "mr") == 0) {
                pgp_hkp_sprint_key(
                  rnp->io, rnp->pubring, key, &pubs.v[pubs.c], &key->key.pubkey, psigs);
            } else {
                pgp_sprint_key(rnp->io,
                               rnp->pubring,
                               key,
                               &pubs.v[pubs.c],
                               "signature ",
                               &key->key.pubkey,
                               psigs);
            }
            if (pubs.v[pubs.c] != NULL) {
                pubs.c += 1;
            }
            k += 1;
        }
    } while (key != NULL);
    if (strcmp(fmt, "mr") == 0) {
        (void) fprintf(fp, "info:%d:%d\n", HKP_VERSION, pubs.c);
    } else {
        (void) fprintf(fp, "%d key%s found\n", pubs.c, (pubs.c == 1) ? "" : "s");
    }
    for (k = 0; k < pubs.c; k++) {
        (void) fprintf(fp, "%s%s", pubs.v[k], (k < pubs.c - 1) ? "\n" : "");
        free(pubs.v[k]);
    }
    free(pubs.v);
    return pubs.c;
}

/* find and list some keys in a keyring - return JSON string */
int
rnp_match_keys_json(rnp_t *rnp, char **json, char *name, const char *fmt, const int psigs)
{
    int          ret = 1;
    pgp_key_t *  key;
    unsigned     from;
    json_object *id_array = json_object_new_array();
    char *       newkey;
    // remove 0x prefix, if any
    if (name[0] == '0' && name[1] == 'x') {
        name += 2;
    }
    printf("%s,%d, NAME: %s\n", __FILE__, __LINE__, name);
    from = 0;
    *json = NULL;
    do {
        if (rnp_key_store_get_next_key_by_name(rnp->io, rnp->pubring, name, &from, &key) !=
            RNP_OK) {
            return 0;
        }
        if (key != NULL) {
            if (strcmp(fmt, "mr") == 0) {
                pgp_hkp_sprint_key(rnp->io, rnp->pubring, key, &newkey, &key->key.pubkey, 0);
                if (newkey) {
                    printf("%s\n", newkey);
                    free(newkey);
                    newkey = NULL;
                }
            } else {
                json_object *obj = json_object_new_object();
                repgp_sprint_json(rnp->io,
                                  rnp->pubring,
                                  key,
                                  obj,
                                  pgp_is_primary_key_tag(key->type) ? "pub" : "sub",
                                  &key->key.pubkey,
                                  psigs);
                json_object_array_add(id_array, obj);
            }
            from += 1;
        }
    } while (key != NULL);
    const char *j = json_object_to_json_string(id_array);
    *json = strdup(j);
    ret = strlen(j);
    json_object_put(id_array);
    return ret;
}

/* find and list some public keys in a keyring */
int
rnp_match_pubkeys(rnp_t *rnp, char *name, void *vp)
{
    pgp_key_t *key;
    unsigned   k;
    ssize_t    cc;
    char       out[1024 * 64];
    FILE *     fp = (FILE *) vp;

    k = 0;
    do {
        if (rnp_key_store_get_next_key_by_name(rnp->io, rnp->pubring, name, &k, &key) !=
            RNP_OK) {
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

/* find a key in a keyring */
bool
rnp_find_key(rnp_t *rnp, const char *id)
{
    pgp_io_t * io;
    pgp_key_t *key;

    io = rnp->io;
    if (id == NULL) {
        (void) fprintf(io->errs, "NULL id to search for\n");
        return RNP_FAIL;
    }
    if (rnp_key_store_get_key_by_name(rnp->io, rnp->pubring, id, &key) != RNP_OK) {
        return RNP_FAIL;
    }
    return key != NULL ? RNP_OK : RNP_FAIL;
}

/* get a key in a keyring */
char *
rnp_get_key(rnp_t *rnp, const char *name, const char *fmt)
{
    const pgp_key_t *key;
    char *           newkey;

    if ((key = resolve_userid(rnp, rnp->pubring, name)) == NULL) {
        return NULL;
    }
    if (strcmp(fmt, "mr") == 0) {
        return (pgp_hkp_sprint_key(rnp->io, rnp->pubring, key, &newkey, &key->key.pubkey, 0) >
                0) ?
                 newkey :
                 NULL;
    }
    return (pgp_sprint_key(
              rnp->io, rnp->pubring, key, &newkey, "signature", &key->key.pubkey, 0) > 0) ?
             newkey :
             NULL;
}

/* export a given key */
char *
rnp_export_key(rnp_t *rnp, const char *name)
{
    const pgp_key_t *key;
    pgp_io_t *       io;

    io = rnp->io;
    if ((key = resolve_userid(rnp, rnp->pubring, name)) == NULL) {
        return NULL;
    }
    return pgp_export_key(io, key, &rnp->passphrase_provider);
}

#define IMPORT_ARMOR_HEAD "-----BEGIN PGP (PUBLIC)|(PRIVATE) KEY BLOCK-----"

/* import a key into our keyring */
int
rnp_import_key(rnp_t *rnp, char *f)
{
    int              realarmor;
    rnp_key_store_t *tmp_keystore = NULL;
    bool             ret = false;
    list             imported_grips = NULL;
    list_item *      item = NULL;

    realarmor = isarmoured(f, NULL, IMPORT_ARMOR_HEAD);
    if (realarmor < 0) {
        goto done;
    }

    // guess the key format (TODO: surely this can be improved)
    size_t fname_len = strlen(f);
    if (fname_len < 4) {
        goto done;
    }
    const char *suffix = f + fname_len - 4;
    const char *fmt = NULL;
    if (strcmp(suffix, ".asc") == 0 || strcmp(suffix, ".gpg") == 0) {
        fmt = RNP_KEYSTORE_GPG;
    } else if (strcmp(suffix, ".kbx") == 0) {
        fmt = RNP_KEYSTORE_KBX;
    } else if (strcmp(suffix, ".key") == 0) {
        fmt = RNP_KEYSTORE_G10;
    } else {
        RNP_LOG("Warning: failed to guess key format, assuming GPG.");
        fmt = RNP_KEYSTORE_GPG;
    }

    // create a temporary key store
    tmp_keystore = rnp_key_store_new(fmt, f);
    if (!tmp_keystore) {
        goto done;
    }

    // load the key(s)
    if (!rnp_key_store_load_from_file(rnp->io, tmp_keystore, realarmor, rnp->pubring)) {
        RNP_LOG("failed to load key from file %s", f);
        goto done;
    }
    if (!tmp_keystore->keyc) {
        RNP_LOG("failed to load any keys to import");
        goto done;
    }

    // loop through each key
    for (unsigned i = 0; i < tmp_keystore->keyc; i++) {
        pgp_key_t *      key = &tmp_keystore->keys[i];
        pgp_key_t *      importedkey = NULL;
        rnp_key_store_t *dest = pgp_is_key_secret(key) ? rnp->secring : rnp->pubring;
        const char *     header = pgp_is_key_secret(key) ? "sec" : "pub";

        // check if it already exists
        importedkey = rnp_key_store_get_key_by_grip(rnp->io, dest, key->grip);
        if (!importedkey) {
            // print it out
            repgp_print_key(rnp->io, tmp_keystore, key, header, pgp_get_pubkey(key), 0);

            // add it to the dest store
            if (!rnp_key_store_add_key(rnp->io, dest, key)) {
                RNP_LOG("failed to add key to destination key store");
                goto done;
            }
            // keep track of what keys have been imported
            list_append(&imported_grips, key->grip, sizeof(key->grip));
            importedkey = rnp_key_store_get_key_by_grip(rnp->io, dest, key->grip);
            for (unsigned j = 0; j < key->subkeyc; j++) {
                pgp_key_t *subkey = key->subkeys[j];

                if (!rnp_key_store_add_key(rnp->io, dest, subkey)) {
                    RNP_LOG("failed to add key to destination key store");
                    goto done;
                }
                // fix up the subkeys dynarray pointers...
                importedkey->subkeys[j] =
                  rnp_key_store_get_key_by_grip(rnp->io, dest, subkey->grip);
                // keep track of what keys have been imported
                list_append(&imported_grips, subkey->grip, sizeof(subkey->grip));
            }
        }
    }

    // update the keyrings on disk
    if (!rnp_key_store_write_to_file(rnp->io, rnp->secring, 0) ||
        !rnp_key_store_write_to_file(rnp->io, rnp->pubring, 0)) {
        RNP_LOG("failed to write keyring");
        goto done;
    }
    ret = true;

done:
    // remove all the imported keys from the temporary store,
    // since we're taking ownership of their internal data
    item = list_front(imported_grips);
    while (item) {
        uint8_t *grip = (uint8_t *) item;
        rnp_key_store_remove_key(
          rnp->io, tmp_keystore, rnp_key_store_get_key_by_grip(rnp->io, tmp_keystore, grip));
        item = list_next(item);
    }
    list_destroy(&imported_grips);
    rnp_key_store_free(tmp_keystore);
    return ret;
}

int
rnp_secret_count(rnp_t *rnp)
{
    return rnp->secring ? ((rnp_key_store_t *) rnp->secring)->keyc : 0;
}

int
rnp_public_count(rnp_t *rnp)
{
    return rnp->pubring ? ((rnp_key_store_t *) rnp->pubring)->keyc : 0;
}

int
rnp_generate_key(rnp_t *rnp)
{
    RNP_MSG("Generating a new key...\n");

    rnp_action_keygen_t *action = &rnp->action.generate_key_ctx;
    pgp_key_t *          primary_sec = NULL;
    pgp_key_t *          primary_pub = NULL;
    pgp_key_t *          subkey_sec = NULL;
    pgp_key_t *          subkey_pub = NULL;
    char *               cp = NULL;
    bool                 ok = false;
    key_store_format_t   key_format = ((rnp_key_store_t *) rnp->secring)->format;

    primary_sec = calloc(1, sizeof(*primary_sec));
    primary_pub = calloc(1, sizeof(*primary_pub));
    subkey_sec = calloc(1, sizeof(*subkey_sec));
    subkey_pub = calloc(1, sizeof(*subkey_pub));
    if (!primary_sec || !primary_pub || !subkey_sec || !subkey_pub) {
        goto end;
    }
    if (!pgp_generate_keypair(&action->primary.keygen,
                              &action->subkey.keygen,
                              true,
                              primary_sec,
                              primary_pub,
                              subkey_sec,
                              subkey_pub,
                              key_format)) {
        RNP_LOG("failed to generate keys");
        goto end;
    }

    // show the primary key
    pgp_sprint_key(rnp->io, NULL, primary_pub, &cp, "pub", &primary_pub->key.pubkey, 0);
    (void) fprintf(stdout, "%s", cp);
    free(cp);

    // protect the primary key
    if (!pgp_key_protect(
          primary_sec, key_format, &action->primary.protection, &rnp->passphrase_provider)) {
        goto end;
    }

    // show the subkey
    pgp_sprint_key(rnp->io, NULL, subkey_pub, &cp, "sub", &subkey_pub->key.pubkey, 0);
    (void) fprintf(stdout, "%s", cp);
    free(cp);

    // protect the subkey
    if (!pgp_key_protect(
          subkey_sec, key_format, &action->subkey.protection, &rnp->passphrase_provider)) {
        RNP_LOG("failed to protect keys");
        goto end;
    }

    // add them all to the key store
    if (!rnp_key_store_add_key(rnp->io, rnp->secring, primary_sec) ||
        !rnp_key_store_add_key(rnp->io, rnp->secring, subkey_sec) ||
        !rnp_key_store_add_key(rnp->io, rnp->pubring, primary_pub) ||
        !rnp_key_store_add_key(rnp->io, rnp->pubring, subkey_pub)) {
        RNP_LOG("failed to add keys to key store");
        goto end;
    }

    // update the keyring on disk
    if (!rnp_key_store_write_to_file(rnp->io, rnp->secring, 0) ||
        !rnp_key_store_write_to_file(rnp->io, rnp->pubring, 0)) {
        RNP_LOG("failed to write keyring");
        goto end;
    }

    ok = true;
end:
    free(primary_sec);
    free(primary_pub);
    free(subkey_sec);
    free(subkey_pub);
    return ok;
}

/* encrypt a file */
int
rnp_encrypt_file(rnp_ctx_t *ctx, const char *userid, const char *f, const char *out)
{
    const pgp_key_t *key;
    const char *     suffix;
    char             outname[MAXPATHLEN];

    if (f == NULL) {
        (void) fprintf(ctx->rnp->io->errs, "rnp_encrypt_file: no filename specified\n");
        return RNP_FAIL;
    }
    /* get key with which to sign */
    if ((key = resolve_userid(ctx->rnp, ctx->rnp->pubring, userid)) == NULL) {
        return RNP_FAIL;
    }
    if (!pgp_key_can_encrypt(key) && !(key = find_suitable_subkey(key, PGP_KF_ENCRYPT))) {
        RNP_LOG("this key can not encrypt");
        return RNP_FAIL;
    }
    /* generate output file name if needed */
    if (out == NULL) {
        suffix = (ctx->armour) ? ".asc" : ".gpg";
        (void) snprintf(outname, sizeof(outname), "%s%s", f, suffix);
        out = outname;
    }
    return (int) pgp_encrypt_file(ctx, ctx->rnp->io, f, out, pgp_get_pubkey(key));
}

#define ARMOR_HEAD "-----BEGIN PGP MESSAGE-----"

/* decrypt a file */
rnp_result_t
rnp_decrypt_file(rnp_ctx_t *ctx, const char *f, const char *out)
{
    int      realarmor;
    unsigned sshkeys;

    if (f == NULL) {
        RNP_LOG("No filename specified");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    realarmor = isarmoured(f, NULL, ARMOR_HEAD);
    if (realarmor < 0) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    sshkeys = (unsigned) use_ssh_keys(ctx->rnp);
    const bool ret = pgp_decrypt_file(ctx->rnp->io,
                                      f,
                                      out,
                                      ctx->rnp->secring,
                                      ctx->rnp->pubring,
                                      realarmor,
                                      ctx->overwrite,
                                      sshkeys,
                                      ctx->rnp->pswdtries,
                                      &ctx->rnp->passphrase_provider);

    return ret ? RNP_SUCCESS : RNP_ERROR_GENERIC;
}

typedef struct pgp_parse_handler_param_t {
    char in[PATH_MAX];
    char out[PATH_MAX];
} pgp_parse_handler_param_t;

/* process the pgp stream */

static bool
rnp_parse_handler_dest(pgp_parse_handler_t *handler, pgp_dest_t *dst, const char *filename)
{
    pgp_parse_handler_param_t *param = handler->param;

    if (!param) {
        return false;
    }

    if (strlen(param->out) > 0) {
        return init_file_dest(dst, param->out) == RNP_SUCCESS;
    } else {
        return init_stdout_dest(dst) == RNP_SUCCESS;
    }
}

rnp_result_t
rnp_process_stream(rnp_ctx_t *ctx, const char *in, const char *out)
{
    pgp_source_t               src;
    pgp_parse_handler_t *      handler = NULL;
    pgp_parse_handler_param_t *param = NULL;
    rnp_result_t               result;
    bool                       is_stdin;
    bool                       is_stdout;

    is_stdin = !in || (strlen(in) == 0) || (strcmp(in, "-") == 0);
    is_stdout = !out || (strlen(out) == 0) || (strcmp(out, "-") == 0);

    if (!is_stdin && (strlen(in) > sizeof(param->in))) {
        (void) fprintf(stderr, "rnp_process_stream: too long input path\n");
        return RNP_ERROR_GENERIC;
    }

    if (!is_stdout && (strlen(out) > sizeof(param->out))) {
        (void) fprintf(stderr, "rnp_process_stream: too long output path\n");
        return RNP_ERROR_GENERIC;
    }

    result = is_stdin ? init_stdin_src(&src) : init_file_src(&src, in);

    if (result != RNP_SUCCESS) {
        return RNP_ERROR_READ;
    }

    if ((handler = calloc(1, sizeof(*handler))) == NULL) {
        result = RNP_ERROR_OUT_OF_MEMORY;
        goto finish;
    }

    if ((param = calloc(1, sizeof(*param))) == NULL) {
        result = RNP_ERROR_OUT_OF_MEMORY;
        goto finish;
    }

    if (!is_stdin) {
        strcpy(param->in, in);
    } else {
        param->in[0] = 0;
    }

    if (!is_stdout) {
        strcpy(param->out, out);
    } else {
        param->out[0] = 0;
    }

    handler->passphrase_provider = &ctx->rnp->passphrase_provider;
    handler->dest_provider = rnp_parse_handler_dest;
    handler->param = param;

    result = process_pgp_source(handler, &src);
    if (result != RNP_SUCCESS) {
        (void) fprintf(stderr, "rnp_process_stream: error 0x%x\n", result);
    }

finish:
    src_close(&src);
    free(handler);
    free(param);
    return result;
}

rnp_result_t
rnp_encrypt_stream(rnp_ctx_t *ctx, const char *in, const char *out)
{
    pgp_source_t         src;
    pgp_dest_t           dst;
    pgp_write_handler_t *handler = NULL;
    rnp_result_t         result;
    bool                 is_stdin;
    bool                 is_stdout;

    is_stdin = !in || (strlen(in) == 0) || (strcmp(in, "-") == 0);
    is_stdout = !out || (strlen(out) == 0) || (strcmp(out, "-") == 0);

    result = is_stdin ? init_stdin_src(&src) : init_file_src(&src, in);
    if (result != RNP_SUCCESS) {
        (void) fprintf(stderr, "rnp_encrypt_stream: failed to initialize reading\n");
        return RNP_ERROR_READ;
    }

    result = is_stdout ? init_stdout_dest(&dst) : init_file_dest(&dst, out);
    if (result != RNP_SUCCESS) {
        (void) fprintf(stderr, "rnp_encrypt_stream: failed to initialize writing\n");
        src_close(&src);
        return RNP_ERROR_WRITE;
    }

    if ((handler = calloc(1, sizeof(*handler))) == NULL) {
        result = RNP_ERROR_OUT_OF_MEMORY;
        goto finish;
    }

    handler->passphrase_provider = &ctx->rnp->passphrase_provider;
    handler->ctx = ctx;
    handler->param = NULL;

    result = rnp_encrypt_src(handler, &src, &dst);
    if (result != RNP_SUCCESS) {
        (void) printf("rnp_encrypt_stream: failed with error code 0x%x\n", (int) result);
    }

finish:
    src_close(&src);
    dst_close(&dst, result != RNP_SUCCESS);
    free(handler);
    return result;
}

rnp_result_t
rnp_dearmor_stream(rnp_ctx_t *ctx, const char *in, const char *out)
{
    pgp_source_t src;
    pgp_dest_t   dst;
    rnp_result_t result;
    bool         is_stdin;
    bool         is_stdout;

    is_stdin = !in || (strlen(in) == 0) || (strcmp(in, "-") == 0);
    is_stdout = !out || (strlen(out) == 0) || (strcmp(out, "-") == 0);

    result = is_stdin ? init_stdin_src(&src) : init_file_src(&src, in);
    if (result != RNP_SUCCESS) {
        (void) fprintf(stderr, "rnp_dearmor_stream: failed to initialize reading\n");
        return RNP_ERROR_READ;
    }

    result = is_stdout ? init_stdout_dest(&dst) : init_file_dest(&dst, out);
    if (result != RNP_SUCCESS) {
        (void) fprintf(stderr, "rnp_dearmor_stream: failed to initialize writing\n");
        src_close(&src);
        return RNP_ERROR_WRITE;
    }

    result = rnp_dearmour_source(&src, &dst);
    if (result != RNP_SUCCESS) {
        (void) printf("rnp_dearmor_stream: error code 0x%x\n", (int) result);
    }

    src_close(&src);
    dst_close(&dst, result != RNP_SUCCESS);
    return result;
}

/* sign a file */
int
rnp_sign_file(rnp_ctx_t * ctx,
              const char *userid,
              const char *f,
              const char *out,
              bool        cleartext,
              bool        detached)
{
    pgp_key_t *         keypair;
    pgp_key_t *         pubkey;
    const pgp_seckey_t *seckey = NULL;
    pgp_seckey_t *      decrypted_seckey = NULL;
    pgp_io_t *          io;
    int                 attempts;
    int                 ret;
    int                 i;

    io = ctx->rnp->io;
    if (f == NULL) {
        (void) fprintf(io->errs, "rnp_sign_file: no filename specified\n");
        return RNP_FAIL;
    }
    /* get key with which to sign */
    if ((keypair = resolve_userid(ctx->rnp, ctx->rnp->pubring, userid)) == NULL) {
        RNP_LOG("unable to locate key %s", userid);
        return RNP_FAIL;
    }
    if (!pgp_key_can_sign(keypair) &&
        !(keypair = find_suitable_subkey(keypair, PGP_KF_SIGN))) {
        RNP_LOG("this key can not sign");
        return RNP_FAIL;
    }
    // key exist and might be used to sign, trying get it from secring
    unsigned from = 0;
    if ((keypair = rnp_key_store_get_key_by_id(
           io, ctx->rnp->secring, keypair->keyid, &from, NULL)) == NULL) {
        return RNP_FAIL;
    }
    ret = RNP_OK;
    attempts = ctx->rnp->pswdtries;

    for (i = 0, seckey = NULL; !seckey && (i < attempts || attempts == INFINITE_ATTEMPTS);
         i++) {
        /* print out the user id */
        if (rnp_key_store_get_key_by_name(io, ctx->rnp->pubring, userid, &pubkey) != RNP_OK) {
            return RNP_FAIL;
        }
        if (pubkey == NULL) {
            (void) fprintf(io->errs, "rnp: warning - using pubkey from secring\n");
            repgp_print_key(
              io, ctx->rnp->pubring, keypair, "signature ", &keypair->key.seckey.pubkey, 0);
        } else {
            repgp_print_key(
              io, ctx->rnp->pubring, pubkey, "signature ", &pubkey->key.pubkey, 0);
        }
        if (!use_ssh_keys(ctx->rnp)) {
            if (pgp_key_is_locked(keypair)) {
                decrypted_seckey = pgp_decrypt_seckey(
                  keypair,
                  &ctx->rnp->passphrase_provider,
                  &(pgp_passphrase_ctx_t){.op = PGP_OP_SIGN, .key = keypair});
                if (decrypted_seckey == NULL) {
                    (void) fprintf(io->errs, "Bad passphrase\n");
                }
                seckey = decrypted_seckey;
            } else {
                seckey = &keypair->key.seckey;
            }
        } else {
            seckey = &((rnp_key_store_t *) ctx->rnp->secring)->keys[0].key.seckey;
        }
    }
    if (!seckey) {
        (void) fprintf(io->errs, "Bad passphrase\n");
        return RNP_FAIL;
    }
    /* sign file */
    if (detached) {
        ret = pgp_sign_detached(ctx, io, f, out, seckey);
    } else {
        ret = pgp_sign_file(ctx, io, f, out, seckey, cleartext);
    }

    if (decrypted_seckey) {
        pgp_seckey_free(decrypted_seckey);
        free(decrypted_seckey);
    }
    return ret;
}

#define ARMOR_SIG_HEAD "-----BEGIN PGP (SIGNATURE|SIGNED MESSAGE|MESSAGE)-----"

/* verify a file */
rnp_result_t
rnp_verify_file(rnp_ctx_t *ctx, const char *in, const char *out)
{
    pgp_validation_t result;
    pgp_io_t *       io;
    int              realarmor;

    (void) memset(&result, 0x0, sizeof(result));
    io = ctx->rnp->io;
    if (in == NULL) {
        RNP_LOG_FD(io->errs, "rnp_verify_file: no filename specified");
        return RNP_ERROR_GENERIC;
    }
    realarmor = isarmoured(in, NULL, ARMOR_SIG_HEAD);
    if (realarmor < 0) {
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    if (pgp_validate_file(io, &result, in, out, (const int) realarmor, ctx->rnp->pubring)) {
        resultp(io, in, &result, ctx->rnp->pubring);
        return RNP_SUCCESS;
    }
    if (result.validc + result.invalidc + result.unknownc == 0) {
        RNP_LOG_FD(io->errs, "\"%s\": No signatures found - is this a signed file?", in);
    } else if (result.invalidc == 0 && result.unknownc == 0) {
        RNP_LOG_FD(
          io->errs, "\"%s\": file verification failure: invalid signature time\n", in);
    } else {
        RNP_LOG_FD(
          io->errs,
          "\"%s\": verification failure: %u invalid signatures, %u unknown signatures",
          in,
          result.invalidc,
          result.unknownc);
    }
    return RNP_ERROR_SIGNATURE_INVALID;
}

/* sign some memory */
int
rnp_sign_memory(rnp_ctx_t * ctx,
                const char *userid,
                const char *mem,
                size_t      size,
                char *      out,
                size_t      outsize,
                bool        cleartext)
{
    pgp_key_t *         keypair;
    pgp_key_t *         pubkey;
    const pgp_seckey_t *seckey = NULL;
    pgp_seckey_t *      decrypted_seckey = NULL;
    pgp_memory_t *      signedmem;
    pgp_io_t *          io;
    int                 attempts;
    int                 ret;
    int                 i;
    unsigned            from;

    io = ctx->rnp->io;
    if (mem == NULL) {
        (void) fprintf(io->errs, "rnp_sign_memory: no memory to sign\n");
        return RNP_FAIL;
    }
    if ((keypair = resolve_userid(ctx->rnp, ctx->rnp->pubring, userid)) == NULL) {
        return RNP_FAIL;
    }
    if (!pgp_key_can_sign(keypair) &&
        !(keypair = find_suitable_subkey(keypair, PGP_KF_SIGN))) {
        RNP_LOG("this key can not sign");
        return RNP_FAIL;
    }
    // key exist and might be used to sign, trying get it from secring
    from = 0;
    if ((keypair = rnp_key_store_get_key_by_id(
           io, ctx->rnp->secring, keypair->keyid, &from, NULL)) == NULL) {
        return RNP_FAIL;
    }
    ret = RNP_OK;
    attempts = ctx->rnp->pswdtries;

    for (i = 0, seckey = NULL; !seckey && (i < attempts || attempts == INFINITE_ATTEMPTS);
         i++) {
        /* print out the user id */
        if (rnp_key_store_get_key_by_name(io, ctx->rnp->pubring, userid, &pubkey) != RNP_OK) {
            return RNP_FAIL;
        }
        if (pubkey == NULL) {
            (void) fprintf(io->errs, "rnp: warning - using pubkey from secring\n");
            repgp_print_key(
              io, ctx->rnp->pubring, keypair, "signature ", &keypair->key.seckey.pubkey, 0);
        } else {
            repgp_print_key(
              io, ctx->rnp->pubring, pubkey, "signature ", &pubkey->key.pubkey, 0);
        }
        if (!use_ssh_keys(ctx->rnp)) {
            if (pgp_key_is_locked(keypair)) {
                decrypted_seckey = pgp_decrypt_seckey(
                  keypair,
                  &ctx->rnp->passphrase_provider,
                  &(pgp_passphrase_ctx_t){.op = PGP_OP_SIGN, .key = keypair});
                if (decrypted_seckey == NULL) {
                    (void) fprintf(io->errs, "Bad passphrase\n");
                }
                seckey = decrypted_seckey;
            } else {
                seckey = &keypair->key.seckey;
            }

        } else {
            seckey = &((rnp_key_store_t *) ctx->rnp->secring)->keys[0].key.seckey;
        }
    }
    if (!seckey) {
        (void) fprintf(io->errs, "Bad passphrase\n");
        return RNP_FAIL;
    }
    /* sign file */
    (void) memset(out, 0x0, outsize);
    signedmem = pgp_sign_buf(ctx, io, mem, size, seckey, cleartext);
    if (signedmem) {
        size_t m;

        m = MIN(pgp_mem_len(signedmem), outsize);
        (void) memcpy(out, pgp_mem_data(signedmem), m);
        pgp_memory_free(signedmem);
        ret = (int) m;
    } else {
        ret = RNP_FAIL;
    }

    if (decrypted_seckey) {
        pgp_seckey_free(decrypted_seckey);
        free(decrypted_seckey);
    }
    return ret;
}

/* verify memory */
int
rnp_verify_memory(rnp_ctx_t *ctx, const void *in, const size_t size, void *out, size_t outsize)
{
    pgp_validation_t result;
    pgp_memory_t *   signedmem;
    pgp_memory_t *   cat;
    pgp_io_t *       io;
    size_t           m;
    int              ret;

    (void) memset(&result, 0x0, sizeof(result));
    io = ctx->rnp->io;
    if (in == NULL) {
        (void) fprintf(io->errs, "rnp_verify_memory: no memory to verify\n");
        return 0;
    }
    signedmem = pgp_memory_new();
    if (signedmem == NULL) {
        (void) fprintf(stderr, "can't allocate mem\n");
        return 0;
    }
    if (!pgp_memory_add(signedmem, in, size)) {
        return 0;
    }
    if (out) {
        cat = pgp_memory_new();
        if (cat == NULL) {
            (void) fprintf(stderr, "can't allocate mem\n");
            return 0;
        }
    }
    ret = pgp_validate_mem(
      io, &result, signedmem, (out) ? &cat : NULL, ctx->armour, ctx->rnp->pubring);
    /* signedmem is freed from pgp_validate_mem */
    if (ret) {
        resultp(io, "<stdin>", &result, ctx->rnp->pubring);
        if (out) {
            m = MIN(pgp_mem_len(cat), outsize);
            (void) memcpy(out, pgp_mem_data(cat), m);
            pgp_memory_free(cat);
        } else {
            m = 1;
        }
        return (int) m;
    }
    if (result.validc + result.invalidc + result.unknownc == 0) {
        (void) fprintf(io->errs, "No signatures found - is this memory signed?\n");
    } else if (result.invalidc == 0 && result.unknownc == 0) {
        (void) fprintf(io->errs, "memory verification failure: invalid signature time\n");
    } else {
        (void) fprintf(
          io->errs,
          "memory verification failure: %u invalid signatures, %u unknown signatures\n",
          result.invalidc,
          result.unknownc);
    }
    return 0;
}

/* encrypt some memory */
int
rnp_encrypt_memory(rnp_ctx_t *  ctx,
                   const char * userid,
                   const void * in,
                   const size_t insize,
                   char *       out,
                   size_t       outsize)
{
    const pgp_key_t *keypair;
    pgp_memory_t *   enc;
    pgp_io_t *       io;
    size_t           m;

    io = ctx->rnp->io;
    if (in == NULL) {
        (void) fprintf(io->errs, "rnp_encrypt_buf: no memory to encrypt\n");
        return 0;
    }
    if ((keypair = resolve_userid(ctx->rnp, ctx->rnp->pubring, userid)) == NULL) {
        (void) fprintf(io->errs, "%s: public key not available\n", userid);
        return 0;
    }
    if (!pgp_key_can_encrypt(keypair) &&
        !(keypair = find_suitable_subkey(keypair, PGP_KF_ENCRYPT))) {
        RNP_LOG("this key can not encrypt");
        return RNP_FAIL;
    }
    if (in == out) {
        (void) fprintf(io->errs,
                       "rnp_encrypt_buf: input and output bufs need to be different\n");
        return 0;
    }
    if (outsize < insize) {
        (void) fprintf(io->errs, "rnp_encrypt_buf: input size is larger than output size\n");
        return 0;
    }
    enc = pgp_encrypt_buf(ctx, io, in, insize, pgp_get_pubkey(keypair));
    m = MIN(pgp_mem_len(enc), outsize);
    (void) memcpy(out, pgp_mem_data(enc), m);
    pgp_memory_free(enc);
    return (int) m;
}

/* decrypt a chunk of memory */
rnp_result_t
rnp_decrypt_memory(
  rnp_ctx_t *ctx, const void *input, const size_t insize, char *out, size_t *outsize)
{
    pgp_memory_t *mem;
    int           realarmour;
    unsigned      sshkeys;
    int           attempts;

    if (input == NULL) {
        RNP_LOG("Input NULL");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    realarmour = isarmoured(NULL, input, ARMOR_HEAD);
    if (realarmour < 0) {
        RNP_LOG("Can't figure out file format");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    sshkeys = (unsigned) use_ssh_keys(ctx->rnp);
    attempts = ctx->rnp->pswdtries;
    mem = pgp_decrypt_buf(ctx->rnp->io,
                          input,
                          insize,
                          ctx->rnp->secring,
                          ctx->rnp->pubring,
                          realarmour,
                          sshkeys,
                          attempts,
                          &ctx->rnp->passphrase_provider);
    if (mem == NULL) {
        return RNP_ERROR_OUT_OF_MEMORY;
    } else if (*outsize <
               pgp_mem_len(mem)) { // TODO: This should be checked earlier in pgp_decrypt_buf
        pgp_memory_free(mem);
        return RNP_ERROR_SHORT_BUFFER;
    }

    (void) memcpy(out, pgp_mem_data(mem), pgp_mem_len(mem));
    *outsize = pgp_mem_len(mem);
    pgp_memory_free(mem);
    return RNP_SUCCESS;
}

/* print the json out on 'fp' */
int
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

/* find a key in keyring, and write it in ssh format */
int
rnp_write_sshkey(rnp_t *rnp, char *s, const char *userid, char *out, size_t size)
{
    pgp_key_t *key;
    pgp_io_t * io;
    unsigned   k;
    size_t     cc;
    char       f[MAXPATHLEN];

    io = NULL;
    cc = 0;
    if ((io = calloc(1, sizeof(pgp_io_t))) == NULL) {
        (void) fprintf(stderr, "rnp_save_sshpub: bad alloc 1\n");
        goto done;
    }
    io->outs = stdout;
    io->errs = stderr;
    io->res = stderr;
    rnp->io = io;
    /* write new to temp file */
    savepubkey(s, f, sizeof(f));

    if (rnp->pubring) {
        rnp_key_store_free(rnp->pubring);
    }

    rnp->pubring = rnp_key_store_new(RNP_KEYSTORE_SSH, f);
    if (rnp->pubring == NULL) {
        goto done;
    }

    if (!rnp_key_store_load_from_file(rnp->io, rnp->pubring, 1, NULL)) {
        (void) fprintf(stderr, "cannot import key\n");
        goto done;
    }

    /* get rsa key */
    k = 0;
    if (rnp_key_store_get_next_key_by_name(rnp->io, rnp->pubring, userid, &k, &key) !=
        RNP_OK) {
        goto done;
    }
    if (key == NULL) {
        (void) fprintf(stderr, "no key found for '%s'\n", userid);
        goto done;
    }
    if (key->key.pubkey.alg != PGP_PKA_RSA) {
        /* we're not interested in supporting DSA either :-) */
        (void) fprintf(stderr, "key not RSA '%s'\n", userid);
        goto done;
    }
    /* XXX - check trust sigs */
    /* XXX - check expiry */
    /* XXX - check start */
    /* XXX - check not weak key */
    /* get rsa e and n */
    (void) memset(out, 0x0, size);
    cc = formatstring((char *) out, (const uint8_t *) "ssh-rsa", 7);
    cc += formatbignum((char *) &out[cc], key->key.pubkey.key.rsa.e);
    cc += formatbignum((char *) &out[cc], key->key.pubkey.key.rsa.n);
done:
    if (io) {
        free(io);
    }
    return (int) cc;
}
