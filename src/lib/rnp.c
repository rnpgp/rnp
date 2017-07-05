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
#include "config.h"

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
#include <time.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include <rnp.h>

#include "packet.h"
#include "packet-parse.h"
#include "packet-print.h"
#include "key_store.h"
#include "errors.h"
#include "packet-show.h"
#include "create.h"
#include "rnpsdk.h"
#include "memory.h"
#include "validate.h"
#include "readerwriter.h"
#include "rnpdefs.h"
#include "crypto.h"
#include "bn.h"
#include "defs.h"
#include "../common/constants.h"
#include "packet-key.h"

#include <json.h>

extern ec_curve_desc_t ec_curves[PGP_CURVE_MAX];

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
        if (sigkey == &key->enckey) {
            (void) fprintf(io->res,
                           "WARNING: signature for %s made with encryption key\n",
                           (f) ? f : "<stdin>");
        }
        pgp_print_keydata(io, ring, key, "signature ", &key->key.pubkey, 0);
    }
}

/* TODO: Make these const; currently their consumers don't preserve const. */

static int
use_ssh_keys(rnp_t *rnp)
{
    return rnp->key_store_format == SSH_KEY_STORE;
}

/* resolve the userid */
static const pgp_key_t *
resolve_userid(rnp_t *rnp, const rnp_key_store_t *keyring, const char *userid)
{
    const pgp_key_t *key;
    pgp_io_t *       io;

    if (userid == NULL) {
        return NULL;
    } else if ((strlen(userid) > 1) && userid[0] == '0' && userid[1] == 'x') {
        userid += 2;
    }
    io = rnp->io;
    if ((key = rnp_key_store_get_key_by_name(io, keyring, userid)) == NULL) {
        (void) fprintf(io->errs, "cannot find key '%s'\n", userid);
    }
    return key;
}

/* return 1 if the file contains ascii-armoured text */
static unsigned
isarmoured(pgp_io_t *io, const char *f, const void *memory, const char *text)
{
    regmatch_t matches[10];
    unsigned   armoured;
    regex_t    r;
    FILE *     fp;
    char       buf[BUFSIZ];

    armoured = 0;
    (void) regcomp(&r, text, REG_EXTENDED);
    if (f) {
        if ((fp = fopen(f, "r")) == NULL) {
            (void) fprintf(io->errs, "isarmoured: cannot open '%s'\n", f);
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
        pobj(fp, tmp, 0);
        p(fp, " ", NULL);
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

    if (json_object_object_get_ex(obj, "birthtime", &tmp)) {
        birthtime = (int64_t) strtoll(json_object_get_string(tmp), NULL, 10);
        p(fp, " ", ptimestr(tbuf, sizeof(tbuf), birthtime), NULL);

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
        p(fp, "\n", "Key fingerprint: ", NULL);
        pobj(fp, tmp, 0);
        p(fp, "\n", NULL);
    }

    if (json_object_object_get_ex(obj, "uid", &tmp)) {
        if (!json_object_is_type(tmp, json_type_null)) {
            p(fp, "uid", NULL);
            pobj(fp, json_object_array_get_idx(tmp, 0), (psigs) ? 4 : 14); /* human name */
            pobj(fp, json_object_array_get_idx(tmp, 1), 1);                /* any revocation */
            p(fp, "\n", NULL);
        }
    }

    if (json_object_object_get_ex(obj, "encryption", &tmp)) {
        if (!json_object_is_type(tmp, json_type_null)) {
            p(fp, "encryption", NULL);
            pobj(fp, json_object_array_get_idx(tmp, 0), 1); /* size */
            p(fp, "/", NULL);
            pobj(fp, json_object_array_get_idx(tmp, 1), 0); /* alg */
            p(fp, " ", NULL);
            pobj(fp, json_object_array_get_idx(tmp, 2), 0); /* id */
            p(fp,
              " ",
              ptimestr(tbuf,
                       sizeof(tbuf),
                       (time_t) strtoll(
                         json_object_get_string(json_object_array_get_idx(tmp, 3)), NULL, 10)),
              "\n",
              NULL);
        }
    }

    if (json_object_object_get_ex(obj, "sig", &tmp)) {
        if (!json_object_is_type(tmp, json_type_null)) {
            p(fp, "sig", NULL);
            pobj(fp, json_object_array_get_idx(tmp, 0), 8); /* size */
            p(fp,
              "  ",
              ptimestr(tbuf,
                       sizeof(tbuf),
                       (time_t) strtoll(
                         json_object_get_string(json_object_array_get_idx(tmp, 1)), NULL, 10)),
              " ",
              NULL);                                        /* time */
            pobj(fp, json_object_array_get_idx(tmp, 2), 0); /* human name */
            p(fp, "\n", NULL);
        }
    }
    p(fp, "\n", NULL);
}

/* save a pgp pubkey to a temp file */
static int
savepubkey(char *res, char *f, size_t size)
{
    size_t len;
    int    cc;
    int    wc;
    int    fd;

    (void) snprintf(f, size, "/tmp/pgp2ssh.XXXXXXX");
    if ((fd = mkstemp(f)) < 0) {
        (void) fprintf(stderr, "cannot create temp file '%s'\n", f);
        return RNP_FAIL;
    }
    len = strlen(res);
    for (cc = 0; (wc = (int) write(fd, &res[cc], len - (size_t) cc)) > 0; cc += wc) {
    }
    (void) close(fd);
    return RNP_OK;
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

/* get the passphrase from the user */
static int
find_passphrase(FILE *passfp, const char *id, char *passphrase, size_t size, int attempts)
{
    char  prompt[BUFSIZ];
    char  buf[128];
    char *cp;
    int   cc;
    int   i;

    if (passfp) {
        if (fgets(passphrase, (int) size, passfp) == NULL) {
            return 0;
        }
        return (int) strlen(passphrase);
    }
    for (i = 0; i < attempts; i++) {
        (void) snprintf(prompt, sizeof(prompt), "Enter passphrase for %.16s: ", id);
        if ((cp = getpass(prompt)) == NULL) {
            break;
        }
        cc = snprintf(buf, sizeof(buf), "%s", cp);
        (void) snprintf(prompt, sizeof(prompt), "Repeat passphrase for %.16s: ", id);
        if ((cp = getpass(prompt)) == NULL) {
            break;
        }
        cc = snprintf(passphrase, size, "%s", cp);
        if (strcmp(buf, passphrase) == 0) {
            (void) memset(buf, 0x0, sizeof(buf));
            return cc;
        }
    }
    (void) memset(buf, 0x0, sizeof(buf));
    (void) memset(passphrase, 0x0, size);
    return 0;
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

/* Gets a passphrase from a file descriptor and set it in the RNP
 * context. Returns 1 on success and 0 on failure.
 *
 * TODO: Replace atoi(). This could create unexpected behaviour for users
 *       that enter nonsense and end up using stdin.
 *
 * TODO: Decouple this layer from the error reporting layer, which should
 *       be in or around rnp_init(). Because the error message requires
 *       passfd to be available this is complicated.
 */
static int
set_pass_fd(rnp_t *rnp, int passfd)
{
    rnp->user_input_fp = fdopen(passfd, "r");
    if (rnp->user_input_fp == NULL) {
        fprintf(rnp->io->errs, "cannot open fd %d for reading\n", passfd);
        return RNP_FAIL;
    }

    return RNP_OK;
}

/* Initialize a RNP context's io stream handles with a user-supplied
 * io struct. Returns 1 on success and 0 on failure. It is the caller's
 * responsibility to de-allocate a dynamically allocated io struct
 * upon failure.
 */
static int
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
            return RNP_FAIL;
        }
    }

    rnp->io = io;

    return RNP_OK;
}

/* Allocate a new io struct and initialize a rnp context with it.
 * Returns 1 on success and 0 on failure.
 *
 * TODO: Set errno with a suitable error code.
 */
static int
init_new_io(rnp_t *rnp, const char *outs, const char *errs, const char *ress)
{
    pgp_io_t *io = (pgp_io_t *) calloc(1, sizeof(*io));

    if (io != NULL) {
        if (init_io(rnp, io, outs, errs, ress))
            return RNP_OK;
        free((void *) io);
    }

    return RNP_FAIL;
}

/*************************************************************************/
/* exported functions start here                                         */
/*************************************************************************/

/* Initialize a rnp_t structure */
int
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
        return RNP_FAIL;
    }
    io = rnp->io;

    /* If a password-carrying file descriptor is in use then load it. */
    if (params->passfd >= 0) {
        if (!set_pass_fd(rnp, params->passfd))
            return RNP_FAIL;
    }

    rnp->pswdtries = MAX_PASSPHRASE_ATTEMPTS;
    /* set keystore type and pathes */
    rnp->key_store_format = params->ks_format;
    rnp->pubpath = strdup(params->pubpath);
    rnp->secpath = strdup(params->secpath);

    rnp->pubring = calloc(1, sizeof(rnp_key_store_t));
    if (rnp->pubring == NULL) {
        fputs("rnp: can't create empty pubring keystore\n", io->errs);
        return RNP_FAIL;
    }

    rnp->secring = calloc(1, sizeof(rnp_key_store_t));
    if (rnp->secring == NULL) {
        fputs("rnp: can't create empty secring keystore\n", io->errs);
        return RNP_FAIL;
    }

    return RNP_OK;
}

/* finish off with the rnp_t struct */
void
rnp_end(rnp_t *rnp)
{
    if (rnp->pubring != NULL) {
        rnp_key_store_free(rnp->pubring);
        free(rnp->pubring);
        rnp->pubring = NULL;
    }
    if (rnp->secring != NULL) {
        rnp_key_store_free(rnp->secring);
        free(rnp->secring);
        rnp->secring = NULL;
    }
    free(rnp->io);
    free(rnp->pubpath);
    free(rnp->secpath);
}

/* rnp_params_t : initialize and free internals */
int
rnp_params_init(rnp_params_t *params)
{
    memset(params, '\0', sizeof(*params));
    params->passfd = -1;

    return RNP_OK;
}

void
rnp_params_free(rnp_params_t *params)
{
    free(params->pubpath);
    free(params->secpath);
    free(params->defkey);
}

/* rnp_ctx_t : init, reset, free internal pointers */
int
rnp_ctx_init(rnp_ctx_t *ctx, rnp_t *rnp)
{
    if (rnp == NULL) {
        return RNP_FAIL;
    }

    memset(ctx, '\0', sizeof(*ctx));
    ctx->rnp = rnp;
    return RNP_OK;
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
    const pgp_key_t *key;
    unsigned         k;
    strings_t        pubs;
    FILE *           fp = (FILE *) vp;

    if (name[0] == '0' && name[1] == 'x') {
        name += 2;
    }
    (void) memset(&pubs, 0x0, sizeof(pubs));
    k = 0;
    do {
        key = rnp_key_store_get_next_key_by_name(rnp->io, rnp->pubring, name, &k);
        if (key != NULL) {
            ALLOC(char *, pubs.v, pubs.size, pubs.c, 10, 10, "rnp_match_keys", return 0);
            if (strcmp(fmt, "mr") == 0) {
                pgp_hkp_sprint_keydata(
                  rnp->io, rnp->pubring, key, &pubs.v[pubs.c], &key->key.pubkey, psigs);
            } else {
                pgp_sprint_keydata(rnp->io,
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
    int              ret = 1;
    const pgp_key_t *key;
    unsigned         k;
    json_object *    id_array = json_object_new_array();
    char *           newkey;
    // remove 0x prefix, if any
    if (name[0] == '0' && name[1] == 'x') {
        name += 2;
    }
    printf("%s,%d, NAME: %s\n", __FILE__, __LINE__, name);
    k = 0;
    *json = NULL;
    do {
        key = rnp_key_store_get_next_key_by_name(rnp->io, rnp->pubring, name, &k);
        if (key != NULL) {
            if (strcmp(fmt, "mr") == 0) {
                pgp_hkp_sprint_keydata(
                  rnp->io, rnp->pubring, key, &newkey, &key->key.pubkey, 0);
                if (newkey) {
                    printf("%s\n", newkey);
                    free(newkey);
                    newkey = NULL;
                }
            } else {
                pgp_sprint_json(
                  rnp->io, rnp->pubring, key, id_array, "signature ", &key->key.pubkey, psigs);
            }
            k += 1;
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
    const pgp_key_t *key;
    unsigned         k;
    ssize_t          cc;
    char             out[1024 * 64];
    FILE *           fp = (FILE *) vp;

    k = 0;
    do {
        key = rnp_key_store_get_next_key_by_name(rnp->io, rnp->pubring, name, &k);
        if (key != NULL) {
            cc = pgp_sprint_pubkey(key, out, sizeof(out));
            (void) fprintf(fp, "%.*s", (int) cc, out);
            k += 1;
        }
    } while (key != NULL);
    return k;
}

/* find a key in a keyring */
int
rnp_find_key(rnp_t *rnp, const char *id)
{
    pgp_io_t *io;

    io = rnp->io;
    if (id == NULL) {
        (void) fprintf(io->errs, "NULL id to search for\n");
        return RNP_FAIL;
    }
    return rnp_key_store_get_key_by_name(rnp->io, rnp->pubring, id) != NULL ? RNP_OK :
                                                                              RNP_FAIL;
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
        return (pgp_hkp_sprint_keydata(
                  rnp->io, rnp->pubring, key, &newkey, &key->key.pubkey, 0) > 0) ?
                 newkey :
                 NULL;
    }
    return (pgp_sprint_keydata(
              rnp->io, rnp->pubring, key, &newkey, "signature", &key->key.pubkey, 0) > 0) ?
             newkey :
             NULL;
}

/* export a given key */
char *
rnp_export_key(rnp_t *rnp, const char *name)
{
    char             keyid[2 * PGP_KEY_ID_SIZE + 1] = {0};
    char             passphrase[MAX_PASSPHRASE_LENGTH] = {0};
    const pgp_key_t *key;
    pgp_io_t *       io;

    io = rnp->io;
    if ((key = resolve_userid(rnp, rnp->pubring, name)) == NULL) {
        return NULL;
    }

    if (key->type == PGP_PTAG_CT_ENCRYPTED_SECRET_KEY) {
        rnp_strhexdump(keyid, key->sigid, PGP_KEY_ID_SIZE, "");
        memset(passphrase, 0, sizeof(passphrase));
        find_passphrase(
          rnp->user_input_fp, keyid, passphrase, sizeof(passphrase), rnp->pswdtries);
    }

    return pgp_export_key(io, key, (uint8_t *) passphrase);
}

#define IMPORT_ARMOR_HEAD "-----BEGIN PGP PUBLIC KEY BLOCK-----"

/* import a key into our keyring */
int
rnp_import_key(rnp_t *rnp, char *f)
{
    pgp_io_t *io;
    unsigned  realarmor;
    int       done;

    io = rnp->io;
    realarmor = isarmoured(io, f, NULL, IMPORT_ARMOR_HEAD);
    done = rnp_key_store_load_from_file(rnp, rnp->pubring, realarmor, f);
    if (!done) {
        (void) fprintf(io->errs, "cannot import key from file %s\n", f);
        return RNP_FAIL;
    }
    return rnp_key_store_list(io, rnp->pubring, 0);
}

static uint32_t
get_numbits(const rnp_keygen_desc_t *key)
{
    switch (key->key_alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return key->rsa.modulus_bit_len;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        return ec_curves[key->ecc.curve].bitlen;
    default:
        return 0;
    }
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

/* generate a new key */
/* TODO: Does this need to take into account SSH keys? */
int
rnp_generate_key(rnp_t *rnp, const char *id)
{
    RNP_MSG("Generating a new key...\n");

    pgp_key_t *key;
    pgp_io_t * io;
    uint8_t *  uid;
    char       passphrase[MAX_PASSPHRASE_LENGTH] = {0};
    char       newid[1024] = {0};
    char       keyid[2 * PGP_KEY_ID_SIZE + 1] = {0};
    char *     cp = NULL;

    io = rnp->io;

    /* generate a new key */
    if (id) {
        snprintf(newid, sizeof(newid), "%s", id);
    } else {
        snprintf(newid,
                 sizeof(newid),
                 "%s %d-bit key <%s@localhost>",
                 pgp_show_pka(rnp->action.generate_key_ctx.key_alg),
                 get_numbits(&rnp->action.generate_key_ctx),
                 getenv("LOGNAME"));
    }
    uid = (uint8_t *) newid;

    key = pgp_generate_keypair(&rnp->action.generate_key_ctx, uid);
    if (key == NULL) {
        (void) fprintf(io->errs, "cannot generate key\n");
        return RNP_FAIL;
    }

    if (!rnp_key_store_add_key(io, rnp->pubring, key, PGP_PTAG_CT_PUBLIC_KEY) ||
        !rnp_key_store_add_key(io, rnp->secring, key, PGP_PTAG_CT_SECRET_KEY)) {
        pgp_keydata_free(key);
        return RNP_FAIL;
    }

    pgp_sprint_keydata(rnp->io, NULL, key, &cp, "signature ", &key->key.seckey.pubkey, 0);
    (void) fprintf(stdout, "%s", cp);
    free(cp);

    /* get the passphrase */
    rnp_strhexdump(keyid, key->sigid, PGP_KEY_ID_SIZE, "");
    memset(passphrase, 0, sizeof(passphrase));
    find_passphrase(rnp->user_input_fp, keyid, passphrase, sizeof(passphrase), rnp->pswdtries);

    /* write keypair */
    if (!rnp_key_store_write_to_file(
          rnp, rnp->secring, (uint8_t *) passphrase, 0, rnp->secpath)) {
        pgp_keydata_free(key);
        return RNP_FAIL;
    }

    if (!rnp_key_store_write_to_file(
          rnp, rnp->pubring, (uint8_t *) passphrase, 0, rnp->pubpath)) {
        pgp_keydata_free(key);
        return RNP_FAIL;
    }

    pgp_keydata_free(key);
    return RNP_OK;
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
    /* generate output file name if needed */
    if (out == NULL) {
        suffix = (ctx->armour) ? ".asc" : ".gpg";
        (void) snprintf(outname, sizeof(outname), "%s%s", f, suffix);
        out = outname;
    }
    return (int) pgp_encrypt_file(ctx, ctx->rnp->io, f, out, key);
}

#define ARMOR_HEAD "-----BEGIN PGP MESSAGE-----"

/* decrypt a file */
int
rnp_decrypt_file(rnp_ctx_t *ctx, const char *f, const char *out)
{
    pgp_io_t *io;
    unsigned  realarmor;
    unsigned  sshkeys;

    io = ctx->rnp->io;
    if (f == NULL) {
        (void) fprintf(io->errs, "rnp_decrypt_file: no filename specified\n");
        return RNP_FAIL;
    }
    realarmor = isarmoured(io, f, NULL, ARMOR_HEAD);
    sshkeys = (unsigned) use_ssh_keys(ctx->rnp);
    return pgp_decrypt_file(ctx->rnp->io,
                            f,
                            out,
                            ctx->rnp->secring,
                            ctx->rnp->pubring,
                            realarmor,
                            ctx->overwrite,
                            sshkeys,
                            ctx->rnp->user_input_fp,
                            ctx->rnp->pswdtries,
                            get_passphrase_cb);
}

/* sign a file */
int
rnp_sign_file(rnp_ctx_t * ctx,
              const char *userid,
              const char *f,
              const char *out,
              int         cleartext,
              int         detached)
{
    const pgp_key_t *keypair;
    const pgp_key_t *pubkey;
    pgp_seckey_t *   seckey;
    pgp_io_t *       io;
    int              attempts;
    int              ret;
    int              i;

    io = ctx->rnp->io;
    if (f == NULL) {
        (void) fprintf(io->errs, "rnp_sign_file: no filename specified\n");
        return RNP_FAIL;
    }
    /* get key with which to sign */
    if ((keypair = resolve_userid(ctx->rnp, ctx->rnp->secring, userid)) == NULL) {
        return RNP_FAIL;
    }
    ret = RNP_OK;
    attempts = ctx->rnp->pswdtries;

    for (i = 0, seckey = NULL; !seckey && (i < attempts || attempts == INFINITE_ATTEMPTS);
         i++) {
        if (ctx->rnp->user_input_fp == NULL) {
            /* print out the user id */
            pubkey = rnp_key_store_get_key_by_name(io, ctx->rnp->pubring, userid);
            if (pubkey == NULL) {
                (void) fprintf(io->errs, "rnp: warning - using pubkey from secring\n");
                pgp_print_keydata(io,
                                  ctx->rnp->pubring,
                                  keypair,
                                  "signature ",
                                  &keypair->key.seckey.pubkey,
                                  0);
            } else {
                pgp_print_keydata(
                  io, ctx->rnp->pubring, pubkey, "signature ", &pubkey->key.pubkey, 0);
            }
        }
        if (!use_ssh_keys(ctx->rnp)) {
            /* now decrypt key */
            seckey = pgp_decrypt_seckey(keypair, ctx->rnp->user_input_fp);
            if (seckey == NULL) {
                (void) fprintf(io->errs, "Bad passphrase\n");
            }
        } else {
            seckey = &((rnp_key_store_t *) ctx->rnp->secring)->keys[0].key.seckey;
        }
    }
    if (seckey == NULL) {
        (void) fprintf(io->errs, "Bad passphrase\n");
        return RNP_FAIL;
    }
    /* sign file */
    if (detached) {
        ret = pgp_sign_detached(ctx, io, f, out, seckey);
    } else {
        ret = pgp_sign_file(ctx, io, f, out, seckey, (unsigned) cleartext);
    }
    pgp_forget(seckey, sizeof(*seckey));
    return ret;
}

#define ARMOR_SIG_HEAD "-----BEGIN PGP (SIGNATURE|SIGNED MESSAGE)-----"

/* verify a file */
int
rnp_verify_file(rnp_ctx_t *ctx, const char *in, const char *out, int armored)
{
    pgp_validation_t result;
    pgp_io_t *       io;
    unsigned         realarmor;

    __PGP_USED(armored);
    (void) memset(&result, 0x0, sizeof(result));
    io = ctx->rnp->io;
    if (in == NULL) {
        (void) fprintf(io->errs, "rnp_verify_file: no filename specified\n");
        return RNP_FAIL;
    }
    realarmor = isarmoured(io, in, NULL, ARMOR_SIG_HEAD);
    if (pgp_validate_file(io, &result, in, out, (const int) realarmor, ctx->rnp->pubring)) {
        resultp(io, in, &result, ctx->rnp->pubring);
        return RNP_OK;
    }
    if (result.validc + result.invalidc + result.unknownc == 0) {
        (void) fprintf(io->errs, "\"%s\": No signatures found - is this a signed file?\n", in);
    } else if (result.invalidc == 0 && result.unknownc == 0) {
        (void) fprintf(
          io->errs, "\"%s\": file verification failure: invalid signature time\n", in);
    } else {
        (void) fprintf(
          io->errs,
          "\"%s\": verification failure: %u invalid signatures, %u unknown signatures\n",
          in,
          result.invalidc,
          result.unknownc);
    }
    return RNP_FAIL;
}

/* sign some memory */
int
rnp_sign_memory(rnp_ctx_t *    ctx,
                const char *   userid,
                char *         mem,
                size_t         size,
                char *         out,
                size_t         outsize,
                const unsigned cleartext)
{
    const pgp_key_t *keypair;
    const pgp_key_t *pubkey;
    pgp_seckey_t *   seckey;
    pgp_memory_t *   signedmem;
    pgp_io_t *       io;
    int              attempts;
    int              ret;
    int              i;

    io = ctx->rnp->io;
    if (mem == NULL) {
        (void) fprintf(io->errs, "rnp_sign_memory: no memory to sign\n");
        return 0;
    }
    if ((keypair = resolve_userid(ctx->rnp, ctx->rnp->secring, userid)) == NULL) {
        return 0;
    }
    ret = 1;
    attempts = ctx->rnp->pswdtries;

    for (i = 0, seckey = NULL; !seckey && (i < attempts || attempts == INFINITE_ATTEMPTS);
         i++) {
        if (ctx->rnp->user_input_fp == NULL) {
            /* print out the user id */
            pubkey = rnp_key_store_get_key_by_name(io, ctx->rnp->pubring, userid);
            if (pubkey == NULL) {
                (void) fprintf(io->errs, "rnp: warning - using pubkey from secring\n");
                pgp_print_keydata(io,
                                  ctx->rnp->pubring,
                                  keypair,
                                  "signature ",
                                  &keypair->key.seckey.pubkey,
                                  0);
            } else {
                pgp_print_keydata(
                  io, ctx->rnp->pubring, pubkey, "signature ", &pubkey->key.pubkey, 0);
            }
        }
        if (!use_ssh_keys(ctx->rnp)) {
            /* now decrypt key */
            seckey = pgp_decrypt_seckey(keypair, ctx->rnp->user_input_fp);
            if (seckey == NULL) {
                (void) fprintf(io->errs, "Bad passphrase\n");
            }
        } else {
            seckey = &((rnp_key_store_t *) ctx->rnp->secring)->keys[0].key.seckey;
        }
    }
    if (seckey == NULL) {
        (void) fprintf(io->errs, "Bad passphrase\n");
        return 0;
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
        ret = 0;
    }
    pgp_forget(seckey, sizeof(*seckey));
    return ret;
}

/* verify memory */
int
rnp_verify_memory(rnp_ctx_t *  ctx,
                  const void * in,
                  const size_t size,
                  void *       out,
                  size_t       outsize,
                  const int    armored)
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
      io, &result, signedmem, (out) ? &cat : NULL, armored, ctx->rnp->pubring);
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
rnp_encrypt_memory(
  rnp_ctx_t *ctx, const char *userid, void *in, const size_t insize, char *out, size_t outsize)
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
    if (in == out) {
        (void) fprintf(io->errs,
                       "rnp_encrypt_buf: input and output bufs need to be different\n");
        return 0;
    }
    if (outsize < insize) {
        (void) fprintf(io->errs, "rnp_encrypt_buf: input size is larger than output size\n");
        return 0;
    }
    enc = pgp_encrypt_buf(ctx, io, in, insize, keypair);
    m = MIN(pgp_mem_len(enc), outsize);
    (void) memcpy(out, pgp_mem_data(enc), m);
    pgp_memory_free(enc);
    return (int) m;
}

/* decrypt a chunk of memory */
int
rnp_decrypt_memory(
  rnp_ctx_t *ctx, const void *input, const size_t insize, char *out, size_t outsize)
{
    pgp_memory_t *mem;
    pgp_io_t *    io;
    unsigned      realarmour;
    unsigned      sshkeys;
    size_t        m;
    int           attempts;

    io = ctx->rnp->io;
    if (input == NULL) {
        (void) fprintf(io->errs, "rnp_decrypt_memory: no memory\n");
        return 0;
    }
    realarmour = isarmoured(io, NULL, input, ARMOR_HEAD);
    sshkeys = (unsigned) use_ssh_keys(ctx->rnp);
    attempts = ctx->rnp->pswdtries;
    mem = pgp_decrypt_buf(ctx->rnp->io,
                          input,
                          insize,
                          ctx->rnp->secring,
                          ctx->rnp->pubring,
                          realarmour,
                          sshkeys,
                          ctx->rnp->user_input_fp,
                          attempts,
                          get_passphrase_cb);
    if (mem == NULL) {
        return -1;
    }
    m = MIN(pgp_mem_len(mem), outsize);
    (void) memcpy(out, pgp_mem_data(mem), m);
    pgp_memory_free(mem);
    return (int) m;
}

/* list all the packets in a file */
int
rnp_list_packets(rnp_t *rnp, char *f, int armor)
{
    rnp_key_store_t *keyring;
    const unsigned   noarmor = 0;
    struct stat      st;
    pgp_io_t *       io;
    int              ret;

    io = rnp->io;
    if (f == NULL) {
        (void) fprintf(io->errs, "No file containing packets\n");
        return RNP_FAIL;
    }
    if (stat(f, &st) < 0) {
        (void) fprintf(io->errs, "No such file '%s'\n", f);
        return RNP_FAIL;
    }
    if ((keyring = calloc(1, sizeof(*keyring))) == NULL) {
        (void) fprintf(io->errs, "rnp_list_packets: bad alloc\n");
        return RNP_FAIL;
    }
    if (!rnp_key_store_load_from_file(rnp, keyring, noarmor, rnp->pubpath)) {
        free(keyring);
        (void) fprintf(io->errs, "cannot read pub keyring %s\n", rnp->pubpath);
        return RNP_FAIL;
    }
    rnp->pubring = keyring;
    ret = pgp_list_packets(io,
                           f,
                           (unsigned) armor,
                           rnp->secring,
                           rnp->pubring,
                           rnp->user_input_fp,
                           get_passphrase_cb);
    free(keyring);
    rnp->pubring = NULL;
    return ret;
}

/* validate all sigs in the pub keyring */
int
rnp_validate_sigs(rnp_t *rnp)
{
    pgp_validation_t result;

    return (int) pgp_validate_all_sigs(&result, rnp->pubring, NULL);
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
    /* clean up */
    json_object_put(ids);
    return idc;
}

/* find a key in keyring, and write it in ssh format */
int
rnp_write_sshkey(rnp_t *rnp, char *s, const char *userid, char *out, size_t size)
{
    const pgp_key_t *key;
    rnp_key_store_t *keyring;
    pgp_io_t *       io;
    unsigned         k;
    size_t           cc;
    char             f[MAXPATHLEN];

    keyring = NULL;
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
    if ((keyring = calloc(1, sizeof(*keyring))) == NULL) {
        (void) fprintf(stderr, "rnp_save_sshpub: bad alloc 2\n");
        goto done;
    }
    if (!rnp_key_store_load_from_file(rnp, rnp->pubring = keyring, 1, f)) {
        (void) fprintf(stderr, "cannot import key\n");
        goto done;
    }
    /* get rsa key */
    k = 0;
    key = rnp_key_store_get_next_key_by_name(rnp->io, rnp->pubring, userid, &k);
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
    if (keyring) {
        free(keyring);
    }
    return (int) cc;
}
