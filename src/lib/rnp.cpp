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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdbool.h>

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
#include <limits.h>
#include <sys/resource.h>

#include <rnp/rnp.h>
#include <rnp/rnp_def.h>
#include <rnp/rnp_sdk.h>
#include <rekey/rnp_key_store.h>

#include "pass-provider.h"
#include "key-provider.h"
#include <repgp/repgp.h>
#include <librepgp/packet-print.h>
#include <librepgp/packet-show.h>
#include <librepgp/validate.h>
#include "errors.h"
#include "memory.h"
#include "utils.h"
#include "crypto.h"
#include "crypto/common.h"
#include "defs.h"
#include <rnp/rnp_def.h>
#include "pgp-key.h"
#include "list.h"
#include "defaults.h"
#include <librepgp/stream-def.h>
#include <librepgp/stream-armor.h>
#include <librepgp/stream-parse.h>
#include <librepgp/stream-write.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-dump.h>

#include <json.h>
#include <rnp.h>

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
    key = rnp_key_store_get_key_by_name(io, keyring, userid, NULL);
    if (!key) {
        (void) fprintf(io->errs, "cannot find key '%s'\n", userid);
        return NULL;
    }
    return key;
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

/* format a string as (len, string) */
static int
formatstring(char *buffer, const uint8_t *s, size_t len)
{
    STORE32BE(buffer, len);
    (void) memcpy(&buffer[4], s, len);
    return 4 + (int) len;
}

static int
formatmpi(char *buffer, const pgp_mpi_t *val)
{
    size_t   len;
    uint8_t *cp;
    int      cc;

    len = mpi_bytes(val);
    if ((cp = (uint8_t *) calloc(1, len + 1)) == NULL) {
        RNP_LOG("calloc failure");
        return 0;
    }

    memcpy(cp + 1, val->mpi, len);
    cp[0] = 0x0;
    cc =
      (cp[1] & 0x80) ? formatstring(buffer, cp, len + 1) : formatstring(buffer, &cp[1], len);
    free(cp);
    return cc;
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
static rnp_result_t
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
            RNP_LOG("Warning - cannot turn off core dumps");
            return RNP_ERROR_GENERIC;
        } else if (limit.rlim_cur == 0) {
            return RNP_SUCCESS; // disabling core dumps ok
        } else {
            return RNP_ERROR_GENERIC; // failed for some reason?
        }
    }
    return RNP_ERROR_GENERIC;
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
    bool      coredumps = true;
    pgp_io_t *io;

    /* If system resource constraints are in effect then attempt to
     * disable core dumps.
     */
    if (!params->enable_coredumps) {
#ifdef HAVE_SYS_RESOURCE_H
        coredumps = disable_core_dumps() != RNP_SUCCESS;
#endif
    }

    if (coredumps) {
        fputs(
          "rnp: warning: core dumps may be enabled, sensitive data may be leaked to disk\n",
          stderr);
    }

    /* Initialize the context's io streams apparatus. */
    if (!init_new_io(rnp, params->outs, params->errs, params->ress)) {
        return RNP_ERROR_GENERIC;
    }
    io = rnp->io;

    // set the key provider
    rnp->key_provider.callback = rnp_key_provider_keyring;
    rnp->key_provider.userdata = rnp;

    // set the default password provider
    rnp->password_provider.callback = rnp_password_provider_stdin;
    rnp->password_provider.userdata = NULL;

    // setup file/pipe password input if requested
    if (params->passfd >= 0) {
        if (!set_pass_fd(rnp, params->passfd)) {
            return RNP_ERROR_GENERIC;
        }
        rnp->password_provider.callback = rnp_password_provider_file;
        rnp->password_provider.userdata = rnp->passfp;
    }

    if (params->password_provider.callback) {
        rnp->password_provider = params->password_provider;
    }

    if (params->userinputfd >= 0) {
        rnp->user_input_fp = fdopen(params->userinputfd, "r");
        if (!rnp->user_input_fp) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }

    rnp->pswdtries = MAX_PASSWORD_ATTEMPTS;

    /* set keystore type and pathes */
    if (!params->keystore_disabled) {
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
    }

    // Lazy mode can't fail
    (void) rng_init(&rnp->rng, RNG_DRBG);
    return RNP_SUCCESS;
}

/* finish off with the rnp_t struct */
void
rnp_end(rnp_t *rnp)
{
    rng_destroy(&rnp->rng);
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
    ctx->rng = &rnp->rng;
    return RNP_SUCCESS;
}

rng_t *
rnp_ctx_rng_handle(const rnp_ctx_t *ctx)
{
    assert(ctx->rng);
    return ctx->rng;
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
    list_destroy(&ctx->recipients);
    list_destroy(&ctx->signers);
    list_destroy(&ctx->passwords);
}

/* list the keys in a keyring */
bool
rnp_list_keys(rnp_t *rnp, const int psigs)
{
    if (rnp->pubring == NULL) {
        (void) fprintf(stderr, "No keyring\n");
        return false;
    }
    return rnp_key_store_list(rnp->io, rnp->pubring, psigs);
}

/* list the keys in a keyring, returning a JSON encoded string */
bool
rnp_list_keys_json(rnp_t *rnp, char **json, const int psigs)
{
    json_object *obj = json_object_new_array();

    if (!obj) {
        return false;
    }
    if (rnp->pubring == NULL) {
        (void) fprintf(stderr, "No keyring\n");
        return false;
    }
    if (!rnp_key_store_json(rnp->io, rnp->pubring, obj, psigs)) {
        (void) fprintf(stderr, "No keys in keyring\n");
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

DEFINE_ARRAY(strings_t, char *);

#ifndef HKP_VERSION
#define HKP_VERSION 1
#endif

/* find and list some keys in a keyring */
int
rnp_match_keys(rnp_t *rnp, char *name, const char *fmt, void *vp, const int psigs)
{
    pgp_key_t *key = NULL;
    strings_t  pubs;
    FILE *     fp = (FILE *) vp;

    if (name[0] == '0' && name[1] == 'x') {
        name += 2;
    }
    (void) memset(&pubs, 0x0, sizeof(pubs));
    do {
        key = rnp_key_store_get_key_by_name(rnp->io, rnp->pubring, name, NULL);
        if (!key) {
            return 0;
        }
        if (key != NULL) {
            ALLOC(char *, pubs.v, pubs.size, pubs.c, 10, 10, "rnp_match_keys", return 0);
            if (strcmp(fmt, "mr") == 0) {
                pgp_hkp_sprint_key(rnp->io, rnp->pubring, key, &pubs.v[pubs.c], psigs);
            } else {
                pgp_sprint_key(
                  rnp->io, rnp->pubring, key, &pubs.v[pubs.c], "signature ", psigs);
            }
            if (pubs.v[pubs.c] != NULL) {
                pubs.c += 1;
            }
        }
    } while (key != NULL);
    if (strcmp(fmt, "mr") == 0) {
        (void) fprintf(fp, "info:%d:%d\n", HKP_VERSION, pubs.c);
    } else {
        (void) fprintf(fp, "%d key%s found\n", pubs.c, (pubs.c == 1) ? "" : "s");
    }
    for (unsigned k = 0; k < pubs.c; k++) {
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
        key = rnp_key_store_get_key_by_name(rnp->io, rnp->pubring, name, key);
        if (!key) {
            return 0;
        }
        if (key != NULL) {
            if (strcmp(fmt, "mr") == 0) {
                pgp_hkp_sprint_key(rnp->io, rnp->pubring, key, &newkey, 0);
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
                                  pgp_is_primary_key_tag(pgp_get_key_type(key)) ? "pub" :
                                                                                  "sub",
                                  psigs);
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

/* find and list some public keys in a keyring */
int
rnp_match_pubkeys(rnp_t *rnp, char *name, void *vp)
{
    pgp_key_t *key = NULL;
    unsigned   k = 0;
    ssize_t    cc;
    char       out[1024 * 64];
    FILE *     fp = (FILE *) vp;

    do {
        key = rnp_key_store_get_key_by_name(rnp->io, rnp->pubring, name, key);
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

/* find a key in a keyring */
bool
rnp_find_key(rnp_t *rnp, const char *id)
{
    pgp_io_t * io;
    pgp_key_t *key;

    io = rnp->io;
    if (id == NULL) {
        (void) fprintf(io->errs, "NULL id to search for\n");
        return false;
    }
    key = rnp_key_store_get_key_by_name(rnp->io, rnp->pubring, id, NULL);
    if (!key) {
        return false;
    }
    return key != NULL;
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
        return (pgp_hkp_sprint_key(rnp->io, rnp->pubring, key, &newkey, 0) > 0) ? newkey :
                                                                                  NULL;
    }
    return (pgp_sprint_key(rnp->io, rnp->pubring, key, &newkey, "signature", 0) > 0) ? newkey :
                                                                                       NULL;
}

/* export a given key */
char *
rnp_export_key(rnp_t *rnp, const char *name, bool secret_key)
{
    const pgp_key_t *key;

    if (!rnp) {
        return NULL;
    }

    key = secret_key ? resolve_userid(rnp, rnp->secring, name) :
                       resolve_userid(rnp, rnp->pubring, name);
    if (!key) {
        return NULL;
    }
    return pgp_export_key(rnp, key);
}

/* import a key into our keyring */
int
rnp_import_key(rnp_t *rnp, char *f)
{
    rnp_key_store_t *tmp_keystore = NULL;
    bool             ret = false;
    list             imported_grips = NULL;
    list_item *      item = NULL;
    const char *     suffix = NULL;
    const char *     fmt = NULL;

    // guess the key format (TODO: surely this can be improved)
    size_t fname_len = strlen(f);
    if (fname_len < 4) {
        goto done;
    }
    suffix = f + fname_len - 4;
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
    if (!rnp_key_store_load_from_file(rnp->io, tmp_keystore, &rnp->key_provider)) {
        RNP_LOG("failed to load key from file %s", f);
        goto done;
    }
    if (!list_length(tmp_keystore->keys)) {
        RNP_LOG("failed to load any keys to import");
        goto done;
    }

    // loop through each key
    for (list_item *key_item = list_front(tmp_keystore->keys); key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *      key = (pgp_key_t *) key_item;
        pgp_key_t *      importedkey = NULL;
        rnp_key_store_t *dest = pgp_is_key_secret(key) ? rnp->secring : rnp->pubring;
        const char *     header = pgp_is_key_secret(key) ? "sec" : "pub";

        // check if it already exists
        importedkey = rnp_key_store_get_key_by_grip(rnp->io, dest, key->grip);
        if (!importedkey) {
            // print it out
            repgp_print_key(rnp->io, tmp_keystore, key, header, 0);

            // add it to the dest store
            if (!rnp_key_store_add_key(rnp->io, dest, key)) {
                RNP_LOG("failed to add key to destination key store");
                goto done;
            }
            // keep track of what keys have been imported
            list_append(&imported_grips, key->grip, sizeof(key->grip));
            importedkey = rnp_key_store_get_key_by_grip(rnp->io, dest, key->grip);
            list_item *subkey_grip = list_front(key->subkey_grips);
            while (subkey_grip) {
                pgp_key_t *subkey = rnp_key_store_get_key_by_grip(
                  rnp->io, tmp_keystore, (uint8_t *) subkey_grip);
                assert(subkey);
                if (!rnp_key_store_add_key(rnp->io, dest, subkey)) {
                    RNP_LOG("failed to add key to destination key store");
                    goto done;
                }
                // keep track of what keys have been imported
                list_append(&imported_grips, subkey->grip, sizeof(subkey->grip));
                subkey_grip = list_next(subkey_grip);
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

size_t
rnp_secret_count(rnp_t *rnp)
{
    return rnp->secring ? list_length(rnp->secring->keys) : 0;
}

size_t
rnp_public_count(rnp_t *rnp)
{
    return rnp->pubring ? list_length(rnp->pubring->keys) : 0;
}

bool
rnp_generate_key(rnp_t *rnp)
{
    RNP_MSG("Generating a new key...\n");

    rnp_action_keygen_t *action = &rnp->action.generate_key_ctx;
    pgp_key_t            primary_sec = {0};
    pgp_key_t            primary_pub = {0};
    pgp_key_t            subkey_sec = {0};
    pgp_key_t            subkey_pub = {0};
    char *               cp = NULL;
    key_store_format_t   key_format = ((rnp_key_store_t *) rnp->secring)->format;

    if (!pgp_generate_keypair(&rnp->rng,
                              &action->primary.keygen,
                              &action->subkey.keygen,
                              true,
                              &primary_sec,
                              &primary_pub,
                              &subkey_sec,
                              &subkey_pub,
                              key_format)) {
        RNP_LOG("failed to generate keys");
        return false;
    }

    // show the primary key
    pgp_sprint_key(rnp->io, NULL, &primary_pub, &cp, "pub", 0);
    (void) fprintf(stdout, "%s", cp);
    free(cp);

    // protect the primary key
    if (!rnp_key_add_protection(
          &primary_sec, key_format, &action->primary.protection, &rnp->password_provider)) {
        return false;
    }

    // show the subkey
    pgp_sprint_key(rnp->io, NULL, &subkey_pub, &cp, "sub", 0);
    (void) fprintf(stdout, "%s", cp);
    free(cp);

    // protect the subkey
    if (!rnp_key_add_protection(
          &subkey_sec, key_format, &action->subkey.protection, &rnp->password_provider)) {
        RNP_LOG("failed to protect keys");
        return false;
    }

    // add them all to the key store
    if (!rnp_key_store_add_key(rnp->io, rnp->secring, &primary_sec) ||
        !rnp_key_store_add_key(rnp->io, rnp->secring, &subkey_sec) ||
        !rnp_key_store_add_key(rnp->io, rnp->pubring, &primary_pub) ||
        !rnp_key_store_add_key(rnp->io, rnp->pubring, &subkey_pub)) {
        RNP_LOG("failed to add keys to key store");
        return false;
    }

    // update the keyring on disk
    if (!rnp_key_store_write_to_file(rnp->io, rnp->secring, 0) ||
        !rnp_key_store_write_to_file(rnp->io, rnp->pubring, 0)) {
        RNP_LOG("failed to write keyring");
        return false;
    }

    return true;
}

typedef struct pgp_parse_handler_param_t {
    char         in[PATH_MAX];
    char         out[PATH_MAX];
    bool         mem;
    bool         hasdst;
    pgp_source_t src;
    pgp_dest_t   dst;
} pgp_parse_handler_param_t;

/** @brief checks whether file exists already and asks user for the new filename
 *  @param path output file name with path. May be NULL, then user is asked for it.
 *  @param newpath preallocated pointer which will store the result on success
 *  @param maxlen maximum number of chars in newfile, including the trailing \0
 *  @param overwrite whether it is allowed to overwrite output file by default
 *  @return true on success, or false otherwise (user cancels the operation)
 **/

static bool
rnp_get_output_filename(const char *path, char *newpath, size_t maxlen, bool overwrite)
{
    char reply[10];

    if (!path || !path[0]) {
        fprintf(stdout, "Please enter the output filename: ");
        if (fgets(newpath, maxlen, stdin) == NULL) {
            return false;
        }
        rnp_strip_eol(newpath);
    } else {
        strncpy(newpath, path, maxlen);
    }

    while (true) {
        if (rnp_file_exists(newpath)) {
            if (overwrite) {
                unlink(newpath);
                return true;
            }

            fprintf(stdout,
                    "File '%s' already exists. Would you like to overwrite it (y/N)?",
                    newpath);

            if (fgets(reply, sizeof(reply), stdin) == NULL) {
                return false;
            }
            if (strlen(reply) > 0 && toupper(reply[0]) == 'Y') {
                unlink(newpath);
                return true;
            }

            fprintf(stdout, "Please enter the new filename: ");
            if (fgets(newpath, maxlen, stdin) == NULL) {
                return false;
            }

            rnp_strip_eol(newpath);

            if (strlen(newpath) == 0) {
                return false;
            }
        } else {
            return true;
        }
    }
}

/** @brief Initialize input and output for streamed RNP operation, based on filename/path
 *  @param ctx Initialized RNP operation context
 *  @param src Allocated source structure to put result in.
 *             May be null - then no input source will be initialized.
 *  @param dst Allocated dest structure to put result in. May be null, like src.
 *  @param in Input filename/path. For NULL or '-' stdin source will be created.
 *  @param out Output filename/path. For NULL or '-' stdout will be created, except some cases
 *  @return RNP_SUCCESS on success, or error code otherwise. Error code will be also returned
 *if both src and dst are NULL.
 **/

static rnp_result_t
rnp_initialize_io(
  rnp_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst, const char *in, const char *out)
{
    char         outname[PATH_MAX] = {0};
    char         newname[PATH_MAX] = {0};
    const char * ext = NULL;
    bool         is_stdin;
    rnp_result_t res = RNP_ERROR_GENERIC;

    is_stdin = !in || !in[0] || !strcmp(in, "-");

    if (src) {
        res = is_stdin ? init_stdin_src(src) : init_file_src(src, in);

        if (res) {
            return res;
        }
    }

    if (dst) {
        /* default to stdout */
        strncpy(outname, "-", sizeof(outname));

        if (out && out[0]) {
            /* give a room for trailing \0 */
            strncpy(outname, out, sizeof(outname) - 1);
        } else if (!is_stdin && (!out || !out[0])) {
            /* no output path is given - so trying to build it based on input path */
            /* try to add the extension depending on operation and flags */
            if (ctx->operation == RNP_OP_ENCRYPT_SIGN) {
                if (ctx->detached) {
                    /* for detached signature add .sig/.asc */
                    ext = ctx->armor ? EXT_ASC : EXT_SIG;
                } else if (ctx->clearsign) {
                    /* for cleartext add .asc */
                    ext = EXT_ASC;
                } else {
                    /* in all other cases add .pgp or .asc, depending on armor */
                    ext = ctx->armor ? EXT_ASC : EXT_PGP;
                }
            } else if ((ctx->operation == RNP_OP_ARMOR) && (ctx->armor)) {
                ext = EXT_ASC;
            }

            if (ext) {
                strncpy(outname, in, sizeof(outname) - 5);
                rnp_path_add_ext(outname, sizeof(outname), ext);
            }
        }

        if (!strcmp(outname, "-")) {
            res = init_stdout_dest(dst);
        } else if (!rnp_get_output_filename(
                     outname, newname, sizeof(newname), ctx->overwrite)) {
            RNP_LOG("Operation failed: file '%s' already exists.", outname);
            res = RNP_ERROR_BAD_PARAMETERS;
        } else {
            res = init_file_dest(dst, newname, false);
        }

        if (res && src) {
            src_close(src);
        }
    }

    return res;
}

/** @brief Initialize input and output for streamed RNP operation, based on memory buffer
 *  @param src Allocated source structure to put result in. May not be NULL.
 *  @param dst NULL or allocated dest structure to put result in.
 *  @param in Source memory buffer
 *  @param len Number of bytes in source memory buffer
 *  @return true on success. False return means RNP_ERROR_OUT_OF_MEMORY
 **/

static bool
rnp_initialize_mem_io(pgp_source_t *src, pgp_dest_t *dst, const void *in, size_t len)
{
    rnp_result_t result;

    /* initialize input */
    if ((result = init_mem_src(src, in, len, false))) {
        return false;
    }

    /* initialize output */
    if (dst && (result = init_mem_dest(dst, NULL, 0))) {
        src_close(src);
        return false;
    }

    return true;
}

static bool
rnp_parse_handler_dest(pgp_parse_handler_t *handler,
                       pgp_dest_t **        dst,
                       bool *               closedst,
                       const char *         filename)
{
    pgp_parse_handler_param_t *param = (pgp_parse_handler_param_t *) handler->param;
    rnp_result_t               res = RNP_ERROR_GENERIC;

    if (!handler->ctx) {
        return false;
    }

    if (handler->ctx->discard) {
        *closedst = true;
        res = init_null_dest(&param->dst);
    } else if (!param->mem) {
        *closedst = true;
        res = rnp_initialize_io(handler->ctx, NULL, &param->dst, param->in, param->out);
    } else {
        *closedst = false;
        res = init_mem_dest(&param->dst, NULL, 0);
    }

    if (res == RNP_SUCCESS) {
        param->hasdst = true;
        *dst = &param->dst;
    } else {
        *dst = NULL;
    }

    return res == RNP_SUCCESS;
}

static bool
rnp_parse_handler_src(pgp_parse_handler_t *handler, pgp_source_t *src)
{
    pgp_parse_handler_param_t *param = (pgp_parse_handler_param_t *) handler->param;
    char                       srcname[PATH_MAX] = {0};

    if (!param) {
        return false;
    }

    if (!param->mem) {
        if (rnp_path_has_ext(param->in, EXT_SIG) || rnp_path_has_ext(param->in, EXT_ASC)) {
            strncpy(srcname, param->in, sizeof(srcname) - 1);
            rnp_path_strip_ext(srcname);
            return init_file_src(src, srcname) == RNP_SUCCESS;
        }
    }

    return false;
}

static bool
rnp_init_parse_handler(pgp_parse_handler_t *handler, rnp_ctx_t *ctx)
{
    pgp_parse_handler_param_t *param;

    if (!(param = (pgp_parse_handler_param_t *) calloc(1, sizeof(*param)))) {
        return false;
    }

    /* context */
    ctx->operation = RNP_OP_DECRYPT_VERIFY;
    handler->ctx = ctx;

    /* handler */
    handler->password_provider = &ctx->rnp->password_provider;
    handler->key_provider = &ctx->rnp->key_provider;
    handler->dest_provider = rnp_parse_handler_dest;
    handler->src_provider = rnp_parse_handler_src;
    handler->on_signatures = (pgp_signatures_func_t *) ctx->on_signatures;
    handler->param = param;

    return true;
}

static void
rnp_free_parse_handler(pgp_parse_handler_t *handler)
{
    free(handler->param);
    memset(handler, 0, sizeof(*handler));
}

rnp_result_t
rnp_process_file(rnp_ctx_t *ctx, const char *in, const char *out)
{
    pgp_parse_handler_t        handler = {0};
    pgp_parse_handler_param_t *param = NULL;
    rnp_result_t               result;

    /* check parameters */
    if (in && (strlen(in) > sizeof(param->in))) {
        RNP_LOG("too long input path");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (out && (strlen(out) > sizeof(param->out))) {
        RNP_LOG("too long output path");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* initialize handler */
    if (!rnp_init_parse_handler(&handler, ctx)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    /* fill param */
    param = (pgp_parse_handler_param_t *) handler.param;
    param->mem = false;

    /* initialize input */
    if (rnp_initialize_io(ctx, &param->src, NULL, in, NULL)) {
        rnp_free_parse_handler(&handler);
        return RNP_ERROR_READ;
    }

    if (in) {
        strncpy(param->in, in, sizeof(param->in) - 1);
    }

    if (out) {
        strncpy(param->out, out, sizeof(param->out) - 1);
    }

    /* process source */
    if ((result = process_pgp_source(&handler, &param->src))) {
        RNP_LOG("error 0x%x", result);
    }

    /* cleanup */
    src_close(&param->src);
    rnp_free_parse_handler(&handler);

    return result;
}

rnp_result_t
rnp_process_mem(
  rnp_ctx_t *ctx, const void *in, size_t len, void *out, size_t outlen, size_t *reslen)
{
    pgp_parse_handler_t        handler = {0};
    pgp_parse_handler_param_t *param = NULL;
    void *                     outdata;
    rnp_result_t               result;

    /* initialize handler */
    if (!rnp_init_parse_handler(&handler, ctx)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    /* fill param */
    param = (pgp_parse_handler_param_t *) handler.param;
    param->mem = true;

    /* initialize input */
    if (!rnp_initialize_mem_io(&param->src, NULL, in, len)) {
        rnp_free_parse_handler(&handler);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    /* process source */
    if ((result = process_pgp_source(&handler, &param->src))) {
        RNP_LOG("error 0x%x", result);
    }

    /* copy result to the output */
    if (reslen) {
        *reslen = result ? 0 : param->dst.writeb;
    }

    if ((result == RNP_SUCCESS) && out) {
        if (outlen < param->dst.writeb) {
            result = RNP_ERROR_SHORT_BUFFER;
        } else {
            outdata = mem_dest_get_memory(&param->dst);
            memcpy(out, outdata, param->dst.writeb);
        }
    }

    /* cleanup */
    src_close(&param->src);
    if (param->hasdst) {
        dst_close(&param->dst, result != RNP_SUCCESS);
    }
    rnp_free_parse_handler(&handler);

    return result;
}

rnp_result_t
rnp_dump_file(rnp_ctx_t *ctx, const char *in, const char *out)
{
    pgp_source_t   src;
    pgp_dest_t     dst;
    rnp_dump_ctx_t dumpctx = {0};
    rnp_result_t   result;

    if (rnp_initialize_io(ctx, &src, &dst, in, out)) {
        return RNP_ERROR_READ;
    }

    /* process source */
    if ((result = stream_dump_packets(&dumpctx, &src, &dst))) {
        RNP_LOG("error 0x%x", result);
    }

    /* cleanup */
    src_close(&src);
    dst_close(&dst, result);

    return result;
}

typedef struct pgp_write_handler_param_t {
    pgp_source_t src;
    pgp_dest_t   dst;
} pgp_write_handler_param_t;

static bool
rnp_init_write_handler(pgp_write_handler_t *handler, rnp_ctx_t *ctx)
{
    pgp_write_handler_param_t *param;

    ctx->operation = RNP_OP_ENCRYPT_SIGN;

    if (!(param = (pgp_write_handler_param_t *) calloc(1, sizeof(*param)))) {
        return false;
    }

    handler->password_provider = &ctx->rnp->password_provider;
    handler->key_provider = &ctx->rnp->key_provider;
    handler->ctx = ctx;
    handler->param = param;

    return true;
}

static void
rnp_free_write_handler(pgp_write_handler_t *handler)
{
    free(handler->param);
    memset(handler, 0, sizeof(*handler));
}

static rnp_result_t
rnp_call_protect_operation(pgp_write_handler_t *handler, pgp_source_t *src, pgp_dest_t *dst)
{
    size_t signc, encrc, passc;

    signc = list_length(handler->ctx->signers);
    encrc = list_length(handler->ctx->recipients);
    passc = list_length(handler->ctx->passwords);

    if ((encrc || passc) && signc) {
        return rnp_encrypt_sign_src(handler, src, dst);
    } else if (signc) {
        return rnp_sign_src(handler, src, dst);
    } else if (encrc || passc) {
        return rnp_encrypt_src(handler, src, dst);
    } else {
        RNP_LOG("no signers or recipients");
        return RNP_ERROR_BAD_PARAMETERS;
    }
}

rnp_result_t
rnp_protect_file(rnp_ctx_t *ctx, const char *in, const char *out)
{
    pgp_write_handler_t        handler = {0};
    pgp_write_handler_param_t *param;
    rnp_result_t               result;

    /* initialize write handler */
    if (!rnp_init_write_handler(&handler, ctx)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_write_handler_param_t *) handler.param;

    /* initialize input/output */
    if ((result = rnp_initialize_io(ctx, &param->src, &param->dst, in, out))) {
        RNP_LOG("failed to initialize reading or writing");
        rnp_free_write_handler(&handler);
        return result;
    }

    result = rnp_call_protect_operation(&handler, &param->src, &param->dst);

    if (result != RNP_SUCCESS) {
        RNP_LOG("failed with error code 0x%x", (int) result);
    }

    src_close(&param->src);
    dst_close(&param->dst, result != RNP_SUCCESS);
    rnp_free_write_handler(&handler);
    return result;
}

rnp_result_t
rnp_protect_mem(
  rnp_ctx_t *ctx, const void *in, size_t len, void *out, size_t outlen, size_t *reslen)
{
    pgp_write_handler_t        handler = {0};
    pgp_write_handler_param_t *param;
    rnp_result_t               result;
    void *                     outdata;

    if (!rnp_init_write_handler(&handler, ctx)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_write_handler_param_t *) handler.param;

    /* initialize input and output */
    if (!rnp_initialize_mem_io(&param->src, &param->dst, in, len)) {
        rnp_free_write_handler(&handler);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    /* do encryption */
    result = rnp_call_protect_operation(&handler, &param->src, &param->dst);
    if (result != RNP_SUCCESS) {
        RNP_LOG("failed with error code 0x%x", (int) result);
    }

    /* copy result to the output */
    if (reslen) {
        *reslen = result ? 0 : param->dst.writeb;
    }

    if ((result == RNP_SUCCESS) && out) {
        if (outlen < param->dst.writeb) {
            result = RNP_ERROR_SHORT_BUFFER;
        } else {
            outdata = mem_dest_get_memory(&param->dst);
            memcpy(out, outdata, param->dst.writeb);
        }
    }

    src_close(&param->src);
    dst_close(&param->dst, result != RNP_SUCCESS);
    rnp_free_write_handler(&handler);
    return result;
}

rnp_result_t
rnp_armor_stream(rnp_ctx_t *ctx, bool armor, const char *in, const char *out)
{
    pgp_source_t      src;
    pgp_dest_t        dst;
    rnp_result_t      result;
    pgp_armored_msg_t msgtype;

    ctx->operation = RNP_OP_ARMOR;
    ctx->armor = armor;

    if ((result = rnp_initialize_io(ctx, &src, &dst, in, out))) {
        RNP_LOG("failed to initialize reading or writing");
        return result;
    }

    if (armor) {
        msgtype = (pgp_armored_msg_t) ctx->armortype;
        if (msgtype == PGP_ARMORED_UNKNOWN) {
            msgtype = rnp_armor_guess_type(&src);
        }

        result = rnp_armor_source(&src, &dst, msgtype);
    } else {
        result = rnp_dearmor_source(&src, &dst);
    }

    if (result != RNP_SUCCESS) {
        RNP_LOG("error code 0x%x", result);
    }

    src_close(&src);
    dst_close(&dst, result != RNP_SUCCESS);
    return result;
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
    pgp_key_t *key = NULL;
    pgp_io_t * io;
    size_t     cc;
    char       f[MAXPATHLEN];

    io = NULL;
    cc = 0;
    if ((io = (pgp_io_t *) calloc(1, sizeof(*io))) == NULL) {
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

    if (!rnp_key_store_load_from_file(rnp->io, rnp->pubring, NULL)) {
        (void) fprintf(stderr, "cannot import key\n");
        goto done;
    }

    /* get rsa key */
    key = rnp_key_store_get_key_by_name(rnp->io, rnp->pubring, userid, key);
    if (!key) {
        (void) fprintf(stderr, "no key found for '%s'\n", userid);
        goto done;
    }
    if (pgp_get_key_alg(key) != PGP_PKA_RSA) {
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
    cc += formatmpi((char *) &out[cc], &pgp_get_key_material(key)->rsa.e);
    cc += formatmpi((char *) &out[cc], &pgp_get_key_material(key)->rsa.n);
done:
    if (io) {
        free(io);
    }
    return (int) cc;
}

rnp_result_t
rnp_encrypt_set_pass_info(rnp_symmetric_pass_info_t *info,
                          const char *               password,
                          pgp_hash_alg_t             hash_alg,
                          size_t                     iterations,
                          pgp_symm_alg_t             s2k_cipher)
{
    info->s2k.usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
    info->s2k.specifier = PGP_S2KS_ITERATED_AND_SALTED;
    info->s2k.hash_alg = hash_alg;
    if (!rng_generate(info->s2k.salt, sizeof(info->s2k.salt))) {
        return RNP_ERROR_GENERIC;
    }
    info->s2k.iterations = pgp_s2k_encode_iterations(iterations);
    info->s2k_cipher = s2k_cipher;
    /* Note: we're relying on the fact that a longer-than-needed key length
     * here does not change the entire derived key (it just generates unused
     * extra bytes at the end). We derive a key of our maximum supported length,
     * which is a bit wasteful.
     *
     * This is done because we do not yet know what cipher this key will actually
     * end up being used with until later.
     *
     * An alternative would be to keep a list of actual passwords and s2k params,
     * and save the key derivation for later.
     */
    if (!pgp_s2k_derive_key(&info->s2k, password, info->key, sizeof(info->key))) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_encrypt_add_password(rnp_ctx_t *ctx)
{
    rnp_result_t              ret = RNP_ERROR_GENERIC;
    rnp_symmetric_pass_info_t info = {{(pgp_s2k_usage_t) 0}};
    char                      password[MAX_PASSWORD_LENGTH] = {0};
    pgp_password_ctx_t        pswdctx = {.op = PGP_OP_ENCRYPT_SYM, .key = NULL};

    if (!pgp_request_password(
          &ctx->rnp->password_provider, &pswdctx, password, sizeof(password))) {
        return RNP_ERROR_BAD_PASSWORD;
    }

    if ((ret =
           rnp_encrypt_set_pass_info(&info,
                                     password,
                                     ctx->halg /* TODO: should be separate s2k-specific */,
                                     DEFAULT_S2K_ITERATIONS /* TODO: make this configurable */,
                                     ctx->ealg /* TODO: should be separate s2k-specific */))) {
        goto done;
    }
    if (!list_append(&ctx->passwords, &info, sizeof(info))) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    ret = RNP_SUCCESS;

done:
    pgp_forget(password, sizeof(password));
    pgp_forget(&info, sizeof(info));
    return ret;
}
