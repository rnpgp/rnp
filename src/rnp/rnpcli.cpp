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

#include <limits.h>
#include <sys/resource.h>

#include "rnpcli.h"
#include <rekey/rnp_key_store.h>

#include "utils.h"
#include "crypto.h"
#include "crypto/common.h"
#include "pgp-key.h"
#include "defaults.h"
#include <librepgp/packet-show.h>
#include <librepgp/stream-def.h>
#include <librepgp/stream-ctx.h>
#include <librepgp/stream-armor.h>
#include <librepgp/stream-parse.h>
#include <librepgp/stream-write.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-key.h>
#include <librepgp/stream-dump.h>
#include <librekey/key_store_internal.h>
#include <json.h>

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
rnp_result_t
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

bool
set_pass_fd(FILE **file, int passfd)
{
    if (!file) {
        return false;
    }
    *file = fdopen(passfd, "r");
    if (!*file) {
        RNP_LOG("cannot open fd %d for reading", passfd);
        return false;
    }
    return true;
}

/** @brief key provider callback which searches for key in rnp_key_store_t. userdata must be
 *pointer to the rnp_t structure
 **/
static pgp_key_t *
rnp_key_provider_keyring(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    rnp_t *rnp = (rnp_t *) userdata;

    if (!rnp) {
        return NULL;
    }
    return rnp_key_provider_store(ctx, ctx->secret ? rnp->secring : rnp->pubring);
}

/*************************************************************************/
/* exported functions start here                                         */
/*************************************************************************/

/* Initialize a rnp_t structure */
rnp_result_t
rnp_init(rnp_t *rnp, const rnp_cfg_t *cfg)
{
    bool coredumps = true;

    /* If system resource constraints are in effect then attempt to
     * disable core dumps.
     */
    if (!rnp_cfg_getbool(cfg, CFG_COREDUMPS)) {
#ifdef HAVE_SYS_RESOURCE_H
        coredumps = disable_core_dumps() != RNP_SUCCESS;
#endif
    }

    if (coredumps) {
        fputs(
          "rnp: warning: core dumps may be enabled, sensitive data may be leaked to disk\n",
          stderr);
    }

    /* Configure the results stream. */
    const char *ress = rnp_cfg_getstr(cfg, CFG_IO_RESS);
    if (!ress || !strcmp(ress, "<stderr>")) {
        rnp->resfp = stderr;
    } else if (strcmp(ress, "<stdout>") == 0) {
        rnp->resfp = stdout;
    } else if (!(rnp->resfp = fopen(ress, "w"))) {
        fprintf(stderr, "cannot open results %s for writing\n", ress);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // set the key provider
    rnp->key_provider.callback = rnp_key_provider_keyring;
    rnp->key_provider.userdata = rnp;

    // set the default password provider
    rnp->password_provider.callback = rnp_password_provider_stdin;
    rnp->password_provider.userdata = NULL;

    // setup file/pipe password input if requested
    if (rnp_cfg_getint_default(cfg, CFG_PASSFD, -1) >= 0) {
        if (!set_pass_fd(&rnp->passfp, rnp_cfg_getint(cfg, CFG_PASSFD))) {
            return RNP_ERROR_GENERIC;
        }
        rnp->password_provider.callback = rnp_password_provider_file;
        rnp->password_provider.userdata = rnp->passfp;
    }

    rnp->pswdtries = MAX_PASSWORD_ATTEMPTS;

    /* set keystore type and pathes */
    if (rnp_cfg_getstr(cfg, CFG_KR_PUB_PATH) && rnp_cfg_getstr(cfg, CFG_KR_PUB_FORMAT)) {
        rnp->pubring = rnp_key_store_new(rnp_cfg_getstr(cfg, CFG_KR_PUB_FORMAT),
                                         rnp_cfg_getstr(cfg, CFG_KR_PUB_PATH));
        if (!rnp->pubring) {
            RNP_LOG("can't create empty pubring keystore");
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }
    if (rnp_cfg_getstr(cfg, CFG_KR_SEC_PATH) && rnp_cfg_getstr(cfg, CFG_KR_SEC_FORMAT)) {
        rnp->secring = rnp_key_store_new(rnp_cfg_getstr(cfg, CFG_KR_SEC_FORMAT),
                                         rnp_cfg_getstr(cfg, CFG_KR_SEC_PATH));
        if (!rnp->secring) {
            RNP_LOG("can't create empty secring keystore");
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }
    if (rnp_cfg_getstr(cfg, CFG_KR_DEF_KEY)) {
        rnp->defkey = strdup(rnp_cfg_getstr(cfg, CFG_KR_DEF_KEY));
        if (!rnp->defkey) {
            RNP_LOG("defkey allocation failed");
            return RNP_ERROR_OUT_OF_MEMORY;
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
    if (rnp->resfp && (rnp->resfp != stderr) && (rnp->resfp != stdout)) {
        fclose(rnp->resfp);
        rnp->resfp = NULL;
    }
}

bool
rnp_load_keyrings(rnp_t *rnp, bool loadsecret)
{
    char id[MAX_ID_LENGTH];

    rnp_key_store_t *pubring = rnp->pubring;
    rnp_key_store_t *secring = rnp->secring;

    rnp_key_store_clear(pubring);

    if (!rnp_key_store_load_from_path(pubring, &rnp->key_provider)) {
        RNP_LOG("cannot read pub keyring");
        return false;
    }

    if (rnp_key_store_get_key_count(pubring) < 1) {
        RNP_LOG("pub keyring '%s' is empty", ((rnp_key_store_t *) pubring)->path);
        return false;
    }

    /* Only read secret keys if we need to */
    if (loadsecret) {
        rnp_key_store_clear(secring);
        if (!rnp_key_store_load_from_path(secring, &rnp->key_provider)) {
            RNP_LOG("cannot read sec keyring");
            return false;
        }

        if (rnp_key_store_get_key_count(secring) < 1) {
            RNP_LOG("sec keyring '%s' is empty", ((rnp_key_store_t *) secring)->path);
            return false;
        }

        /* Now, if we don't have a valid user, use the first
         * in secring.
         */
        if (!rnp->defkey) {
            if (rnp_key_store_get_first_ring(secring, id, sizeof(id), 0)) {
                rnp->defkey = strdup(id);
            }
        }

    } else if (!rnp->defkey) {
        /* encrypting - get first in pubring */
        if (rnp_key_store_get_first_ring(rnp->pubring, id, sizeof(id), 0)) {
            rnp->defkey = strdup(id);
        }
    }

    return true;
}

/* resolve the userid */
pgp_key_t *
resolve_userid(rnp_t *rnp, const rnp_key_store_t *keyring, const char *userid)
{
    pgp_key_t *key;

    if (userid == NULL) {
        return NULL;
    }
    key = rnp_key_store_get_key_by_name(keyring, userid, NULL);
    if (!key) {
        (void) fprintf(stderr, "cannot find key '%s'\n", userid);
        return NULL;
    }
    return key;
}

/* find a key in a keyring */
bool
rnp_find_key(rnp_t *rnp, const char *id)
{
    pgp_key_t *key;

    if (id == NULL) {
        RNP_LOG("NULL id to search for");
        return false;
    }
    key = rnp_key_store_get_key_by_name(rnp->pubring, id, NULL);
    if (!key) {
        return false;
    }
    return key != NULL;
}

/* export a given key */
char *
rnp_export_key(rnp_t *rnp, const char *name, bool secret_key)
{
    const pgp_key_t *      key;
    const rnp_key_store_t *keyring;

    if (!rnp) {
        return NULL;
    }

    keyring = secret_key ? rnp->secring : rnp->pubring;
    key = resolve_userid(rnp, keyring, name);
    if (!key) {
        return NULL;
    }
    return pgp_export_key(keyring, key);
}

bool
rnp_add_key(rnp_t *rnp, const char *path, bool print)
{
    rnp_key_store_t *tmp_keystore = NULL;
    bool             ret = false;
    const char *     suffix = NULL;
    const char *     fmt = NULL;
    char             keyid[MAX_ID_LENGTH] = {0};

    // guess the key format (TODO: surely this can be improved)
    size_t fname_len = strlen(path);
    if (fname_len < 4) {
        goto done;
    }
    suffix = path + fname_len - 4;
    if (strcmp(suffix, ".asc") == 0 || strcmp(suffix, ".gpg") == 0) {
        fmt = RNP_KEYSTORE_GPG;
    } else if (strcmp(suffix, ".kbx") == 0) {
        fmt = RNP_KEYSTORE_KBX;
    } else if ((strcmp(suffix, ".key") == 0) || (strcmp(suffix, "v1.d") == 0)) {
        fmt = RNP_KEYSTORE_G10;
    } else {
        RNP_LOG("Warning: failed to guess key format, assuming GPG.");
        fmt = RNP_KEYSTORE_GPG;
    }

    // create a temporary key store
    tmp_keystore = rnp_key_store_new(fmt, path);
    if (!tmp_keystore) {
        goto done;
    }
    // load the key(s)
    if (!rnp_key_store_load_from_path(tmp_keystore, &rnp->key_provider)) {
        RNP_LOG("failed to load key from file %s", path);
        goto done;
    }
    if (!rnp_key_store_get_key_count(tmp_keystore)) {
        RNP_LOG("failed to load any keys");
        goto done;
    }

    // loop through each key
    for (list_item *ki = list_front(rnp_key_store_get_keys(tmp_keystore)); ki;
         ki = list_next(ki)) {
        pgp_key_t  keycp = {};
        pgp_key_t *imported = (pgp_key_t *) ki;
        pgp_key_t *exkey = NULL;
        size_t     expackets = 0;
        bool       changed = false;

        /* validate imported key's material */
        if (validate_pgp_key_material(pgp_key_get_material(imported), &rnp->rng)) {
            RNP_LOG("invalid key material in added key");
            continue;
        }
        /* add public key */
        if (pgp_key_copy(&keycp, imported, true)) {
            RNP_LOG("failed to create key copy");
            continue;
        }
        exkey = rnp_key_store_get_key_by_grip(rnp->pubring, pgp_key_get_grip(imported));
        expackets = exkey ? pgp_key_get_rawpacket_count(exkey) : 0;
        if (!(exkey = rnp_key_store_add_key(rnp->pubring, &keycp))) {
            RNP_LOG("failed to add key to the keyring");
            pgp_key_free_data(&keycp);
            continue;
        }
        changed = pgp_key_get_rawpacket_count(exkey) > expackets;

        /* add secret key if there is one */
        if (!pgp_key_is_secret(imported)) {
            if (changed && print) {
                rnp_print_key_info(rnp->resfp, rnp->pubring, exkey, false);
            }
            continue;
        }

        if (pgp_key_copy(&keycp, imported, false)) {
            RNP_LOG("failed to create secret key copy");
            continue;
        }
        exkey = rnp_key_store_get_key_by_grip(rnp->secring, pgp_key_get_grip(imported));
        expackets = exkey ? pgp_key_get_rawpacket_count(exkey) : 0;
        if (!(exkey = rnp_key_store_add_key(rnp->secring, &keycp))) {
            RNP_LOG("failed to add key to the keyring");
            pgp_key_free_data(&keycp);
            continue;
        }

        if (print && (changed || (pgp_key_get_rawpacket_count(exkey) > expackets))) {
            rnp_print_key_info(rnp->resfp, rnp->secring, exkey, false);
        }
    }

    /* set the default key if needed */
    if (!rnp->defkey && rnp_key_store_get_first_ring(rnp->pubring, keyid, sizeof(keyid), 0)) {
        rnp->defkey = strdup(keyid);
    }

    ret = true;
done:
    rnp_key_store_free(tmp_keystore);
    return ret;
}

/* import a key into our keyring */
bool
rnp_import_key(rnp_t *rnp, const char *f)
{
    if (!rnp_add_key(rnp, f, true)) {
        return false;
    }

    if (!rnp_key_store_write_to_path(rnp->secring) ||
        !rnp_key_store_write_to_path(rnp->pubring)) {
        RNP_LOG("failed to write keyring");
        return false;
    }

    return true;
}

/* return the time as a string */
char *
ptimestr(char *dest, size_t size, time_t t)
{
    struct tm *tm;

    tm = gmtime(&t);
    (void) snprintf(
      dest, size, "%04d-%02d-%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    return dest;
}

static char *
key_usage_str(uint8_t flags, char *buf)
{
    char *orig = buf;

    if (flags & PGP_KF_ENCRYPT) {
        *buf++ = 'E';
    }
    if (flags & PGP_KF_SIGN) {
        *buf++ = 'S';
    }
    if (flags & PGP_KF_CERTIFY) {
        *buf++ = 'C';
    }
    if (flags & PGP_KF_AUTH) {
        *buf++ = 'A';
    }
    *buf = '\0';
    return orig;
}

void
rnp_print_key_info(FILE *fp, rnp_key_store_t *keyring, const pgp_key_t *key, bool psigs)
{
    char        buf[64] = {0};
    const char *header = NULL;

    /* header */
    if (pgp_key_is_secret(key)) {
        header = pgp_key_is_primary_key(key) ? "sec" : "ssb";
    } else {
        header = pgp_key_is_primary_key(key) ? "pub" : "sub";
    }
    if (pgp_key_is_primary_key(key)) {
        fprintf(fp, "\n");
    }
    fprintf(fp, "%s   ", header);
    /* key bits */
    fprintf(fp, "%d/", (int) pgp_key_get_bits(key));
    /* key algorithm */
    fprintf(fp, "%s ", pgp_show_pka(pgp_key_get_alg(key)));
    /* key id */
    rnp_strhexdump(buf, pgp_key_get_keyid(key), PGP_KEY_ID_SIZE, "");
    fprintf(fp, "%s", buf);
    /* key creation time */
    fprintf(fp, " %s", ptimestr(buf, sizeof(buf), pgp_key_get_creation(key)));
    /* key usage */
    fprintf(fp, " [%s]", key_usage_str(pgp_key_get_flags(key), buf));
    /* key expiration */
    if (pgp_key_get_expiration(key) > 0) {
        time_t now = time(NULL);
        time_t expiry = pgp_key_get_creation(key) + pgp_key_get_expiration(key);
        ptimestr(buf, sizeof(buf), expiry);
        fprintf(fp, " [%s %s]", expiry < now ? "EXPIRED" : "EXPIRES", buf);
    }
    /* fingerprint */
    rnp_strhexdump(buf, pgp_key_get_fp(key)->fingerprint, pgp_key_get_fp(key)->length, "");
    fprintf(fp, "\n      %s\n", buf);
    /* user ids */
    for (size_t i = 0; i < pgp_key_get_userid_count(key); i++) {
        pgp_revoke_t *revoke = pgp_key_get_userid_revoke(key, i);
        if (revoke && (revoke->code == PGP_REVOCATION_COMPROMISED)) {
            continue;
        }

        /* userid itself with revocation status */
        fprintf(fp, "uid           %s", pgp_key_get_userid(key, i));
        fprintf(fp, "%s\n", revoke ? "[REVOKED]" : "");

        /* print signatures only if requested */
        if (!psigs) {
            continue;
        }

        for (size_t j = 0; j < pgp_key_get_subsig_count(key); j++) {
            pgp_subsig_t *   subsig = pgp_key_get_subsig(key, j);
            uint8_t          signerid[PGP_KEY_ID_SIZE] = {0};
            const pgp_key_t *signer = NULL;

            if (subsig->uid != i) {
                continue;
            }

            signature_get_keyid(&subsig->sig, signerid);
            signer = rnp_key_store_get_key_by_id(keyring, signerid, NULL);

            /* signer key id */
            rnp_strhexdump(buf, signerid, PGP_KEY_ID_SIZE, "");
            fprintf(fp, "sig           %s ", buf);
            /* signature creation time */
            fprintf(
              fp, "%s", ptimestr(buf, sizeof(buf), signature_get_creation(&subsig->sig)));
            /* signer's userid */
            fprintf(fp, " %s\n", signer ? pgp_key_get_primary_userid(signer) : "[unknown]");
        }
    }
}

size_t
rnp_secret_count(rnp_t *rnp)
{
    return rnp->secring ? rnp_key_store_get_key_count(rnp->secring) : 0;
}

size_t
rnp_public_count(rnp_t *rnp)
{
    return rnp->pubring ? rnp_key_store_get_key_count(rnp->pubring) : 0;
}

pgp_key_t *
rnp_generate_key(rnp_t *rnp)
{
    rnp_action_keygen_t *action = &rnp->action.generate_key_ctx;
    pgp_key_t            primary_sec = {0};
    pgp_key_t            primary_pub = {0};
    pgp_key_t            subkey_sec = {0};
    pgp_key_t            subkey_pub = {0};
    pgp_key_t *          result = NULL;
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
        return NULL;
    }

    // protect the primary key
    if (!rnp_key_add_protection(
          &primary_sec, key_format, &action->primary.protection, &rnp->password_provider)) {
        return NULL;
    }

    // protect the subkey
    if (!rnp_key_add_protection(
          &subkey_sec, key_format, &action->subkey.protection, &rnp->password_provider)) {
        RNP_LOG("failed to protect keys");
        return NULL;
    }

    // add them all to the key store
    if (!(result = rnp_key_store_add_key(rnp->secring, &primary_sec)) ||
        !rnp_key_store_add_key(rnp->secring, &subkey_sec) ||
        !rnp_key_store_add_key(rnp->pubring, &primary_pub) ||
        !rnp_key_store_add_key(rnp->pubring, &subkey_pub)) {
        RNP_LOG("failed to add keys to key store");
        return NULL;
    }

    // update the keyring on disk
    if (!rnp_key_store_write_to_path(rnp->secring) ||
        !rnp_key_store_write_to_path(rnp->pubring)) {
        RNP_LOG("failed to write keyring");
        return NULL;
    }

    return result;
}

typedef struct pgp_parse_handler_param_t {
    char         in[PATH_MAX];
    char         out[PATH_MAX];
    bool         mem;
    bool         hasdst;
    pgp_source_t src;
    pgp_dest_t   dst;
    rnp_ctx_t *  ctx;
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

static void
rnp_signatures_func_proxy(pgp_signature_info_t *sigs, int count, void *param)
{
    pgp_parse_handler_param_t *hparam = (pgp_parse_handler_param_t *) param;
    if (hparam->ctx->on_signatures) {
        pgp_signatures_func_t *func = (pgp_signatures_func_t *) hparam->ctx->on_signatures;
        func(sigs, count, hparam->ctx->sig_cb_param);
    }
}

static bool
rnp_init_parse_handler(pgp_parse_handler_t *handler, rnp_t *rnp, rnp_ctx_t *ctx)
{
    pgp_parse_handler_param_t *param;

    /* param */
    if (!(param = (pgp_parse_handler_param_t *) calloc(1, sizeof(*param)))) {
        return false;
    }
    param->ctx = ctx;

    /* context */
    ctx->operation = RNP_OP_DECRYPT_VERIFY;
    handler->ctx = ctx;

    /* handler */
    handler->password_provider = &rnp->password_provider;
    handler->key_provider = &rnp->key_provider;
    handler->dest_provider = rnp_parse_handler_dest;
    handler->src_provider = rnp_parse_handler_src;
    handler->on_signatures = rnp_signatures_func_proxy;
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
rnp_process_file(rnp_t *rnp, rnp_ctx_t *ctx, const char *in, const char *out)
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
    if (!rnp_init_parse_handler(&handler, rnp, ctx)) {
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
rnp_process_mem(rnp_t *     rnp,
                rnp_ctx_t * ctx,
                const void *in,
                size_t      len,
                void *      out,
                size_t      outlen,
                size_t *    reslen)
{
    pgp_parse_handler_t        handler = {0};
    pgp_parse_handler_param_t *param = NULL;
    void *                     outdata;
    rnp_result_t               result;

    /* initialize handler */
    if (!rnp_init_parse_handler(&handler, rnp, ctx)) {
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
    dumpctx.dump_grips = true;
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
rnp_init_write_handler(pgp_write_handler_t *handler, rnp_t *rnp, rnp_ctx_t *ctx)
{
    pgp_write_handler_param_t *param;

    ctx->operation = RNP_OP_ENCRYPT_SIGN;

    if (!(param = (pgp_write_handler_param_t *) calloc(1, sizeof(*param)))) {
        return false;
    }

    handler->password_provider = &rnp->password_provider;
    handler->key_provider = &rnp->key_provider;
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
rnp_protect_file(rnp_t *rnp, rnp_ctx_t *ctx, const char *in, const char *out)
{
    pgp_write_handler_t        handler = {0};
    pgp_write_handler_param_t *param;
    rnp_result_t               result;

    /* initialize write handler */
    if (!rnp_init_write_handler(&handler, rnp, ctx)) {
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
rnp_protect_mem(rnp_t *     rnp,
                rnp_ctx_t * ctx,
                const void *in,
                size_t      len,
                void *      out,
                size_t      outlen,
                size_t *    reslen)
{
    pgp_write_handler_t        handler = {0};
    pgp_write_handler_param_t *param;
    rnp_result_t               result;
    void *                     outdata;

    if (!rnp_init_write_handler(&handler, rnp, ctx)) {
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

rnp_result_t
rnp_encrypt_add_password(rnp_t *rnp, rnp_ctx_t *ctx)
{
    rnp_result_t       ret = RNP_ERROR_GENERIC;
    char               password[MAX_PASSWORD_LENGTH] = {0};
    pgp_password_ctx_t pswdctx = {.op = PGP_OP_ENCRYPT_SYM, .key = NULL};

    if (!pgp_request_password(&rnp->password_provider, &pswdctx, password, sizeof(password))) {
        return RNP_ERROR_BAD_PASSWORD;
    }
    ret = rnp_ctx_add_encryption_password(ctx, password, ctx->halg, ctx->ealg, 0);
    pgp_forget(password, sizeof(password));
    return ret;
}

rnp_result_t
rnp_validate_keys_signatures(rnp_t *rnp)
{
    const rnp_key_store_t *ring = rnp->pubring;
    pgp_signatures_info_t  result = {0};
    rnp_result_t           ret;
    bool                   valid = true;

    if (!rnp) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    for (list_item *key = list_front(rnp_key_store_get_keys(ring)); key;
         key = list_next(key)) {
        ret = validate_pgp_key_signatures(&result, (pgp_key_t *) key, ring);
        valid &= check_signatures_info(&result);
        free_signatures_info(&result);
        if (ret) {
            break;
        }
    }

    return valid ? RNP_SUCCESS : RNP_ERROR_GENERIC;
}

/** @brief compose path from dir, subdir and filename, and store it in the res
 *  @param dir [in] null-terminated directory path, cannot be NULL
 *  @param subddir [in] null-terminated subdirectory to add to the path, can be NULL
 *  @param filename [in] null-terminated filename (or path/filename), cannot be NULL
 *  @param res [out] preallocated buffer
 *  @param res_size [in] size of output res buffer
 *
 *  @return true if path constructed successfully, or false otherwise
 **/
static bool
rnp_path_compose(
  const char *dir, const char *subdir, const char *filename, char *res, size_t res_size)
{
    int pos;

    /* checking input parameters for conrrectness */
    if (!dir || !filename || !res) {
        return false;
    }

    /* concatenating dir, subdir and filename */
    if (strlen(dir) > res_size - 1) {
        return false;
    }

    strcpy(res, dir);
    pos = strlen(dir);

    if (subdir) {
        if ((pos > 0) && (res[pos - 1] != '/')) {
            res[pos++] = '/';
        }

        if (strlen(subdir) + pos > res_size - 1) {
            return false;
        }

        strcpy(res + pos, subdir);
        pos += strlen(subdir);
    }

    if ((pos > 0) && (res[pos - 1] != '/')) {
        res[pos++] = '/';
    }

    if (strlen(filename) + pos > res_size - 1) {
        return false;
    }

    strcpy(res + pos, filename);

    return true;
}

/* helper function : get key storage subdir in case when user didn't specify homedir */
static const char *
rnp_cfg_get_ks_subdir(rnp_cfg_t *cfg, int defhomedir, const char *ksfmt)
{
    const char *subdir;

    if (!defhomedir) {
        subdir = NULL;
    } else {
        if ((subdir = rnp_cfg_getstr(cfg, CFG_SUBDIRGPG)) == NULL) {
            subdir = SUBDIRECTORY_RNP;
        }
    }

    return subdir;
}

static bool
rnp_cfg_set_ks_info(rnp_cfg_t *cfg)
{
    bool        defhomedir = false;
    const char *homedir;
    const char *subdir;
    const char *ks_format;
    char        pubpath[MAXPATHLEN] = {0};
    char        secpath[MAXPATHLEN] = {0};
    struct stat st;

    /* getting path to keyrings. If it is specified by user in 'homedir' param then it is
     * considered as the final path */
    if (rnp_cfg_getint_default(cfg, CFG_KEYSTORE_DISABLED, 0)) {
        if (!rnp_cfg_getstr(cfg, CFG_KEYFILE)) {
            return true;
        }

        return rnp_cfg_setstr(cfg, CFG_KR_PUB_PATH, "") &&
               rnp_cfg_setstr(cfg, CFG_KR_SEC_PATH, "") &&
               rnp_cfg_setstr(cfg, CFG_KR_PUB_FORMAT, RNP_KEYSTORE_GPG) &&
               rnp_cfg_setstr(cfg, CFG_KR_SEC_FORMAT, RNP_KEYSTORE_GPG);
    }

    if (!(homedir = rnp_cfg_getstr(cfg, CFG_HOMEDIR))) {
        homedir = getenv("HOME");
        defhomedir = true;
    }

    /* detecting key storage format */
    if (!(ks_format = rnp_cfg_getstr(cfg, CFG_KEYSTOREFMT))) {
        if (!(subdir = rnp_cfg_getstr(cfg, CFG_SUBDIRGPG))) {
            subdir = SUBDIRECTORY_RNP;
        }
        if (!rnp_path_compose(
              homedir, defhomedir ? subdir : NULL, PUBRING_KBX, pubpath, sizeof(pubpath))) {
            return false;
        }
        if (!rnp_path_compose(
              homedir, defhomedir ? subdir : NULL, SECRING_G10, secpath, sizeof(secpath))) {
            return false;
        }

        bool pubpath_exists = stat(pubpath, &st) == 0;
        bool secpath_exists = stat(secpath, &st) == 0;

        if (pubpath_exists && secpath_exists) {
            ks_format = RNP_KEYSTORE_GPG21;
        } else if (secpath_exists) {
            ks_format = RNP_KEYSTORE_G10;
        } else if (pubpath_exists) {
            ks_format = RNP_KEYSTORE_KBX;
        } else {
            ks_format = RNP_KEYSTORE_GPG;
        }
    }

    /* building pubring/secring pathes */
    subdir = rnp_cfg_get_ks_subdir(cfg, defhomedir, ks_format);

    /* creating home dir if needed */
    if (defhomedir && subdir) {
        if (!rnp_path_compose(homedir, NULL, subdir, pubpath, sizeof(pubpath))) {
            return false;
        }
        if (mkdir(pubpath, 0700) == -1 && errno != EEXIST) {
            RNP_LOG("cannot mkdir '%s' errno = %d", pubpath, errno);
            return false;
        }
    }

    const char *pub_format = RNP_KEYSTORE_GPG;
    const char *sec_format = RNP_KEYSTORE_GPG;

    if (strcmp(ks_format, RNP_KEYSTORE_GPG) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_GPG, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_GPG, secpath, sizeof(secpath))) {
            return false;
        }
        pub_format = RNP_KEYSTORE_GPG;
        sec_format = RNP_KEYSTORE_GPG;
    } else if (strcmp(ks_format, RNP_KEYSTORE_GPG21) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_KBX, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_G10, secpath, sizeof(secpath))) {
            return false;
        }
        pub_format = RNP_KEYSTORE_KBX;
        sec_format = RNP_KEYSTORE_G10;
    } else if (strcmp(ks_format, RNP_KEYSTORE_KBX) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_KBX, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_KBX, secpath, sizeof(secpath))) {
            return false;
        }
        pub_format = RNP_KEYSTORE_KBX;
        sec_format = RNP_KEYSTORE_KBX;
    } else if (strcmp(ks_format, RNP_KEYSTORE_G10) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_G10, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_G10, secpath, sizeof(secpath))) {
            return false;
        }
        pub_format = RNP_KEYSTORE_G10;
        sec_format = RNP_KEYSTORE_G10;
    } else {
        RNP_LOG("unsupported keystore format: \"%s\"", ks_format);
        return false;
    }

    return rnp_cfg_setstr(cfg, CFG_KR_PUB_PATH, pubpath) &&
           rnp_cfg_setstr(cfg, CFG_KR_SEC_PATH, secpath) &&
           rnp_cfg_setstr(cfg, CFG_KR_PUB_FORMAT, pub_format) &&
           rnp_cfg_setstr(cfg, CFG_KR_SEC_FORMAT, sec_format);
}

/* read any gpg config file */
static bool
conffile(const char *homedir, char *userid, size_t length)
{
    regmatch_t matchv[10];
    regex_t    keyre;
    char       buf[BUFSIZ];
    FILE *     fp;

    (void) snprintf(buf, sizeof(buf), "%s/.gnupg/gpg.conf", homedir);
    if ((fp = fopen(buf, "r")) == NULL) {
        return false;
    }
    (void) memset(&keyre, 0x0, sizeof(keyre));
    if (regcomp(&keyre, "^[ \t]*default-key[ \t]+([0-9a-zA-F]+)", REG_EXTENDED) != 0) {
        RNP_LOG("failed to compile regular expression");
        fclose(fp);
        return false;
    }
    while (fgets(buf, (int) sizeof(buf), fp) != NULL) {
        if (regexec(&keyre, buf, 10, matchv, 0) == 0) {
            (void) memcpy(userid,
                          &buf[(int) matchv[1].rm_so],
                          MIN((unsigned) (matchv[1].rm_eo - matchv[1].rm_so), length));

            (void) fprintf(stderr,
                           "rnp: default key set to \"%.*s\"\n",
                           (int) (matchv[1].rm_eo - matchv[1].rm_so),
                           &buf[(int) matchv[1].rm_so]);
        }
    }
    (void) fclose(fp);
    regfree(&keyre);
    return true;
}

static void
rnp_cfg_set_defkey(rnp_cfg_t *cfg)
{
    char        id[MAX_ID_LENGTH];
    const char *userid;
    const char *homedir;
    bool        defhomedir = false;

    if ((homedir = rnp_cfg_getstr(cfg, CFG_HOMEDIR)) == NULL) {
        homedir = getenv("HOME");
        defhomedir = true;
    }

    /* If a userid has been given, we'll use it. */
    if (!(userid = rnp_cfg_getstr(cfg, CFG_USERID))) {
        /* also search in config file for default id */

        if (defhomedir) {
            memset(id, 0, sizeof(id));
            conffile(homedir, id, sizeof(id));
            if (id[0] != 0x0) {
                rnp_cfg_setstr(cfg, CFG_USERID, id);
                rnp_cfg_setstr(cfg, CFG_KR_DEF_KEY, id);
            }
        }
    } else {
        rnp_cfg_setstr(cfg, CFG_KR_DEF_KEY, userid);
    }
}

bool
cli_cfg_set_keystore_info(rnp_cfg_t *cfg)
{
    /* detecting keystore pathes and format */
    if (!rnp_cfg_set_ks_info(cfg)) {
        RNP_LOG("cannot obtain keystore path(es)");
        return false;
    }

    /* default key/userid */
    rnp_cfg_set_defkey(cfg);

    return true;
}
