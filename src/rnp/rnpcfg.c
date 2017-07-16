/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <regex.h>

#include "rnpcfg.h"
#include "rnpsdk.h"
#include "constants.h"

/** @brief initialize rnp_cfg structure internals. When structure is not needed anymore 
 *  it should be freed via rnp_cfg_free function call
 **/
void
rnp_cfg_init(rnp_cfg_t *cfg)
{
    memset(cfg, '\0', sizeof(rnp_cfg_t));
}

void
rnp_cfg_load_defaults(rnp_cfg_t *cfg)
{
    rnp_cfg_setint(cfg, CFG_OVERWRITE, 1);
    rnp_cfg_set(cfg, CFG_OUTFILE, NULL);
    rnp_cfg_set(cfg, CFG_HASH, DEFAULT_HASH_ALG);
    rnp_cfg_set(cfg, CFG_CIPHER, "cast5");
    rnp_cfg_setint(cfg, CFG_MAXALLOC, 4194304);
    rnp_cfg_set(cfg, CFG_SUBDIRGPG, SUBDIRECTORY_RNP);
    rnp_cfg_set(cfg, CFG_SUBDIRSSH, SUBDIRECTORY_SSH);
    rnp_cfg_setint(cfg, CFG_NUMTRIES, MAX_PASSPHRASE_ATTEMPTS);
}

/** @brief apply configuration from keys-vals storage to rnp_params_t structure
 *  @param cfg [in] rnp config, must be allocated and initialized
 *  @param params [out] this structure will be filled so can be further feed into rnp_init. 
 *                Must be later freed using the rnp_params_free even if rnp_cfg_apply fails.
 *
 *  @return true on success, false if something went wrong
 **/
bool
rnp_cfg_apply(rnp_cfg_t *cfg, rnp_params_t *params)
{
    int         passfd;
    const char *stream;

    /* enabling core dumps if user wants this */
    if (rnp_cfg_getbool(cfg, CFG_COREDUMPS)) {
        params->enable_coredumps = 1;
    }

    /* checking if password input was specified */
    if ((passfd = rnp_cfg_getint(cfg, CFG_PASSFD))) {
        params->passfd = passfd;
    }

    /* stdout/stderr and results redirection */
    if ((stream = rnp_cfg_get(cfg, CFG_IO_OUTS))) {
        params->outs = stream;
    }

    if ((stream = rnp_cfg_get(cfg, CFG_IO_ERRS))) {
        params->errs = stream;
    }

    if ((stream = rnp_cfg_get(cfg, CFG_IO_RESS))) {
        params->ress = stream;
    }

    /* detecting keystore pathes and format */
    if (!rnp_cfg_get_ks_info(cfg, params)) {
        fprintf(stderr, "rnp_cfg_apply: cannot obtain keystore path(es) \n");
        return false;
    }

    /* default key/userid */
    rnp_cfg_get_defkey(cfg, params);

    return true;
}

/* find the value name in the rnp_cfg */
static int
rnp_cfg_find(const rnp_cfg_t *cfg, const char *key)
{
    unsigned i;

    for (i = 0; i < cfg->count && strcmp(cfg->keys[i], key) != 0; i++)
        ;
    return (i == cfg->count) ? -1 : (int) i;
}

/** @brief resize keys/vals arrays to the new size. Only expanding is supported now.
 *  Pointers keys and vals will be freed in rnp_cfg_free
 *
 *  @return true on success, false if allocation fails.
 **/
static bool
rnp_cfg_resize(rnp_cfg_t *cfg, unsigned newsize)
{
    char **temp;

    if (cfg->size == 0) {
        /* only get here first time around */
        cfg->keys = calloc(sizeof(char *), newsize);
        cfg->vals = calloc(sizeof(char *), newsize);

        if ((cfg->keys == NULL) || (cfg->vals == NULL)) {
            (void) fprintf(stderr, "rnp_cfg_resize: bad alloc\n");
            return false;
        }
        cfg->size = newsize;
    } else if (cfg->count == cfg->size) {
        /* only uses 'needed' when filled array */
        temp = realloc(cfg->keys, sizeof(char *) * newsize);
        if (temp == NULL) {
            (void) fprintf(stderr, "rnp_cfg_resize: bad realloc\n");
            return false;
        }
        cfg->keys = temp;

        temp = realloc(cfg->vals, sizeof(char *) * newsize);
        if (temp == NULL) {
            (void) fprintf(stderr, "rnp_cfg_resize: bad realloc\n");
            return false;
        }
        cfg->vals = temp;
        cfg->size = newsize;
    }

    return true;
}

/** @brief set val for the key in config, copying them
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *  @param val value, must be null-terminated string
 *
 *  @return false if allocation is failed. keys and vals fields will be freed in rnp_cfg_free
 **/
bool
rnp_cfg_set(rnp_cfg_t *cfg, const char *key, const char *val)
{
    char *newval = NULL;
    char *newkey;
    int   i;

    /* protect against the case where 'value' is rnp->value[i] */
    if (val != NULL) {
        newval = rnp_strdup(val);
        if (newval == NULL) {
            (void) fprintf(stderr, "rnp_cfg_set: bad alloc\n");
            return false;
        }
    }

    if ((i = rnp_cfg_find(cfg, key)) < 0) {
        /* add the element to the array */
        if (rnp_cfg_resize(cfg, cfg->size + 15)) {
            newkey = rnp_strdup(key);
            if (newkey == NULL) {
                (void) fprintf(stderr, "rnp_cfg_set: bad alloc\n");
                free(newval);
                return false;
            }
            cfg->keys[i = cfg->count++] = newkey;
        } else {
            free(newval);
            return false;
        }
    } else {
        /* replace the element in the array */
        if (cfg->vals[i]) {
            free(cfg->vals[i]);
            cfg->vals[i] = NULL;
        }
    }

    cfg->vals[i] = newval;
    return true;
}

/** @brief unset value for the key in config, making it NULL
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *
 *  @return true if value was found and set to NULL or false otherwise
 **/
bool
rnp_cfg_unset(rnp_cfg_t *cfg, const char *key)
{
    int i;

    if ((i = rnp_cfg_find(cfg, key)) >= 0) {
        free(cfg->vals[i]);
        cfg->vals[i] = NULL;
        return true;
    }
    return false;
}

/** @brief set integer value for the key in config
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *  @param val value, which will be set
 *
 *  @return true if operation succeeds or false otherwise
 **/
bool
rnp_cfg_setint(rnp_cfg_t *cfg, const char *key, int val)
{
    char st[16] = {0};
    snprintf(st, sizeof(st), "%d", val);
    return rnp_cfg_set(cfg, key, st);
}

/** @brief set boolean value for the key in config
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *  @param val value, which will be set
 *
 *  @return true if operation succeeds or false otherwise
 **/
bool
rnp_cfg_setbool(rnp_cfg_t *cfg, const char *key, bool val)
{
    return rnp_cfg_set(cfg, key, val ? "true" : "false");
}

/** @brief return value for the key if there is one
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *
 *  @return true if operation succeeds or false otherwise
 **/
const char *
rnp_cfg_get(const rnp_cfg_t *cfg, const char *key)
{
    int i;

    return ((i = rnp_cfg_find(cfg, key)) < 0) ? NULL : cfg->vals[i];
}

/** @brief return integer value for the key if there is one
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *
 *  @return integer value or 0 if there is no value or it is non-integer
 **/
int
rnp_cfg_getint(rnp_cfg_t *cfg, const char *key)
{
    const char *val = rnp_cfg_get(cfg, key);
    return val ? atoi(val) : 0;
}

/** @brief return boolean value for the key if there is one
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *
 *  @return true if 'true', 'True', or non-zero integer is stored in value, false otherwise
 **/
bool 
rnp_cfg_getbool(rnp_cfg_t *cfg, const char *key)
{
    const char *val = rnp_cfg_get(cfg, key);

    if (val) {
        if ((strcmp(val, "true") == 0) || (strcmp(val, "True") == 0)) {
            return true;
        } else if (atoi(val) > 0) {
            return true;
        } else
            return false;
    } else {
        return false;
    }
}

/** @brief free the memory allocated in rnp_cfg_t
 *  @param cfg rnp config, must be allocated and initialized
 **/
void
rnp_cfg_free(rnp_cfg_t *cfg)
{
    int i;

    for (i = 0; i < cfg->count; i++) {
        free(cfg->vals[i]);
        free(cfg->keys[i]);
    }

    free(cfg->keys);
    free(cfg->vals);
}

int
rnp_cfg_get_pswdtries(rnp_cfg_t *cfg)
{
    const char *numtries;
    int         num;

    numtries = rnp_cfg_get(cfg, CFG_NUMTRIES);

    if ((numtries == NULL) || ((num = atoi(numtries)) <= 0)) {
        return MAX_PASSPHRASE_ATTEMPTS;
    } else if (strcmp(numtries, "unlimited")) {
        return INFINITE_ATTEMPTS;
    } else {
        return num;
    }
}

int
rnp_cfg_check_homedir(rnp_cfg_t *cfg, char *homedir)
{
    struct stat st;
    int         ret;

    if (homedir == NULL) {
        fputs("rnp: homedir option and HOME environment variable are not set \n", stderr);
        return RNP_FAIL;
    } else if ((ret = stat(homedir, &st)) == 0 && !S_ISDIR(st.st_mode)) {
        /* file exists in place of homedir */
        fprintf(stderr, "rnp: homedir \"%s\" is not a dir\n", homedir);
        return RNP_FAIL;
    } else if (ret != 0 && errno == ENOENT) {
        /* If the path doesn't exist then fail. */
        fprintf(stderr, "rnp: warning homedir \"%s\" not found\n", homedir);
        return RNP_FAIL;
    } else if (ret != 0) {
        /* If any other occurred then fail. */
        fprintf(stderr, "rnp: an unspecified error occurred\n");
        return RNP_FAIL;
    }

    return RNP_OK;
}

/* read any gpg config file */
static int
conffile(const char *homedir, char *userid, size_t length)
{
    regmatch_t matchv[10];
    regex_t    keyre;
    char       buf[BUFSIZ];
    FILE *     fp;

    (void) snprintf(buf, sizeof(buf), "%s/.gnupg/gpg.conf", homedir);
    if ((fp = fopen(buf, "r")) == NULL) {
        return RNP_FAIL;
    }
    (void) memset(&keyre, 0x0, sizeof(keyre));
    if (regcomp(&keyre, "^[ \t]*default-key[ \t]+([0-9a-zA-F]+)", REG_EXTENDED) != 0) {
        (void) fprintf(stderr, "conffile: failed to compile regular expression");
        return RNP_FAIL;
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
    return RNP_OK;
}

/** @brief compose path from dir, subdir and filename, and store it in the res
 *  @param dir [in] null-terminated directory path, cannot be NULL
 *  @param subddir [in] null-terminated subdirectory to add to the path, can be NULL
 *  @param filename [in] null-terminated filename (or path/filename), cannot be NULL
 *  @param res [out] preallocated buffer, large enough to store the result
 *
 *  @return true if path constructed successfully, or false otherwise
 **/
static bool
rnp_path_compose(const char *dir, const char *subdir, const char *filename, char *res)
{
    int pos;

    /* checking input parameters for conrrectness */
    if (!dir || !filename || !res) {
        return false;
    }

    /* concatenating dir, subdir and filename */
    strcpy(res, dir);
    pos = strlen(dir);

    if (subdir) {
        if ((pos > 0) && (res[pos - 1] != '/')) {
            res[pos++] = '/';
        }

        strcpy(res + pos, subdir);
        pos += strlen(subdir);
    }

    if ((pos > 0) && (res[pos - 1] != '/')) {
        res[pos++] = '/';
    }

    strcpy(res + pos, filename);

    return true;
}

static bool
parse_ks_format(enum key_store_format_t *key_store_format, const char *format)
{
    if (rnp_strcasecmp(format, CFG_KEYSTORE_GPG) == 0) {
        *key_store_format = GPG_KEY_STORE;
    } else if (rnp_strcasecmp(format, CFG_KEYSTORE_KBX) == 0) {
        *key_store_format = KBX_KEY_STORE;
    } else if (rnp_strcasecmp(format, CFG_KEYSTORE_SSH) == 0) {
        *key_store_format = SSH_KEY_STORE;
    } else {
        fprintf(stderr, "rnp: unsupported keystore format: \"%s\"\n", format);
        return false;
    }
    return true;
}

/* helper function : get key storage subdir in case when user didn't specify homedir */
const char *
rnp_cfg_get_ks_subdir(rnp_cfg_t *cfg, int defhomedir, enum key_store_format_t ksfmt)
{
    const char *subdir;

    if (!defhomedir) {
        subdir = NULL;
    } else if (ksfmt == SSH_KEY_STORE) {
        if ((subdir = rnp_cfg_get(cfg, CFG_SUBDIRSSH)) == NULL) {
            subdir = SUBDIRECTORY_SSH;
        }
    } else {
        if ((subdir = rnp_cfg_get(cfg, CFG_SUBDIRGPG)) == NULL) {
            subdir = SUBDIRECTORY_RNP;
        }
    }

    return subdir;
}

/**
 * @brief Fill the keyring pathes according to user-specified settings
 *
 *  @param cfg [in] rnp config, must be allocated and initialized
 *  @param params [out] in this structure public and secret keyring pathes  will be filled
 *  @return true on success or false if something went wrong
 */
bool
rnp_cfg_get_ks_info(rnp_cfg_t *cfg, rnp_params_t *params)
{
    bool        defhomedir = false;
    const char *homedir;
    const char *format;
    const char *subdir;
    const char *sshfile;
    char        pubpath[MAXPATHLEN] = {0};
    char        secpath[MAXPATHLEN] = {0};
    struct stat st;

    /* getting path to keyrings. If it is specified by user in 'homedir' param then it is
     * considered as the final path, no .rnp/.ssh is added */
    if ((homedir = rnp_cfg_get(cfg, CFG_HOMEDIR)) == NULL) {
        homedir = getenv("HOME");
        defhomedir = true;
    }

    /* detecting key storage format */
    if ((format = rnp_cfg_get(cfg, CFG_KEYSTOREFMT)) == NULL) {
        if (rnp_cfg_get(cfg, CFG_SSHKEYFILE)) {
            format = CFG_KEYSTORE_SSH;
        } else {
            if ((subdir = rnp_cfg_get(cfg, CFG_SUBDIRGPG)) == NULL) {
                subdir = SUBDIRECTORY_RNP;
            }
            rnp_path_compose(homedir, defhomedir ? subdir : NULL, PUBRING_KBX, pubpath);

            if (!stat(pubpath, &st)) {
                format = CFG_KEYSTORE_KBX;
            } else {
                format = CFG_KEYSTORE_GPG;
            }
        }
    }

    if (!parse_ks_format(&params->ks_format, format)) {
        return false;
    }

    /* building pubring/secring pathes */
    subdir = rnp_cfg_get_ks_subdir(cfg, defhomedir, params->ks_format);

    /* creating home dir if needed */
    if (defhomedir && subdir) {
        rnp_path_compose(homedir, NULL, subdir, pubpath);
        if (mkdir(pubpath, 0700) == -1 && errno != EEXIST) {
            fprintf(stderr, "cannot mkdir '%s' errno = %d \n", pubpath, errno);
            return false;
        }
    }

    if (params->ks_format == GPG_KEY_STORE) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_GPG, pubpath) ||
            !rnp_path_compose(homedir, subdir, SECRING_GPG, secpath)) {
            return false;
        }
        params->pubpath = strdup(pubpath);
        params->secpath = strdup(secpath);
    } else if (params->ks_format == KBX_KEY_STORE) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_KBX, pubpath) ||
            !rnp_path_compose(homedir, subdir, SECRING_KBX, secpath)) {
            return false;
        }
        params->pubpath = strdup(pubpath);
        params->secpath = strdup(secpath);
    } else if (params->ks_format == SSH_KEY_STORE) {
        if ((sshfile = rnp_cfg_get(cfg, CFG_SSHKEYFILE)) == NULL) {
            /* set reasonable default for RSA key */
            if (!rnp_path_compose(homedir, subdir, "id_rsa.pub", pubpath) ||
                !rnp_path_compose(homedir, subdir, "id_rsa", secpath)) {
                return false;
            }
        } else if ((strlen(sshfile) < 4) ||
                   (strcmp(&sshfile[strlen(sshfile) - 4], ".pub") != 0)) {
            /* got ssh keys, but no .pub extension */
            (void) snprintf(pubpath, sizeof(pubpath), "%s.pub", sshfile);
            (void) snprintf(secpath, sizeof(secpath), "%s", sshfile);
        } else {
            /* got ssh key name with .pub extension */
            strncpy(pubpath, sshfile, sizeof(pubpath));
            strncpy(secpath, sshfile, sizeof(secpath));
            secpath[strlen(sshfile) - 4] = 0;
        }

        params->pubpath = strdup(pubpath);
        params->secpath = strdup(secpath);
    } else {
        fprintf(stderr, "rnp: unsupported keystore format: \"%d\"\n", (int) params->ks_format);
        return false;
    }

    return true;
}

/**
 * @brief Attempt to get the default key id/name in a number of ways
 * Tries to find via user-specified parameters and  GnuPG conffile.
 *
 *  @param cfg [in] rnp config, must be allocated and initialized
 *  @param params [out] in this structure defkey will be filled if found
 */
void
rnp_cfg_get_defkey(rnp_cfg_t *cfg, rnp_params_t *params)
{
    char        id[MAX_ID_LENGTH];
    const char *userid;
    const char *homedir;
    bool        defhomedir = false;

    if ((homedir = rnp_cfg_get(cfg, CFG_HOMEDIR)) == NULL) {
        homedir = getenv("HOME");
        defhomedir = true;
    }

    /* If a userid has been given, we'll use it. */
    if ((userid = rnp_cfg_get(cfg, CFG_USERID)) == NULL) {
        /* also search in config file for default id */

        if (defhomedir) {
            memset(id, 0, sizeof(id));
            conffile(homedir, id, sizeof(id));
            if (id[0] != 0x0) {
                params->defkey = strdup(id);
                rnp_cfg_set(cfg, CFG_USERID, id);
            }
        }
    } else {
        params->defkey = strdup(userid);
    }
}

/**
 * @brief Grabs date from the string in %Y-%m-%d format
 *
 * @param s [in] NULL-terminated string with the date
 * @param t [out] On successfull return result will be placed here
 * @return true on success or false otherwise
 */

static bool
grabdate(const char *s, int64_t *t)
{
    static regex_t r;
    static int     compiled;
    regmatch_t     matches[10];
    struct tm      tm;

    if (!compiled) {
        compiled = 1;
        if (regcomp(&r, "([0-9][0-9][0-9][0-9])[-/]([0-9][0-9])[-/]([0-9][0-9])", REG_EXTENDED) != 0) {
            fprintf(stderr, "grabdate: failed to compile regexp");
            return false;
        }
    }
    if (regexec(&r, s, 10, matches, 0) == 0) {
        (void) memset(&tm, 0x0, sizeof(tm));
        tm.tm_year = (int) strtol(&s[(int) matches[1].rm_so], NULL, 10);
        tm.tm_mon = (int) strtol(&s[(int) matches[2].rm_so], NULL, 10) - 1;
        tm.tm_mday = (int) strtol(&s[(int) matches[3].rm_so], NULL, 10);
        *t = mktime(&tm);
        return true;
    }
    return false;
}

/**
 * @brief Get signature validity duration time from the user input
 *
 * Signature duration may be specified in different formats:
 * - 10d : 10 days (you can use [h]ours, d[ays], [w]eeks, [m]onthes)
 * - 2017-07-12 : as the exact date when signature becomes invalid
 * - 60000 : number of seconds
 *
 * @param s [in] NULL-terminated string with the date
 * @param t [out] On successfull return result will be placed here
 * @return duration time in seconds
 */

uint64_t
get_duration(const char *s)
{
    uint64_t now;
    int64_t  t;
    char *   mult;

    if ((s == NULL) || (strlen(s) < 1)) {
        return 0;
    }
    now = (uint64_t) strtoull(s, NULL, 10);
    if ((mult = strchr("hdwmy", s[strlen(s) - 1])) != NULL) {
        switch (*mult) {
        case 'h':
            return now * 60 * 60;
        case 'd':
            return now * 60 * 60 * 24;
        case 'w':
            return now * 60 * 60 * 24 * 7;
        case 'm':
            return now * 60 * 60 * 24 * 31;
        case 'y':
            return now * 60 * 60 * 24 * 365;
        }
    }
    if (grabdate(s, &t)) {
        return t;
    }
    return (uint64_t) strtoll(s, NULL, 10);
}

/**
 * @brief Get signature validity start time from the user input
 *
 * Signature validity may be specified in different formats:
 * - 2017-07-12 : as the exact date when signature becomes invalid
 * - 1499334073 : timestamp
 *
 * @param s [in] NULL-terminated string with the date
 * @return timestamp of the validity start
 */

int64_t
get_birthtime(const char *s)
{
    int64_t t;

    if (s == NULL) {
        return time(NULL);
    }
    if (grabdate(s, &t)) {
        return t;
    }
    return (uint64_t) strtoll(s, NULL, 10);
}

void
rnp_cfg_copy(rnp_cfg_t *dst, const rnp_cfg_t *src)
{
    if (!src) {
        return;
    }

    for (unsigned i = 0; i < src->count; i++) {
        rnp_cfg_set(dst, src->keys[i], src->vals[i]);
    }
}
