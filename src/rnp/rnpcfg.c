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
#include "rnpcfg.h"
#include <rnpsdk.h>
#include <../common/constants.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <regex.h>

/* SHA1 is now looking as though it should not be used.  Let's
 * pre-empt this by specifying SHA256 - gpg interoperates just fine
 * with SHA256 - agc, 20090522
 */
#define DEFAULT_HASH_ALG "SHA256"

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

int
rnp_cfg_apply(rnp_cfg_t *cfg, rnp_params_t *params)
{
    int         passfd;
    const char *stream;

    /* enabling core dumps if user wants this */
    if (rnp_cfg_getint(cfg, CFG_COREDUMPS)) {
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
    if (!rnp_cfg_get_ks_info(cfg, params))
        return RNP_FAIL;

    /* default key/userid */
    if (!rnp_cfg_get_defkey(cfg, params))
        return RNP_FAIL;

    return RNP_OK;
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

/* resize keys/vals arrays to the new size. Only expanding is supported */
static int
rnp_cfg_resize(rnp_cfg_t *cfg, unsigned newsize)
{
    char **temp;

    if (cfg->size == 0) {
        /* only get here first time around */
        cfg->keys = calloc(sizeof(char *), newsize);
        cfg->vals = calloc(sizeof(char *), newsize);

        if ((cfg->keys == NULL) || (cfg->keys == NULL)) {
            (void) fprintf(stderr, "rnp_cfg_resize: bad alloc\n");
            return RNP_FAIL;
        }
        cfg->size = newsize;
    } else if (cfg->count == cfg->size) {
        /* only uses 'needed' when filled array */
        temp = realloc(cfg->keys, sizeof(char *) * newsize);
        if (temp == NULL) {
            (void) fprintf(stderr, "rnp_cfg_resize: bad realloc\n");
            return RNP_FAIL;
        }
        cfg->keys = temp;

        temp = realloc(cfg->vals, sizeof(char *) * newsize);
        if (temp == NULL) {
            (void) fprintf(stderr, "rnp_cfg_resize: bad realloc\n");
            return RNP_FAIL;
        }
        cfg->vals = temp;
        cfg->size = newsize;
    }

    return RNP_OK;
}

/* set val for the key in config. key and val are duplicated */
int
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
            return RNP_FAIL;
        }
    }

    if ((i = rnp_cfg_find(cfg, key)) < 0) {
        /* add the element to the array */
        if (rnp_cfg_resize(cfg, cfg->size + 15)) {
            newkey = rnp_strdup(key);
            if (newkey == NULL) {
                (void) fprintf(stderr, "rnp_cfg_set: bad alloc\n");
                return RNP_FAIL;
            }
            cfg->keys[i = cfg->count++] = newkey;
        } else {
            free(newval);
            return RNP_FAIL;
        }
    } else {
        /* replace the element in the array */
        if (cfg->vals[i]) {
            free(cfg->vals[i]);
            cfg->vals[i] = NULL;
        }
    }

    cfg->vals[i] = newval;
    return RNP_OK;
}

/* unset var for key, setting it to NULL if it exists in cfg */
int
rnp_cfg_unset(rnp_cfg_t *cfg, const char *key)
{
    int i;

    if ((i = rnp_cfg_find(cfg, key)) >= 0) {
        free(cfg->vals[i]);
        cfg->vals[i] = NULL;
        return RNP_OK;
    }
    return RNP_FAIL;
}

/* set int value for the key */
int
rnp_cfg_setint(rnp_cfg_t *cfg, const char *key, int val)
{
    char st[16] = {0};
    sprintf(st, "%d", val);
    return rnp_cfg_set(cfg, key, st);
}

/* get value for the key. Returns NULL if there is no value */
const char *
rnp_cfg_get(const rnp_cfg_t *cfg, const char *key)
{
    int i;

    return ((i = rnp_cfg_find(cfg, key)) < 0) ? NULL : cfg->vals[i];
}

/* get int value for the key */
int
rnp_cfg_getint(rnp_cfg_t *cfg, const char *key)
{
    const char *val = rnp_cfg_get(cfg, key);
    return val ? atoi(val) : 0;
}

/* free the memory, used by cfg internally */
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
    (void) regcomp(&keyre, "^[ \t]*default-key[ \t]+([0-9a-zA-F]+)", REG_EXTENDED);
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

/*
  Compose path from dir, subdir and filename. subdir can be null, then just dir and filename
  will be used.
  res should point to the allocated buffer.
*/
int
rnp_path_compose(const char *dir, const char *subdir, const char *filename, char *res)
{
    int pos;

    /* checking input parameters for conrrectness */
    if (!dir || !filename || !res) {
        return RNP_FAIL;
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

    return RNP_OK;
}

static int
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
        return RNP_FAIL;
    }
    return RNP_OK;
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

int
rnp_cfg_get_ks_info(rnp_cfg_t *cfg, rnp_params_t *params)
{
    int         defhomedir = 0;
    const char *homedir;
    const char *format;
    const char *subdir;
    char        pubpath[MAXPATHLEN] = {0};
    char        secpath[MAXPATHLEN] = {0};
    struct stat st;

    /* getting path to keyrings. If it is specified by user in 'homedir' param then it is
     * considered as the final path, no .rnp/.ssh is added */
    if ((homedir = rnp_cfg_get(cfg, CFG_HOMEDIR)) == NULL) {
        homedir = getenv("HOME");
        defhomedir = 1;
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
        return RNP_FAIL;
    }

    /* building pubring/secring pathes */
    subdir = rnp_cfg_get_ks_subdir(cfg, defhomedir, params->ks_format);

    /* creating home dir if needed */
    if (defhomedir && subdir) {
        rnp_path_compose(homedir, NULL, subdir, pubpath);
        if (mkdir(pubpath, 0700) == -1 && errno != EEXIST) {
            fprintf(stderr, "cannot mkdir '%s' errno = %d \n", pubpath, errno);
            return RNP_FAIL;
        }
    }

    if (params->ks_format == GPG_KEY_STORE) {
        rnp_path_compose(homedir, subdir, PUBRING_GPG, pubpath);
        params->pubpath = strdup(pubpath);
        rnp_path_compose(homedir, subdir, SECRING_GPG, secpath);
        params->secpath = strdup(secpath);
    } else if (params->ks_format == KBX_KEY_STORE) {
        rnp_path_compose(homedir, subdir, PUBRING_KBX, pubpath);
        params->pubpath = strdup(pubpath);
        rnp_path_compose(homedir, subdir, SECRING_KBX, secpath);
        params->secpath = strdup(secpath);
    } else {
        fprintf(stderr, "rnp: unsupported keystore format: \"%d\"\n", (int) params->ks_format);
        return RNP_FAIL;
    }

    return RNP_OK;
}

int
rnp_cfg_get_defkey(rnp_cfg_t *cfg, rnp_params_t *params)
{
    char        id[MAX_ID_LENGTH];
    const char *userid;
    const char *homedir;
    int         defhomedir = 0;

    if ((homedir = rnp_cfg_get(cfg, CFG_HOMEDIR)) == NULL) {
        homedir = getenv("HOME");
        defhomedir = 1;
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

    return RNP_OK;
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
