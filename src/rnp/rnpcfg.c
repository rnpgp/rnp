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
#include <rnpcfg.h>
#include <rnpsdk.h>

int 
rnp_cfg_init(rnp_cfg_t *cfg)
{
    memset((void *) cfg, '\0', sizeof(rnp_cfg_t));
    return 1;
}

int 
rnp_cfg_load_defaults(rnp_cfg_t *cfg)
{
    rnp_cfg_setint(&cfg, CFG_OVERWRITE, 1);
    rnp_cfg_set(&cfg, CFG_OUTFILE, NULL);
    rnp_cfg_set(&cfg, CFG_HASH, DEFAULT_HASH_ALG);
    rnp_cfg_set(&cfg, CFG_CIPHER, 'cast5');    
    rnp_cfg_setint(&cfg, CFG_MAXALLOC, 4194304);
    rnp_cfg_set(&cfg, CFG_SUBDIRGPG, SUBDIRECTORY_GNUPG);
    rnp_cfg_set(&cfg, CFG_SUBDIRSSH, SUBDIRECTOR_SSH);
}

int
rnp_cfg_apply(rnp_cfg_t *cfg, rnp_init_t *params)
{
    if (rnp_cfg_getint(CFG_COREDUMPS))
        params->enable_coredumps = 1;
}

/* find the value name in the rnp_cfg */
static int
rnp_cfg_find(rnp_cfg_t *cfg, const char *key)
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
            return 0;
        }
        cfg->size = newsize;
    } else if (cfg->count == cfg->size) {
        /* only uses 'needed' when filled array */
        temp = realloc(cfg->keys, sizeof(char *) * newsize);
        if (temp == NULL) {
            (void) fprintf(stderr, "rnp_cfg_resize: bad realloc\n");
            return 0;
        }
        cfg->keys = temp;

        temp = realloc(cfg->vals, sizeof(char *) * newsize);
        if (temp == NULL) {
            (void) fprintf(stderr, "rnp_cfg_resize: bad realloc\n");
            return 0;
        }        
        cfg->vals = temp;
        cfg->size = newsize;
    }

    return 1;
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
            return 0;
        }
    }

    if ((i = rnp_cfg_find(cfg, key)) < 0) {
        /* add the element to the array */
        if (rnp_cfg_resize(cfg, cfg->size + 15)) {
            newkey = rnp_strdup(key);
            if (newkey == NULL) {
                (void) fprintf(stderr, "rnp_cfg_set: bad alloc\n");
                return 0;                
            }
            cfg->keys[i = cfg->count++] = newkey;
        } else {
            free(newval);
            return 0;
        }
    } else {
        /* replace the element in the array */
        if (cfg->vals[i]) {
            free(cfg->vals[i]);
            cfg->vals[i] = NULL;
        }
    }

    cfg->vals[i] = newval;
    return 1;
}

/* unset var for key, setting it to NULL if it exists in cfg */
int 
rnp_cfg_unset(rnp_cfg_t *cfg, const char *key)
{
    int i;

    if ((i = rnp_cfg_find(cfg, key)) >= 0) {
        if (cfg->vals[i]) {
            free(cfg->vals[i]);
        }
        cfg->vals[i] = NULL;
        return 1;
    }
    return 0;    
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
rnp_cfg_get(rnp_cfg_t *cfg, const char *key)
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
        if (cfg->vals[i])
            free(cfg->vals[i]);
        free(cfg->keys[i]);
    }

    if (cfg->keys) {
        free(cfg->keys);
    }

    if (cfg->vals) {
        free(cfg->vals);
    }
}

int
rnp_cfg_apply_homedir(rnp_t *rnp, rnp_cfg_t *cfg, const int quiet)
{
    struct stat st;
    int         ret;

    /* TODO: Replace `stderr` with the rnp context's error file when we
     *       are sure that all utilities and bindings don't call
     *       rnp_set_homedir ahead of rnp_init.
     */

    /* Check that a NULL parameter wasn't passed. */
    if (home == NULL) {
        if (!quiet)
            fprintf(stderr, "rnp: null homedir\n");
        return 0;

        /* If the path is not a directory then fail. */
    } else if ((ret = stat(home, &st)) == 0 && !S_ISDIR(st.st_mode)) {
        if (!quiet)
            fprintf(stderr, "rnp: homedir \"%s\" is not a dir\n", home);
        return 0;

        /* If the path doesn't exist then fail. */
    } else if (ret != 0 && errno == ENOENT) {
        if (!quiet)
            fprintf(stderr, "rnp: warning homedir \"%s\" not found\n", home);
        return 0;

        /* If any other occurred then fail. */
    } else if (ret != 0) {
        if (!quiet)
            fprintf(stderr, "rnp: an unspecified error occurred\n");
        return 0;
    }

    return 1;
}
