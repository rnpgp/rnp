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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <regex.h>
#include <time.h>
#include <errno.h>

#include "rnpcfg.h"
#include "utils.h"
#include "defaults.h"
#include <rnp/rnp_sdk.h>
#include <rekey/rnp_key_store.h>

typedef enum rnp_cfg_val_type_t {
    RNP_CFG_VAL_NULL = 0,
    RNP_CFG_VAL_INT = 1,
    RNP_CFG_VAL_BOOL = 2,
    RNP_CFG_VAL_STRING = 3,
    RNP_CFG_VAL_LIST = 4
} rnp_cfg_val_type_t;

typedef struct rnp_cfg_val_t {
    rnp_cfg_val_type_t type;
    union {
        int   _int;
        bool  _bool;
        char *_string;
        list  _list;
    } val;
} rnp_cfg_val_t;

typedef struct rnp_cfg_item_t {
    char *        key;
    rnp_cfg_val_t val;
} rnp_cfg_item_t;

void
rnp_cfg_init(rnp_cfg_t *cfg)
{
    memset(cfg, '\0', sizeof(rnp_cfg_t));
}

void
rnp_cfg_load_defaults(rnp_cfg_t *cfg)
{
    rnp_cfg_setbool(cfg, CFG_OVERWRITE, false);
    rnp_cfg_setstr(cfg, CFG_OUTFILE, NULL);
    rnp_cfg_setint(cfg, CFG_ZALG, DEFAULT_Z_ALG);
    rnp_cfg_setint(cfg, CFG_ZLEVEL, DEFAULT_Z_LEVEL);
    rnp_cfg_setstr(cfg, CFG_CIPHER, DEFAULT_SYMM_ALG);
    rnp_cfg_setstr(cfg, CFG_SUBDIRGPG, SUBDIRECTORY_RNP);
    rnp_cfg_setint(cfg, CFG_NUMTRIES, MAX_PASSWORD_ATTEMPTS);
    rnp_cfg_setint(cfg, CFG_S2K_MSEC, DEFAULT_S2K_MSEC);
}

static void
rnp_cfg_val_free(rnp_cfg_val_t *val)
{
    switch (val->type) {
    case RNP_CFG_VAL_STRING:
        free(val->val._string);
        break;
    case RNP_CFG_VAL_LIST:
        for (list_item *li = list_front(val->val._list); li; li = list_next(li)) {
            rnp_cfg_val_free((rnp_cfg_val_t *) li);
        }
        list_destroy(&val->val._list);
        break;
    default:
        break;
    }

    memset(val, 0, sizeof(*val));
}

static void
rnp_cfg_item_free(rnp_cfg_item_t *item)
{
    rnp_cfg_val_free(&item->val);
    free(item->key);
    item->key = NULL;
}

const char *
rnp_cfg_val_getstr(rnp_cfg_val_t *val)
{
    return val && (val->type == RNP_CFG_VAL_STRING) ? val->val._string : NULL;
}

static bool
rnp_cfg_val_copy(rnp_cfg_val_t *dst, rnp_cfg_val_t *src)
{
    memset(dst, 0, sizeof(*dst));

    switch (src->type) {
    case RNP_CFG_VAL_NULL:
    case RNP_CFG_VAL_INT:
    case RNP_CFG_VAL_BOOL:
        *dst = *src;
        break;
    case RNP_CFG_VAL_STRING:
        dst->type = RNP_CFG_VAL_STRING;
        if (src->val._string && !(dst->val._string = strdup(src->val._string))) {
            return false;
        }
        break;
    case RNP_CFG_VAL_LIST:
        dst->type = RNP_CFG_VAL_LIST;
        for (list_item *li = list_front(src->val._list); li; li = list_next(li)) {
            rnp_cfg_val_t val = {};
            if (!rnp_cfg_val_copy(&val, (rnp_cfg_val_t *) li) ||
                !list_append(&dst->val._list, &val, sizeof(val))) {
                rnp_cfg_val_free(dst);
                return false;
            }
        }
        break;
    default:
        return false;
    }

    return true;
}

/* find the value name in the rnp_cfg */
static rnp_cfg_item_t *
rnp_cfg_find(const rnp_cfg_t *cfg, const char *key)
{
    rnp_cfg_item_t *it = NULL;

    for (list_item *li = list_front(cfg->vals); li; li = list_next(li)) {
        if (strcmp(((rnp_cfg_item_t *) li)->key, key) == 0) {
            it = (rnp_cfg_item_t *) li;
            break;
        }
    }

    return it;
}

/** @brief set val for the key in config, copying key and assigning val
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *  @param val value, which will be copied as it is
 *
 *  @return false if allocation is failed. keys and vals fields will be freed in rnp_cfg_free
 **/
static rnp_cfg_item_t *
rnp_cfg_set(rnp_cfg_t *cfg, const char *key, rnp_cfg_val_t *val)
{
    rnp_cfg_item_t *it;

    if (!(it = rnp_cfg_find(cfg, key))) {
        it = (rnp_cfg_item_t *) list_append(&cfg->vals, NULL, sizeof(*it));

        if (!it || !(it->key = strdup(key))) {
            RNP_LOG("bad alloc");
            return NULL;
        }
    } else {
        rnp_cfg_val_free(&it->val);
    }

    it->val = *val;
    return it;
}

bool
rnp_cfg_unset(rnp_cfg_t *cfg, const char *key)
{
    rnp_cfg_item_t *it;

    if ((it = rnp_cfg_find(cfg, key))) {
        rnp_cfg_item_free(it);
        list_remove((list_item *) it);
        return true;
    }

    return false;
}

bool
rnp_cfg_hasval(const rnp_cfg_t *cfg, const char *key)
{
    return rnp_cfg_find(cfg, key) != NULL;
}

bool
rnp_cfg_setint(rnp_cfg_t *cfg, const char *key, int val)
{
    rnp_cfg_val_t _val = {.type = RNP_CFG_VAL_INT, .val = {._int = val}};
    return rnp_cfg_set(cfg, key, &_val) != NULL;
}

bool
rnp_cfg_setbool(rnp_cfg_t *cfg, const char *key, bool val)
{
    rnp_cfg_val_t _val = {.type = RNP_CFG_VAL_BOOL, .val = {._bool = val}};
    return rnp_cfg_set(cfg, key, &_val) != NULL;
}

bool
rnp_cfg_setstr(rnp_cfg_t *cfg, const char *key, const char *val)
{
    rnp_cfg_val_t _val = {.type = RNP_CFG_VAL_STRING, .val = {._string = NULL}};

    if (val && !(_val.val._string = strdup(val))) {
        return false;
    }

    if (!rnp_cfg_set(cfg, key, &_val)) {
        free(_val.val._string);
        return false;
    }

    return true;
}

bool
rnp_cfg_addstr(rnp_cfg_t *cfg, const char *key, const char *str)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);
    rnp_cfg_val_t   val;
    bool            added = false;

    if (!it) {
        memset(&val, 0, sizeof(val));
        val.type = RNP_CFG_VAL_LIST;
        if (!(it = rnp_cfg_set(cfg, key, &val))) {
            return false;
        }
        added = true;
    }

    if (it->val.type != RNP_CFG_VAL_LIST) {
        RNP_LOG("wrong param");
        return false;
    }

    val.type = RNP_CFG_VAL_STRING;
    if (!(val.val._string = strdup(str)) ||
        !list_append(&it->val.val._list, &val, sizeof(val))) {
        if (added) {
            rnp_cfg_unset(cfg, key);
        }
        return false;
    }

    return true;
}

const char *
rnp_cfg_getstr(const rnp_cfg_t *cfg, const char *key)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);

    if (it && (it->val.type == RNP_CFG_VAL_STRING)) {
        return it->val.val._string;
    }

    return NULL;
}

const char *
rnp_cfg_gethashalg(const rnp_cfg_t *cfg)
{
    const char *hash_alg = rnp_cfg_getstr(cfg, CFG_HASH);
    if (hash_alg) {
        return hash_alg;
    }
    return DEFAULT_HASH_ALG;
}

int
rnp_cfg_getint(const rnp_cfg_t *cfg, const char *key)
{
    return rnp_cfg_getint_default(cfg, key, 0);
}

int
rnp_cfg_getint_default(const rnp_cfg_t *cfg, const char *key, int def)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);

    if (it) {
        switch (it->val.type) {
        case RNP_CFG_VAL_INT:
            return it->val.val._int;
        case RNP_CFG_VAL_BOOL:
            return it->val.val._bool;
        case RNP_CFG_VAL_STRING:
            return atoi(it->val.val._string);
        default:
            break;
        }
    }

    return def;
}

bool
rnp_cfg_getbool(const rnp_cfg_t *cfg, const char *key)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);

    if (it) {
        switch (it->val.type) {
        case RNP_CFG_VAL_INT:
            return it->val.val._int != 0;
        case RNP_CFG_VAL_BOOL:
            return it->val.val._bool;
        case RNP_CFG_VAL_STRING:
            return (strcasecmp(it->val.val._string, "true") == 0) ||
                   (atoi(it->val.val._string) > 0);
        default:
            break;
        }
    }

    return false;
}

list *
rnp_cfg_getlist(rnp_cfg_t *cfg, const char *key)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);

    if (it && (it->val.type == RNP_CFG_VAL_LIST)) {
        return &it->val.val._list;
    }

    return NULL;
}

bool
rnp_cfg_copylist_str(rnp_cfg_t *cfg, list *dst, const char *key)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);

    if (!it) {
        /* copy empty list is okay */
        return true;
    }

    if (it->val.type != RNP_CFG_VAL_LIST) {
        goto fail;
    }

    for (list_item *li = list_front(it->val.val._list); li; li = list_next(li)) {
        rnp_cfg_val_t *val = (rnp_cfg_val_t *) li;
        if ((val->type != RNP_CFG_VAL_STRING) || !val->val._string) {
            RNP_LOG("wrong item in string list");
            goto fail;
        }
        if (!list_append(dst, val->val._string, strlen(val->val._string) + 1)) {
            RNP_LOG("allocation failed");
            goto fail;
        }
    }

    return true;

fail:
    list_destroy(dst);
    return false;
}

void
rnp_cfg_free(rnp_cfg_t *cfg)
{
    const char *passwd = rnp_cfg_getstr(cfg, CFG_PASSWD);

    if (passwd) {
        pgp_forget((void *) passwd, strlen(passwd) + 1);
    }

    for (list_item *li = list_front(cfg->vals); li; li = list_next(li)) {
        rnp_cfg_item_free((rnp_cfg_item_t *) li);
    }

    list_destroy(&cfg->vals);
}

int
rnp_cfg_get_pswdtries(const rnp_cfg_t *cfg)
{
    const char *numtries;
    int         num;

    numtries = rnp_cfg_getstr(cfg, CFG_NUMTRIES);

    if ((numtries == NULL) || ((num = atoi(numtries)) <= 0)) {
        return MAX_PASSWORD_ATTEMPTS;
    } else if (strcmp(numtries, "unlimited")) {
        return INFINITE_ATTEMPTS;
    } else {
        return num;
    }
}

#if 0
bool
rnp_cfg_check_homedir(rnp_cfg_t *cfg, char *homedir)
{
    struct stat st;
    int         ret;

    if (homedir == NULL) {
        fputs("rnp: homedir option and HOME environment variable are not set \n", stderr);
        return false;
    } else if ((ret = stat(homedir, &st)) == 0 && !S_ISDIR(st.st_mode)) {
        /* file exists in place of homedir */
        RNP_LOG("homedir \"%s\" is not a dir", homedir);
        return false;
    } else if (ret != 0 && errno == ENOENT) {
        /* If the path doesn't exist then fail. */
        RNP_LOG("warning homedir \"%s\" not found", homedir);
        return false;
    } else if (ret != 0) {
        /* If any other occurred then fail. */
        RNP_LOG("an unspecified error occurred");
        return false;
    }

    return true;
}
#endif

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
        if (regcomp(&r,
                    "([0-9][0-9][0-9][0-9])[-/]([0-9][0-9])[-/]([0-9][0-9])",
                    REG_EXTENDED) != 0) {
            RNP_LOG("failed to compile regexp");
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

uint64_t
get_expiration(const char *s)
{
    uint64_t    now;
    int64_t     t;
    const char *mult;

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

int64_t
get_creation(const char *s)
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
    bool          res = true;
    rnp_cfg_val_t val;

    if (!src || !dst) {
        return;
    }

    for (list_item *li = list_front(src->vals); li; li = list_next(li)) {
        if (!rnp_cfg_val_copy(&val, &((rnp_cfg_item_t *) li)->val) ||
            !rnp_cfg_set(dst, ((rnp_cfg_item_t *) li)->key, &val)) {
            res = false;
            break;
        }
    }

    if (!res) {
        rnp_cfg_free(dst);
    }
}
