/*
 * Copyright (c) 2017-2020 [Ribose Inc](https://www.ribose.com).
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
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#else
#include "uniwin.h"
#endif
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <stdexcept>

#include "rnpcfg.h"
#include "defaults.h"
#include <rnp/rnp_sdk.h>
#include <rekey/rnp_key_store.h>

// must be placed after include "utils.h"
#ifndef RNP_USE_STD_REGEX
#include <regex.h>
#else
#include <regex>
#endif

typedef enum rnp_cfg_val_type_t {
    RNP_CFG_VAL_NULL = 0,
    RNP_CFG_VAL_INT = 1,
    RNP_CFG_VAL_BOOL = 2,
    RNP_CFG_VAL_STRING = 3,
    RNP_CFG_VAL_LIST = 4
} rnp_cfg_val_type_t;

class rnp_cfg_val {
    rnp_cfg_val_type_t type_;

  public:
    rnp_cfg_val(rnp_cfg_val_type_t t) : type_(t){};
    rnp_cfg_val_type_t
    type() const
    {
        return type_;
    };

    virtual ~rnp_cfg_val(){};
};

class rnp_cfg_int_val : public rnp_cfg_val {
    int val_;

  public:
    rnp_cfg_int_val(int val) : rnp_cfg_val(RNP_CFG_VAL_INT), val_(val){};
    int
    val() const
    {
        return val_;
    };
};

class rnp_cfg_bool_val : public rnp_cfg_val {
    bool val_;

  public:
    rnp_cfg_bool_val(bool val) : rnp_cfg_val(RNP_CFG_VAL_BOOL), val_(val){};
    bool
    val() const
    {
        return val_;
    };
};

class rnp_cfg_str_val : public rnp_cfg_val {
    std::string val_;

  public:
    rnp_cfg_str_val(const std::string &val) : rnp_cfg_val(RNP_CFG_VAL_STRING), val_(val){};
    const std::string &
    val() const
    {
        return val_;
    };
};

class rnp_cfg_list_val : public rnp_cfg_val {
    std::vector<std::string> val_;

  public:
    rnp_cfg_list_val() : rnp_cfg_val(RNP_CFG_VAL_LIST), val_(){};
    std::vector<std::string> &
    val()
    {
        return val_;
    };
    const std::vector<std::string> &
    val() const
    {
        return val_;
    };
};

void
rnp_cfg::load_defaults()
{
    set_bool(CFG_OVERWRITE, false);
    set_str(CFG_OUTFILE, "");
    set_str(CFG_ZALG, DEFAULT_Z_ALG);
    set_int(CFG_ZLEVEL, DEFAULT_Z_LEVEL);
    set_str(CFG_CIPHER, DEFAULT_SYMM_ALG);
    set_int(CFG_NUMTRIES, MAX_PASSWORD_ATTEMPTS);
    set_int(CFG_S2K_MSEC, DEFAULT_S2K_MSEC);
}

void
rnp_cfg::set_str(const std::string &key, const std::string &val)
{
    unset(key);
    vals_[key] = new rnp_cfg_str_val(val);
}

void
rnp_cfg::set_str(const std::string &key, const char *val)
{
    unset(key);
    vals_[key] = new rnp_cfg_str_val(val);
}

void
rnp_cfg::set_int(const std::string &key, int val)
{
    unset(key);
    vals_[key] = new rnp_cfg_int_val(val);
}

void
rnp_cfg::set_bool(const std::string &key, bool val)
{
    unset(key);
    vals_[key] = new rnp_cfg_bool_val(val);
}

void
rnp_cfg::unset(const std::string &key)
{
    if (!vals_.count(key)) {
        return;
    }
    delete vals_[key];
    vals_.erase(key);
}

void
rnp_cfg::add_str(const std::string &key, const std::string &val)
{
    if (!vals_.count(key)) {
        vals_[key] = new rnp_cfg_list_val();
    }
    if (vals_[key]->type() != RNP_CFG_VAL_LIST) {
        RNP_LOG("expected list val for \"%s\"", key.c_str());
        throw std::invalid_argument("type");
    }
    rnp_cfg_list_val *list = dynamic_cast<rnp_cfg_list_val *>(vals_[key]);
    list->val().push_back(val);
}

bool
rnp_cfg::has(const std::string &key) const
{
    return vals_.count(key);
}

const std::string &
rnp_cfg::get_str(const std::string &key) const
{
    if (!has(key) || (vals_.at(key)->type() != RNP_CFG_VAL_STRING)) {
        return empty_str_;
    }
    return (dynamic_cast<const rnp_cfg_str_val *>(vals_.at(key)))->val();
}

const char *
rnp_cfg::get_cstr(const std::string &key) const
{
    if (!has(key) || (vals_.at(key)->type() != RNP_CFG_VAL_STRING)) {
        return NULL;
    }
    return (dynamic_cast<const rnp_cfg_str_val *>(vals_.at(key)))->val().c_str();
}

int
rnp_cfg::get_int(const std::string &key, int def) const
{
    if (!has(key)) {
        return def;
    }
    const rnp_cfg_val *val = vals_.at(key);
    switch (val->type()) {
    case RNP_CFG_VAL_INT:
        return (dynamic_cast<const rnp_cfg_int_val *>(val))->val();
    case RNP_CFG_VAL_BOOL:
        return (dynamic_cast<const rnp_cfg_bool_val *>(val))->val();
    case RNP_CFG_VAL_STRING:
        return atoi((dynamic_cast<const rnp_cfg_str_val *>(val))->val().c_str());
    default:
        return def;
    }
}

bool
rnp_cfg::get_bool(const std::string &key) const
{
    if (!has(key)) {
        return false;
    }
    const rnp_cfg_val *val = vals_.at(key);
    switch (val->type()) {
    case RNP_CFG_VAL_INT:
        return (dynamic_cast<const rnp_cfg_int_val *>(val))->val();
    case RNP_CFG_VAL_BOOL:
        return (dynamic_cast<const rnp_cfg_bool_val *>(val))->val();
    case RNP_CFG_VAL_STRING: {
        const std::string &str = (dynamic_cast<const rnp_cfg_str_val *>(val))->val();
        return !strcasecmp(str.c_str(), "true") || (atoi(str.c_str()) > 0);
    }
    default:
        return false;
    }
}

size_t
rnp_cfg::get_count(const std::string &key) const
{
    if (!has(key) || (vals_.at(key)->type() != RNP_CFG_VAL_LIST)) {
        return 0;
    }
    const rnp_cfg_list_val *val = dynamic_cast<const rnp_cfg_list_val *>(vals_.at(key));
    return val->val().size();
}

const std::string &
rnp_cfg::get_str(const std::string &key, size_t idx) const
{
    if (get_count(key) <= idx) {
        RNP_LOG("idx is out fo bounds for \"%s\"", key.c_str());
        throw std::invalid_argument("idx");
    }
    const rnp_cfg_list_val *val = dynamic_cast<const rnp_cfg_list_val *>(vals_.at(key));
    return val->val().at(idx);
}

std::vector<std::string>
rnp_cfg::get_list(const std::string &key) const
{
    if (!has(key)) {
        /* it's okay to return empty list */
        return std::vector<std::string>();
    }
    if (vals_.at(key)->type() != RNP_CFG_VAL_LIST) {
        RNP_LOG("no list at the key \"%s\"", key.c_str());
        throw std::invalid_argument("key");
    }
    const rnp_cfg_list_val *val = dynamic_cast<const rnp_cfg_list_val *>(vals_.at(key));
    return val->val();
}

int
rnp_cfg::get_pswdtries() const
{
    const std::string &numtries = get_str(CFG_NUMTRIES);
    int                num = atoi(numtries.c_str());
    if (numtries.empty() || (num <= 0)) {
        return MAX_PASSWORD_ATTEMPTS;
    } else if (numtries == "unlimited") {
        return INFINITE_ATTEMPTS;
    }
    return num;
}

const std::string
rnp_cfg::get_hashalg() const
{
    const std::string hash_alg = get_str(CFG_HASH);
    if (!hash_alg.empty()) {
        return hash_alg;
    }
    return DEFAULT_HASH_ALG;
}

void
rnp_cfg::copy(const rnp_cfg &src)
{
    for (const auto &it : src.vals_) {
        if (has(it.first)) {
            unset(it.first);
        }
        rnp_cfg_val *val = NULL;
        switch (it.second->type()) {
        case RNP_CFG_VAL_INT:
            val = new rnp_cfg_int_val(*(dynamic_cast<rnp_cfg_int_val *>(it.second)));
            break;
        case RNP_CFG_VAL_BOOL:
            val = new rnp_cfg_bool_val(*(dynamic_cast<rnp_cfg_bool_val *>(it.second)));
            break;
        case RNP_CFG_VAL_STRING:
            val = new rnp_cfg_str_val(*(dynamic_cast<rnp_cfg_str_val *>(it.second)));
            break;
        case RNP_CFG_VAL_LIST:
            val = new rnp_cfg_list_val(*(dynamic_cast<rnp_cfg_list_val *>(it.second)));
            break;
        default:
            continue;
        }
        vals_[it.first] = val;
    }
}

void
rnp_cfg::clear()
{
    for (const auto &it : vals_) {
        delete it.second;
    }
    vals_.clear();
}

rnp_cfg::~rnp_cfg()
{
    clear();
}

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
    rnp_cfg_setstr(cfg, CFG_ZALG, DEFAULT_Z_ALG);
    rnp_cfg_setint(cfg, CFG_ZLEVEL, DEFAULT_Z_LEVEL);
    rnp_cfg_setstr(cfg, CFG_CIPHER, DEFAULT_SYMM_ALG);
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

std::string
rnp_cfg_getstring(const rnp_cfg_t *cfg, const std::string &key)
{
    const char *val = rnp_cfg_getstr(cfg, key.c_str());
    return val ? val : "";
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

std::string
rnp_cfg_getlist_string(const rnp_cfg_t *cfg, const std::string &key, size_t index)
{
    list *lval = rnp_cfg_getlist(const_cast<rnp_cfg_t *>(cfg), key.c_str());
    if (!lval) {
        return "";
    }

    if (!(index < list_length(*lval))) {
        RNP_LOG("wrong item index");
        return "";
    }

    rnp_cfg_val_t *val = (rnp_cfg_val_t *) list_at(*lval, index);
    const char *   sval = rnp_cfg_val_getstr(val);
    return sval ? sval : "";
}

bool
rnp_cfg_copylist_str(const rnp_cfg_t *cfg, list *dst, const char *key)
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

bool
rnp_cfg_copylist_string(const rnp_cfg_t *         cfg,
                        std::vector<std::string> &dst,
                        const std::string &       key)
{
    dst.clear();

    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key.c_str());

    if (!it) {
        /* copy empty list is okay */
        return true;
    }

    if (it->val.type != RNP_CFG_VAL_LIST) {
        return false;
    }

    for (list_item *li = list_front(it->val.val._list); li; li = list_next(li)) {
        rnp_cfg_val_t *val = (rnp_cfg_val_t *) li;
        if ((val->type != RNP_CFG_VAL_STRING) || !val->val._string) {
            RNP_LOG("wrong item in string list");
            goto fail;
        }
        try {
            dst.emplace_back(val->val._string);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            goto fail;
        }
    }

    return true;
fail:
    dst.clear();
    return false;
}

void
rnp_cfg_free(rnp_cfg_t *cfg)
{
    const char *passwd = rnp_cfg_getstr(cfg, CFG_PASSWD);

    if (passwd) {
        rnp_buffer_clear((void *) passwd, strlen(passwd) + 1);
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
#ifndef RNP_USE_STD_REGEX
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
#else
    struct tm tm;

    static std::regex re("([0-9][0-9][0-9][0-9])[-/]([0-9][0-9])[-/]([0-9][0-9])",
                         std::regex_constants::extended);
    std::smatch       result;
    std::string       input = s;

    if (std::regex_search(input, result, re)) {
        (void) memset(&tm, 0x0, sizeof(tm));
        tm.tm_year = (int) strtol(result[1].str().c_str(), NULL, 10);
        tm.tm_mon = (int) strtol(result[2].str().c_str(), NULL, 10) - 1;
        tm.tm_mday = (int) strtol(result[3].str().c_str(), NULL, 10);
        *t = mktime(&tm);
        return true;
    }
#endif
    return false;
}

uint64_t
get_expiration(const char *s)
{
    uint64_t    now;
    int64_t     t;
    const char *mult;

    if (!s || !strlen(s)) {
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

    if (!s || !strlen(s)) {
        return time(NULL);
    }
    if (grabdate(s, &t)) {
        return t;
    }
    return (uint64_t) strtoll(s, NULL, 10);
}

bool
rnp_cfg_copy(rnp_cfg_t *dst, const rnp_cfg_t *src)
{
    bool          res = true;
    rnp_cfg_val_t val;

    if (!src || !dst) {
        return false;
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
    return res;
}
