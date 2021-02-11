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
        RNP_LOG("idx is out of bounds for \"%s\"", key.c_str());
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

/**
 * @brief Grabs date from the string in %Y-%m-%d format
 *
 * @param s [in] NULL-terminated string with the date
 * @param t [out] On successful return result will be placed here
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
