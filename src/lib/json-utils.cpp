/*
 * Copyright (c) 2021, [Ribose Inc](https://www.ribose.com).
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

#include "json-utils.h"
#include "logging.h"
#include "crypto/mem.h"

namespace rnp {
namespace json {

/* Internal helper: pull a pointer to a field if it exists and matches the
 * type predicate, otherwise nullptr. */
static nlohmann::json *
get_field(nlohmann::json &obj, const char *name, bool (*pred)(const nlohmann::json &))
{
    if (!obj.is_object() || !obj.contains(name)) {
        return nullptr;
    }
    nlohmann::json *field = &obj[name];
    if (!pred(*field)) {
        return nullptr;
    }
    return field;
}

bool
add(nlohmann::json &obj, const char *name, const char *value)
{
    obj[name] = value;
    return true;
}

bool
add(nlohmann::json &obj, const char *name, const char *value, size_t len)
{
    obj[name] = std::string(value, len);
    return true;
}

bool
add(nlohmann::json &obj, const char *name, const std::string &value)
{
    obj[name] = value;
    return true;
}

bool
add(nlohmann::json &obj, const char *name, bool value)
{
    obj[name] = value;
    return true;
}

bool
add(nlohmann::json &obj, const char *name, int value)
{
    obj[name] = value;
    return true;
}

bool
add(nlohmann::json &obj, const char *name, uint64_t value)
{
    obj[name] = value;
    return true;
}

bool
add_hex(nlohmann::json &obj, const char *name, const uint8_t *val, size_t val_len)
{
    if (val_len > 1024 * 1024) {
        RNP_LOG("too large json hex field: %zu", val_len);
        val_len = 1024 * 1024;
    }
    obj[name] = bin_to_hex(val, val_len, rnp::HexFormat::Lowercase);
    return true;
}

bool
add_hex(nlohmann::json &obj, const char *name, const std::vector<uint8_t> &vec)
{
    return add_hex(obj, name, vec.data(), vec.size());
}

bool
add(nlohmann::json &obj, const char *name, const pgp::KeyID &keyid)
{
    return add_hex(obj, name, keyid.data(), keyid.size());
}

bool
add(nlohmann::json &obj, const char *name, const pgp::Fingerprint &fp)
{
    return add_hex(obj, name, fp.data(), fp.size());
}

bool
array_add(nlohmann::json &arr, const char *val)
{
    arr.push_back(val);
    return true;
}

bool
array_add(nlohmann::json &arr, nlohmann::json val)
{
    arr.push_back(std::move(val));
    return true;
}

bool
get_str(nlohmann::json &obj, const char *name, std::string &out, bool del)
{
    auto *field = get_field(obj, name, [](const nlohmann::json &v) { return v.is_string(); });
    if (!field) {
        return false;
    }
    out = field->get_ref<const std::string &>();
    if (del) {
        obj.erase(name);
    }
    return true;
}

bool
get_int(nlohmann::json &obj, const char *name, int &out, bool del)
{
    auto *field = get_field(
        obj, name, [](const nlohmann::json &v) { return v.is_number_integer(); });
    if (!field) {
        return false;
    }
    out = field->get<int>();
    if (del) {
        obj.erase(name);
    }
    return true;
}

bool
get_uint64(nlohmann::json &obj, const char *name, uint64_t &out, bool del)
{
    auto *field = get_field(
        obj, name, [](const nlohmann::json &v) { return v.is_number(); });
    if (!field) {
        return false;
    }
    out = field->get<uint64_t>();
    if (del) {
        obj.erase(name);
    }
    return true;
}

bool
get_str_arr(nlohmann::json &            obj,
            const char *                name,
            std::vector<std::string> &  out,
            bool                        del)
{
    auto *arr = get_field(obj, name, [](const nlohmann::json &v) { return v.is_array(); });
    if (!arr) {
        return false;
    }
    out.clear();
    for (const auto &item : *arr) {
        if (!item.is_string()) {
            return false;
        }
        out.push_back(item.get_ref<const std::string &>());
    }
    if (del) {
        obj.erase(name);
    }
    return true;
}

nlohmann::json *
get_obj(nlohmann::json &obj, const char *name)
{
    return get_field(obj, name, [](const nlohmann::json &v) { return v.is_object(); });
}

} // namespace json
} // namespace rnp
