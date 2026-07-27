/*
 * Copyright (c) 2019, [Ribose Inc](https://www.ribose.com).
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
#ifndef RNP_JSON_UTILS_H_
#define RNP_JSON_UTILS_H_

#include <stdio.h>
#include "types.h"
#include <limits.h>
#include "fingerprint.hpp"

#include <nlohmann/json.hpp>

namespace rnp {

/**
 * @brief JSON helpers over nlohmann::ordered_json.
 *
 * Free-function overloads for the domain-specific concerns (hex blobs with
 * a 1 MiB cap, KeyID/Fingerprint encoding, type-safe gets with optional
 * field removal). nlohmann::ordered_json's value semantics replace the old
 * json-c refcounted json_object* + rnp::JSONObject RAII shim.
 *
 * Design notes:
 *  - Writes return bool for compatibility with the legacy API; for
 *    nlohmann::ordered_json they always succeed (the only failure mode in the
 *    legacy code was allocation failure, which nlohmann::ordered_json reports
 *    via exception).
 *  - The optional `del` parameter on reads mirrors the legacy semantics
 *    (erase the field after extraction); it defaults to false because
 *    nlohmann::ordered_json copies are cheap and the json-c del=true pattern was
 *    a workaround for refcounted shared ownership.
 *  - Domain helpers (add_hex with the 1 MiB cap, add(KeyID)/add(Fingerprint))
 *    preserve the same business rules as the legacy implementation.
 */
namespace json {

/** Add string field. */
bool add(nlohmann::ordered_json &obj, const char *name, const char *value);
bool add(nlohmann::ordered_json &obj, const char *name, const char *value, size_t len);
bool add(nlohmann::ordered_json &obj, const char *name, const std::string &value);

/** Add bool field. */
bool add(nlohmann::ordered_json &obj, const char *name, bool value);

/** Add int / uint64 field. */
bool add(nlohmann::ordered_json &obj, const char *name, int value);
bool add(nlohmann::ordered_json &obj, const char *name, uint64_t value);

/** Add hex-encoded binary field (1 MiB cap, lowercase). */
bool add_hex(nlohmann::ordered_json &obj, const char *name, const uint8_t *val, size_t len);
bool add_hex(nlohmann::ordered_json &obj, const char *name, const std::vector<uint8_t> &vec);

/** Add hex-encoded KeyID / Fingerprint field. */
bool add(nlohmann::ordered_json &obj, const char *name, const pgp::KeyID &keyid);
bool add(nlohmann::ordered_json &obj, const char *name, const pgp::Fingerprint &fp);

/** Append string to JSON array. */
bool array_add(nlohmann::ordered_json &arr, const char *val);
/** Append arbitrary JSON value to array. */
bool array_add(nlohmann::ordered_json &arr, nlohmann::ordered_json val);

/** Read string field. Returns false if missing or wrong-typed. */
bool get_str(nlohmann::ordered_json &obj, const char *name, std::string &out, bool del = true);
/** Read int field. */
bool get_int(nlohmann::ordered_json &obj, const char *name, int &out, bool del = true);
/** Read uint64 field. */
bool get_uint64(nlohmann::ordered_json &obj, const char *name, uint64_t &out, bool del = true);
/** Read string-array field. */
bool get_str_arr(nlohmann::ordered_json   &obj,
                 const char               *name,
                 std::vector<std::string> &out,
                 bool                      del = true);

/** Get a non-owning pointer to a sub-object, or nullptr if missing/wrong-typed. */
nlohmann::ordered_json *get_obj(nlohmann::ordered_json &obj, const char *name);

/**
 * @brief Serialize JSON to a string in json-c-compatible PRETTY format.
 *
 * json-c's JSON_C_TO_STRING_PRETTY uses 2-space indent and no space after
 * the colon between key and value. nlohmann::ordered_json::dump(2) uses 2-space
 * indent but adds a space after the colon. Existing callers (CLI, FFI
 * output) and tests expect the json-c shape, so this helper preserves it.
 */
std::string dump_pretty(const nlohmann::ordered_json &jso);

} // namespace json
} // namespace rnp

#endif
