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
#include "json_object.h"
#include "json.h"

/**
 * @brief Add field to the json object.
 *        Note: this function is for convenience, it will check val for NULL and destroy val
 *        on failure.
 * @param obj allocated json_object of object type.
 * @param name name of the field
 * @param val json object of any type. Will be checked for NULL.
 * @return true if val is not NULL and field was added successfully, false otherwise.
 */
bool obj_add_field_json(json_object *obj, const char *name, json_object *val);

/**
 * @brief Shortcut to add string via obj_add_field_json().
 */
bool json_add(json_object *obj, const char *name, const char *value);

/**
 * @brief Shortcut to add string with length via obj_add_field_json().
 */
bool json_add(json_object *obj, const char *name, const char *value, size_t len);

/**
 * @brief Shortcut to add bool via obj_add_field_json().
 */
bool json_add(json_object *obj, const char *name, bool value);

/**
 * @brief Add hex representation of binary data as string field to JSON object.
 *        Note: this function follows conventions of obj_add_field_json().
 */
bool obj_add_hex_json(json_object *obj, const char *name, const uint8_t *val, size_t val_len);

/**
 * @brief Add element to JSON array.
 *        Note: this function follows convention of the obj_add_field_json.
 */
bool array_add_element_json(json_object *obj, json_object *val);

namespace rnp {
class JSONObject {
    json_object *obj_;

  public:
    JSONObject(json_object *obj) : obj_(obj)
    {
    }

    ~JSONObject()
    {
        if (obj_) {
            json_object_put(obj_);
        }
    }
};
} // namespace rnp

#endif
