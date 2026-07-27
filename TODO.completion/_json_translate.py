#!/usr/bin/env python3
"""
Mechanical translator for json-c → nlohmann::json.
Conservative: only touches clear json-c patterns.
Expects manual fixup for: NULL pointer semantics, json_object_object_get_ex
with separate variable, type mismatches with char*.
"""
import re
import sys

def translate(text):
    # ---- includes ----
    text = re.sub(r'#include\s+"json_object\.h"', '#include <nlohmann/json.hpp>', text)
    text = re.sub(r'#include\s+"json\.h"', '#include <nlohmann/json.hpp>', text)
    text = re.sub(r'#include\s+<json_object\.h>', '#include <nlohmann/json.hpp>', text)
    text = re.sub(r'#include\s+<json\.h>', '#include <nlohmann/json.hpp>', text)

    # ---- type rename: json_object *foo  →  nlohmann::json foo ----
    # Both `json_object *foo` and `json_object* foo`
    text = re.sub(r'\bjson_object\s*\*\s*', 'nlohmann::json ', text)
    # Handle: `nlohmann::json foo = NULL;` → `nlohmann::json foo;`
    # Only when var type was just rewritten to nlohmann::json (i.e., was json_object*)
    text = re.sub(r'(nlohmann::json\s+\w+\s*=\s*)NULL(\s*;)', r'\1\2', text)

    # ---- constructors ----
    text = re.sub(r'\bjson_object_new_object\s*\(\s*\)', 'nlohmann::json::object()', text)
    text = re.sub(r'\bjson_object_new_array\s*\(\s*\)', 'nlohmann::json::array()', text)
    # Leave json_object_new_string/int/bool alone — these become calls
    # into nlohmann::json. They typically appear inside json_object_array_add
    # or json_object_object_add, which we'll convert.

    # ---- parser ----
    text = re.sub(r'\bjson_tokener_parse_verbose\s*\(\s*([^,()]+?)\s*,\s*&\w+\s*\)',
                  r'nlohmann::json::parse(\1)', text)
    text = re.sub(r'\bjson_tokener_parse\s*\(', 'nlohmann::json::parse(', text)
    text = re.sub(r'\bjson_tokener_error_desc\s*\(\s*([^()]+?)\s*\)',
                  r'"parse error"', text)

    # ---- predicates ----
    text = re.sub(r'\bjson_object_is_type\s*\(\s*([^,()]+?)\s*,\s*json_type_string\s*\)',
                  r'\1.is_string()', text)
    text = re.sub(r'\bjson_object_is_type\s*\(\s*([^,()]+?)\s*,\s*json_type_int\s*\)',
                  r'\1.is_number_integer()', text)
    text = re.sub(r'\bjson_object_is_type\s*\(\s*([^,()]+?)\s*,\s*json_type_boolean\s*\)',
                  r'\1.is_boolean()', text)
    text = re.sub(r'\bjson_object_is_type\s*\(\s*([^,()]+?)\s*,\s*json_type_object\s*\)',
                  r'\1.is_object()', text)
    text = re.sub(r'\bjson_object_is_type\s*\(\s*([^,()]+?)\s*,\s*json_type_array\s*\)',
                  r'\1.is_array()', text)
    text = re.sub(r'\bjson_object_is_type\s*\(\s*([^,()]+?)\s*,\s*json_type_double\s*\)',
                  r'\1.is_number_float()', text)

    # ---- getters (do NOT touch these that need .get vs ->get) ----
    # We use a heuristic: if arg looks like a value (lowercase identifier without ->),
    # use .get; if pointer (with ->), use ->get. Conservative: only convert the most
    # common form (value access on local var).
    text = re.sub(r'\bjson_object_get_string\s*\(\s*(\w+)\s*\)',
                  r'\1.get_ref<const std::string &>()', text)
    text = re.sub(r'\bjson_object_get_int64\s*\(\s*(\w+)\s*\)',
                  r'\1.get<int64_t>()', text)
    text = re.sub(r'\bjson_object_get_int\s*\(\s*(\w+)\s*\)',
                  r'\1.get<int>()', text)
    text = re.sub(r'\bjson_object_get_boolean\s*\(\s*(\w+)\s*\)',
                  r'\1.get<bool>()', text)
    text = re.sub(r'\bjson_object_get_double\s*\(\s*(\w+)\s*\)',
                  r'\1.get<double>()', text)
    # Pointer access variants: json_object_get_string((*ptr)) etc.
    # Leave for manual fixup.

    # ---- array ops ----
    text = re.sub(r'\bjson_object_array_length\s*\(\s*(\w+)\s*\)',
                  r'\1.size()', text)
    text = re.sub(r'\bjson_object_array_get_idx\s*\(\s*(\w+)\s*,\s*([^()]+?)\s*\)',
                  r'\1.at(\2)', text)
    text = re.sub(r'\bjson_object_array_add\s*\(\s*(\w+)\s*,\s*([^()]+?)\s*\)',
                  r'\1.push_back(\2)', text)

    # ---- object ops ----
    text = re.sub(r'\bjson_object_object_del\s*\(\s*(\w+)\s*,\s*([^()]+?)\s*\)',
                  r'\1.erase(\2)', text)
    # json_object_object_add(obj, "k", val) → obj["k"] = std::move(val)
    text = re.sub(r'\bjson_object_object_add\s*\(\s*(\w+)\s*,\s*([^,()]+?)\s*,\s*([^()]+?)\s*\)',
                  r'\1[\2] = std::move(\3)', text)

    # ---- json_object_object_get_ex: too complex to translate mechanically.
    # Leave alone; require manual fixup. ----

    # ---- RAII cleanup ----
    text = re.sub(r'\bjson_object_put\s*\(\s*(\w+)\s*\)\s*;',
                  r'/* json_object_put removed: \1 */', text)

    # ---- serializer ----
    text = re.sub(r'\bjson_object_to_json_string_ext\s*\(\s*(\w+)\s*,\s*JSON_C_TO_STRING_PLAIN\s*\)',
                  r'\1.dump()', text)
    text = re.sub(r'\bjson_object_to_json_string_ext\s*\(\s*(\w+)\s*,\s*JSON_C_TO_STRING_PRETTY\s*\)',
                  r'\1.dump(4)', text)
    text = re.sub(r'\bjson_object_to_json_string\s*\(\s*(\w+)\s*\)',
                  r'\1.dump()', text)

    return text

if __name__ == '__main__':
    for path in sys.argv[1:]:
        with open(path) as f:
            text = f.read()
        new = translate(text)
        with open(path, 'w') as f:
            f.write(new)
        print(f"translated {path}")