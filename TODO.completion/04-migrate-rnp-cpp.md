# 04 — Migrate `src/lib/rnp.cpp` (83 callsites, P0)

## Why first

`rnp.cpp` is the FFI implementation core — it produces the JSON that
`rnp_dump_key_to_json`, `rnp_request_json`, etc. emit. Getting it right
first gates all the CLI and test consumers.

## Approach

1. Read current uses of `json_object_*` in `rnp.cpp`.
2. Mechanical translation table:

| json-c | nlohmann::json |
|--------|----------------|
| `json_object *o = json_object_new_object();` | `nlohmann::json o = nlohmann::json::object();` |
| `json_object *a = json_object_new_array();` | `nlohmann::json a = nlohmann::json::array();` |
| `json_object_object_add(o, "k", v);` | `o["k"] = v;` (v is `nlohmann::json`) |
| `json_object_array_add(a, v);` | `a.push_back(v);` |
| `json_object_new_string(s);` | `nlohmann::json(s)` or just `s` in assignment |
| `json_object_new_int(i);` | `i` in assignment |
| `json_object_new_uint64(u);` | `u` in assignment |
| `json_object_new_boolean(b);` | `b` in assignment |
| `json_object_get_string(o)` | `o.get<std::string>()` or `o.get_ref<const std::string&>()` |
| `json_object_get_int(o)` | `o.get<int>()` |
| `json_object_get_int64(o)` | `o.get<int64_t>()` |
| `json_object_object_get_ex(o, "k", &v)` | `o.contains("k")` + `v = o["k"]` |
| `json_object_object_del(o, "k");` | `o.erase("k");` |
| `json_object_array_length(a)` | `a.size()` |
| `json_object_array_get_idx(a, i)` | `a[i]` |
| `json_object_is_type(o, json_type_string)` | `o.is_string()` |
| `json_object_put(o);` | (delete; nlohmann is RAII) |
| `json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN)` | `o.dump()` |
| `json_tokener_parse_ex(...)` | `nlohmann::json::parse(str)` |

3. Use helpers from `json-utils.h` (now `rnp::json::add`, `add_hex`,
   `array_add`) where they exist — preserves the 1 MiB hex cap and
   domain encoding.

4. **Output stability**: confirm that
   `json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN)` ==
   `nlohmann::json::parse(o.dump()).dump()` for each call. The CLI diff
   test (test vector) is in `src/tests/ffi.cpp`.

## Acceptance

- `rnp.cpp` has zero `json_object_*` or `json_tokener_*` calls.
- All `rnp_tests` cases that emit JSON still pass with byte-identical output
  vs. pre-migration baseline (capture baseline before, diff after).

## Files touched

- `src/lib/rnp.cpp`