# 05 — Migrate `src/tests/ffi.cpp` (71 callsites, P0)

## Goal

Test-side migration. Tests both consume JSON (via `json_tokener_parse`) and
assert on JSON shape. Direct use of `nlohmann::json` is fine here — tests
don't need the production helper layer.

## Approach

1. Replace `json_object *obj = json_tokener_parse(str.c_str());` with
   `auto obj = nlohmann::json::parse(str);` wrapped in `try/catch` for
   parse errors.
2. Replace assertions:
   - `CHECK(json_object_object_get_ex(obj, "key", &val))` → `CHECK(obj.contains("key"))`
   - `CHECK_STREQ(json_object_get_string(val), "...")` → `CHECK(obj["key"] == "...")`
3. Use `rnp::json::get_str` etc. where the test reads back domain-encoded
   values (hex blobs especially).
4. Add `#include <nlohmann/json.hpp>` at top, remove `<json.h>`.

## Acceptance

- `ffi.cpp` builds without json-c headers.
- All `rnp_tests` cases defined in `ffi.cpp` pass.

## Files touched

- `src/tests/ffi.cpp`