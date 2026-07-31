# 04 — Migrate `src/lib/rnp.cpp` (145 callsites, P0)

## Status

**Partially done** — 1 of 145 callsites migrated.

The first callsite, `rnp_supported_features`, is migrated as a worked
example. Commit `f52f2df1` shows the pattern:

- `nlohmann::json features = nlohmann::json::array();` replaces the
  `json_object* features = json_object_new_array()` +
  `rnp::JSONObject featwrap(features)` RAII pair. `nlohmann::json` has
  value semantics, so RAII is implicit.
- `rnp::json::array_add(features, ...)` replaces
  `json_array_add(features, ...)`.
- `features.dump(4).c_str()` replaces
  `json_object_to_json_string_ext(features, JSON_C_TO_STRING_PRETTY)`.
  The `dump(4)` reproduces json-c's 4-space indent.

## Remaining work (144 callsites)

Migrate the rest of rnp.cpp in this order (each is a logical chunk that
commits independently and builds cleanly):

| Lines | Function | Callsites |
|-------|----------|-----------|
| 1674-1694 | key info dumps | ~20 |
| 1745-1786 | key dumps via dump_key_to_json | ~40 |
| 1806-1878 | signature dumps | ~70 |
| 4407-4610 | `rnp_key_gen_*` request parsing (`json_get_*` family) | ~200 |
| 4620-4660 | key generation JSON output | ~40 |
| 4734-4823 | request parsing (`json_tokener_parse_verbose`) | ~90 |
| 8000-8045 | `usage_flags_to_json` + `key_flags_to_json` | ~45 |
| 8200-8665 | large `rnp_dump_key_to_json` + `rnp_dump_signature_to_json` | ~600 |

That's more like ~1100 callsites by line count, but many are similar
boilerplate (`json_add(jso, "name", value)` × N). Total time to migrate
all of rnp.cpp correctly with build + test verification at each step is
estimated at 4-8 hours of focused work.

## Output stability

`features.dump(4)` does not byte-match `JSON_C_TO_STRING_PRETTY`:
- json-c escapes `/` (e.g. `"a\/b"`), nlohmann does not (`"a/b"`).
- json-c terminates the output with `\n` in some configurations;
  nlohmann does not.
- Minor differences in Unicode handling.

Tests in `src/tests/ffi*.cpp` parse JSON and assert on values, so they
should be robust to these deltas. CLI golden-output tests (if any)
might need their fixtures updated.

## Files to touch

- `src/lib/rnp.cpp` (this file)
- `src/tests/ffi.cpp`, `src/tests/ffi-key.cpp` (test updates if output
  diff affects assertions — see TODO #05-#07)