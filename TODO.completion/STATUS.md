# Status — issue #2366 migration

**Branch:** `replace-json-c-with-nlohmann` in worktree `wt-nlohmann-json`

**Build state:** GREEN — librnp, rnp, rnpkeys, rnp_tests all compile.
No remaining references to json-c in `src/`, `cmake/`, `.github/`,
`ci/`. `FindJSON-C.cmake` deleted. CI workflows updated. Packaging
updated. Production code is 100% nlohmann::json.

**11 commits on the branch**, all buildable:
- `c44f42c` — vendored nlohmann/json v3.11.3 + new rnp::json::* API
- `f52f2df` — rnp_supported_features migration
- `f5ca78c` — rnp_generate_key_json request parsing
- `a516fb9` — rnp_import_keys, rnp_import_signatures
- `264e243` — dump_key_to_json + helpers
- `c0a6741` — stream-dump DumpContextJson
- `a5dc8c2` — fficli, rnpkeys CLI
- `90e68a7` — tests/support check_json_field_*
- `96b6797` — bulk mechanical migration of test files
- `362add2` — remove json-c dependency entirely from production code
- `12b2867` — complete migration to nlohmann::json (build green)

## Known test failures (7 of 9 spot-checked)

`ctest -R "test_ffi_keygen_json|test_ffi_key_to_json|test_ffi_supported_features"`:
- `test_ffi_supported_features` — `[json.exception.type_error.302] type must be boolean, but is array`
- `test_ffi_keygen_json_pair`, `_pair_dsa_elg`, `_primary`, `_sub`, `_sub_pass_required`
- `test_ffi_key_to_json` — `get_json_obj(jso, "primary key grip")` returns nullptr

These are behavioral deltas from the migration that the test suite caught,
exactly as intended ("the tests will tell us if the behavior is correct").
The translator scripts (TODO.completion/_json_translate*.py) handled
mechanical patterns; semantics-level fixups remain.

## Likely root causes to investigate

1. **`get_json_obj` helper in tests** — likely returns `nlohmann::json*`
   but tests then call `.get<bool>()` or similar without checking type.
   The test_ffi_supported_features failure suggests a get-on-array bug.
2. **JSON output structure change** — `dump_key_to_json` may emit a
   different shape (e.g., missing "primary key grip" when there's no
   primary). Compare key_to_json output before/after on a fixture.
3. **String-vs-array confusion** — some json_object_get_string calls
   in tests may have been on fields that are now arrays.

## Recommended next steps (follow-up session)

1. Run `ctest -E fuzz --output-on-failure` to get full failure inventory.
2. For each failure, compare JSON output before (origin/main) and after
   (this branch) using `rnp --list-packets` and `rnpkeys --list`.
3. Fix root causes in rnp.cpp / stream-dump.cpp / ffi-priv-types.h.
4. Update test assertions only where the new JSON shape is intentionally
   different (e.g., slash escaping, indent).
5. Run full ctest, expect 100% pass.

## What is done and clean

- ✅ nlohmann/json vendored (single-header, MIT, copyright intact)
- ✅ rnp::json::* helper API in json-utils.{h,cpp}
- ✅ All production source migrated (rnp.cpp, stream-dump.cpp, fficli.cpp,
  rnpkeys.cpp, ffi-priv-types.h, support.cpp)
- ✅ All test files migrated (build clean)
- ✅ CMake: json-c dependency removed from src/lib, src/rnp, src/rnpkeys,
  src/tests
- ✅ cmake/rnp-config.cmake.in: find_dependency(JSON-C) removed
- ✅ cmake/Modules/FindJSON-C.cmake: deleted
- ✅ cmake/packaging.cmake: FreeBSD deps updated
- ✅ CI workflows: libjson-c-dev removed from all platforms
- ✅ ci/tests/pk-tests.sh, downstream-consumer.sh: updated
- ✅ Full build clean (configure + librnp + rnp + rnpkeys + rnp_tests)

## What needs follow-up

- ⚠️ Behavioral test failures (7+) — investigate root cause, fix
- ⚠️ Run full ctest to find any other failures
- ⚠️ Output stability verification on real keyrings
- ⚠️ Verify CLI golden output (rnp --list-packets, rnpkeys --list)