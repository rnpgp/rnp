# 00 — Overview: Replace json-c with nlohmann/json

Resolves [rnpgp/rnp#2366](https://github.com/rnpgp/rnp/issues/2366).

## Why

- `json-c` is a non-header-only library with a C API that requires a runtime
  link step and per-distro packaging (`json-c-dev`, `json-c12`, `json-c13`).
- `nlohmann/json` is header-only, idiomatic C++, and can be vendored with
  zero system dependency.

## Architectural decisions

1. **Vendor nlohmann/json** via `FetchContent` (preferred) with a
   `find_package(nlohmann_json)` fallback for distros that ship it.
   Mirrors the existing `sexpp` pattern (`SYSTEM_LIBSEXPP`).

2. **Drop the C `json_object*` API surface** in `src/lib/json-utils.{h,cpp}`.
   Replace it with a thin C++ helper layer over `nlohmann::json`:
   - Free functions that add fields (string/bool/int/uint64/hex/KeyID/Fingerprint).
   - Free functions that read fields (`str`, `int`, `uint64`, `str_arr`, `obj`).
   - **No `rnp::JSONObject` RAII shim** — `nlohmann::json` has value semantics
     so RAII is implicit.

3. **Strangler migration**: rewrite one callsite-file at a time. The old
   `json_object*`-based API is removed only after the last consumer migrates.
   Tests run after each file to keep semantics stable.

4. **JSON output must be byte-identical** to the existing `json-c` output
   for the FFI boundary (CLI, FFI consumers). nlohmann/json defaults to
   compact output with deterministic key ordering if we use
   `j.dump()` with no indent and avoid `push_back` to objects (which
   preserves insertion order — matching `json_object_object_add`).

5. **No double-handling for hex blobs**. Keep `bin_to_hex` integration for
   `KeyID`/`Fingerprint`/raw bytes — those are domain rules, not JSON.

## Principles applied (per project standards)

- **OCP**: helpers are free functions over `nlohmann::json`, no custom
  container class. Adding a new field type = one overload, no class edit.
- **MECE**: each helper has one concern (add X / get X). No mixed-utility
  structs.
- **DRY**: hex encoding, key-id encoding, fingerprint encoding — all live
  in one place, reused by every caller.
- **Model-driven**: `nlohmann::json` *is* the model. No wrapper class that
  hides it. C++ idioms (assignment, `.value()`, `.contains()`) replace
  `json_object_*` calls at callsites.
- **Performance**: `nlohmann::json` uses value semantics — copying is
  cheap for small objects, deep only on mutation. Avoid
  `parse()` in hot loops; prefer `nlohmann::json::parse(stream)`.
- **Tests**: every migration file gets a CMake target that compiles and
  the existing fixtures (`rnp_tests`) are reused. No new test framework.

## Phasing

| Pri | File | Subject |
|-----|------|---------|
| P0 | 01 | Vendor nlohmann/json + CMake target |
| P0 | 02 | Rewrite `src/lib/json-utils.{h,cpp}` over `nlohmann::json` |
| P0 | 03 | Update `cmake/rnp-config.cmake.in` (drop JSON-C dep) |
| P0 | 04 | Migrate `src/lib/rnp.cpp` (83 callsites) — model authority |
| P0 | 05 | Migrate `src/tests/ffi.cpp` (71 callsites) — first tests gate |
| P0 | 06 | Migrate `src/tests/support.cpp` (12 callsites) |
| P0 | 07 | Migrate `src/tests/ffi-key.cpp`, `ffi-enc.cpp`, `ffi-key-sig.cpp`, `streams.cpp`, `partial-length.cpp`, `pipe.cpp`, `s2k-iterations.cpp` |
| P1 | 08 | Migrate `src/lib/json-utils.cpp` consumers in `src/lib/` |
| P1 | 09 | Migrate `src/rnp/fficli.{cpp,h}` (7 callsites) |
| P1 | 10 | Migrate `src/rnpkeys/rnpkeys.cpp` (12 callsites) |
| P1 | 11 | Migrate `src/librepgp/stream-dump.{cpp,h}` (26 callsites) |
| P2 | 12 | Remove `cmake/Modules/FindJSON-C.cmake` |
| P2 | 13 | Drop json-c from `cmake/packaging.cmake` FreeBSD deps |
| P2 | 14 | Remove `libjson-c-dev` from all `.github/workflows/*.yml` |
| P2 | 15 | Update `ci/tests/pk-tests.sh` and `downstream-consumer.sh` |
| P3 | 16 | Update README/docs/vcpkg/brew/conan/snap packaging files |
| P3 | 17 | Cleanup, final review, PR-ready commit |

## Out of scope

- Adding new JSON APIs (none requested).
- Changing the FFI JSON output format (must remain byte-identical for
  downstream callers).
- Refactoring unrelated modules (stick to scope strictly).