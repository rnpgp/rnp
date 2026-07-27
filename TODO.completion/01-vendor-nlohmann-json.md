# 01 — Vendor nlohmann/json single-header (P0) — DONE

## Approach taken

Vendored nlohmann/json v3.11.3 as a single-header file under
`src/lib/nlohmann/nlohmann/` (the standard nlohmann include layout, so
`#include <nlohmann/json.hpp>` resolves). Two files vendored:

- `src/lib/nlohmann/nlohmann/json.hpp` (~900KB, the full single-header)
- `src/lib/nlohmann/nlohmann/json_fwd.hpp` (forward declarations)

**Why this over FetchContent / submodule:**

- Matches the issue's stated motivation: header-only, no install complexity.
- Avoids the FetchContent → install(EXPORT) dependency-tracking issue
  (nlohmann_json as a non-IMPORTED target doesn't fit rnp's existing
  export set without extra CMake glue).
- No configure-time network dependency.
- No `.gitmodules` change needed.
- ~900KB of source is acceptable for a vendored single-header.

## Steps executed

1. Downloaded nlohmann/json v3.11.3 via FetchContent into `build/_deps`
   (transient — removed before commit).
2. Copied `single_include/nlohmann/json.hpp` and `single_include/nlohmann/json_fwd.hpp`
   to `src/lib/nlohmann/nlohmann/`.
3. In top-level `CMakeLists.txt`: documented the choice (no code needed).
4. In `src/lib/CMakeLists.txt`: added `src/lib/nlohmann` to the
   `target_include_directories(librnp-obj PUBLIC ...)` list (PUBLIC because
   it's a header-only include path; in practice no public rnp header uses
   it, so PRIVATE would also work — kept PUBLIC for downstream consumer
   flexibility).

## Acceptance — verified

- `cmake -B build -S . -DENABLE_DOC=Off -DENABLE_FUZZERS=Off -DBUILD_TESTING=Off` configures cleanly.
- `cmake --build build -j4` compiles librnp, rnp, rnpkeys successfully.
- A standalone test including `<nlohmann/json.hpp>` compiles and runs.

## Files touched

- `src/lib/nlohmann/nlohmann/json.hpp` (new, vendored)
- `src/lib/nlohmann/nlohmann/json_fwd.hpp` (new, vendored)
- `src/lib/CMakeLists.txt` (added include directory)