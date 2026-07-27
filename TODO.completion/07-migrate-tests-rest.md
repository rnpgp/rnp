# 07 — Migrate remaining test files (P0)

## Files

| File | Callsites |
|------|-----------|
| `src/tests/ffi-key.cpp` | (count after #04 lands) |
| `src/tests/ffi-enc.cpp` | " |
| `src/tests/ffi-key-sig.cpp` | " |
| `src/tests/streams.cpp` | " |
| `src/tests/partial-length.cpp` | " |
| `src/tests/pipe.cpp` | " |
| `src/tests/s2k-iterations.cpp` | " |

## Approach

Same translation table as #05. Each file is independent and can be migrated
in isolation. Run `rnp_tests` after each.

## Acceptance

- All `src/tests/*.cpp` build without json-c.
- Full `rnp_tests` suite passes.

## Files touched

- All listed files.