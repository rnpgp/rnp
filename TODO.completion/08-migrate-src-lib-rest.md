# 08 — Migrate remaining `src/lib/` consumers (P1)

## Goal

After `rnp.cpp` (#04), check for any remaining `json_object_*` callsites
in `src/lib/` (e.g., `rnp_keys.c` if present, `ffi-priv-types.h`).

## Approach

`grep -n "json_object_\|json_tokener" src/lib/*.cpp src/lib/*.h` to enumerate.
Apply the same translation table.

## Acceptance

- `src/lib/` is json-c-free.

## Files touched

- TBD by grep.