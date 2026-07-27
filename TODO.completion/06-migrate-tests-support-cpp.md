# 06 — Migrate `src/tests/support.cpp` (12 callsites, P0)

## Goal

Test support helpers — mostly JSON construction for fixtures.

## Approach

Same translation table as #04. Use `rnp::json::add` helpers for hex fields.

## Acceptance

- Builds without json-c.
- Test fixtures still produce the same JSON.

## Files touched

- `src/tests/support.cpp`