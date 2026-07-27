# 10 — Migrate `src/rnpkeys/rnpkeys.cpp` (P1)

## Goal

`rnpkeys` CLI — 12 callsites.

## Approach

Same translation table. Same output-stability check as #09.

## Acceptance

- `rnpkeys` builds without json-c.
- Generated keys have byte-identical JSON metadata vs main.

## Files touched

- `src/rnpkeys/rnpkeys.cpp`