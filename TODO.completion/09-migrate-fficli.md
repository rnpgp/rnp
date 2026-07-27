# 09 — Migrate `src/rnp/fficli.{cpp,h}` (P1)

## Goal

CLI's FFI glue — 7 callsites. Mostly parses JSON returned by FFI for display.

## Approach

Same translation table. Use `nlohmann::json::parse(str, nullptr, true)`
for exception-on-error parsing.

## Acceptance

- `rnp` CLI builds without json-c.
- CLI output identical (run `rnp --version` and a key dump, diff against main).

## Files touched

- `src/rnp/fficli.cpp`
- `src/rnp/fficli.h`