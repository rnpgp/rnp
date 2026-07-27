# 11 — Migrate `src/librepgp/stream-dump.{cpp,h}` (P1)

## Goal

Packet dumper — 26 callsites. Builds the JSON used by `rnp --list-packets`.

## Approach

Same translation table. **Output stability is critical here**: list-packets
output is consumed by users and tools; run `rnp --list-packets` against a
fixture packet before/after, diff must be empty.

## Acceptance

- `stream-dump.cpp` builds without json-c.
- `rnp --list-packets` byte-identical output on fixture keyring.

## Files touched

- `src/librepgp/stream-dump.cpp`
- `src/librepgp/stream-dump.h`