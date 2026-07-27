# 15 — Update `ci/tests/pk-tests.sh` and `downstream-consumer.sh` (P2)

## Files

- `ci/tests/pk-tests.sh:61-63`: replace `pkg_check_modules(JSONC ... json-c12|json-c)`
  with `pkg_check_modules(NLOHMANN_JSON nlohmann_json)` if needed (most likely
  just delete the block — it was specifically about RHEL json-c12/13 fallbacks).
- `ci/tests/downstream-consumer.sh:50,89`: drop `-ljson-c` from the link line.

## Acceptance

- pk-tests pass.
- downstream-consumer test builds against an installed librnp without json-c.

## Files touched

- `ci/tests/pk-tests.sh`
- `ci/tests/downstream-consumer.sh`