# 16 — Update docs / external packaging references (P3)

## Files to audit

- `README.adoc` (or `.md`) — install instructions
- `INSTALL.rst` / `docs/`
- `ci/build_tarball.sh`
- External (out of repo): vcpkg, brew, conan, snap, chocolatey recipes
  — note in PR description, downstream maintainers will follow.

## Acceptance

- No mention of `json-c` as a build/runtime requirement in repo docs.
- nlohmann/json is documented as the JSON library (vendored by default).

## Files touched

- TBD by grep `grep -ri "json-c\|json_c" README* docs/ INSTALL*`.