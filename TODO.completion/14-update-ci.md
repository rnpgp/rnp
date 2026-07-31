# 14 — Remove `libjson-c-dev` from CI workflows (P2)

## Workflows to update

| File | Lines |
|------|-------|
| `.github/workflows/ubuntu.yml` | 102, 136, 177, 224, 289, 326 |
| `.github/workflows/codeql.yml` | 35 |
| `.github/workflows/coverity.yml` | 20 |
| `.github/workflows/windows-msys2.yml` | 110 (`json-c:p`) |
| `.github/workflows/windows-native.yml` | 128 (vcpkg `json-c`) |
| `.github/workflows/centos-and-fedora.yml` | 379-381 (json-c-devel setup) |

## Steps

1. Remove `libjson-c-dev` / `json-c:p` / `json-c` from package install lines.
2. Remove the entire `Setup json-c` step in `centos-and-fedora.yml`.
3. For `windows-native.yml`, remove `json-c` from `vcpkg install` line.

## Acceptance

- `grep -r "json-c" .github/` returns nothing.

## Files touched

- All listed workflow files.