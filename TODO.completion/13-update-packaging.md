# 13 — Drop json-c from packaging (P2)

## Steps

1. `cmake/packaging.cmake:78`: change
   `set(CPACK_FREEBSD_PACKAGE_DEPS bzip2 json-c botan3)`
   to
   `set(CPACK_FREEBSD_PACKAGE_DEPS bzip2 botan3)`.
2. Search `cmake/`, `packaging/`, `*.cmake` for any other json-c packaging refs.

## Acceptance

- No `json-c` in packaging metadata.

## Files touched

- `cmake/packaging.cmake`
- (others if found)