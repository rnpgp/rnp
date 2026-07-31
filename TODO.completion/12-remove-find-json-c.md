# 12 — Remove `cmake/Modules/FindJSON-C.cmake` (P2)

## Goal

After all callsites are migrated (#04–#11), the find-module is dead code.

## Steps

1. `git rm cmake/Modules/FindJSON-C.cmake`
2. Grep for any remaining `find_package(JSON-C)` / `find_dependency(JSON-C)`
   in `*.cmake`, `*.in`. Remove.
3. Remove `JSON-C::JSON-C` from all `target_link_libraries`.

## Acceptance

- No CMake file references JSON-C.
- Build works without json-c installed.

## Files touched

- `cmake/Modules/FindJSON-C.cmake` (deleted)
- `CMakeLists.txt`
- `src/lib/CMakeLists.txt`