# 03 — Update `cmake/rnp-config.cmake.in` (DEFERRED)

## Status

**Deferred until #04-#11 land.** The `find_dependency(JSON-C 0.11)` line must
stay until `target_link_libraries(librnp ... JSON-C::JSON-C)` is removed
in #12. Otherwise downstream consumers' `find_package(rnp)` will fail when
JSON-C is not installed.

## Steps (when ready)

1. Edit `cmake/rnp-config.cmake.in`:
   - Remove line `find_dependency(JSON-C 0.11)`.
   - Update comment block (lines 29-31) — drop mention of `JSON-C::JSON-C`.
2. Update `cmake/Modules/FindJSON-C.cmake` install rule in
   `src/lib/CMakeLists.txt:670` to not list `FindJSON-C.cmake`.
3. Bundled `nlohmann/json.hpp` requires no `find_dependency` because
   it ships with rnp's headers (under `include/nlohmann/` after install).
   Will need `install(FILES src/lib/nlohmann/nlohmann/json.hpp DESTINATION
   include/nlohmann)` in src/lib/CMakeLists.txt.

## Files to touch

- `cmake/rnp-config.cmake.in`
- `src/lib/CMakeLists.txt` (FindJSON-C.cmake install list, nlohmann header install)