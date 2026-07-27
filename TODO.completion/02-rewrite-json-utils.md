# 02 — Rewrite `src/lib/json-utils.{h,cpp}` over `nlohmann::json` (P0)

## Goal

Replace the `json_object*`-based helpers with a `nlohmann::json`-based
equivalent. Preserve call signatures as much as possible (just swap the
first parameter type) so callsite migration is mechanical.

## Design

New `json-utils.h` exposes free functions over `nlohmann::json&`:

```cpp
namespace rnp::json {

// Add field, returns true on success (always true for nlohmann; kept for parity)
bool add(nlohmann::json &obj, const char *name, const char *value);
bool add(nlohmann::json &obj, const char *name, const char *value, size_t len);
bool add(nlohmann::json &obj, const char *name, const std::string &value);
bool add(nlohmann::json &obj, const char *name, bool value);
bool add(nlohmann::json &obj, const char *name, int value);
bool add(nlohmann::json &obj, const char *name, uint64_t value);
bool add(nlohmann::json &obj, const char *name, const pgp::KeyID &keyid);
bool add(nlohmann::json &obj, const char *name, const pgp::Fingerprint &fp);

bool add_hex(nlohmann::json &obj, const char *name, const uint8_t *val, size_t len);
bool add_hex(nlohmann::json &obj, const char *name, const std::vector<uint8_t> &vec);

bool array_add(nlohmann::json &arr, const char *val);
bool array_add(nlohmann::json &arr, nlohmann::json val);

bool get_str (const nlohmann::json &obj, const char *name, std::string &out, bool del = false);
bool get_int (const nlohmann::json &obj, const char *name, int &out,         bool del = false);
bool get_uint64(const nlohmann::json &obj, const char *name, uint64_t &out,  bool del = false);
bool get_str_arr(const nlohmann::json &obj, const char *name,
                 std::vector<std::string> &out, bool del = false);

const nlohmann::json *get_obj(const nlohmann::json &obj, const char *name);

} // namespace rnp::json
```

### Semantics notes

- `del` defaults to **false** (nlohmann::json copies are cheap; the json-c
  `del=true` semantics existed because json-c used refcounted shared
  ownership). For parity, callers that explicitly want field removal after
  read can pass `del=true` — implemented via `obj.erase(name)`.
- `add_hex` retains the 1 MiB cap from the current implementation (domain rule).
- Failure returns `false` only when the field is missing or wrong-typed
  on read paths. Writes always succeed for nlohmann::json.

### Removed

- `rnp::JSONObject` RAII class (json-c specific; nlohmann has value semantics).
- All `json_object*` parameters.
- Direct includes of `<json.h>` and `<json_object.h>`.

## Acceptance

- `json-utils.{h,cpp}` compiles with `nlohmann/json.hpp` only.
- No remaining `#include "json_object.h"` or `#include "json.h"` in `src/lib/`.
- Existing tests in `src/tests/` that don't yet use json-c directly still build
  (they will fail to compile where they call old API — that's #05/#06/#07).

## Files touched

- `src/lib/json-utils.h`
- `src/lib/json-utils.cpp`