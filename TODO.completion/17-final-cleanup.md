# 17 — Final cleanup, review, PR-ready commit (P3)

## Checklist

- [ ] `grep -r "json_object_\|json_tokener_\|json-c\|<json\.h>" src/ cmake/ .github/ ci/ CMakeLists.txt`
      returns zero hits.
- [ ] Full build clean: `cmake --build build`.
- [ ] Full test suite passes: `ctest --test-dir build --output-on-failure`.
- [ ] No regressions in CLI output (golden diffs).
- [ ] `git diff main --stat` makes sense (no incidental churn).
- [ ] Commit history is one logical commit per phase (or squashed sensibly).
- [ ] **No AI attribution in commits** (per project rule).
- [ ] PR body references `Closes #2366`.

## Pre-PR sanity

```bash
cd /Users/mulgogi/src/rnp/rnp/wt-nlohmann-json
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure -E 'fuzz|long'
```

All must pass before pushing the branch and opening the PR.