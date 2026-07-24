# Contributing to RNP

Thanks for your interest in contributing to RNP! This document covers the
practical bits you'll need to send a pull request that lands smoothly.

## Project context

RNP is a C++ OpenPGP library used by Thunderbird, GpgFrontend, and a long
tail of smaller integrators. The OpenPGP ecosystem moves slowly on purpose;
correctness and interop matter more than feature velocity. Reviewers will
spend most of their attention on:

- **Standards compliance** with RFC 9580 (the crypto-refresh) and
  RFC 4880 (legacy). If your change touches packet parsing, AEAD, signature
  verification, or key material, cite the relevant section.
- **Interop with GnuPG** and other implementations. See
  `src/tests/cli_tests.py` for the existing GnuPG interop matrix.
- **API stability** of the FFI in `include/rnp/rnp.h`. Breaking changes
  require a deprecation cycle; talk to a maintainer before adding one.

## Before you start

- For anything beyond a small fix, **open an issue first** to check that
  the approach fits. Reviews go faster when the design discussion has
  already happened.
- Pull the latest `main` and rebase your branch before sending a PR.
- If your work depends on an unmerged PR, stack the branch on top of that
  PR's branch (don't rebroadcast its commits in your own).

## Build & test locally

```bash
cmake -B build -DCRYPTO_BACKEND=botan -DENABLE_CRYPTO_REFRESH=ON -DENABLE_PQC=ON .
cmake --build build --parallel $(nproc)
RNP_TEST_DATA="$PWD/src/tests/data" ctest --parallel $(nproc) --test-dir build --output-on-failure
```

If you only have OpenSSL:

```bash
cmake -B build -DCRYPTO_BACKEND=OpenSSL .
cmake --build build --parallel $(nproc)
RNP_TEST_DATA="$PWD/src/tests/data" ctest --parallel $(nproc) --test-dir build --output-on-failure
```

Tests must pass on **both** backends before a PR merges. If you can only
test one locally, that's fine — CI will cover the other; just say so in
the PR description.

## Code style

- Run `clang-format` (v11; the repo's `.clang-format` file is the source
  of truth) on every C/C++ change before pushing.
- For CMake: 2-space indent, lowercase commands, no tabs.
- For Python (`src/tests/cli_tests.py`): 4-space indent; match the
  surrounding style.

## Commit messages

- Subject line ≤ 50 characters, imperative mood (`Add X`, not `Added X`).
- Body wrapped at 72 columns.
- Explain **why** the change is needed, not just what the change is.
- No AI-attribution trailers (`Co-authored-by: Copilot`, etc.) — see the
  project policy on this.

## PR checklist

Before requesting review:

- [ ] Branch is rebased on the latest `main`.
- [ ] `clang-format` clean (CI runs this; fix locally first).
- [ ] All tests pass on at least one backend.
- [ ] If you changed observable behaviour, added or updated a test that
      would fail without the change.
- [ ] PR description explains the why, links the relevant issue, and
      lists any follow-up work explicitly.
- [ ] If you touched `include/rnp/rnp.h`, called out the API change in
      the PR description (additive / breaking / deprecation).

## Crypto-path test discipline

For changes to encrypt / sign / export-secret-key code paths, prefer
tests that assert **the output is encrypted and contains no plaintext
key material** — a known-plaintext assertion that the operation cannot
silently leak. This is the discipline described in
`TODO.rnp-roadmap/10-assert-encrypted-output-tests.md` and prevents the
class of bug where a refactor accidentally swaps the encrypt-and-sign
order.

## Adding a new FFI function

The FFI lives in `include/rnp/rnp.h` (public) and `src/lib/rnp.cpp`
(implementation). Patterns:

- Functions return `rnp_result_t` (`RNP_SUCCESS` on success).
- Memory the caller must free uses `rnp_buffer_destroy`.
- Opaque handles (`rnp_ffi_t`, `rnp_key_handle_t`, etc.) follow the
  `*_create` / `*_destroy` pattern.
- Add a test in `src/tests/ffi*.cpp` that exercises both the success and
  the failure paths (NULL args, wrong type, etc.).

## Adding a new build option

If you're adding a CMake option, follow the existing `ENABLE_*` pattern.
For optional features (e.g. `ENABLE_BZIP2`, `ENABLE_CAST5`), use the
tri-state `tristate_feature_auto()` helper so users can do
`-DENABLE_X=On|Off|Auto`.

## Reporting security issues

**Do not open a public GitHub issue for security vulnerabilities.** Email
the maintainers at security@rnpgp.org (or see `docs/security.adoc` for
the current disclosure process).

## Code of Conduct

Everyone participating in this project is expected to follow the
[Code of Conduct](docs/code-of-conduct.adoc).

## Licensing

By contributing, you agree that your changes are licensed under the
project's license (the same BSD-2-Clause + LGPL-2.1 split that the rest
of rnp uses; see `LICENSE` and `LICENSE.LESSer`).
