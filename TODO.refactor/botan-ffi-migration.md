# Botan native C++ API → FFI migration

Status: planning / in progress (2026-07-30)
Owner: Ronald Tse (for discussion with Jack Lloyd / Botan)

## TL;DR

**No Botan FFI gaps were found.** Every operation rnp currently performs via
Botan's *unstable native C++ API* (`Botan::*`) in the crypto-refresh / PQC code
paths has a *stable* FFI equivalent (`botan_*`). Nothing needs to be requested
upstream — the work is migration, not API additions.

The native C++ API is the root cause of the recurring build breakage: it changes
every Botan release (e.g. 3.12 tightened include hygiene so `EC_Group` /
`EC_AffinePoint` are no longer transitively included, and deprecated
`public_point()` / `Ed25519_PrivateKey(span)`). The rest of rnp already uses the
FFI (the stable C ABI), which is why it rides across Botan 2.x/3.x untouched.
This migration extends that discipline to the crypto-refresh/PQC code.

## Why migrate (the breakage on Botan 3.12)

`-DENABLE_CRYPTO_REFRESH=ON` against Botan 3.12 fails to compile because the
native-API code in these files bit-rotted:

| File | Failure | Root cause |
|------|---------|------------|
| `src/lib/crypto/ec.cpp` (`ec_generate_generic_native`) | `error: incomplete type 'Botan::EC_Group'`; `error: member access into incomplete type 'const EC_Point'`; `warning: 'public_point' is deprecated` | missing `<botan/ec_group.h>` / `<botan/ec_point.h>` (3.12 include hygiene); deprecated `public_point()` |
| `src/lib/crypto/exdsa_ecdhkem.cpp` | `error: incomplete type 'Botan::EC_Group'`; `error: 'Botan::BigInt' is an incomplete type`; `error: member access into incomplete type 'Botan::EC_AffinePoint'`; `warning: 'Ed25519_PrivateKey' is deprecated` | missing includes; deprecated `Ed25519_PrivateKey(span)` ctor |
| `src/lib/crypto/ed25519_ed448.cpp` | `warning: 'Ed25519_PrivateKey' is deprecated: Use from_seed or from_bytes` | deprecated ctor |

These are all fixable without version switches by moving to FFI.

## FFI coverage audit (no gaps)

Audited against Botan 3.12 `<botan/ffi.h>`. Every native op maps to a stable FFI
call, several of which rnp already uses elsewhere:

| Native (crypto-refresh/PQC) | FFI replacement | Already used in rnp? |
|-----------------------------|-----------------|----------------------|
| `ECDH_PrivateKey` + `EC_Group::from_name` + `public_point().xy_bytes()` / `public_value()` | `botan_privkey_create("ECDH", curve)` + `botan_pubkey_get_field("public_x"/"public_y")` + `botan_privkey_get_field("x")` | yes — `ec.cpp::Key::generate()`, `ecdh.cpp` |
| `ECDH_PrivateKey`/`PublicKey` from scalar / SEC1 point | `botan_privkey_load_ecdh`, `botan_pubkey_load_ecdh` | partial |
| `ECDSA_PrivateKey`/`PublicKey` from scalar / point | `botan_privkey_load_ecdsa`, `botan_pubkey_load_ecdsa` | partial |
| `PK_Key_Agreement` ... `derive_key` (ECDH KEM encap/decap) | `botan_pk_op_key_agreement_*` | yes — `ecdh.cpp` |
| `PK_Signer` / `PK_Verifier` (ECDSA/Ed25519/Ed448/ML-DSA/SLH-DSA) | `botan_pk_op_sign_*` / `botan_pk_op_verify_*` | yes — `eddsa.cpp`, `ecdsa.cpp`, `sm2.cpp` |
| `Ed25519_PrivateKey(span)` (deprecated) | `botan_privkey_load_ed25519` / generic `botan_privkey_create("Ed25519")` + `view_raw` | yes — `eddsa.cpp` |
| `Ed448_PrivateKey` / `raw_private_key_bits` / `public_key_bits` | `botan_privkey_load_ed448` / `botan_pubkey_load_ed448` (3.4+) + generic `view_raw` | no (new) |
| `X25519_PrivateKey` / `X448_PrivateKey` | `botan_privkey_load_x25519` / `_x448`, `botan_pubkey_load_x25519` / `_x448` | partial |
| `check_key(...)` | `botan_pubkey_check_key`, `botan_privkey_check_key` | yes |
| `Dilithium_PrivateKey` / `Kyber_PrivateKey` modes | `botan_privkey_load_ml_dsa` / `botan_privkey_load_ml_kem` (+ mode string) | no (new) |
| `SLH_DSA_PrivateKey` / param set / hash type | `botan_privkey_load_slh_dsa` (+ mode string) | no (new) |
| `PK_KEM_Encryptor` / `PK_KEM_Decryptor` (ML-KEM) | `botan_pk_op_kem_encrypt_*` / `botan_pk_op_kem_decrypt_*` (3.0+) | no (new) |
| `rfc3394_keywrap` / `rfc3394_keyunwrap` | `botan_nist_kw_enc` / `botan_nist_kw_dec` | yes — `ecdh.cpp` |
| raw key bytes (`raw_private_key_bits`, `public_key_bits`) | `botan_privkey_view_raw` / `botan_pubkey_view_raw` (3.6+; see PR #2446) | yes |

**Conclusion for Jack:** no new FFI entry points are required. (If anything,
the only friction is documentation/confirmation of the exact byte encoding
returned by `botan_*_view_raw` for ML-KEM/ML-DSA/SLH-DSA and for the "Raw"
key-agreement output — see Verification below.)

## Migration plan

### Phase 1 — unblock the Botan 3.12 build (this branch)

The three files that failed `ENABLE_CRYPTO_REFRESH`, migrated to FFI:

- [x] `src/lib/crypto/ec.cpp` — `ec_generate_generic_native` now mirrors the
      FFI pattern already in `Key::generate()` (`botan_privkey_create`,
      `botan_pubkey_get_field`, `botan_privkey_get_field`). Native
      `<botan/bigint.h>`/`<botan/ecdh.h>` includes dropped.
- [x] `src/lib/crypto/ed25519_ed448.cpp` — Ed25519/Ed448 keygen, sign, verify,
      validate moved to `botan_privkey_create`/`load_*`, `botan_pk_op_sign_*`/
      `verify_*`, `botan_*_check_key`.
- [x] `src/lib/crypto/exdsa_ecdhkem.cpp` (+ `.h`) — replaced the `Botan::*`
      key-object helpers with FFI key handles; ECDH KEM via
      `botan_pk_op_key_agreement_*`, ECDSA sign/verify, `check_key`, SEC1
      loaders (`botan_pubkey_load_ecdh_sec1` / `_ecdsa_sec1`). The private
      `key_` member moved from `Botan::secure_vector` to `rnp::secure_bytes`;
      all `<botan/*>` includes removed from the header.

Validated: `ENABLE_CRYPTO_REFRESH=ON` builds clean on Botan 3.12 (no native-API
errors); full `rnp_tests` suite passes (280 tests, including v6, ECDSA keygen,
Ed25519/Ed448, ECDH, and CLI examples).

Note: `ed25519_ed448.cpp` still calls the deprecated `botan_privkey_ed25519_
get_privkey` / `botan_*_ed448_get_*` getters (consistent with the existing
`eddsa.cpp` on `main`). These are the same `-Wdeprecated-declarations` class
that PR #2446 migrates to `botan_*_view_raw`; that migration should be extended
to these three new call sites.

### Phase 2 — finish the native→FFI discipline (follow-up PRs)

Not broken on 3.12, but still on the unstable native API. Migrate per the table
above, lowest-risk first:

- [ ] `src/lib/crypto/x25519_x448.cpp` (X25519/X448 keygen, RFC 3394 keywrap)
- [ ] `src/lib/crypto/dilithium.cpp` / `dilithium_common.cpp` (ML-DSA)
- [ ] `src/lib/crypto/kyber.cpp` / `kyber_common.cpp` (ML-KEM)
- [ ] `src/lib/crypto/kyber_ecdh_composite.cpp` (ML-KEM+X25519 composite —
      built from FFI primitives; the composition logic stays in rnp)
- [ ] `src/lib/crypto/sphincsplus.cpp` (SLH-DSA)

## Verification / risks

- Compile-check on Botan 3.12 with `-DENABLE_CRYPTO_REFRESH=ON`.
- Behavioral check via `rnp_tests` (PQC / v6 / composite keygen, sign, encrypt,
  KEM) — **must run** before merge; the migration touches security-critical
  paths and header-level analysis cannot prove byte-for-byte equivalence.
- Items to confirm during migration (not FFI gaps, just things to get exactly
  right):
  - exact bytes returned by `botan_privkey_view_raw` / `botan_pubkey_view_raw`
    for ML-DSA / ML-KEM / SLH-DSA (private vs. public encodings);
  - `botan_pk_op_key_agreement` "Raw" output equals `PK_Key_Agreement("Raw")` +
    `.bits_of()`;
  - ML-DSA/ML-KEM/SLH-DSA mode strings accepted by `botan_*_load_*` and
    `botan_privkey_create` (`"ML-DSA-65"`, `"ML-KEM-768"`, `"SLH-DSA-128s"`, …).
