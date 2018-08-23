# rnpkeys_generatekey_verifySupportedHashAlg

Component
: rnpkeys

Feature
: Generate-key

## Objective

Verify SupportedHashAlg.

## Description

The test aims to test key generation with all possible hash algorithm.
Following hash algorithm are tested for the key generation:

* `MD5`
* `SHA-1`
* `RIPEMD160`
* `SHA256`
* `SHA384`
* `SHA512`
* `SHA224`

## Preconditions

* Initialize RNP
* Set the default value for `res`, `format`, `hash` via `rnp_setvar()`.

## Test steps and expected behavior

1. Set the hash algorithm via `rnp_setvar`

1. Call the API to generate key (`rnp_generate_key`)

Expectation: key is generated using options set via `rnp_setvar`

## Verification steps and logic

1. Load the newly generated RNP keys
  * Rationale: Ensures keys are loaded in the `rnp` control structure
  for verification.

1. Find existence of key via `userId`.

  * **Note**: If `userid` variable is not set, default is `always`.
  * Rationale: Ensures the key exists by finding it.

## Comments

It is required to delete the old keys if the test case iterates over the
hashing algorithm.


# rnpkeys_generatekey_VerifyUserIdOption

Component
: rnpkeys

Feature
: Generate-key

## Objective

Verify `UserIdOption`

## Description

The test aims to test key generation with command line option `UserId`.

Following different `userid`s are tested:

* `rnpkeys_Generatekey_VerifyUserIdOption_MD5`
* `rnpkeys_Generatekey_VerifyUserIdOption_SHA-1`
* `rnpkeys_Generatekey_VerifyUserIdOption_RIPEMD160`
* `rnpkeys_Generatekey_VerifyUserIdOption_SHA256`
* `rnpkeys_Generatekey_VerifyUserIdOption_SHA384`
* `rnpkeys_Generatekey_VerifyUserIdOption_SHA512`
* `rnpkeys_Generatekey_VerifyUserIdOption_SHA224`


## Preconditions

* Initialize RNP
* Set the default value for res, format, hash via `rnp_setvar`.

## Test steps and expected behavior

1. Set the userId via `rnp_setvar`

1. Call the API to generate key (`rnp_generate_key`)

Expectation: key is generated using options set via `rnp_setvar`

## Verification steps and logic

1. Load the newly generated RNP keys
  * Rationale: Ensures keys are loaded in the rnp control structure for
  verification.

1. Find the existence of the key via finding the key with the userId.


# rnpkeys_generatekey_verifykeyRingOptions

Component
: rnpkeys

Feature
: Generate-key

## Objective

Verify keyRingOptions.

## Description

The test aims to test key generation with the user specified keyring.

## Preconditions

* Initialize RNP
* Set the default value for `res`, `format`, `hash` via `rnp_setvar()`.

## Test steps and expected behavior

1. Set the keyring via `rnp_setvar`

1. Call the API to generate key (`rnp_generate_key`)

Expectation: key is generated using options set via `rnp_setvar`

## Verification steps and logic

1. Delete the default keyring i.e. `pubring.gpg` and `secring.gpg` found
   in the homedir

  * Rationale: To ensure that default keyring is **NOT** available.

1. Load the newly generated RNP keys

  * Rationale: Ensures keys are loaded in the `rnp` control structure
  for verification.

1. Find existence of key via `userId`.

  * **Note**: If `userid` variable is not set, default is `always`.
  * Rationale: Ensures the key exists by finding it.


# rnpkeys_generatekey_verifykeyHomeDirOption

Component
: rnpkeys

Feature
: Generate-key

## Objective

Verify keyHomeDirOption.

## Description

The test aims to test key generation with the user specified keyring.

## Preconditions

* Create new home dir with read/write permissions.
* Delete the keys (if any) in the previous default directory.
* Initialize RNP
* Set the default value for `res`, `format`, `hash` via `rnp_setvar()`.

## Test steps and expected behavior

1. Call the API to generate key (`rnp_generate_key`)

Expectation: key is generated using options set via `rnp_setvar`

## Verification steps and logic

1. Load the newly generated RNP keys

  * Rationale: Ensures keys are loaded in the rnp control structure for
  verification.

1. Find existence of key via `userId`.

  * **Note**: If `userid` variable is not set, default is `always`.
  * Rationale: Ensures the key exists by finding it.

