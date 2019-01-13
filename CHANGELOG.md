## Changelog

### 0.12.0 [01-13-2019]
#### General

* We now require Botan 2.8+.
* Fixed key grip calculations for various key types.
* Fixed SM2 signatures hashing the hash of the message. See comment in issue #436.
* Added support for G10 ECC keys.
* Fixed dumping of partial-length packets.
* Added support for extra ECC curves:
  * Brainpool p256, p384, p512 ECDSA/ECDH
  * secp256k1 ECDSA/ECDH
  * x25519
* Fixed AEAD with newer versions of Botan.
* Removed a lot of legacy code.

#### CLI

* rnp: Added -f/--keyfile option to load keys directly from a file.
* rnp: Fixed issue with selecting G10 secret keys via userid.
* rnpkeys: Added support for SM2 with arbitrary hashes.
* redumper: Added -g option to dump fingerprints and grips.
* redumper: Display key id/fingerprint/grip in packet listings.

#### FFI

* Added FFI examples.
* Fixed a regression with loading subkeys directly.
* Implemented support for per-signature hash and creation/expiration time.
* Added AEAD support.

### 0.11.0 [09-16-2018]
#### General

* Remove some old SSH key support.
* Add support for dynamically calculating the S2K iterations.
* Add support for extracing the public key from the secret key.
* Add support for merging information between keys.

#### CLI

* Add options for custom S2K iterations/times (dynamic by default).

### 0.10.0 [08-20-2018]
#### General

* Fixed some compiler warnings.
* Switched armoring to use PRIVATE KEY instead of SECRET KEY.

#### ECDSA

* Use the matching hash to be used for the deterministic nonce generation.
* Check that the input is of the expected length.
* Removed the code to truncate the ECDSA input since this is now handled by Botan.

#### FFI

* Added enarmor and dearmor support.
* Added library version retrieval.
* Removed rnp_export_public_key, added rnp_key_export.


### 0.9.2 [08-13-2018]
#### General

* Support for generation and verification of embedded signature subpacket for signing subkeys
* Verification of public key signatures and key material
* Improved performance of assymetric operations (key material is now validated on load)

#### FFI

* Fixed rnp_op_add_signature for G10 keys


### 0.9.1 [07-12-2018]
#### General

* Added issuer fingerprint to certifications and subkey bindings.

#### CLI

* Added support for keyid/fpr usage with (some) spaces and 0x prefix in
  operations (--sign, etc).

#### FFI

* Fixed key search by fingerprint. 


### 0.9.0 [06-27-2018]
* First official release.

