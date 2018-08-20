## Changelog

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

