## Changelog

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

