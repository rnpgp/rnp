# Introduction

This folder includes examples of rnp library usage for developers.
Following sample applications are available:

* generate : includes code which shows how to generate keys, load and save keyrings, export keys.

Examples are built together with rnp library, and are available in `src/examples` directory of your build folder.

## generate

This example first generates Curve-25519 key with subkey using the low-level functions from rnp library, then saves
generated keys to keyring files as well as prints them to stdout in ASCII-armored format. This is done in `generate_lowlevel_25519()` function.
Afterwards higher-level code from `generate_highlevel_rsa()` loads generated keyrings, generate RSA/RSA keypair, saves keyrings and also prints newly generated ASCII-armored keys to stdout.
