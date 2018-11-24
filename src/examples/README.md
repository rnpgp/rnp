# Introduction

This folder includes examples of rnp library usage for developers.
All samples utilize API, exposed via header file `rnp2.h`, check it for more details.

Following sample applications are available:

* generate : includes code which shows how to generate keys, save/load keyrings, export keys.

Examples are built together with rnp library, and are available in `src/examples` directory of your build folder.

## generate

This example is composed from 2 functions:
 * `ffi_generate_keys()`. It shows how to generate and save different key types (RSA and EDDSA/Curve25519) using the JSON key description. Also it demonstrate usage of password provider. Keyrings will be saved to files `pubring.pgp` and `secring.pgp` in the current directory.
 To check generated key(s) properties you may use command `rnp --list-packets pubring.pgp`.

 * `ffi_output_keys()`. This function shows how to load keyrings, search for the keys (in helper functions `ffi_print_key()`/`ffi_export_key()`), and export them to memory or file in armored format.
