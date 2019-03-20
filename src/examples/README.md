# Introduction

This folder includes examples of RNP library usage for developers.

All samples below use APIs exposed via header file [`rnp2.h`](/include/rnp/rnp2.h),
check it out for more documentation.

Following sample applications are available:

* generate : includes code which shows how to generate keys, save/load keyrings, export keys.

* encrypt : includes code which shows how to encrypt file, using the password and/or key.

* decrypt : this one shows how to decrypt OpenPGP data, using the key or password

* sign : shows how to sign messages, using the key(s) from loaded keyring

* verify : shows how to verify signed messages, using dynamic keys fetching (sample key provider implementation)

Examples are built together with rnp library, and are available in `src/examples` directory of your build folder.

## generate

This example is composed from 2 functions:
 * `ffi_generate_keys()`. It shows how to generate and save different key types (RSA and EDDSA/Curve25519) using the JSON key description. Also it demonstrate usage of password provider. Keyrings will be saved to files `pubring.pgp` and `secring.pgp` in the current directory.
 To check generated key(s) properties you may use command `rnp --list-packets pubring.pgp`.

 * `ffi_output_keys()`. This function shows how to load keyrings, search for the keys (in helper functions `ffi_print_key()`/`ffi_export_key()`), and export them to memory or file in armored format.

## encrypt

This code sample first loads public keyring (`pubring.pgp`), created by `generate` example. Then it creates encryption operation structure and configures it with misc options (including setup of password encryption and public-key encryption).
The result is encrypted and armored (for easier reading) message `RNP encryption sample message`.
It is saved to the file `encrypted.asc` in current directory.

You can investigate it via the `rnp --list-packets encrypted.asc` command.
Also you may want to decrypt saved file via `rnp --keyfile secring.pgp -d encrypted.asc`.

## decrypt

This example uses keyrings, generated in `generate` sample to decrypt messages, encrypted by `encrypt` sample.
It shows how to decrypt message with password or with a key, and implements custom password provider for decryption or key password.
Decrypted message is saved to the memory and then printed to the stdout.

## sign

This example uses keyrings, generated in `generate` example. Then it configures signing context, and signs message, saving it to the `signed.asc` file.
Attached signature is used, i.e. data is encapsulated into the resulting message.

You can investigate the signed message by issuing `rnp --list-packets signed.asc` command.
To verify message, use `rnp --keyfile pubring.pgp -v signed.asc`

## verify

This example uses keyrings, generated in `generate` example. However, instead of loading the whole keyring it implements dynamic key fetching via custom key provider (see function `example_key_provider`).
After verification sample outputs verified embedded message, and all signatures with signing key ids and statueses.
