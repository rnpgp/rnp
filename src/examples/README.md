# Introduction

This folder includes examples of rnp library usage for developers.
Following sample applications are available:

* generate : includes code which shows how to generate keys, load and save keyrings, export keys.

* encrypt : includes code which shows how to encrypt file, using the password and/or key.

* decrypt : this one shows how to decrypt OpenPGP data, using the key or password

* sign : shows how to sign messages, using the key(s) from keyring

* verify : shows how to verify signed messages, using dynamic keys fetching (sample key provider implementation)

Examples are built together with rnp library, and are available in `src/examples` directory of your build folder.

## generate

This example first generates Curve-25519 key with subkey using the low-level functions from rnp library, then saves
generated keys to keyring files as well as prints them to stdout in ASCII-armored format. This is done in `generate_lowlevel_25519()` function.
Afterwards higher-level code from `generate_highlevel_rsa()` loads generated keyrings, generate RSA/RSA keypair, saves keyrings and also prints newly generated ASCII-armored keys to stdout.
Keyrings will be saved to files `pubring.pgp` and `secring.pgp` in the current directory.

To check generated key(s) properties you may use command `rnp --list-packets pubring.pgp`.

## encrypt

This code sample first loads keyrings, created by `generate` example. Then it configures encryption context with encryption options (including setup of password encryption and public-key encryption).
The result is encrypted and armored (for easier reading) message `RNP encryption sample message`.
It is printed to stdout and saved to the file `encrypted.asc` in current directory.

You can investigate it via the `rnp --list-packets encrypted.asc` command.
Also you may want to decrypt saved file via `rnp --keyfile secring.pgp -d encrypted.asc`.

## decrypt

This example uses keyrings, generated in `generate` sample to decrypt messages, encrypted by `encrypt` sample.
It shows how to configure `rnp_t` and `rnp_ctx_t` structures to decrypt message with key or password, also custom password provider is implemented.
Resulting message is printed to the stdout.

## sign

This example uses keyrings, generated in `generate` example. Then it configures signing context, and signs message, saving it to the `signed.asc` file and printing to the stdout.
Attached signature is used, i.e. data is encapsulated into the resulting message.

You can investigate the signed message by issuing `rnp --list-packets signed.asc` command.
To verify message, use `rnp --keyfile pubring.pgp -v signed.asc`

## verify

This example uses keyrings, generated in `generate` example. However, instead of loading the whole keyring into `rnp_t` structure it implements dynamic key fetching via custom key provider (see function `key_provider_example`).
While verification is done in single `rnp_process_mem` call, `on_signatures` callback is used to notify about the signature(s) verification status.
