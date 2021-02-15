---
title: RNPKEYS
section: 1
header: RNPKEYS user manual
footer: version 0.14.0
date: Jan, 21 2021
---

# NAME
RNPKEYS - OpenPGP key management utility.

# SYNOPSIS
**rnpkeys** [**\-\-homedir** *dir*] [*options*] *command* ...

# DESCRIPTION
**rnpkeys** utility is part of **RNP** suite and provides OpenPGP key management functionality, like key listing, generation, import/export, editing, etc.

## Using rnpkeys
By default **rnpkeys** will use keyrings, stored in *~/.rnp* directory.

This may be overridden with **\-\-homedir** parameter.

If *command* needs password it will be asked via stdin/tty unless **\-\-password** or **\-\-pass-fd** option was not given.

## Specifying keys
Many of the commands require key locator or filter, representing single or multiple keys. It may be specified as:

- part of the **userid** : for **"Alice <alice@rnpgp.com>"** *alice*, *alice@rnpgp*, *rnpgp.com* will all work.  
- **keyid** or it's rightmost 8 chars, with or without *0x* at the beginning and spaces/tabs inside : *0x725F6F2D6D5F6120*, *"725F6F2D 6D5F6120"*, *0x6D5F6120*  
- 40-char key's **fingerprint** : *"0x416E746F 6E537669 72696465 6E6B6F20"*  

# RETURN VALUE
On success 0 value will be returned. Non-zero value will be returned on error.

# COMMANDS

## Informational
**-h**, **\-\-help**
: Display short help message. No options expected.

**-V**, **\-\-version**
: Display version information. No options expected.

**-l**, **\-\-list-keys**
: List keys and short information about them. With option **\-\-with-sigs** signature are listed as well.

## Key generation

**-g**, **\-\-generate-key**
: Generate a new keypair. Without other options RSA primary key with RSA subkey will be generated, asking for the encryption password afterwards.
Default RSA key size is **2048** bits and may be changed via the **\-\-numbits**.
Option **\-\-expert** may be used to override defaults and select key algorithms interactively.
To specify userid use the **\-\-userid** option. 
Options **\-\-hash**, **\-\-cipher**, **\-\-s2k-iterations**, **\-\-s2k-msec** may be used to control how generated secret key is encrypted.

## Key/signature import

**\-\-import**, **\-\-import-keys**, **\-\-import-sigs**
: Import keys or signatures. While normally **rnpkeys** would recognize input data format, you still may specify whether input is keys or signatures.
By default import will stop on first erroneous key or signature. To skip errored or unsupported packets you may use option **\-\-permissive**

## Key/signature export

**\-\-export-key** [**\-\-userid**=*filter*] [*filter*]
: Export key(s), matching specified filter. If filter matches primary key then subkeys are exported as well.
If no **\-\-output** option is specified then the key data is written to the stdout, in ASCII armored format. By default command will export public key(s), use the **\-\-secret** option to export the secret key(s) instead.

**\-\-export-rev** *key*
: Export revocation signature for the specified secret key. It may be used later in a case of key loss or compromise. Options **\-\-rev-type** and **\-\-rev-reason** may be used to specify revocation type and reason.

## Key manipulation

**\-\-revoke-key** *key*
: Issue revocation signature for the secret key and save it in the keyring. Revoked keys cannot be used further. Options **\-\-rev-type** and **\-\-rev-reason** may be used to specify revocation type and reason.

**\-\-remove-key** *key*
: Remove the specified key. If primary key is specified then all of its subkeys are removed as well. If key is secret then it will not be deleted without confirmation or option **\-\-force**.

## Options

**\-\-homedir** *dir*
: Change homedir (where RNP is looking for keyrings) to the specified value. Default homedir is *~/.rnp*

**\-\-output** *path*
: Write output to the path specified. Combine it with **\-\-force** to overwrite file if it already exists.

**\-\-userid** *userid*
: Use the specified userid during key generation and in some key-searching operations.

**\-\-numbits** *bits*
: Set size in bits for the generated key and subkey. *bits* may be in range **1024**-**16384**, if public key algorithm doesn't limit it further.

**\-\-cipher** *algorithm*
: Set the key encryption algorithm, currently applies only to the key generation. Default value is *AES256*.

**\-\-hash** *algorithm*
: Use the specified hash algorithm for signatures and derivation of the encrypting key from password for secret key encryption. Default value is *SHA256*.

**\-\-expert**
: Use **expert** key generation mode, allowing to choose key/subkey algorithms. Using it following keys can be generated:  

    - **DSA** key with **ElGamal** encryption subkey
    - **DSA** key with **RSA** subkey
    - **ECDSA** key with **ECDH** subkey
    - **EdDSA** key with **x25519** subkey
    - **SM2** key with subkey
  
     For **ECDSA** and **ECDH** underlying curve may be selected as well:  

    - NIST P-256, NIST P-384, NIST P-521
    - brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
    - secp256k1

**\-\-pass-fd** *fd*
: File descriptor to read passwords from instead of stdin/tty.

**\-\-password** *password*
: Use the specified password when it is needed. Not recommended for the production use since may have security problems, use **\-\-pass-fd** for the batch operations instead.

**\-\-with-sigs**
: Print signature information when listing keys via **-l** command.

**\-\-force**
: Force certain action without asking the user, like output file overwrite, secret key removal, revoking already revoked key.

**\-\-permissive**
: Skip malformed or unknown keys/signatures during key import. By default **rnpkeys** will stop on first erroring packet and report an error.

**\-\-rev-type** *type*
: Use the specified type during revocation signature generation instead of default 0. Following values are supported:  

    - 0, or "no": no revocation type specified.
    - 1, or "superseded": key was superseded with another key.
    - 2, or "compromised": key was compromised and no longer valid.
    - 3, or "retired": key is retired.
  
    See **RFC 4880** for the detailed explanation.

**\-\-rev-reason** *reason*
: Add the specified human-readable revocation *reason* to the signature instead of empty string.

**\-\-s2k-iterations** *number*
: Set the S2K (string-to-key) iterations number. It is used during derivation of the symmetric key, which encrypts a secret key, from the password. See RFC 4880 for the details.

**\-\-s2k-msec** *number*
: Pick **\-\-s2k-iterations** value so single key derivation operation would take *number* of milliseconds on the current system. For example, setting it to 2000 would mean that each secret key decryption operation takes around 2 seconds.

# AUTHORS

# BUGS
May be reported via the **RNP** GitHub repository: *https://www.github.com/rnpgp/rnp*

Please note that it is a public repository, so security issues must be reported in other way.

# SEE ALSO
**rnp(1)**, **librnp(3)**