---
title: RNP
section: 1
header: RNP user manual
footer: version 0.14.0
date: Jan, 21 2021
---

# NAME
RNP - OpenPGP-compatible signatures and encryption, GnuPG alternative.

# SYNOPSIS
**rnp** [**\-\-homedir** *dir*] [*options*] *command* [*input-file*, ..]...

# DESCRIPTION
**rnp** utility is part of **RNP** suite and provides signing and encryption functionality using the OpenPGP standard.
It would not allow you to manipulate your keys or keyrings - use the **rnpkeys** instead.

## Using rnp
By default **rnp** will apply *command*, additionally configured with *options*, to all of *input-file* or stdin if no *input-file* is given.

Depending on the input, output may be written to the file with removed or added extension (*.pgp*, *.asc*, *.sig*) or to the stdout. Without option **\-\-armor** output will be binary.

If *command* requires public or private keys, **rnp** will look for the keyrings in **~/.rnp**. See **\-\-homedir** and **\-\-keyfile** to override this.

If *command* needs password it will be asked via stdin/tty unless **\-\-password** or **\-\-pass-fd** option was not given.

# RETURN VALUE
On success 0 value will be returned. Non-zero value will be returned on error.

# COMMANDS

## Informational
**-h**, **\-\-help**
: Display short help message. No options expected.

**-V**, **\-\-version**
: Display version information. No options expected.

## Encryption and signing
**-e**, **\-\-encrypt**
: Encrypt data with public key(s), and sign, if **\-\-sign** command is added. Most likely you'd like to specify one or more **\-\-recipient**, pick **\-\-cipher** instead of default, or change compression options via **-z**, **\-\-zip**, **\-\-bzip**.
Another common setting would be to output ascii data instead of binary via the **\-\-armor** option. If input is *file.ext*, and **\-\-output** is not specified, then data will be written, depending on **\-\-armor** option, to the *file.ext.pgp* or *file.ext.asc*.
If such file already exists, and **\-\-overwrite** option is not given, you'll be asked for the permission to overwrite or new file name. See the **Options** section for more information.

**-c**, **\-\-symmetric**
: Encrypt data with password(s). Can be combined with **\-\-encrypt** and **\-\-sign**. Encryption to multiple passwords is possible with **\-\-passwords** option. Each password would be asked via stdin/tty unless **\-\-password** or **\-\-pass-fd** is specified. Options, which apply to the **\-\-encrypt** command, will apply here as well.

**-s**, **\-\-sign**
: Digitally sign data, using one or more secret keys you own. Public-key or password-based encryption may be added via the **\-\-encrypt** and **\-\-symmetric** commands. By default first secret key you own will be picked for signing. To overcome it, or use multiple keys, use the **-u**/**\-\-userid** option. Without additional options signed data will be stored together with the signature attached.
To make detached from the data signature (*file.ext.sig*), add the **\-\-detach** option. You may want to use **\-\-hash** option to override default hash algorithm settings. As with encryption, output may be converted to ascii via the  **\-\-armor** option.
Compression options also apply here. Since secret key is usually stored encrypted you'll be asked for the password to decrypt it via stdin/tty unless **\-\-password** or **\-\-pass-fd** is specified.

**\-\-clearsign**
: Digitally sign text data, producing human-readable output with the signature attached. In this mode data cannot be additionally encrypted or compressed. However other signing options, like **\-\-hash**, **\-u**, **\-\-password** still may be used here.

## Decryption and verification

**-d**, **\-\-decrypt**
: Decrypt and verify data from the *input-file* or stdin. Output, if not overridden with **\-\-output**, will be written to the file with stripped *.pgp* extension or stdout. If *input-file* doesn't have *.pgp* extension then output file name will be asked via stdin/tty.
Depending on encryption options you may be asked for the password to one of your secret keys, or for the encryption password. Options **\-\-password**, **\-\-pass-fd** may be useful here.
If data was signed, signature verification information will be printed to the tty/stdout.

**-v**, **\-\-verify**
: Verify signature(s) without writing embedded data out, if any. To verify detached signature of the file *file.ext* it must have file name *file.ext.sig* or *file.ext.asc*. If data is encrypted then you may be asked for password like in **\-\-decrypt** command.

## Other commands

**\-\-list-packets**
: Show detailed information about the OpenPGP data in *input-file* or stdin. Would be useful for curiosity, troubleshooting or debugging. Additional options may be used:

    - **\-\-json** : output json data instead of human-readable
    - **\-\-grips** : print key fingerprints and grips
    - **\-\-mpi** : print all the MPI values
    - **\-\-raw** : print raw hex-encoded packets as well

**\-\-enarmor[=msg|pubkey|seckey|sign]**
: Convert binary data to the ASCII-armored as per OpenPGP standard. This includes *-----BEGIN PGP MESSAGE-----* header and footer, and Base64-encoded data.
Output for the *file.ext* will be written to *file.ext.asc* (if it doesn't exist) or stdout. Options **\-\-overwrite** and **\-\-output** may be used to override this.
In addition you may specify OpenPGP header:

    - **msg** : *\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-*
    - **pubkey** : *\-\-\-\-\-BEGIN PGP PUBLIC KEY BLOCK\-\-\-\-\-*
    - **seckey** : *\-\-\-\-\-BEGIN PGP SECRET KEY BLOCK\-\-\-\-\-*
    - **sign**: *\-\-\-\-\-BEGIN PGP SIGNATURE\-\-\-\-\-*

**\-\-dearmor**
: This command would attempt to convert data from armored to the binary. For the *file.ext.asc* output would be written to the *file.ext*, if it doesn't exist, otherwise new filename will be asked.
Options **\-\-overwrite** and **\-\-output** may be used to override this.

## Options

**\-\-home**, **\-\-homedir** *dir*
: Change homedir (where RNP is looking for keyrings) to the specified value. Default homedir is *~/.rnp*

**-f**, **\-\-keyfile** *path*
: Instead of loading keyrings, use the key(s) from the file specified.

**-u**, **\-\-userid** *key*
: Specify one or more signing keys, searching for it via *key*. See **rnpkeys(1)** for possible values.

**-r**, **\-\-recipient** *key*
: Add message's recipient, i.e. public key to which message will be encrypted to. See **rnpkeys(1)** for possible values.

**\-\-armor**, **\-\-ascii**
: Apply ASCII armoring to the output, so it may be transferred as text. See RFC-4880 for the details.

**\-\-detach**, **\-\-detached**
: Create detached signature.

**\-\-output** *path*
: Write data-processing related output to the file specified. If not specified then output filename will be guessed by the input filename/extension or asked from the user via tty/stdin.

**\-\-overwrite**
: Overwrite already existing files without prompt.

**\-\-hash** *algorithm*
: Set hash algorithm which will be used for signing and derivation of encryption key from the password. Default value is *SHA256*.

**\-\-cipher** *algorithm*
: Set the symmetric algorithm, used during encryption. Default value is *AES256*.

**\-\-aead** [*EAX*, *OCB*]
: Enable AEAD encryption, and choose algorithm used.

**\-\-aead\-chunk\-bits** *bits*
: Change AEAD chunk size, most likely you'll need this only for testing or debugging.

**\-\-zip**, **\-\-zlib**, **\-\-bzip2**
: Use corresponding algorithm to compress data. See RFC4880 for the details.

**\-z** **0..9**
: Set the compression level. **9** is the highest compression level, **0** disables compression. Default value is **6**.

**\-\-pass-fd** *fd*
: File descriptor to read passwords from instead of stdin/tty.

**\-\-password** *password*
: Use the specified password when it is needed. Not recommended for the production use since may have security problems, use **\-\-pass-fd** for the batch operations instead.

**\-\-passwords** *count*
: Set number of passwords for **\-\-symmetric** encryption. While it is not commonly used, you may encrypt message to any reasonable number of passwords.

**\-\-creation** *time*
: Override signature creation time. Normally it is set to the current time, but may be changed via this option. It could be specified in *yyyy-mm-dd* format, or as UNIX timestamp.

**\-\-expiration** *time*
: Set signature expiration time, starting from the creation time. By default signatures do not expire. May be specified as number of hours/days/months/years via *20h*/*30d*/*1m*/*1y*, expiration date in *yyyy-mm-dd* format, or number of seconds.

**\-\-keystore-format** **GPG|KBX|G10|G21**
: Set keystore format. RNP automatically detects key store format, however this behavior may be overridden with this command.

**\-\-debug** *filename.cpp*
: Enable debug output for the source file specified. Most likely you will not need this.

# EXAMPLES

**rnp** **\-\-homedir** *.rnp* **\-\-encrypt** **-r** *0x6E69636B6F6C6179* **\-\-output** *document.txt.encrypted* *document.txt*
: Load keyrings from the folder *.rnp* in current directory, and encrypt file to the key with keyid *0x6E69636B6F6C6179*.

**rnp** **\-\-keyfile** *john-sec.asc* **-s** **\-\-detach** **\-\-hash** *SHA512* *document.txt*
: Generate detached signature over the file *document.txt*, using the secret key, stored in the file. Additionally override hash algorithm.

**rnp** **\-\-keyfile** *john-pub.asc* **\-\-verify** *document.txt.sig*
: Verify detached signature, using the key, stored in file. Signed data assumed to be in file *document.txt*.

**rnp** **-e** **-c** **-s** **\-\-passwords** *3* **-r** *0x526F6E616C642054* **-r** *"john@doe.com"* **-u** *0x44616E69656C2057* *document.txt*
: Encrypt *document.txt* with 2 keys (specified via keyid *0x526F6E616C642054* and userid *john@doe.com*), and 3 passwords, so **any** of these may be used to decrypt the resulting file.
Additionally it will be signed with key *0x44616E69656C2057*.

# AUTHORS

# BUGS
May be reported via the **RNP** GitHub repository: *https://www.github.com/rnpgp/rnp*

Please note that it is a public repository, so security issues must be reported in other way.

# SEE ALSO
**rnpkeys(1)**, **librnp(3)**