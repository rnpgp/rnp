# Introduction

"rnp" is a set of OpenPGP (RFC4880) tools that works on Linux, \*BSD and
macOS as a replacement of GnuPG. It is maintained by Ribose after being
forked from NetPGP, itself originally written for NetBSD.

"librnp" is the library used by rnp for all OpenPGP functions, useful
for developers to build against. Thanks to Alistair, it is a "real"
library, not a wrapper like GPGME of GnuPG.

NetPGP was originally written (and still maintained) by Alistair Crooks
of NetBSD.

# Status

[![Travis CI Build Status](https://travis-ci.org/riboseinc/rnp.svg?branch=master)](https://travis-ci.org/riboseinc/rnp)
[![Coverity Scan Build Status](https://img.shields.io/coverity/scan/12616.svg)](https://scan.coverity.com/projects/riboseinc-rnp)


# Supported Platforms

Currently supported platforms:

* Fedora 25
* RHEL/CentOS 7

Upcoming supported platforms:

* Ubuntu 14.04 LTS, 16.04 LTS, 17.04
* Debian 8, 9
* OpenSUSE Leap 42.2, 42.3
* SLES 12


# Usage

## Generating an RSA Private Key

By default ``rnpkeys  --generate-key`` will generate 2048-bit RSA key.

``` sh
export keydir=/tmp
rnpkeys --generate-key --homedir=${keydir}
```

=>

``` sh
rnpkeys: generated keys in directory ${keydir}/6ed2d908150b82e7
```

In case you're curious, `6ed2d...` is the key fingerprint.

In order to use fully featured key pair generation ``--expert`` flag should be used. With this flag added to  ``rnpkeys --generate-key`` user has a possibility to generate keypair for any supported algorithm and/or key size.

Example:

``` sh
> export keydir=/tmp
> rnpkeys --generate-key --expert --homedir=${keydir}

Please select what kind of key you want:
    (1)  RSA (Encrypt or Sign)
    (19) ECDSA
    (22) EDDSA
> 19

Please select which elliptic curve you want:
    (1) NIST P-256
    (2) NIST P-384
    (3) NIST P-521
> 2

Generating a new key...
signature  384/ECDSA d45592277b75ada1 2017-06-21
Key fingerprint: 4244 2969 07ca 42f7 b6d8 1636 d455 9227 7b75 ada1
uid              ECDSA 384-bit key <flowher@localhost>
rnp: generated keys in directory /tmp/.rnp
Enter password for d45592277b75ada1:
Repeat password for d45592277b75ada1:
>
```


## Listing Keys

``` sh
export keyringdir=${keydir}/MYFINGERPRINT
rnpkeys --list-keys --homedir=${keyringdir}

```

=>

```
1 key found
...
```


## Signing a File


### Signing in binary format

``` sh
rnp --sign --homedir=${keyringdir} ${filename}
```

=>

Created `${filename}.gpg` which is an OpenPGP message that includes the
message together with the signature as a 'signed message'.

This type of file can be verified by:

* `rnp --verify --homedir=${keyringdir} ${filename}.gpg`


### Signing in binary detatched format

``` sh
rnp --sign --detach --homedir=${keyringdir} ${filename}
```

=>

Created `${filename}.sig` which is an OpenPGP message in binary
format, that only contains the signature.

This type of file can be verified by:

* `rnp --verify --homedir=${keyringdir} ${filename}.sig`


### Signing in Armored (ASCII-Armored) format

``` sh
rnp --sign --armor --homedir=${keyringdir} ${filename}
```

=>

Created `${filename}.asc` which is an OpenPGP message in ASCII-armored
format, including the message together with the signature as a 'signed
message'.

This type of file can be verified by:

* `rnp --verify --homedir=${keyringdir} ${filename}.asc`


### Other options

* `--clearsign` option will append a separate PGP Signaure to the end of
  the message (the new output)

* `--detach` option will append a separate PGP Signaure to the end of
  the message (the new output)


## Encrypt


``` sh
rnp --encrypt --homedir=${keyringdir} ${filename}
```

=>

Creates: `${filename}.gpg`


## Decrypt

``` sh
rnp --decrypt --homedir=${keyringdir} ${filename}.gpg
```

=>

Creates: `${filename}`



# Install

## Binaries installed

* `rnp`
* `rnpkeys`

## On macOS using Homebrew

``` sh
brew tap riboseinc/rnp
brew install rnp
```

## On RHEL and CentOS via YUM

``` sh
rpm --import https://github.com/riboseinc/yum/raw/master/ribose-packages.pub
curl -L https://github.com/riboseinc/yum/raw/master/ribose.repo > /etc/yum.repos.d/ribose.repo
yum install -y rnp
```

## On Debian

(WIP)


## Compiling from source

Clone this repo or download a release and expand it.

``` bash
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=off .
make install
```

# Versioning

rnp follows the [semantic versioning](http://semver.org/) syntax.

## Checking versions

The '--version' output of the `rnp` commands contains the `git` hash of
the version the binary was built from, which value is generated when
`cmake` ran, consequently a release tarball generated with `make
dist` will contain this hash version.

## Historic

The first version of rnp started at `0.8.0` to indicate its development
completeness (or lack thereof).

