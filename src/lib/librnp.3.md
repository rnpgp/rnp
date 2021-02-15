---
title: LIBRNP
section: 3
header: LIBRNP user manual
footer: version 0.14.0
date: Jan, 21 2021
---

# NAME
LIBRNP - OpenPGP implementation, available via FFI interface.

# SYNOPSIS
**#include <rnp/rnp.h>**  
**#include <rnp/rnp_err.h>**  

# DESCRIPTION
**librnp** is part of **RNP** suite and base for **rnp** and **rnpkeys** utilities.
It provides FFI interface to the functions required for OpenPGP protocol implementation.

Interface to the library is exposed via **<rnp/rnp.h>** and **<rnp/rnp_err.h>** headers.
See the headers for the full function list and detailed documentation.
Also you'll need to link to **librnp**.

# EXAMPLES
There is a bunch of examples in *src/examples* folder of the **RNP** suite source tree.

**generate.c**
: This example show how to generate OpenPGP keypair, using the JSON key description and may be used to generate any custom key types, supported by the **RNP** suite.

**encrypt.c**
: This example shows how to make OpenPGP-encrypted messages. Message is encrypted with keys, generated via **./generate**, and with hardcoded password.

**decrypt.c**
: This example shows how to decrypt OpenPGP messages. It needs **./encrypt** to be run first, producing the sample encrypted message.

**sign.c**
: This example shows how to sign messages. It needs **./generate** to be run first to generate and write out secret keys.

**verify.c**
: This example shows how to verify signed messages, taking as example message produced by **./sign**.

# AUTHORS

# BUGS
May be reported via the **RNP** GitHub repository: *https://www.github.com/rnpgp/rnp*

Please note that it is a public repository, so security issues must be reported in other way.

# SEE ALSO
**rnp(1)**, **rnpkeys(1)**
