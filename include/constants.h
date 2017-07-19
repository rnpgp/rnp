/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __RNP__CONSTANTS_H__
#define __RNP__CONSTANTS_H__

/* The dot directory relative to the user's home directory where keys
 * are stored.
 *
 * TODO: Consider making this an overridable config setting.
 *
 * TODO: For now the dot dot directory is .rnp to prevent competition with
 *       developers' .gnupg installations.
 */

#define SUBDIRECTORY_GNUPG ".gnupg"
#define SUBDIRECTORY_RNP ".rnp"
#define SUBDIRECTORY_SSH ".ssh"
#define PUBRING_KBX "pubring.kbx"
#define SECRING_KBX "secring.kbx"
#define PUBRING_GPG "pubring.gpg"
#define SECRING_GPG "secring.gpg"

#define MAX_PASSPHRASE_ATTEMPTS 3
#define INFINITE_ATTEMPTS -1

/* SHA1 is not considered secured anymore and SHOULD NOT be used to create messages (as per
 * Appendix C of RFC 4880-bis-02). SHA2 MUST be implemented.
 * Let's pre-empt this by specifying SHA256 - gpg interoperates just fine with SHA256 - agc,
 * 20090522
 */
#define DEFAULT_HASH_ALG "SHA256"

/* Function return codes, more will be added later */

#define RNP_OK 1
#define RNP_FAIL 0
#define RNP_EOF -1

enum {
    /* Error codes definitions */
    RNP_SUCCESS = 0x00000000,

    RNP_ERROR_GENERIC = 0x71000000,
    RNP_ERROR_BAD_FORMAT,
    RNP_ERROR_BAD_PARAMETERS,
    RNP_ERROR_NOT_IMPLEMENTED,
    RNP_ERROR_NOT_SUPPORTED,
    RNP_ERROR_OUT_OF_MEMORY,
    RNP_ERROR_SHORT_BUFFER,

    /* Storage */
    RNP_ERROR_STORAGE_NOT_AVAILABLE = 0x72000001,
    RNP_ERROR_READ,
    RNP_ERROR_WRITE,

    /* Crypto */
    RNP_ERROR_BAD_STATE = 0x73000000,
    RNP_ERROR_MAC_INVALID,
    RNP_ERROR_SIGNATURE_INVALID,
    RNP_ERROR_KEY_GENERATION,

    /* Parsing */
    RNP_ERROR_NOT_ENOUGH_DATA = 0x74000000,
    RNP_ERROR_UNKNOWN_TAG,
    RNP_ERROR_PACKET_NOT_CONSUMED,
    RNP_ERROR_NO_USERID,
};

#endif
