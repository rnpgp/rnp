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

#include "config.h"

#include "rnp.h"
#include "rnpsdk.h"
#include "keyring.h"
#include "keyring_ssh.h"

#include "ssh2pgp.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* read keys from ssh key files */
static int
readsshkeys(rnp_t *rnp, char *homedir, const char *needseckey)
{
    keyring_t	*pubring;
    keyring_t	*secring;
    struct stat	 st;
    unsigned	 hashtype;
    char		*hash;
    char		 f[MAXPATHLEN];
    char		*filename;

    if ((filename = rnp_getvar(rnp, "sshkeyfile")) == NULL) {
        /* set reasonable default for RSA key */
        (void) snprintf(f, sizeof(f), "%s/id_rsa.pub", homedir);
        filename = f;
    } else if (strcmp(&filename[strlen(filename) - 4], ".pub") != 0) {
        /* got ssh keys, check for pub file name */
        (void) snprintf(f, sizeof(f), "%s.pub", filename);
        filename = f;
    }
    /* check the pub file exists */
    if (stat(filename, &st) != 0) {
        (void) fprintf(stderr, "readsshkeys: bad pubkey filename '%s'\n", filename);
        return 0;
    }
    if ((pubring = calloc(1, sizeof(*pubring))) == NULL) {
        (void) fprintf(stderr, "readsshkeys: bad alloc\n");
        return 0;
    }
    /* openssh2 keys use md5 by default */
    hashtype = PGP_HASH_MD5;
    if ((hash = rnp_getvar(rnp, "hash")) != NULL) {
        /* openssh 2 hasn't really caught up to anything else yet */
        if (rnp_strcasecmp(hash, "md5") == 0) {
            hashtype = PGP_HASH_MD5;
        } else if (rnp_strcasecmp(hash, "sha1") == 0) {
            hashtype = PGP_HASH_SHA1;
        } else if (rnp_strcasecmp(hash, "sha256") == 0) {
            hashtype = PGP_HASH_SHA256;
        }
    }
    if (!pgp_ssh2_readkeys(rnp->io, pubring, NULL, filename, NULL, hashtype)) {
        free(pubring);
        (void) fprintf(stderr, "readsshkeys: cannot read %s\n",
                       filename);
        return 0;
    }
    if (rnp->pubring == NULL) {
        rnp->pubring = pubring;
    } else {
        pgp_append_keyring(rnp->pubring, pubring);
    }
    if (needseckey) {
        rnp_setvar(rnp, "sshpubfile", filename);
        /* try to take the ".pub" off the end */
        if (filename == f) {
            f[strlen(f) - 4] = 0x0;
        } else {
            (void) snprintf(f, sizeof(f), "%.*s",
                            (int)strlen(filename) - 4, filename);
            filename = f;
        }
        if ((secring = calloc(1, sizeof(*secring))) == NULL) {
            free(pubring);
            (void) fprintf(stderr, "readsshkeys: bad alloc\n");
            return 0;
        }
        if (!pgp_ssh2_readkeys(rnp->io, pubring, secring, NULL, filename, hashtype)) {
            free(pubring);
            free(secring);
            (void) fprintf(stderr, "readsshkeys: cannot read sec %s\n", filename);
            return 0;
        }
        rnp->secring = secring;
        rnp_setvar(rnp, "sshsecfile", filename);
    }
    return 1;
}

int
ssh_keyring_load_keys(rnp_t *rnp, char *homedir)
{
    int       last = (rnp->pubring != NULL);
    char      id[MAX_ID_LENGTH];
    char     *userid;
    pgp_io_t *io = rnp->io;

    /* TODO: Double-check whether or not ID needs to be zeroed. */

    if (! readsshkeys(rnp, homedir,
                      rnp_getvar(rnp, "need seckey"))) {
        fprintf(io->errs, "cannot read ssh keys\n");
        return 0;
    }
    if ((userid = rnp_getvar(rnp, "userid")) == NULL) {
        /* TODO: Handle get_first_ring() failure. */
        keyring_get_first_ring(rnp->pubring, id,
                       sizeof(id), last);
        rnp_setvar(rnp, "userid", userid = id);
    }
    if (userid == NULL) {
        if (rnp_getvar(rnp, "need userid") != NULL) {
            fprintf(io->errs, "cannot find user id\n");
            return 0;
        }
    } else {
        rnp_setvar(rnp, "userid", userid);
    }

    return 1;
}