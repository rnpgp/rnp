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
#ifndef __RNP__CFG_H__
#define __RNP__CFG_H__

/* cfg variables known by rnp */
#define CFG_OVERWRITE    "overwrite"   /* overwrite output file if it is already exist or fail */
#define CFG_ARMOUR       "armour"      /* armour output data or not */
#define CFG_DETACHED     "detached"    /* produce the detached signature */
#define CFG_OUTFILE      "outfile"     /* name/path of the output file */
#define CFG_RESULTS      "results"     /* name/path for results, not used right now */
#define CFG_MAXALLOC     "maxalloc"    /* maximum memory allocation during the reading from stdin */
#define CFG_KEYSTOREFMT  "keystorefmt" /* keyring format : GPG, SSH */
#define CFG_SSHKEYFILE   "sshkeyfile"  /* SSH key file */
#define CFG_SUBDIRGPG    "subdirgpg"   /* gpg/rnp files subdirectory: .rnp by default */
#define CFG_SUBDIRSSH    "subdirssh"   /* ssh files (keys) subdirectory: .ssh by default */
#define CFG_COREDUMPS    "coredumps"   /* enable/disable core dumps. 1 or 0. */
#define CFG_NEEDSUSERID  "needsuserid" /* needs user id for the ongoing operation - i.e. signing, encryption */
#define CFG_NEEDSSECKEY  "needsseckey" /* needs secret key for the ongoing operation - i.e. signing, decryption, so secret keyring will be loaded */
#define CFG_KEYRING      "keyring"     /* path to the keyring ?? */
#define CFG_USERID       "userid"      /* userid for the ongoing operation */
#define CFG_VERBOSE      "verbose"     /* verbose logging */
#define CFG_HOMEDIR      "homedir"     /* home directory - folder with keyrings and possibly other stuff */
#define CFG_PASSFD       "pass-fd"     /* password file descriptor */
#define CFG_NUMTRIES     "numtries"    /* number of password request tries, or 'unlimited' for unlimited attempts */
#define CFG_DURATION     "duration"    /* signature validity duration */
#define CFG_BIRTHTIME    "birthtime"   /* signature validity start */
#define CFG_CIPHER       "cipher"      /* symmetric encryption algorithm as string */
#define CFG_HASH         "hash"        /* hash algorithm used, string like 'SHA1'*/
#define CFG_IO_OUTS      "outs"        /* output stream */
#define CFG_IO_ERRS      "errs"        /* error stream */
#define CFG_IO_RESS      "ress"        /* results stream */

/* additional cfg constants */
#define CFG_KEYSTORE_GPG "GPG" /* GPG keyring format */
#define CFG_KEYSTORE_SSH "SSH" /* SSH keyring format */

/* rnp CLI config : contains all the system-dependent and specified by the user configuration options */
typedef struct rnp_cfg_t {
    unsigned  count;   /* number of elements used */
    unsigned  size;    /* allocated number of elements in the array */
    char **   keys;    /* key names */
    char **   vals;   /* values */
} rnp_cfg_t;

int rnp_cfg_init(rnp_cfg_t *cfg);
int rnp_cfg_load_defaults(rnp_cfg_t *cfg);
int rnp_cfg_apply(rnp_cfg_t *cfg, rnp_init_t *params);
int rnp_cfg_set(rnp_cfg_t *cfg, const char *key, const char *val);
int rnp_cfg_unset(rnp_cfg_t *cfg, const char *key);
int rnp_cfg_setint(rnp_cfg_t *cfg, const char *key, int val);
const char * rnp_cfg_get(rnp_cfg_t *cfg, const char *key);
int rnp_cfg_getint(rnp_cfg_t *cfg, const char *key);
void rnp_cfg_free(rnp_cfg_t *cfg);

int rnp_cfg_apply_homedir(rnp_t *rnp, rnp_cfg_t *rnp, const int quiet);
int rnp_cfg_get_pswdtries(rnp_cfg_t *cfg);


#endif
