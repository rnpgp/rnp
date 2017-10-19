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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef RNP_CFG_H_
#define RNP_CFG_H_

#include <rnp/rnp.h>
#include <stdbool.h>

/* cfg variables known by rnp */
#define CFG_OVERWRITE "overwrite" /* overwrite output file if it is already exist or fail */
#define CFG_ARMOUR "armour"       /* armour output data or not */
#define CFG_ARMOUR_DATA_TYPE                                                       \
    "armour_type"               /* armour data type, used with ``enarmour`` option \
                                   */
#define CFG_DETACHED "detached" /* produce the detached signature */
#define CFG_OUTFILE "outfile"   /* name/path of the output file */
#define CFG_RESULTS "results"   /* name/path for results, not used right now */
#define CFG_MAXALLOC "maxalloc" /* maximum memory allocation during the reading from stdin */
#define CFG_KEYSTOREFMT "keystorefmt" /* keyring format : GPG, SSH */
#define CFG_SSHKEYFILE "sshkeyfile"   /* SSH key file */
#define CFG_SUBDIRGPG "subdirgpg"     /* gpg/rnp files subdirectory: .rnp by default */
#define CFG_SUBDIRSSH "subdirssh"     /* ssh files (keys) subdirectory: .ssh by default */
#define CFG_COREDUMPS "coredumps"     /* enable/disable core dumps. 1 or 0. */
#define CFG_NEEDSUSERID "needsuserid" /* needs user id for the ongoing operation */
#define CFG_NEEDSSECKEY "needsseckey" /* needs secret key for the ongoing operation */
#define CFG_KEYRING "keyring" /* path to the keyring ?? seems not to be used anywhere */
#define CFG_USERID "userid"   /* userid for the ongoing operation */
#define CFG_VERBOSE "verbose" /* verbose logging */
#define CFG_HOMEDIR "homedir" /* home directory - folder with keyrings and so on */
#define CFG_PASSFD "pass-fd"  /* password file descriptor */
#define CFG_PASSWD "password" /* password as command-line constant */
#define CFG_USERINPUTFD "user-input-fd" /* user input file descriptor */
#define CFG_NUMTRIES "numtries"         /* number of password request tries, or 'unlimited' */
#define CFG_DURATION "duration"         /* signature validity duration */
#define CFG_BIRTHTIME "birthtime"       /* signature validity start */
#define CFG_CIPHER "cipher"             /* symmetric encryption algorithm as string */
#define CFG_HASH "hash"                 /* hash algorithm used, string like 'SHA1'*/
#define CFG_IO_OUTS "outs"              /* output stream */
#define CFG_IO_ERRS "errs"              /* error stream */
#define CFG_IO_RESS "ress"              /* results stream */
#define CFG_NUMBITS "numbits"           /* number of bits in generated key */
#define CFG_KEYFORMAT "format"          /* key format : "human" for human-readable or ... */
#define CFG_EXPERT "expert"             /* expert key generation mode */
#define CFG_ZLEVEL "zlevel"             /* compression level: 0..9 (0 for no compression) */
#define CFG_ZALG "zalg"                 /* compression algorithm: zip, zlib or bzip2 */
#define CFG_KEYSTORE_DISABLED \
    "disable_keystore" /* indicates wether keystore must be initialized */

/* rnp CLI config : contains all the system-dependent and specified by the user configuration
 * options */
typedef struct rnp_cfg_t {
    unsigned count; /* number of elements used */
    unsigned size;  /* allocated number of elements in the array */
    char **  keys;  /* key names */
    char **  vals;  /* values */
} rnp_cfg_t;

void rnp_cfg_init(rnp_cfg_t *cfg);
void rnp_cfg_load_defaults(rnp_cfg_t *cfg);
bool rnp_cfg_apply(rnp_cfg_t *cfg, rnp_params_t *params);
bool rnp_cfg_set(rnp_cfg_t *cfg, const char *key, const char *val);
bool rnp_cfg_unset(rnp_cfg_t *cfg, const char *key);
bool rnp_cfg_setint(rnp_cfg_t *cfg, const char *key, int val);
bool rnp_cfg_setbool(rnp_cfg_t *cfg, const char *key, bool val);
const char *rnp_cfg_get(const rnp_cfg_t *cfg, const char *key);
int rnp_cfg_getint(rnp_cfg_t *cfg, const char *key);
bool rnp_cfg_getbool(rnp_cfg_t *cfg, const char *key);
void rnp_cfg_free(rnp_cfg_t *cfg);

/**
 *  @brief      Returns integer value for the key if there is one, or default value otherwise
 *
 *  @param cfg  rnp config, must be allocated and initialized
 *  @param key  must be null-terminated string
 *  @param def  value returned if key not found
 *
 *  @return     Integer value or def if there is no value or it is non-integer
 **/
int rnp_cfg_getint_default(rnp_cfg_t *cfg, const char *key, int def);

/*
 * @brief   Copies or overrides configuration
 *
 * @param   dst resulting configuration object
 * @param   src vals in dst will be overriden (if key exist) or coppied (if not)
 *          from this object
 *
 * @pre     dst is correctly initialized and not NULL
 *
 */
void rnp_cfg_copy(rnp_cfg_t *dst, const rnp_cfg_t *src);

bool rnp_cfg_get_ks_info(rnp_cfg_t *cfg, rnp_params_t *params);
void rnp_cfg_get_defkey(rnp_cfg_t *cfg, rnp_params_t *params);
int rnp_cfg_get_pswdtries(rnp_cfg_t *cfg);

/* rnp CLI helper functions */
uint64_t get_duration(const char *s);
int64_t get_birthtime(const char *s);

#endif
