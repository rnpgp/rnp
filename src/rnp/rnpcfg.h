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

#include <stdbool.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <unordered_map>

/* cfg variables known by rnp */
#define CFG_OVERWRITE "overwrite" /* overwrite output file if it is already exist or fail */
#define CFG_ARMOR "armor"         /* armor output data or not */
#define CFG_ARMOR_DATA_TYPE "armor_type" /* armor data type, used with ``enarmor`` option */
#define CFG_COMMAND "command"            /* command to execute over input data */
#define CFG_DETACHED "detached"          /* produce the detached signature */
#define CFG_CLEARTEXT "cleartext"        /* cleartext signing should be used */
#define CFG_SIGN_NEEDED "sign_needed"    /* signing is needed during data protection */
#define CFG_OUTFILE "outfile"            /* name/path of the output file */
#define CFG_NO_OUTPUT "no_output"        /* do not output any data - just verify or process */
#define CFG_INFILE "infile"              /* name/path of the input file */
#define CFG_RESULTS "results"            /* name/path for results, not used right now */
#define CFG_KEYSTOREFMT "keystorefmt"    /* keyring format : GPG, G10, KBX */
#define CFG_COREDUMPS "coredumps"        /* enable/disable core dumps. 1 or 0. */
#define CFG_NEEDSSECKEY "needsseckey"    /* needs secret key for the ongoing operation */
#define CFG_USERID "userid"              /* userid for the ongoing operation */
#define CFG_RECIPIENTS "recipients"      /* list of encrypted data recipients */
#define CFG_SIGNERS "signers"            /* list of signers */
#define CFG_VERBOSE "verbose"            /* verbose logging */
#define CFG_HOMEDIR "homedir"            /* home directory - folder with keyrings and so on */
#define CFG_KEYFILE "keyfile"     /* path to the file with key(s), used instead of keyring */
#define CFG_PASSFD "pass-fd"      /* password file descriptor */
#define CFG_PASSWD "password"     /* password as command-line constant */
#define CFG_PASSWORDC "passwordc" /* number of passwords for symmetric encryption */
#define CFG_USERINPUTFD "user-input-fd" /* user input file descriptor */
#define CFG_NUMTRIES "numtries"         /* number of password request tries, or 'unlimited' */
#define CFG_EXPIRATION "expiration"     /* signature expiration time */
#define CFG_CREATION "creation"         /* signature validity start */
#define CFG_CIPHER "cipher"             /* symmetric encryption algorithm as string */
#define CFG_HASH "hash"                 /* hash algorithm used, string like 'SHA1'*/
#define CFG_S2K_ITER "s2k-iter"         /* number of S2K hash iterations to perform */
#define CFG_S2K_MSEC "s2k-msec"         /* number of milliseconds S2K should target */
#define CFG_ENCRYPT_PK "encrypt_pk"     /* public key should be used during encryption */
#define CFG_ENCRYPT_SK "encrypt_sk"     /* password encryption should be used */
#define CFG_IO_RESS "ress"              /* results stream */
#define CFG_NUMBITS "numbits"           /* number of bits in generated key */
#define CFG_KEYFORMAT "format"          /* key format : "human" for human-readable or ... */
#define CFG_EXPERT "expert"             /* expert key generation mode */
#define CFG_ZLEVEL "zlevel"             /* compression level: 0..9 (0 for no compression) */
#define CFG_ZALG "zalg"                 /* compression algorithm: zip, zlib or bzip2 */
#define CFG_AEAD "aead"                 /* if nonzero then AEAD enryption mode, int */
#define CFG_AEAD_CHUNK "aead_chunk"     /* AEAD chunk size bits, int from 0 to 56 */
#define CFG_KEYSTORE_DISABLED \
    "disable_keystore"              /* indicates whether keystore must be initialized */
#define CFG_FORCE "force"           /* force command to succeed operation */
#define CFG_SECRET "secret"         /* indicates operation on secret key */
#define CFG_WITH_SIGS "with-sigs"   /* list keys with signatures */
#define CFG_JSON "json"             /* list packets with JSON output */
#define CFG_GRIPS "grips"           /* dump grips when dumping key packets */
#define CFG_MPIS "mpis"             /* dump MPI values when dumping packets */
#define CFG_RAW "raw"               /* dump raw packet contents */
#define CFG_REV_TYPE "rev-type"     /* revocation reason code */
#define CFG_REV_REASON "rev-reason" /* revocation reason human-readable string */
#define CFG_PERMISSIVE "permissive" /* ignore bad packets during key import */

/* rnp keyring setup variables */
#define CFG_KR_PUB_FORMAT "kr-pub-format"
#define CFG_KR_SEC_FORMAT "kr-sec-format"
#define CFG_KR_PUB_PATH "kr-pub-path"
#define CFG_KR_SEC_PATH "kr-sec-path"
#define CFG_KR_DEF_KEY "kr-def-key"

/* key generation variables */
#define CFG_KG_PRIMARY_ALG "kg-primary-alg"
#define CFG_KG_PRIMARY_BITS "kg-primary-bits"
#define CFG_KG_PRIMARY_CURVE "kg-primary-curve"
#define CFG_KG_PRIMARY_EXPIRATION "kg-primary-expiration"
#define CFG_KG_SUBKEY_ALG "kg-subkey-alg"
#define CFG_KG_SUBKEY_BITS "kg-subkey-bits"
#define CFG_KG_SUBKEY_CURVE "kg-subkey-curve"
#define CFG_KG_SUBKEY_EXPIRATION "kg-subkey-expiration"
#define CFG_KG_HASH "kg-hash"
#define CFG_KG_PROT_HASH "kg-prot-hash"
#define CFG_KG_PROT_ALG "kg-prot-alg"
#define CFG_KG_PROT_ITERATIONS "kg-prot-iterations"

/* rnp CLI config : contains all the system-dependent and specified by the user configuration
 * options */
class rnp_cfg_val;

class rnp_cfg {
  private:
    std::unordered_map<std::string, rnp_cfg_val *> vals_;
    std::string                                    empty_str_;

  public:
    /** @brief load default settings */
    void load_defaults();
    /** @brief set string value for the key in config */
    void set_str(const std::string &key, const std::string &val);
    void set_str(const std::string &key, const char *val);
    /** @brief set int value for the key in config */
    void set_int(const std::string &key, int val);
    /** @brief set bool value for the key in config */
    void set_bool(const std::string &key, bool val);
    /** @brief remove key and corresponding value from the config */
    void unset(const std::string &key);
    /** @brief add string item to the list value */
    void add_str(const std::string &key, const std::string &val);
    /** @brief check whether config has value for the key */
    bool has(const std::string &key) const;
    /** @brief get string value from the config. If it is absent then empty string will be
     *         returned */
    const std::string &get_str(const std::string &key) const;
    /** @brief get C string value from the config. Will return 0 instead of empty string if
     * value is absent. */
    const char *get_cstr(const std::string &key) const;
    /** @brief get int value from the config. If it is absent then def will be returned */
    int get_int(const std::string &key, int def = 0) const;
    /** @brief get bool value from the config. If it is absent then false will be returned */
    bool get_bool(const std::string &key) const;
    /** @brief get number of items in the string list value. If it is absent then 0 will be
     *         returned. */
    size_t get_count(const std::string &key) const;
    /** @brief get string from the list value at the corresponding position. If there is no
     *         corresponding value or index too large then empty string will be returned. */
    const std::string &get_str(const std::string &key, size_t idx) const;
    /** @brief get all strings from the list value */
    std::vector<std::string> get_list(const std::string &key) const;
    /** @brief get number of the password tries */
    int get_pswdtries() const;
    /** @brief get hash algorithm */
    const std::string get_hashalg() const;
    /** @brief copy or override a configuration.
     *  @param src vals will be overridden (if key exist) or copied (if not) from this object
     */
    void copy(const rnp_cfg &src);
    void clear();
    /* delete unneeded operators */
    rnp_cfg &operator=(const rnp_cfg &src) = delete;
    rnp_cfg &operator=(const rnp_cfg &&src) = delete;
    /** @brief destructor */
    ~rnp_cfg();
};

/* rnp CLI helper functions */

/** @brief Get signature validity expiration time from the user input
 *
 *  Signature expiration may be specified in different formats:
 *  - 10d : 10 days (you can use [h]ours, d[ays], [w]eeks, [m]onthes)
 *  - 2017-07-12 : as the exact date when signature becomes invalid
 *  - 60000 : number of seconds
 *
 *  @param s [in] NULL-terminated string with the date
 *  @param t [out] On successfull return result will be placed here
 *  @return 0 on success
 *          -1 on parse error
 *          -2 if a date in the past was specified
 *          -3 overflow
 */
int get_expiration(const char *s, uint32_t *t);

/** @brief Get signature validity start time from the user input
 *
 *  Signature validity may be specified in different formats:
 *  - 2017-07-12 : as the exact date when signature becomes invalid
 *  - 1499334073 : timestamp
 *
 *  @param s [in] NULL-terminated string with the date
 *  @return timestamp of the validity start
 */
int64_t get_creation(const char *s);

#endif
