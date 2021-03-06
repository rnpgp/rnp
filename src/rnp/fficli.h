/*
 * Copyright (c) 2019-2021, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef FFICLI_H_
#define FFICLI_H_

#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include "rnp/rnp.h"
#include "rnp/rnp_err.h"
#include "config.h"
#include "rnpcfg.h"
#include "json.h"

typedef struct cli_rnp_t {
    rnp_ffi_t ffi{};
    rnp_cfg   cfg{};
    FILE *    resfp{};      /* where to put result messages, defaults to stdout */
    FILE *    passfp{};     /* file pointer for password input */
    FILE *    userio_in{};  /* file pointer for user's inputs */
    FILE *    userio_out{}; /* file pointer for user's outputs */
    int       pswdtries{};  /* number of password tries, -1 for unlimited */
} cli_rnp_t;

typedef enum cli_search_flags_t {
    CLI_SEARCH_SECRET = 1 << 0,     /* search secret keys only */
    CLI_SEARCH_SUBKEYS = 1 << 1,    /* add subkeys as well */
    CLI_SEARCH_FIRST_ONLY = 1 << 2, /* return only first key matching */
    CLI_SEARCH_SUBKEYS_AFTER =
      (1 << 3) | CLI_SEARCH_SUBKEYS, /* put subkeys after the primary key */
    CLI_SEARCH_DEFAULT = 1 << 4      /* add default key if nothing found */
} cli_search_flags_t;

/**
 * @brief Set keystore parameters to the rnp_cfg_t. This includes keyring paths, types and
 *        default key.
 *
 * @param cfg pointer to the allocated rnp_cfg_t structure
 * @return true on success or false otherwise.
 * @return false
 */
bool cli_cfg_set_keystore_info(rnp_cfg &cfg);

rnp_cfg &         cli_rnp_cfg(cli_rnp_t &rnp);
const std::string cli_rnp_defkey(cli_rnp_t *rnp);
const std::string cli_rnp_pubpath(cli_rnp_t *rnp);
const std::string cli_rnp_secpath(cli_rnp_t *rnp);
const std::string cli_rnp_pubformat(cli_rnp_t *rnp);
const std::string cli_rnp_secformat(cli_rnp_t *rnp);

bool cli_rnp_init(cli_rnp_t *, const rnp_cfg &);
bool cli_rnp_baseinit(cli_rnp_t *);
void cli_rnp_end(cli_rnp_t *);
bool cli_rnp_load_keyrings(cli_rnp_t *rnp, bool loadsecret);
bool cli_rnp_save_keyrings(cli_rnp_t *rnp);
void cli_rnp_set_default_key(cli_rnp_t *rnp);
void cli_rnp_print_key_info(
  FILE *fp, rnp_ffi_t ffi, rnp_key_handle_t key, bool psecret, bool psigs);
bool cli_rnp_set_generate_params(rnp_cfg &cfg);
bool cli_rnp_generate_key(cli_rnp_t *rnp, const char *username);
/**
 * @brief Find key(s) matching set of flags and search string.
 *
 * @param rnp initialized cli_rnp_t object.
 * @param keys search results will be added here, leaving already existing items.
 * @param str search string: may be part of the userid, keyid, fingerprint or grip.
 * @param flags combination of the following flags:
 *              CLI_SEARCH_SECRET : require key to be secret,
 *              CLI_SEARCH_SUBKEYS : include subkeys to the results (see
 *                CLI_SEARCH_SUBKEYS_AFTER description).
 *              CLI_SEARCH_FIRST_ONLY : include only first key found
 *              CLI_SEARCH_SUBKEYS_AFTER : for each primary key add its subkeys after the main
 *                key. This changes behaviour of subkey search, since those will be added only
 *                if subkey is orphaned or primary key matches search.
 * @return true if operation succeeds and at least one key is found, or false otherwise.
 */
bool cli_rnp_keys_matching_string(cli_rnp_t *                    rnp,
                                  std::vector<rnp_key_handle_t> &keys,
                                  const std::string &            str,
                                  int                            flags);
/**
 * @brief Find key(s) matching set of flags and search string(s).
 *
 * @param rnp initialized cli_rnp_t object.
 * @param keys search results will be put here, overwriting vector's contents.
 * @param strs set of search strings, may be empty.
 * @param flags the same flags as for cli_rnp_keys_matching_string(), except additional one:
 *              CLI_SEARCH_DEFAULT : if no key is found then default key from cli_rnp_t will be
 *                searched.
 * @return true if operation succeeds and at least one key is found for each search string, or
 *         false otherwise.
 */
bool        cli_rnp_keys_matching_strings(cli_rnp_t *                     rnp,
                                          std::vector<rnp_key_handle_t> & keys,
                                          const std::vector<std::string> &strs,
                                          int                             flags);
bool        cli_rnp_export_keys(cli_rnp_t *rnp, const char *filter);
bool        cli_rnp_export_revocation(cli_rnp_t *rnp, const char *key);
bool        cli_rnp_revoke_key(cli_rnp_t *rnp, const char *key);
bool        cli_rnp_remove_key(cli_rnp_t *rnp, const char *key);
bool        cli_rnp_add_key(cli_rnp_t *rnp);
bool        cli_rnp_dump_file(cli_rnp_t *rnp);
bool        cli_rnp_armor_file(cli_rnp_t *rnp);
bool        cli_rnp_dearmor_file(cli_rnp_t *rnp);
bool        cli_rnp_setup(cli_rnp_t *rnp);
bool        cli_rnp_protect_file(cli_rnp_t *rnp);
bool        cli_rnp_process_file(cli_rnp_t *rnp);
std::string cli_rnp_escape_string(const std::string &src);

void clear_key_handles(std::vector<rnp_key_handle_t> &keys);

const char *json_obj_get_str(json_object *obj, const char *key);
int64_t     json_obj_get_int64(json_object *obj, const char *key);
bool        rnp_casecmp(const std::string &str1, const std::string &str2);

#ifdef _WIN32
bool rnp_win_substitute_cmdline_args(int *argc, char ***argv);
void rnp_win_clear_args(int argc, char **argv);
#endif

/* TODO: we should decide what to do with functions/constants/defines below */
#define RNP_KEYID_SIZE 8
#define RNP_FP_SIZE 20
#define RNP_GRIP_SIZE 20

#define ERR_MSG(...)                           \
    do {                                       \
        (void) fprintf((stderr), __VA_ARGS__); \
        (void) fprintf((stderr), "\n");        \
    } while (0)

#define EXT_ASC (".asc")
#define EXT_SIG (".sig")
#define EXT_PGP (".pgp")
#define EXT_GPG (".gpg")

#define SUBDIRECTORY_GNUPG ".gnupg"
#define SUBDIRECTORY_RNP ".rnp"
#define PUBRING_KBX "pubring.kbx"
#define SECRING_KBX "secring.kbx"
#define PUBRING_GPG "pubring.gpg"
#define SECRING_GPG "secring.gpg"
#define PUBRING_G10 "public-keys-v1.d"
#define SECRING_G10 "private-keys-v1.d"

#endif
