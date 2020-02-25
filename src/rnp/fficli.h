/*
 * Copyright (c) 2019-2020, [Ribose Inc](https://www.ribose.com).
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
#include "rnpcfg.h"
#include "json.h"

typedef struct cli_rnp_t {
    rnp_ffi_t ffi;
    rnp_cfg_t cfg;
    FILE *    resfp;      /* where to put result messages, defaults to stdout */
    FILE *    passfp;     /* file pointer for password input */
    FILE *    userio_in;  /* file pointer for user's inputs */
    FILE *    userio_out; /* file pointer for user's outputs */
    int       pswdtries;  /* number of password tries, -1 for unlimited */
} cli_rnp_t;

/**
 * @brief Set keystore parameters to the rnp_cfg_t. This includes keyring pathes, types and
 *        default key.
 *
 * @param cfg pointer to the allocated rnp_cfg_t structure
 * @return true on success or false otherwise.
 * @return false
 */
bool cli_cfg_set_keystore_info(rnp_cfg_t *cfg);

rnp_cfg_t *       cli_rnp_cfg(cli_rnp_t *rnp);
const std::string cli_rnp_defkey(cli_rnp_t *rnp);
const std::string cli_rnp_pubpath(cli_rnp_t *rnp);
const std::string cli_rnp_secpath(cli_rnp_t *rnp);
const std::string cli_rnp_pubformat(cli_rnp_t *rnp);
const std::string cli_rnp_secformat(cli_rnp_t *rnp);

bool cli_rnp_init(cli_rnp_t *, rnp_cfg_t *);
bool cli_rnp_baseinit(cli_rnp_t *);
void cli_rnp_end(cli_rnp_t *);
bool cli_rnp_load_keyrings(cli_rnp_t *rnp, bool loadsecret);
bool cli_rnp_save_keyrings(cli_rnp_t *rnp);
void cli_rnp_set_default_key(cli_rnp_t *rnp);
void cli_rnp_print_key_info(
  FILE *fp, rnp_ffi_t ffi, rnp_key_handle_t key, bool psecret, bool psigs);
bool        cli_rnp_set_generate_params(rnp_cfg_t *cfg);
bool        cli_rnp_generate_key(cli_rnp_t *rnp, const char *username);
list        cli_rnp_get_keylist(cli_rnp_t *rnp, const char *filter, bool secret, bool subkeys);
void        cli_rnp_keylist_destroy(list *keys);
bool        cli_rnp_export_keys(cli_rnp_t *rnp, const char *filter);
bool        cli_rnp_export_revocation(cli_rnp_t *rnp, const char *key);
bool        cli_rnp_add_key(cli_rnp_t *rnp);
bool        cli_rnp_dump_file(cli_rnp_t *rnp);
bool        cli_rnp_armor_file(cli_rnp_t *rnp);
bool        cli_rnp_dearmor_file(cli_rnp_t *rnp);
bool        cli_rnp_setup(cli_rnp_t *rnp);
bool        cli_rnp_protect_file(cli_rnp_t *rnp);
bool        cli_rnp_process_file(cli_rnp_t *rnp);
std::string cli_rnp_escape_string(const std::string &src);

const char *json_obj_get_str(json_object *obj, const char *key);
int64_t     json_obj_get_int64(json_object *obj, const char *key);
bool        rnp_casecmp(const std::string &str1, const std::string &str2);

/* TODO: we should decide what to do with functions/constants/defines below */
#define RNP_KEYID_SIZE 8
#define RNP_FP_SIZE 20
#define RNP_GRIP_SIZE 20

#define MAX_PASSWORD_ATTEMPTS 3

#define ERR_MSG(...)                           \
    do {                                       \
        (void) fprintf((stderr), __VA_ARGS__); \
        (void) fprintf((stderr), "\n");        \
    } while (0)

#define EXT_ASC (".asc")
#define EXT_SIG (".sig")
#define EXT_PGP (".pgp")
#define EXT_GPG (".gpg")

char *rnp_strip_eol(char *s);

#endif
