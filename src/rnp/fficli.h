/*
 * Copyright (c) 2019, [Ribose Inc](https://www.ribose.com).
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

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct cli_rnp_t {
    rnp_ffi_t ffi;
    FILE *    resfp;     /* where to put result messages, defaults to stdout */
    FILE *    passfp;    /* file pointer for password input */
    int       pswdtries; /* number of password tries, -1 for unlimited */
    char *    pubpath;   /* path to the public keyring */
    char *    pubformat; /* format of the public keyring */
    char *    secpath;   /* path to the secret keyring */
    char *    secformat; /* format of the secret keyring */
    char *    defkey;    /* default key id */
} cli_rnp_t;

bool cli_cfg_set_keystore_info(rnp_cfg_t *cfg);
bool cli_rnp_init(cli_rnp_t *, rnp_cfg_t *);
void cli_rnp_end(cli_rnp_t *);
bool cli_rnp_load_keyrings(cli_rnp_t *rnp, bool loadsecret);
bool cli_rnp_save_keyrings(cli_rnp_t *rnp);
void cli_rnp_set_default_key(cli_rnp_t *rnp);
void cli_rnp_print_key_info(
  FILE *fp, rnp_ffi_t ffi, rnp_key_handle_t key, bool psecret, bool psigs);
bool cli_rnp_set_generate_params(rnp_cfg_t *cfg);
bool cli_rnp_generate_key(rnp_cfg_t *cfg, cli_rnp_t *rnp, const char *username);
list cli_rnp_get_keylist(cli_rnp_t *rnp, const char *filter, bool secret);
void cli_rnp_keylist_destroy(list *keys);
bool cli_rnp_export_keys(rnp_cfg_t *cfg, cli_rnp_t *rnp, const char *filter);
bool cli_rnp_add_key(const rnp_cfg_t *cfg, cli_rnp_t *rnp);
bool cli_rnp_dump_file(const rnp_cfg_t *cfg);
bool cli_rnp_armor_file(const rnp_cfg_t *cfg);
bool cli_rnp_dearmor_file(const rnp_cfg_t *cfg);
bool cli_rnp_setup(const rnp_cfg_t *cfg, cli_rnp_t *rnp);
bool cli_rnp_protect_file(const rnp_cfg_t *cfg, cli_rnp_t *rnp);
bool cli_rnp_process_file(const rnp_cfg_t *cfg, cli_rnp_t *rnp);

const char *json_obj_get_str(json_object *obj, const char *key);
int64_t     json_obj_get_int64(json_object *obj, const char *key);
bool        set_pass_fd(FILE **file, int passfd);
char *      ptimestr(char *dest, size_t size, time_t t);

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

rnp_result_t disable_core_dumps(void);
char *       rnp_strip_eol(char *s);
void         pgp_forget(void *vp, size_t size);
bool rnp_get_output_filename(const char *path, char *newpath, size_t maxlen, bool overwrite);

#if defined(__cplusplus)
}
#endif

#endif
