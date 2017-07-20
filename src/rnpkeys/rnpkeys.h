#ifndef _rnpkeys_H_
#define _rnpkeys_H_

#include <stdbool.h>
#include <sys/param.h>

#define EXIT_ERROR 2
#define DEFAULT_RSA_NUMBITS 2048

typedef enum {
    /* commands */
    CMD_LIST_KEYS = 260,
    CMD_LIST_SIGS,
    CMD_FIND_KEY,
    CMD_EXPORT_KEY,
    CMD_IMPORT_KEY,
    CMD_GENERATE_KEY,
    CMD_VERSION,
    CMD_HELP,
    CMD_GET_KEY,
    CMD_TRUSTED_KEYS,

    /* options */
    OPT_SSHKEYS,
    OPT_KEYRING,
    OPT_KEY_STORE_FORMAT,
    OPT_USERID,
    OPT_HOMEDIR,
    OPT_NUMBITS,
    OPT_HASH_ALG,
    OPT_VERBOSE,
    OPT_COREDUMPS,
    OPT_PASSWDFD,
    OPT_RESULTS,
    OPT_SSHKEYFILE,
    OPT_CIPHER,
    OPT_FORMAT,
    OPT_EXPERT,

    /* debug */
    OPT_DEBUG
} optdefs_t;

pgp_errcode_t rnp_generate_key_expert_mode(rnp_t *rnp);
bool rnp_cmd(rnp_cfg_t *cfg, rnp_t *rnp, optdefs_t cmd, char *f);
int setoption(rnp_cfg_t *cfg, optdefs_t *cmd, int val, char *arg);
void print_praise(void);
void print_usage(const char *usagemsg);
int parse_option(rnp_cfg_t *cfg, optdefs_t *cmd, const char *s);

/* -----------------------------------------------------------------------------
 * @brief   Initializes rnpkeys. Function allocates memory dynamically for
 *          cfg and rnp arguments, which must be freed by the caller.
 *
 * @param   [out] cfg configuration to be used by rnd_cmd
 * @param   [out[ rnp initialized rnp context
 * @param   [in]  opt_cfg configuration with settings from command line
 * @param   [in]  load_keys wether rnpkeys should be configured to
 *                run key generation
 *
 * @pre     cfg and rnp must be not NULL
 *
 * @returns true if on success, otherwise false. If false returned, no
 *          memory allocation was done.
 *
-------------------------------------------------------------------------------- */
bool rnpkeys_init(rnp_cfg_t *cfg, rnp_t *rnp, const rnp_cfg_t *opt_cfg, bool is_generate_key);

#endif /* _rnpkeys_ */
