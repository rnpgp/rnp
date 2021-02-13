#ifndef RNPKEYS_H_
#define RNPKEYS_H_

#include <stdbool.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#else
#include "uniwin.h"
#endif
#include "../rnp/fficli.h"
#include "logging.h"

#define DEFAULT_RSA_NUMBITS 2048

typedef enum {
    /* commands */
    CMD_LIST_KEYS = 260,
    CMD_EXPORT_KEY,
    CMD_IMPORT,
    CMD_IMPORT_KEYS,
    CMD_IMPORT_SIGS,
    CMD_GENERATE_KEY,
    CMD_EXPORT_REV,
    CMD_REVOKE_KEY,
    CMD_REMOVE_KEY,
    CMD_VERSION,
    CMD_HELP,

    /* options */
    OPT_KEY_STORE_FORMAT,
    OPT_USERID,
    OPT_HOMEDIR,
    OPT_NUMBITS,
    OPT_HASH_ALG,
    OPT_VERBOSE,
    OPT_COREDUMPS,
    OPT_PASSWDFD,
    OPT_PASSWD,
    OPT_RESULTS,
    OPT_CIPHER,
    OPT_FORMAT,
    OPT_EXPERT,
    OPT_OUTPUT,
    OPT_FORCE,
    OPT_SECRET,
    OPT_S2K_ITER,
    OPT_S2K_MSEC,
    OPT_EXPIRATION,
    OPT_WITH_SIGS,
    OPT_REV_TYPE,
    OPT_REV_REASON,
    OPT_PERMISSIVE,

    /* debug */
    OPT_DEBUG
} optdefs_t;

bool rnp_cmd(cli_rnp_t *rnp, optdefs_t cmd, const char *f);
bool setoption(rnp_cfg &cfg, optdefs_t *cmd, int val, const char *arg);
void print_praise(void);
void print_usage(const char *usagemsg);
bool parse_option(rnp_cfg &cfg, optdefs_t *cmd, const char *s);

/**
 * @brief Initializes rnpkeys. Function allocates memory dynamically for
 *        rnp argument, which must be freed by the caller.
 *
 * @param rnp initialized rnp context
 * @param cfg configuration with settings from command line
 * @return true on success, or false otherwise.
 */
bool rnpkeys_init(cli_rnp_t *rnp, const rnp_cfg &cfg);

#endif /* _rnpkeys_ */
