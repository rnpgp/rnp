#ifndef _rnpkeys_H_
#define _rnpkeys_H_

#include <sys/param.h>

#define EXIT_ERROR 2
#define DEFAULT_RSA_NUMBITS 2048

enum optdefs {
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
};

pgp_errcode_t rnp_generate_key_expert_mode(rnp_t *rnp);
int rnp_cmd(rnp_cfg_t *cfg, rnp_t *rnp, int cmd, char *f);
int setoption(rnp_cfg_t *cfg, int *cmd, int val, char *arg);
void print_praise(void);
void print_usage(const char *usagemsg);
int parse_option(rnp_cfg_t *cfg, int *cmd, const char *s);

#endif /* _rnpkeys_ */
