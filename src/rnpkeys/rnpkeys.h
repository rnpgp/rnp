#ifndef _rnpkeys_H_
#define _rnpkeys_H_

#include <sys/param.h>

#define EXIT_ERROR 2
#define DEFAULT_RSA_NUMBITS 2048

enum optdefs {
    /* commands */
    LIST_KEYS = 260,
    LIST_SIGS,
    FIND_KEY,
    EXPORT_KEY,
    IMPORT_KEY,
    GENERATE_KEY,
    VERSION_CMD,
    HELP_CMD,
    GET_KEY,
    TRUSTED_KEYS,

    /* options */
    SSHKEYS,
    KEYRING,
    KEY_STORE_FORMAT,
    USERID,
    HOMEDIR,
    NUMBITS,
    HASH_ALG,
    VERBOSE,
    COREDUMPS,
    PASSWDFD,
    RESULTS,
    SSHKEYFILE,
    CIPHER,
    FORMAT,
    EXPERT,

    /* debug */
    OPS_DEBUG

};

/* gather up program variables into one struct */
typedef struct prog_t {
    char keyring[MAXPATHLEN + 1]; /* name of keyring */
    int  numbits;                 /* # of bits */
    int  cmd;                     /* rnpkeys command */
} prog_t;

void print_praise(void);
void print_usage(const char *usagemsg);
int setoption(rnp_t *rnp, prog_t *p, int val, char *arg);
int parse_option(rnp_t *rnp, prog_t *p, const char *s);
int rnp_cmd(rnp_t *rnp, prog_t *p, char *f);
pgp_errcode_t rnp_generate_key_expert_mode(rnp_t *rnp);

#endif /* _rnpkeys_ */
