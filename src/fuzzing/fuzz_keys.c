#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <rnp.h>
#include <keyring.h>
#include <keyring_pgp.h>

int
main(int argc, char *argv[])
{
    keyring_t keyring;
    memset(&keyring, 0, sizeof(keyring));
    pgp_keyring_read_from_file(NULL, &keyring, 1, argv[1]);
}
