#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <rnp.h>
#include <key_store.h>
#include <key_store_pgp.h>

int
main(int argc, char *argv[])
{
    rnp_key_store_t key_store;
    memset(&key_store, 0, sizeof(key_store));
    rnp_key_store_pgp_read_from_file(NULL, &key_store, 1, argv[1]);
}
