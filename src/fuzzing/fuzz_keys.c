#include <rnp.h>
#include <key_store.h>

int
main(int argc, char *argv[])
{
    rnp_t rnp;
    rnp_init(&rnp);
    rnp_key_store_t key_store;
    rnp_key_store_load_from_file(&rnp, &key_store, 1, argv[1]);
}
