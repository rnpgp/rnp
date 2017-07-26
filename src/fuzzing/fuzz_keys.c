#include <rnp/rnp.h>
#include <rekey/rnp_key_store.h>

int
main(int argc, char *argv[])
{
    rnp_t        rnp;
    rnp_params_t params;

    rnp_init(&rnp, &params);
    rnp_key_store_t key_store;
    rnp_key_store_load_from_file(&rnp, &key_store, 1, argv[1]);
}
