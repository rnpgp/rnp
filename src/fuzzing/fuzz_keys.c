#include <rnp/rnp.h>
#include <rekey/rnp_key_store.h>

int
main(int argc, char *argv[])
{
    rnp_t        rnp;
    rnp_params_t params;

    rnp_init(&rnp, &params);
    rnp_key_store_t *key_store = rnp_key_store_new(RNP_KEYSTORE_GPG, argv[1]);
    if (key_store == NULL) {
        return 1;
    }
    rnp_key_store_load_from_file(rnp.io, key_store, 1, NULL);
    rnp_key_store_free(key_store);
    return 0;
}
