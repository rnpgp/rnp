#include <rnp/rnp.h>
#include <rekey/rnp_key_store.h>

int
main(int argc, char *argv[])
{
    rnp_key_store_t *key_store = NULL;
    try {
        key_store = new rnp_key_store_t(RNP_KEYSTORE_GPG, argv[1]);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return 1;
    }
    rnp_key_store_load_from_path(key_store, NULL);
    delete key_store;
    return 0;
}
