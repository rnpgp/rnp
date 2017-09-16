#include <stdio.h>
#include <repgp/repgp.h> /* repgp API */
#include <rnp/rnp.h>     /* rnp_t, rnp_ctx_t et. all */

#define PFX "redumper: "

int
main(int argc, const char *argv[])
{
    rnp_t     rnp = {0};
    rnp_ctx_t ctx = {0};

    if (argc != 2) {
        fprintf(stderr, PFX "Usage: %s input.pgp\n", argv[0]);
        return 1;
    }

    if (rnp_ctx_init(&ctx, &rnp) != RNP_SUCCESS) {
        fprintf(stderr, PFX "Initialization failed\n");
        return 1;
    }

    repgp_handle_t *handle = create_filepath_handle(argv[1]);
    rnp_result      res = repgp_dump_packets(&ctx, handle);
    repgp_destroy_handle(handle);
    rnp_end(&rnp);

    if (res != RNP_SUCCESS) {
        fprintf(stderr, PFX "Operation failed [error code: 0x%X]\n", res);
        return 1;
    }

    return 0;
}