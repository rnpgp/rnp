#include <stdio.h>
#include <unistd.h>      /* getopt() */
#include <repgp/repgp.h> /* repgp API */
#include <rnp/rnp.h>     /* rnp_t, rnp_ctx_t et. all */

#define PFX "redumper: "

void
print_usage(const char *program_name)
{
    fprintf(stderr,
            PFX "Program dumps PGP packets.\n"
                "\tUsage: %s -i input.pgp [-d] [-h]\n",
            program_name);
}

int
main(int argc, char *const argv[])
{
    rnp_t     rnp = {0};
    rnp_ctx_t ctx = {0};

    struct opt_t {
        char *input_file;
        bool  dump_content;
    } opts = {0};

    /* -------------------------------------------------------------------------
        Parse command line options:
            -i input_file [mandatory]: specifies name of the file with PGP packets
            -d : indicates wether to dump whole packet content
            -h : prints help and exists
        -------------------------------------------------------------------------*/
    int opt = 0;
    while ((opt = getopt(argc, argv, "i:dh")) != -1) {
        switch (opt) {
        case 'i':
            opts.input_file = optarg;
            break;
        case 'd':
            opts.dump_content = true;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /*  -------------------------------------------------------------------------
        Input file is mandatory - ensure it was provided
        -------------------------------------------------------------------------*/
    if (!opts.input_file) {
        print_usage(argv[0]);
        return 1;
    }

    /*  -------------------------------------------------------------------------
        Initialize context and process packets
        -------------------------------------------------------------------------*/
    if (rnp_ctx_init(&ctx, &rnp) != RNP_SUCCESS) {
        fprintf(stderr, PFX "Initialization failed\n");
        return 1;
    }

    repgp_handle_t *handle = create_filepath_handle(opts.input_file);
    rnp_result      res = repgp_dump_packets(&ctx, handle, opts.dump_content);
    repgp_destroy_handle(handle);
    rnp_end(&rnp);

    /*  -------------------------------------------------------------------------
        Inform in case of error occured during parsing
        -------------------------------------------------------------------------*/
    if (res != RNP_SUCCESS) {
        fprintf(stderr, PFX "Operation failed [error code: 0x%X]\n", res);
        return 1;
    }

    return 0;
}