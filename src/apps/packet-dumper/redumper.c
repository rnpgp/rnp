#include <stdio.h>
#include <unistd.h>      /* getopt() */
#include <repgp/repgp.h> /* repgp API */
#include <rnp/rnp.h>     /* rnp_t, rnp_ctx_t et. all */
#include <libgen.h>      /* basename() */

#define PFX "redumper: "

void
print_usage(char *program_name)
{
    fprintf(stderr,
            PFX
            "Program dumps PGP packets. \n\nUsage:\n"
            "\t%s [-d|-h] [input.pgp]\n"
            "\t  -d : indicates whether to print packet content. Data is represented as hex\n"
            "\t  -h : prints help and exists\n",
            basename(program_name));
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
    while ((opt = getopt(argc, argv, "dh")) != -1) {
        if (opt == 'd') {
            opts.dump_content = true;
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    /*  -------------------------------------------------------------------------
        Input file is mandatory - ensure it was provided
        -------------------------------------------------------------------------*/
    if (optind < argc) {
        opts.input_file = argv[optind];
    }

    /*  -------------------------------------------------------------------------
        Initialize context and process packets
        -------------------------------------------------------------------------*/
    if (rnp_ctx_init(&ctx, &rnp) != RNP_SUCCESS) {
        fprintf(stderr, PFX "Initialization failed\n");
        return 1;
    }

    repgp_handle_t *handle =
      opts.input_file ? create_filepath_handle(opts.input_file) : create_stdin_handle();
    rnp_result_t res = repgp_list_packets(&ctx, handle, opts.dump_content);
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