#include <stdio.h>
#include <unistd.h> /* getopt() */
#include <getopt.h>
#include <librepgp/stream-ctx.h>
#include <librepgp/stream-dump.h>
#include "utils.h"
#include "rnp.h"    /* rnp_ctx_t et. all */
#include <libgen.h> /* basename() */

#define PFX "redumper: "

static void
print_usage(char *program_name)
{
    fprintf(stderr,
            PFX
            "Program dumps PGP packets. \n\nUsage:\n"
            "\t%s [-d|-h] [input.pgp]\n"
            "\t  -d : indicates whether to print packet content. Data is represented as hex\n"
            "\t  -m : dump mpi values\n"
            "\t  -g : dump key fingerprints and grips\n"
            "\t  -h : prints help and exists\n",
            basename(program_name));
}

int
main(int argc, char *const argv[])
{
    pgp_source_t   src = {0};
    pgp_dest_t     dst = {0};
    rnp_result_t   res = RNP_ERROR_GENERIC;
    rnp_dump_ctx_t ctx = {0};
    char *         input_file = NULL;

    /* Parse command line options:
        -i input_file [mandatory]: specifies name of the file with PGP packets
        -d : indicates wether to dump whole packet content
        -m : dump mpi contents
        -g : dump key grips and fingerprints
        -h : prints help and exists
    */
    int opt = 0;
    while ((opt = getopt(argc, argv, "dmgh")) != -1) {
        switch (opt) {
        case 'd':
            ctx.dump_packets = true;
            break;
        case 'm':
            ctx.dump_mpi = true;
            break;
        case 'g':
            ctx.dump_grips = true;
            break;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /*  Check whether we have input file */
    if (optind < argc) {
        input_file = argv[optind];
    }

    res = input_file ? init_file_src(&src, input_file) : init_stdin_src(&src);
    if (res) {
        RNP_LOG("failed to open source: error 0x%x", (int) res);
        return 1;
    }
    res = init_stdout_dest(&dst);
    if (res) {
        RNP_LOG("failed to open stdout: error 0x%x", (int) res);
        src_close(&src);
        return 1;
    }

    res = stream_dump_packets(&ctx, &src, &dst);

    src_close(&src);
    dst_close(&dst, false);

    /* Inform in case of error occured during parsing */
    if (res != RNP_SUCCESS) {
        fprintf(stderr, PFX "Operation failed [error code: 0x%X]\n", res);
        return 1;
    }

    return 0;
}
