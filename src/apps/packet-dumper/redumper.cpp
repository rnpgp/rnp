#include <stdio.h>
#include <unistd.h> /* getopt() */
#include <getopt.h>
#include <rnp/rnp.h>
#include <libgen.h> /* basename() */
#include "../../rnp/fficli.h"

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
            "\t  -j : JSON output\n"
            "\t  -h : prints help and exists\n",
            basename(program_name));
}

ssize_t
stdin_reader(void *app_ctx, void *buf, size_t len)
{
    return read(STDIN_FILENO, buf, len);
}

bool
stdout_writer(void *app_ctx, const void *buf, size_t len)
{
    ssize_t wlen = write(STDOUT_FILENO, buf, len);
    return (wlen >= 0) && (size_t) wlen == len;
}

int
main(int argc, char *const argv[])
{
    char *   input_file = NULL;
    uint32_t flags = 0;
    uint32_t jflags = 0;
    bool     json = false;

    /* Parse command line options:
        -i input_file [mandatory]: specifies name of the file with PGP packets
        -d : indicates wether to dump whole packet content
        -m : dump mpi contents
        -g : dump key grips and fingerprints
        -j : JSON output
        -h : prints help and exists
    */
    int opt = 0;
    while ((opt = getopt(argc, argv, "dmgjh")) != -1) {
        switch (opt) {
        case 'd':
            flags |= RNP_DUMP_RAW;
            jflags |= RNP_JSON_DUMP_RAW;
            break;
        case 'm':
            flags |= RNP_DUMP_MPI;
            jflags |= RNP_JSON_DUMP_MPI;
            break;
        case 'g':
            flags |= RNP_DUMP_GRIP;
            jflags |= RNP_JSON_DUMP_GRIP;
            break;
        case 'j':
            json = true;
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

    rnp_input_t  input = NULL;
    rnp_result_t ret = 0;
    if (input_file) {
        ret = rnp_input_from_path(&input, input_file);
    } else {
        ret = rnp_input_from_callback(&input, stdin_reader, NULL, NULL);
    }
    if (ret) {
        ERR_MSG("failed to open source: error 0x%x", (int) ret);
        return 1;
    }

    if (!json) {
        rnp_output_t output = NULL;
        ret = rnp_output_to_callback(&output, stdout_writer, NULL, NULL);
        if (ret) {
            ERR_MSG("failed to open stdout: error 0x%x", (int) ret);
            rnp_input_destroy(input);
            return 1;
        }
        ret = rnp_dump_packets_to_output(input, output, flags);
        rnp_output_destroy(output);
    } else {
        char *json = NULL;
        ret = rnp_dump_packets_to_json(input, jflags, &json);
        if (!ret) {
            fprintf(stdout, "%s\n", json);
        }
    }
    rnp_input_destroy(input);

    /* Inform in case of error occured during parsing */
    if (ret) {
        ERR_MSG(PFX "Operation failed [error code: 0x%X]\n", ret);
        return 1;
    }

    return 0;
}
