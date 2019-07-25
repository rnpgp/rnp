/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Command line program to perform rnp operations */
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "rnp/rnpcfg.h"
#include "rnpkeys.h"

extern struct option options[];
extern const char *  usage;

const char *rnp_keys_progname = NULL;

#ifndef RNP_RUN_TESTS
int
main(int argc, char **argv)
#else
int rnpkeys_main(int argc, char **argv);
int
rnpkeys_main(int argc, char **argv)
#endif
{
    cli_rnp_t rnp = {};
    rnp_cfg_t opt_cfg = {};
    rnp_cfg_t cfg = {};
    optdefs_t cmd = (optdefs_t) 0;
    int       optindex = 0;
    int       ret = EXIT_FAILURE;
    int       ch;

    rnp_keys_progname = argv[0];

    if (argc < 2) {
        print_usage(usage);
        return EXIT_FAILURE;
    }

    rnp_cfg_init(&opt_cfg);

    while ((ch = getopt_long(argc, argv, "Vglo:", options, &optindex)) != -1) {
        if (ch >= CMD_LIST_KEYS) {
            /* getopt_long returns 0 for long options */
            if (!setoption(&opt_cfg, &cmd, options[optindex].val, optarg)) {
                fprintf(stderr, "Bad setoption result %d\n", ch);
                goto end;
            }
        } else {
            switch (ch) {
            case 'V':
                print_praise();
                ret = EXIT_SUCCESS;
                goto end;
            case 'g':
                cmd = CMD_GENERATE_KEY;
                break;
            case 'l':
                cmd = CMD_LIST_KEYS;
                break;
            case 'o':
                if (!parse_option(&opt_cfg, &cmd, optarg)) {
                    (void) fprintf(stderr, "Bad parse_option\n");
                    goto end;
                }
                break;
            default:
                cmd = CMD_HELP;
                break;
            }
        }
    }

    if (!rnpkeys_init(&cfg, &rnp, &opt_cfg, true)) {
        ret = EXIT_FAILURE;
        goto end;
    }

    /* now do the required action for each of the command line args */
    ret = EXIT_SUCCESS;
    if (optind == argc) {
        if (!rnp_cmd(&cfg, &rnp, cmd, NULL)) {
            ret = EXIT_FAILURE;
        }
    } else {
        for (int i = optind; i < argc; i++) {
            if (!rnp_cmd(&cfg, &rnp, cmd, argv[i])) {
                ret = EXIT_FAILURE;
            }
        }
    }

end:
    rnp_cfg_free(&cfg);
    rnp_cfg_free(&opt_cfg);
    cli_rnp_end(&rnp);
    return ret;
}
