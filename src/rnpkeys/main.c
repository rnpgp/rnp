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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
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

#include "rnp.h"
#include "crypto.h"
#include "../common/constants.h"
#include "rnpkeys.h"

extern struct option options[];
extern const char *  usage;

int
main(int argc, char **argv)
{
    rnp_t  rnp;
    prog_t p;
    int    optindex;
    int    ret;
    int    ch;
    int    i;

    memset(&p, '\0', sizeof(p));
    memset(&rnp, '\0', sizeof(rnp));

    p.numbits = DEFAULT_RSA_NUMBITS;

    if (argc < 2) {
        print_usage(usage);
        exit(EXIT_ERROR);
    }

    rnp_setvar(&rnp, "sshkeydir", "/etc/ssh");
    rnp_setvar(&rnp, "res", "<stdout>");
    rnp_setvar(&rnp, "format", "human");

    optindex = 0;

    while ((ch = getopt_long(argc, argv, "S:Vglo:s", options, &optindex)) != -1) {
        if (ch >= LIST_KEYS) {
            /* getopt_long returns 0 for long options */
            if (!setoption(&rnp, &p, options[optindex].val, optarg))
                fprintf(stderr, "Bad setoption result %d\n", ch);
        } else {
            switch (ch) {
            case 'S':
                rnp_setvar(&rnp, "key_store_format", "SSH");
                rnp_setvar(&rnp, "sshkeyfile", optarg);
                break;
            case 'V':
                print_praise();
                exit(EXIT_SUCCESS);
            case 'g':
                p.cmd = GENERATE_KEY;
                break;
            case 'l':
                p.cmd = LIST_KEYS;
                break;
            case 'o':
                if (!parse_option(&rnp, &p, optarg)) {
                    (void) fprintf(stderr, "Bad parse_option\n");
                }
                break;
            case 's':
                p.cmd = LIST_SIGS;
                break;
            default:
                p.cmd = HELP_CMD;
                break;
            }
        }
    }
    if (!rnp_init(&rnp)) {
        fputs("fatal: failed to initialize rnpkeys\n", stderr);
        return EXIT_ERROR;
    }

    if (!rnp_load_keys(&rnp)) {
        /* Keys mightn't loaded if this is a key generation step. */
        if (p.cmd != GENERATE_KEY) {
            fputs("fatal: failed to load keys\n", stderr);
            return EXIT_ERROR;
        }
    }

    /* now do the required action for each of the command line args */
    ret = EXIT_SUCCESS;
    if (optind == argc) {
        if (!rnp_cmd(&rnp, &p, NULL))
            ret = EXIT_FAILURE;
    } else {
        for (i = optind; i < argc; i++) {
            if (!rnp_cmd(&rnp, &p, argv[i]))
                ret = EXIT_FAILURE;
        }
    }
    rnp_end(&rnp);

    return ret;
}
