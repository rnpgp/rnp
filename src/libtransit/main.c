/*-
 * Copyright (c) 2014 Alistair Crooks <agc@NetBSD.org>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/types.h>
#include <sys/stat.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "transit.h"

#define PROGRAM_NAME	"transit"
#define PROGRAM_AUTHOR	"transit@agc.ac"
#define PROGRAM_VERSION	"20140223"

/* process all data in a stream */
static char *
dostream(FILE *fp, size_t *size)
{
	struct stat	 st;
	char		*s;

	fstat(fileno(fp), &st);
	*size = st.st_size;
	s = calloc(1, *size);
	fread(s, 1, *size, fp);
	return s;
}

/* open a file and process the stream */
static char *
dofile(const char *f, size_t *size)
{
	FILE		*fp;
	char		*s;

	if ((fp = fopen(f, "r")) == NULL) {
		fprintf(stderr, "can't open '%s'\n", f);
		return NULL;
	}
	s = dostream(fp, size);
	fclose(fp);
	return s;
}

/* recursive walk function */
static int
recwalk1(transit_t *t, unsigned *from, FILE *fp, unsigned indent, const char *term)
{
	transit_atom_t	*atom;
	unsigned	 i;

	atom = transit_atom(t, *from);
	for (i = 0 ; i < indent ; i++) {
		fputc('\t', fp);
	}
	switch(transit_atom_type(atom)) {
	case TRANSIT_NUMBER:
		fprintf(fp, "number\t%" PRIu64 "%s", transit_atom_size(atom), term);
		return *from += 1;
	case TRANSIT_STRING:
		fprintf(fp, "string\t");
		fwrite(transit_atom_ptr(atom), 1, transit_atom_size(atom), fp);
		fprintf(fp, "%s", term);
		return *from += 1;
	case TRANSIT_LIST:
		fprintf(fp, "list\n");
		for (*from += 1; *from < transit_size(t) && transit_atom_type(&t->atoms[*from]) != TRANSIT_END ; ) {
			recwalk1(t, from, fp, indent + 1, term);
		}
		return *from += 1;
	case TRANSIT_DICT:
		fprintf(fp, "dict\n");
		for (*from += 1; *from < transit_size(t) && transit_atom_type(&t->atoms[*from]) != TRANSIT_END ; ) {
			recwalk1(t, from, fp, indent + 1, "\t");
			recwalk1(t, from, fp, indent + 1, "\n");
		}
		return *from += 1;
	default:
		return t->c;
	}
}

/* print indent */
static inline void
doindent(FILE *fp, unsigned in)
{
	unsigned	i;

	for (i = 0 ; i < in ; i++) {
		fputc('\t', fp);
	}
}

/* array-based walk function */
static int
arrwalk1(transit_t *t, uint64_t a, FILE *fp, unsigned indent, const char *term)
{
	transit_atom_t	*atom;
	uint64_t	*v;
	unsigned	 i;

	atom = transit_atom(t, a);
	switch(transit_atom_type(atom)) {
	case TRANSIT_NUMBER:
		doindent(fp, indent);
		fprintf(fp, "number\t%" PRIu64 "%s", transit_atom_size(atom), term);
		return 1;
	case TRANSIT_STRING:
		doindent(fp, indent);
		fprintf(fp, "string\t");
		fwrite(transit_atom_ptr(atom), 1, transit_atom_size(atom), fp);
		fprintf(fp, "%s", term);
		return 1;
	case TRANSIT_LIST:
		doindent(fp, indent);
		fprintf(fp, "list\n");
		v = transit_atom_ptr(atom);
		for (i = 0 ; i < transit_atom_size(atom) ; i++) {
			arrwalk1(t, v[i], fp, indent + 1, term);
		}
		return 1;
	case TRANSIT_DICT:
		doindent(fp, indent);
		fprintf(fp, "dict\n");
		v = transit_atom_ptr(atom);
		for (i = 0 ; i < transit_atom_size(atom) - 1 ; i += 2) {
			arrwalk1(t, v[i], fp, indent + 1, "\t");
			arrwalk1(t, v[i + 1], fp, 1, term);
		}
		return 1;
	case TRANSIT_END:
		return 1;
	default:
		fprintf(stderr, "unrecognised atom: %d\n", transit_atom_type(atom));
		return t->c;
	}
}

/* walk function */
static int
walk(transit_t *t, FILE *fp, int recursive)
{
	unsigned	i;

	if (recursive) {
		for (i = 0 ; i < transit_size(t) ; ) {
			recwalk1(t, &i, fp, 0, "\n");
		}
	} else {
		arrwalk1(t, 0, fp, 0, "\n");
	}
	return 1;
}


int
main(int argc, char **argv)
{
	transit_t	 t;
	size_t		 size;
	char		*in;
	char		 buf[8192];
	int		 recursive;
	int		 decoding;
	int		 json;
	int		 cc;
	int		 i;

	memset(&t, 0x0, sizeof(t));
	decoding = 0;
	json = 0;
	recursive = 0;
	while ((i = getopt(argc, argv, "Vdjr")) != -1) {
		switch(i) {
		case 'V':
			printf("%s by %s, version %s\n",
				PROGRAM_NAME, PROGRAM_AUTHOR, PROGRAM_VERSION);
			exit(EXIT_SUCCESS);
		case 'd':
			decoding = 1;
			break;
		case 'j':
			json = 1;
			break;
		case 'r':
			recursive = 1;
			break;
		default:
			break;
		}
	}
	if (decoding) {
		in = NULL;
		if (optind == argc) {
			in = dostream(stdin, &size);
			cc = transit_decode(&t, in, size);
		} else {
			for (i = optind ; i < argc ; i++) {
				in = dofile(argv[i], &size);
				cc = transit_decode(&t, in, size);
			}
		}
		if (json) {
			cc = transit_format_json(&t, buf, sizeof(buf));
			fwrite(buf, 1, cc, stdout);
			printf("\n");
		} else {
			walk(&t, stdout, recursive);
		}
		free(in);
		transit_free(&t);
	} else {
		if (json) {
			for (i = optind ; i < argc ; i++) {
				transit_read_json(&t, argv[i], strlen(argv[i]));
			}
		} else {
			transit_encode_special(&t, TRANSIT_LIST);
			for (i = optind ; i < argc ; i++) {
				transit_encode_string(&t, argv[i], strlen(argv[i]));
			}
			transit_encode_special(&t, TRANSIT_END);
		}
		fwrite(transit_encoded(&t), 1, transit_size(&t), stdout);
		transit_free(&t);
	}
	exit(EXIT_SUCCESS);
}
