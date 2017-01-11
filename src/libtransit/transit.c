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
#include <sys/param.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "transit.h"

#define ATOM_ARRAY	'a'
#define ENCODED_ARRAY	'e'

/* make sure we can grow the array */
static inline int
grow_array(transit_t *trans, uint64_t needed, char ch)
{
	uint64_t	 newsize;
	void		*newv;

	if (trans->size < needed) {
		newsize = (((needed / 1024) + 1) * 1024);
		newv = (ch == ENCODED_ARRAY) ?
			realloc(trans->encoded, newsize) :
			realloc(trans->atoms, newsize * sizeof(*trans->atoms));
		if (newv == NULL) {
			fprintf(stderr, "transit: can't grow array\n");
			return 0;
		}
		trans->size = newsize;
		if (ch == ENCODED_ARRAY) {
			trans->encoded = newv;
		} else {
			trans->atoms = newv;
		}
	}
	return 1;
}

/* retrieve a natural number from input string. stop when char value is < 128 */
static int
decode_number(transit_t *trans, const char *in, size_t insize)
{
	const uint8_t	*u;
	transit_atom_t	*atom;
	unsigned	 pow;
	int		 cc;

	atom = &trans->atoms[trans->c++];
	memset(atom, 0x0, sizeof(*atom));
	atom->type = TRANSIT_NUMBER;
	pow = 0;
	u = (const uint8_t *)in;
	for (cc = 0 ; cc < (int)insize ; cc++) {
		atom->n += (u[cc] << pow);
		if (u[cc] < 0x80) {
			break;
		}
		pow += 7;
	}
	return cc + 1;
}

/* get a string from the input */
static int
decode_string(transit_t *trans, const char *in, size_t insize)
{
	transit_atom_t	*atom;
	int		cc;

	atom = &trans->atoms[trans->c];
	memset(atom, 0x0, sizeof(*atom));
	cc = decode_number(trans, in, insize);
	/* sanity check that someone isn't trying to hork us */
	if (atom->n > insize - cc) {
		fprintf(stderr, "transit: string size too large for input\n");
		return insize;
	}
	atom->type = TRANSIT_STRING;
	if ((atom->v = calloc(1, atom->n)) == NULL) {
		fprintf(stderr, "transit: string size -- out of memory\n");
		return insize;
	}
	memcpy(atom->v, &in[cc], atom->n);
	return cc + atom->n;
}

/* get a special type from the input */
static int
decode_special(transit_t *trans, uint8_t type)
{
	transit_atom_t	*atom;

	atom = &trans->atoms[trans->c++];
	memset(atom, 0x0, sizeof(*atom));
	switch(atom->type = type) {
	case TRANSIT_LIST:
	case TRANSIT_DICT:
	case TRANSIT_END:
		break;
	}
	return 0;
}

/* grow the array of children */
static inline int
grow_children(transit_atom_t *parent)
{
	uint64_t	*children;

	if (parent->n % 6 == 0) {
		if ((children = realloc(parent->v, (parent->n + 8) * sizeof(*children))) == NULL) {
			fprintf(stderr, "transit: can't allocate list/dict space\n");
			return 0;
		}
		parent->v = children;
	}
	return 1;
}

/* decode the input */
static int
decode_atoms(transit_t *trans, const char *in, size_t insize, transit_atom_t *parent)
{
	uint64_t	*children;
	uint8_t		 type;
	size_t		 cc;

	children = NULL;
	if (parent) {
		parent->n = 0;
	}
	for (cc = 0 ; cc < insize ; ) {
		if (!grow_array(trans, trans->c + 10, ATOM_ARRAY)) {
			return insize;
		}
		if (parent) {
			if (!grow_children(parent)) {
				return insize;
			}
			children = parent->v;
			children[parent->n++] = trans->c;
		}
		switch(type = in[cc++]) {
		case TRANSIT_NUMBER:
			cc += decode_number(trans, &in[cc], insize - cc);
			break;
		case TRANSIT_STRING:
			cc += decode_string(trans, &in[cc], insize - cc);
			break;
		case TRANSIT_LIST:
		case TRANSIT_DICT:
			cc += decode_special(trans, type);
			cc += decode_atoms(trans, &in[cc], insize - cc, &trans->atoms[trans->c - 1]);
			break;
		case TRANSIT_END:
			return cc + decode_special(trans, type);
		default:
			fprintf(stderr, "transit: unrecognised type %d at %zu\n", type, cc - 1);
			return insize;
		}
	}
	return cc;
}

/* output JSON */
static int
format_json(transit_t *t, uint64_t a, char *buf, size_t size)
{
	transit_atom_t	*atom;
	uint64_t	*v;
	unsigned	 i;
	size_t		 n;
	int		 cc;

	atom = transit_atom(t, a);
	cc = 0;
	switch(atom->type) {
	case TRANSIT_NUMBER:
		return snprintf(buf, size, "%" PRIu64, atom->n);
	case TRANSIT_STRING:
		buf[cc++] = '"';
		n = MIN(atom->n, size - 1 - 1);
		memcpy(&buf[cc], atom->v, n);
		cc += n;
		buf[cc++] = '"';
		return cc;
	case TRANSIT_LIST:
		buf[cc++] = '[';
		v = atom->v;
		for (i = 0 ; i < atom->n ; i++) {
			cc += format_json(t, v[i], &buf[cc], size - cc);
			if (i < atom->n - 2) {
				buf[cc++] = ',';
			}
		}
		buf[cc++] = ']';
		return cc;
	case TRANSIT_DICT:
		buf[cc++] = '{';
		v = atom->v;
		for (i = 0 ; i < atom->n - 1 ; i += 2) {
			cc += format_json(t, v[i], &buf[cc], size - cc);
			buf[cc++] = ':';
			cc += format_json(t, v[i + 1], &buf[cc], size - cc);
			if (i < atom->n - 3) {
				buf[cc++] = ',';
			}
		}
		buf[cc++] = '}';
		return cc;
	case TRANSIT_END:
		return 0;
	default:
		fprintf(stderr, "unrecognised atom: %d\n", transit_atom_type(atom));
		return 0;
	}
}

/*******************************************/

/* encode a number */
int
transit_encode_number(transit_t *trans, uint64_t n)
{
	uint64_t	num;
	uint64_t	r;

	if (trans) {
		if (!grow_array(trans, trans->c + 32, ENCODED_ARRAY)) {
			return 0;
		}
		trans->encoded[trans->c++] = TRANSIT_NUMBER;
		for (num = n; num >= 0x80 ; trans->c++) {
			r = (num - 0x80) >> 7;
			trans->encoded[trans->c] = num - (r << 7);
			num = r;
		}
		trans->encoded[trans->c++] = num;
		return 1;
	}
	return 0;
}

/* encode a string into serialised output */
int
transit_encode_string(transit_t *trans, const char *s, size_t len)
{
	uint64_t	pos;

	if (trans && s) {
		if (len == TRANSIT_STRLEN) {
			len = strlen(s);
		}
		if (!grow_array(trans, trans->c + len + 20, ENCODED_ARRAY)) {
			return 0;
		}
		pos = trans->c;
		transit_encode_number(trans, len);
		trans->encoded[pos] = TRANSIT_STRING;
		memcpy(&trans->encoded[trans->c], s, len);
		trans->c += len;
		return 1;
	}
	return 0;
}

/* encode a special type - list, dict or end */
int
transit_encode_special(transit_t *trans, uint8_t type)
{
	if (trans) {
		if (!grow_array(trans, trans->c + 10, ENCODED_ARRAY)) {
			return 0;
		}
		switch(type) {
		case TRANSIT_LIST:
		case TRANSIT_DICT:
		case TRANSIT_END:
			trans->encoded[trans->c++] = type;
			return 1;
		default:
			return 0;
		}
	}
	return 0;
}

/* decode the input */
int
transit_decode(transit_t *trans, const char *in, size_t insize)
{
	if (trans && in) {
		return decode_atoms(trans, in, insize, NULL);
	}
	return 0;
}

/* convert from json to transit */
int
transit_read_json(transit_t *t, const char *json, size_t jsize)
{
	uint64_t	 num;
	size_t		 i;
	char		*cp;

	if (t && json) {
		switch(json[0]) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			num = strtoull(json, &cp, 0);
			transit_encode_number(t, num);
			return (int)(cp - json);
		case '"':
			for (i = 1, cp = __UNCONST(&json[i]) ; json[i] != '"' ; i++) {
				if (json[i] == '\\') {
					i += 1;
				}
			}
			transit_encode_string(t, &json[1], (size_t)(&json[i] - cp));
			return i + 1;
		case '[':
			transit_encode_special(t, TRANSIT_LIST);
			for (i = 1 ; i < jsize && json[i] != ']' ; ) {
				i += transit_read_json(t, &json[i], jsize - i);
				if (json[i] == ',') {
					i += 1;
				}
			}
			transit_encode_special(t, TRANSIT_END);
			if (json[i] == ']') {
				i += 1;
			}
			return i;
		case '{':
			transit_encode_special(t, TRANSIT_DICT);
			for (i = 1 ; json[i] != '}' && i < jsize ; ) {
				i += transit_read_json(t, &json[i], jsize - i);
				if (json[i] == ':') {
					i += 1;
				} else {
					i = jsize;
					break;
				}
				i += transit_read_json(t, &json[i], jsize - i);
				if (json[i] == ',') {
					i += 1;
				}
			}
			transit_encode_special(t, TRANSIT_END);
			if (json[i] == '}') {
				i += 1;
			}
			return i;
		default:
			if (strncasecmp(json, "null", 4) == 0) {
				transit_encode_number(t, 0);
				return 4;
			}
			if (strncasecmp(json, "false", 5) == 0) {
				transit_encode_number(t, 0);
				return 5;
			}
			if (strncasecmp(json, "true", 4) == 0) {
				transit_encode_number(t, 1);
				return 4;
			}
			fprintf(stderr, "transit: bad json char %c\n", json[0]);
			break;
		}
	}
	return (int)jsize;
}

/* format as JSON */
int
transit_format_json(transit_t *t, char *buf, size_t size)
{
	if (t && buf) {
		return format_json(t, 0, buf, size);
	}
	return 0;
}

/* create a new structure */
transit_t *
transit_new(void)
{
	return calloc(1, sizeof(transit_t));
}

/* free resources allocated */
void
transit_free(transit_t *t)
{
	unsigned	i;

	if (t) {
		if (t->encoded) {
			free(t->encoded);
		} else {
			for (i = 0 ; i < t->c ; i++) {
				switch(t->atoms[i].type) {
				case TRANSIT_STRING:
				case TRANSIT_LIST:
				case TRANSIT_DICT:
					free(t->atoms[i].v);
					t->atoms[i].v = NULL;
					break;
				}
			}
			free(t->atoms);
			t->atoms = NULL;
		}
	}
}

/*****************************************************/

/* accessor functions */

/* return the 'n' value in the atom */
uint64_t
transit_atom_size(transit_atom_t *atom)
{
	return (atom) ? atom->n : 0;
}

/* return the 'type' value in the atom */
uint8_t
transit_atom_type(transit_atom_t *atom)
{
	return (atom) ? atom->type : 0;
}

/* return the 'v' value in the atom */
void *
transit_atom_ptr(transit_atom_t *atom)
{
	return (atom) ? atom->v : 0;
}

/* return a pointer to the decoded atom */
transit_atom_t *
transit_atom(transit_t *trans, uint64_t a)
{
	return (trans && a < trans->c) ? &trans->atoms[a] : NULL;
}

/* return the encoded text */
uint8_t *
transit_encoded(transit_t *trans)
{
	return (trans) ? trans->encoded : NULL;
}

/* return the # of atoms */
uint64_t
transit_size(transit_t *trans)
{
	return (trans) ? trans->c : 0;
}

/*****************************************************/

/* dictionary/list accessors */

/* return the contents of the list/dict field, accessed by number */
int
transit_field_by_index(transit_t *t, uint32_t dict, uint32_t field, transit_atom_t *ret)
{
	transit_atom_t	*atom;
	transit_atom_t	*el;
	uint64_t	*indices;

	atom = transit_atom(t, dict);
	indices = transit_atom_ptr(atom);
	el = transit_atom(t, indices[field]);
	memcpy(ret, el, sizeof(*ret));
	return 1;
}

/* return the contents of the dict value, accessed by name */
int
transit_field_by_name(transit_t *t, uint32_t dict, const char *name, transit_atom_t *ret)
{
	transit_atom_t	*atom;
	transit_atom_t	*el;
	uint64_t	*indices;
	uint64_t	 i;

	atom = transit_atom(t, dict);
	indices = transit_atom_ptr(atom);
	for (i = 2 ; i < transit_atom_size(atom) ; i += 2) {
		el = transit_atom(t, indices[i]);
		if (el->type == TRANSIT_STRING && memcmp(name, el->v, el->n) == 0) {
			el = transit_atom(t, indices[i + 1]);
			memcpy(ret, el, sizeof(*ret));
			return 1;
		}
	}
	return 0;
}

