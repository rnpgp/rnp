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
#ifndef TRANSIT_H_
#define TRANSIT_H_	20140306

#include <sys/types.h>

#include <inttypes.h>

#define TRANSIT_NUMBER	0x01
#define TRANSIT_STRING	0x02
#define TRANSIT_LIST	0x03
#define TRANSIT_DICT	0x04
#define TRANSIT_END	0x05

/* basic structure for transit operations */
typedef struct transit_atom_t {
	void		*v;		/* pointer */
	uint64_t	 n;		/* numeric value */
	uint8_t		 type;		/* type of atom */
} transit_atom_t;

/* main transit structure, either encoding or decoding */
typedef struct transit_t {
	uint64_t	 c;		/* # of atoms/size of string */
	uint64_t	 size;		/* allocated size */
	uint8_t		*encoded;	/* encoded string */
	transit_atom_t	*atoms;		/* decoded atoms */
} transit_t;

#define TRANSIT_STRLEN		((uint64_t)0xffffffffffffffff)

#ifndef __BEGIN_DECLS
#  if defined(__cplusplus)
#  define __BEGIN_DECLS           extern "C" {
#  define __END_DECLS             }
#  else
#  define __BEGIN_DECLS
#  define __END_DECLS
#  endif
#endif

__BEGIN_DECLS

int transit_encode_number(transit_t */*trans*/, uint64_t /*n*/);
int transit_encode_string(transit_t */*trans*/, const char */*s*/, size_t /*len*/);
int transit_encode_special(transit_t */*trans*/, uint8_t /*type*/);

int transit_decode(transit_t */*trans*/, const char */*in*/, size_t /*insize*/);

/* JSON input and output */
int transit_read_json(transit_t */*t*/, const char */*json*/, size_t /*jsize*/);
int transit_format_json(transit_t */*t*/, char */*buf*/, size_t /*size*/);

transit_t *transit_new(void);
void transit_free(transit_t */*t*/);

/* accessor functions */
uint64_t transit_atom_size(transit_atom_t */*atom*/);
uint8_t transit_atom_type(transit_atom_t */*atom*/);
void *transit_atom_ptr(transit_atom_t */*atom*/);
transit_atom_t *transit_atom(transit_t */*trans*/, uint64_t /*a*/);
uint8_t *transit_encoded(transit_t */*trans*/);
uint64_t transit_size(transit_t */*trans*/);

/* list/dict accessor functions */
int transit_field_by_index(transit_t */*t*/, uint32_t /*dict*/, uint32_t /*field*/, transit_atom_t */*ret*/);
int transit_field_by_name(transit_t */*t*/, uint32_t /*dict*/, const char */*name*/, transit_atom_t */*ret*/);

__END_DECLS

#endif
