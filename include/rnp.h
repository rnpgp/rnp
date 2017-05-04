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
#ifndef RNP_H_
#define RNP_H_

#include <stddef.h>

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

/* structure used to hold (key,value) pair information */
typedef struct rnp_t {
	unsigned	  c;		/* # of elements used */
	unsigned	  size;		/* size of array */
	char		**name;		/* key names */
	char		**value;	/* value information */
	void		 *pubring;	/* public key ring */
	void		 *secring;	/* s3kr1t key ring */
	void		 *io;		/* the io struct for results/errs */
	void		 *passfp;	/* file pointer for password input */
} rnp_t;

/* begin and end */
int rnp_init(rnp_t *);
int rnp_end(rnp_t *);

/* debugging, reflection and information */
int rnp_set_debug(const char *);
int rnp_get_debug(const char *);
const char *rnp_get_info(const char *);
int rnp_list_packets(rnp_t *, char *, int, char *);

/* variables */
int rnp_setvar(rnp_t *, const char *, const char *);
char *rnp_getvar(rnp_t *, const char *);
int rnp_incvar(rnp_t *, const char *, const int);
int rnp_unsetvar(rnp_t *, const char *);

/* set home directory information */
int rnp_set_homedir(rnp_t *, char *, const int);

/* key management */
int rnp_list_keys(rnp_t *, const int);
int rnp_list_keys_json(rnp_t *, char **, const int);
int rnp_load_keys(rnp_t *);
int rnp_find_key(rnp_t *, char *);
char *rnp_get_key(rnp_t *, const char *, const char *);
char *rnp_export_key(rnp_t *, char *);
int rnp_import_key(rnp_t *, char *);
int rnp_generate_key(rnp_t *, char *, int);

/* file management */
int rnp_encrypt_file(rnp_t *, const char *, const char *, char *, int);
int rnp_decrypt_file(rnp_t *, const char *, char *, int);
int rnp_sign_file(rnp_t *, const char *, const char *, char *, int, int, int);
int rnp_verify_file(rnp_t *, const char *, const char *, int);

/* memory signing and encryption */
int rnp_sign_memory(rnp_t *, const char *, char *, size_t, char *, size_t, const unsigned, const unsigned);
int rnp_verify_memory(rnp_t *, const void *, const size_t, void *, size_t, const int);
int rnp_encrypt_memory(rnp_t *, const char *, void *, const size_t, char *, size_t, int);
int rnp_decrypt_memory(rnp_t *, const void *, const size_t, char *, size_t, const int);

/* match and hkp-related functions */
int rnp_match_keys_json(rnp_t *, char **, char *, const char *, const int);
int rnp_match_keys(rnp_t *, char *, const char *, void *, const int);
int rnp_match_pubkeys(rnp_t *, char *, void *);
int rnp_format_json(void *, const char *, const int);

int rnp_validate_sigs(rnp_t *);

/* save pgp key in ssh format */
int rnp_write_sshkey(rnp_t *, char *, const char *, char *, size_t);


__END_DECLS

#endif /* !RNP_H_ */
