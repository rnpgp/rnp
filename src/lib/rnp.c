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
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: rnp.c,v 1.98 2016/06/28 16:34:40 christos Exp $");
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mman.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include <rnp.h>

#include "packet.h"
#include "packet-parse.h"
#include "keyring.h"
#include "errors.h"
#include "packet-show.h"
#include "create.h"
#include "rnpsdk.h"
#include "memory.h"
#include "validate.h"
#include "readerwriter.h"
#include "rnpdefs.h"
#include "crypto.h"
#include "bn.h"
#include "ssh2pgp.h"
#include "defs.h"
#include "../common/constants.h"

/* read any gpg config file */
static int
conffile(rnp_t *rnp, char *homedir, char *userid, size_t length)
{
	regmatch_t	 matchv[10];
	regex_t		 keyre;
	char		 buf[BUFSIZ];
	FILE		*fp;

	__PGP_USED(rnp);
	(void) snprintf(buf, sizeof(buf), "%s/gpg.conf", homedir);
	if ((fp = fopen(buf, "r")) == NULL) {
		return 0;
	}
	(void) memset(&keyre, 0x0, sizeof(keyre));
	(void) regcomp(&keyre, "^[ \t]*default-key[ \t]+([0-9a-zA-F]+)",
		REG_EXTENDED);
	while (fgets(buf, (int)sizeof(buf), fp) != NULL) {
		if (regexec(&keyre, buf, 10, matchv, 0) == 0) {
			(void) memcpy(userid, &buf[(int)matchv[1].rm_so],
				MIN((unsigned)(matchv[1].rm_eo -
						matchv[1].rm_so), length));
			if (rnp->passfp == NULL) {
				(void) fprintf(stderr,
				"rnp: default key set to \"%.*s\"\n",
				(int)(matchv[1].rm_eo - matchv[1].rm_so),
				&buf[(int)matchv[1].rm_so]);
			}
		}
	}
	(void) fclose(fp);
	regfree(&keyre);
	return 1;
}

/* small function to pretty print an 8-character raw userid */
static char    *
userid_to_id(const uint8_t *userid, char *id)
{
	static const char *hexes = "0123456789abcdef";
	int		   i;

	for (i = 0; i < 8 ; i++) {
		id[i * 2] = hexes[(unsigned)(userid[i] & 0xf0) >> 4];
		id[(i * 2) + 1] = hexes[userid[i] & 0xf];
	}
	id[8 * 2] = 0x0;
	return id;
}

/* print out the successful signature information */
static void
resultp(pgp_io_t *io,
	const char *f,
	pgp_validation_t *res,
	pgp_keyring_t *ring)
{
	const pgp_key_t	*key;
	pgp_pubkey_t		*sigkey;
	unsigned		 from;
	unsigned		 i;
	time_t			 t;
	char			 id[MAX_ID_LENGTH + 1];

	for (i = 0; i < res->validc; i++) {
		(void) fprintf(io->res,
			"Good signature for %s made %s",
			(f) ? f : "<stdin>",
			ctime(&res->valid_sigs[i].birthtime));
		if (res->duration > 0) {
			t = res->birthtime + res->duration;
			(void) fprintf(io->res, "Valid until %s", ctime(&t));
		}
		(void) fprintf(io->res,
			"using %s key %s\n",
			pgp_show_pka(res->valid_sigs[i].key_alg),
			userid_to_id(res->valid_sigs[i].signer_id, id));
		from = 0;
		key = pgp_getkeybyid(io, ring,
			(const uint8_t *) res->valid_sigs[i].signer_id,
			&from, &sigkey);
		if (sigkey == &key->enckey) {
			(void) fprintf(io->res,
				"WARNING: signature for %s made with encryption key\n",
				(f) ? f : "<stdin>");
		}
		pgp_print_keydata(io, ring, key, "signature ", &key->key.pubkey, 0);
	}
}

/* check there's enough space in the arrays */
static int
size_arrays(rnp_t *rnp, unsigned needed)
{
	char	**temp;

	if (rnp->size == 0) {
		/* only get here first time around */
		rnp->size = needed;
		if ((rnp->name = calloc(sizeof(char *), needed)) == NULL) {
			(void) fprintf(stderr, "size_arrays: bad alloc\n");
			return 0;
		}
		if ((rnp->value = calloc(sizeof(char *), needed)) == NULL) {
			free(rnp->name);
			(void) fprintf(stderr, "size_arrays: bad alloc\n");
			return 0;
		}
	} else if (rnp->c == rnp->size) {
		/* only uses 'needed' when filled array */
		rnp->size += needed;
		temp = realloc(rnp->name, sizeof(char *) * needed);
		if (temp == NULL) {
			(void) fprintf(stderr, "size_arrays: bad alloc\n");
			return 0;
		}
		rnp->name = temp;
		temp = realloc(rnp->value, sizeof(char *) * needed);
		if (temp == NULL) {
			(void) fprintf(stderr, "size_arrays: bad alloc\n");
			return 0;
		}
		rnp->value = temp;
	}
	return 1;
}

/* TODO: Make these const; currently their consumers don't preserve const. */

static int
use_ssh_keys(rnp_t *rnp)
{
    return rnp->keyring_format == SSH_KEYRING;
}

/* Get the home directory when resolving gnupg key directory. */
static char *
get_homedir_gnupg(rnp_t *rnp)
{
	char *homedir;

	homedir = rnp_getvar(rnp, "homedir_gpg");
	if (homedir == NULL)
		homedir = rnp_getvar(rnp, "homedir");
	return homedir;
}

/* Get the home directory when resolving ssh key directory. */
static char *
get_homedir_ssh(rnp_t *rnp)
{
	char *homedir;

	homedir = rnp_getvar(rnp, "homedir_ssh");
	if (homedir == NULL)
		homedir = rnp_getvar(rnp, "homedir");
	return homedir;
}

static int
keydir_common(rnp_t *rnp, char *buffer, char *homedir, char *subdir,
		size_t buffer_size)
{
	/* TODO: Check that the path is valid and communicate that error. */

	if (snprintf(buffer, buffer_size, "%s/%s", homedir, subdir)
			> buffer_size) {
		errno = ENOBUFS;
		return -1;
	} else
		return  0;
}

/* Get the key directory for gnupg keys. */
static int
keydir_gnupg(rnp_t *rnp, char *buffer, size_t buffer_size)
{
	return keydir_common(rnp, buffer, get_homedir_gnupg(rnp),
			rnp_getvar(rnp, "subdir_gpg"), buffer_size);
}

/* Get the key directory for ssh keys. */
static int
keydir_ssh(rnp_t *rnp, char *buffer, size_t buffer_size)
{
	return keydir_common(rnp, buffer, get_homedir_ssh(rnp),
			rnp_getvar(rnp, "subdir_ssh"), buffer_size);
}

/* Get the key directory of the current type of key. */
static int
keydir(rnp_t *rnp, char *buffer, size_t buffer_size)
{
	return use_ssh_keys(rnp) ?
			keydir_ssh(rnp, buffer, buffer_size) :
			keydir_gnupg(rnp, buffer, buffer_size);
}

/* find the name in the array */
static int
findvar(rnp_t *rnp, const char *name)
{
	unsigned i;

	for (i = 0 ; i < rnp->c && strcmp(rnp->name[i], name) != 0; i++);
	return (i == rnp->c) ? -1 : (int)i;
}

/* read a keyring and return it */
static void *
readkeyring(rnp_t *rnp, const char *name)
{
	pgp_keyring_t	*keyring;
	const unsigned	 noarmor = 0;
	char		 f[MAXPATHLEN];
	char		*filename;
	char		 homedir[MAXPATHLEN];

	keydir(rnp, homedir, sizeof(homedir));
	if ((filename = rnp_getvar(rnp, name)) == NULL) {
		snprintf(f, sizeof(f), "%s/%s.gpg", homedir, name);
		filename = f;
	}
	if ((keyring = calloc(1, sizeof(*keyring))) == NULL) {
		fprintf(stderr, "readkeyring: bad alloc\n");
		return NULL;
	}
	if (!pgp_keyring_fileread(keyring, noarmor, filename)) {
		free(keyring);
		fprintf(stderr, "cannot read %s %s\n", name, filename);
		return NULL;
	}
	rnp_setvar(rnp, name, filename);
	return keyring;
}

/* read keys from ssh key files */
static int
readsshkeys(rnp_t *rnp, char *homedir, const char *needseckey)
{
	pgp_keyring_t	*pubring;
	pgp_keyring_t	*secring;
	struct stat	 st;
	unsigned	 hashtype;
	char		*hash;
	char		 f[MAXPATHLEN];
	char		*filename;

	if ((filename = rnp_getvar(rnp, "sshkeyfile")) == NULL) {
		/* set reasonable default for RSA key */
		(void) snprintf(f, sizeof(f), "%s/id_rsa.pub", homedir);
		filename = f;
	} else if (strcmp(&filename[strlen(filename) - 4], ".pub") != 0) {
		/* got ssh keys, check for pub file name */
		(void) snprintf(f, sizeof(f), "%s.pub", filename);
		filename = f;
	}
	/* check the pub file exists */
	if (stat(filename, &st) != 0) {
		(void) fprintf(stderr, "readsshkeys: bad pubkey filename '%s'\n", filename);
		return 0;
	}
	if ((pubring = calloc(1, sizeof(*pubring))) == NULL) {
		(void) fprintf(stderr, "readsshkeys: bad alloc\n");
		return 0;
	}
	/* openssh2 keys use md5 by default */
	hashtype = PGP_HASH_MD5;
	if ((hash = rnp_getvar(rnp, "hash")) != NULL) {
		/* openssh 2 hasn't really caught up to anything else yet */
		if (rnp_strcasecmp(hash, "md5") == 0) {
			hashtype = PGP_HASH_MD5;
		} else if (rnp_strcasecmp(hash, "sha1") == 0) {
			hashtype = PGP_HASH_SHA1;
		} else if (rnp_strcasecmp(hash, "sha256") == 0) {
			hashtype = PGP_HASH_SHA256;
		}
	}
	if (!pgp_ssh2_readkeys(rnp->io, pubring, NULL, filename, NULL, hashtype)) {
		free(pubring);
		(void) fprintf(stderr, "readsshkeys: cannot read %s\n",
				filename);
		return 0;
	}
	if (rnp->pubring == NULL) {
		rnp->pubring = pubring;
	} else {
		pgp_append_keyring(rnp->pubring, pubring);
	}
	if (needseckey) {
		rnp_setvar(rnp, "sshpubfile", filename);
		/* try to take the ".pub" off the end */
		if (filename == f) {
			f[strlen(f) - 4] = 0x0;
		} else {
			(void) snprintf(f, sizeof(f), "%.*s",
					(int)strlen(filename) - 4, filename);
			filename = f;
		}
		if ((secring = calloc(1, sizeof(*secring))) == NULL) {
			free(pubring);
			(void) fprintf(stderr, "readsshkeys: bad alloc\n");
			return 0;
		}
		if (!pgp_ssh2_readkeys(rnp->io, pubring, secring, NULL, filename, hashtype)) {
			free(pubring);
			free(secring);
			(void) fprintf(stderr, "readsshkeys: cannot read sec %s\n", filename);
			return 0;
		}
		rnp->secring = secring;
		rnp_setvar(rnp, "sshsecfile", filename);
	}
	return 1;
}

/* Format a PGP key to a readable hexadecimal string in a user supplied
 * buffer.
 *
 * buffer: the buffer to write into
 * sigid:  the PGP key ID to format
 * len:    the length of buffer, including the null terminator
 *
 * TODO: There is no error checking here.
 * TODO: Make this function more general or use an existing one.
 */

static void
format_key(char *buffer, uint8_t *sigid, int len)
{
	unsigned int i;
	unsigned int n;

	/* Chunks of two bytes are processed at a time because we can
	 * always be reasonably sure that PGP_KEY_ID_SIZE will be
	 * divisible by two. However, if the RFCs specify a fixed
	 * fixed size for PGP key IDs it might be more constructive
	 * to format this in one call and do a compile-time size
	 * check of the constant. If somebody wanted to do
	 * something exotic they can easily re-implement
	 * this function.
	 */
	for (i = 0, n = 0; i < PGP_KEY_ID_SIZE; i += 2) {
		n += snprintf(&buffer[n], len - n, "%02x%02x",
				sigid[i], sigid[i + 1]);
	}
	buffer[n] = 0x0;
}

/* Get the uid of the first key in the keyring.
 *
 * TODO: Set errno on failure.
 * TODO: Check upstream calls to this function - they likely won't
 *       handle the new error condition.
 */
static int
get_first_ring(pgp_keyring_t *ring, char *id, size_t len, int last)
{
	uint8_t	*src;

	/* The NULL test on the ring may not be necessary for non-debug
	 * builds - it would be much better that a NULL ring never
	 * arrived here in the first place.
	 *
	 * The ring length check is a temporary fix for a case where
	 * an empty ring arrives and causes an access violation in
	 * some circumstances.
	 */

	errno = 0;

	if (ring == NULL || ring->keyc < 1) {
		errno = EINVAL;
		return 0;
	}

	memset(id, 0x0, len);

	src = (uint8_t *) &ring->keys[(last) ? ring->keyc - 1 : 0].sigid;
	format_key(id, src, len);

	return 1;
}

/* find the time - in a specific %Y-%m-%d format - using a regexp */
static int
grabdate(char *s, int64_t *t)
{
	static regex_t	r;
	static int	compiled;
	regmatch_t	matches[10];
	struct tm	tm;

	if (!compiled) {
		compiled = 1;
		(void) regcomp(&r, "([0-9][0-9][0-9][0-9])[-/]([0-9][0-9])[-/]([0-9][0-9])", REG_EXTENDED);
	}
	if (regexec(&r, s, 10, matches, 0) == 0) {
		(void) memset(&tm, 0x0, sizeof(tm));
		tm.tm_year = (int)strtol(&s[(int)matches[1].rm_so], NULL, 10);
		tm.tm_mon = (int)strtol(&s[(int)matches[2].rm_so], NULL, 10) - 1;
		tm.tm_mday = (int)strtol(&s[(int)matches[3].rm_so], NULL, 10);
		*t = mktime(&tm);
		return 1;
	}
	return 0;
}

/* get expiration in seconds */
static uint64_t
get_duration(char *s)
{
	uint64_t	 now;
	int64_t	 	 t;
	char		*mult;

	if (s == NULL) {
		return 0;
	}
	now = (uint64_t)strtoull(s, NULL, 10);
	if ((mult = strchr("hdwmy", s[strlen(s) - 1])) != NULL) {
		switch(*mult) {
		case 'h':
			return now * 60 * 60;
		case 'd':
			return now * 60 * 60 * 24;
		case 'w':
			return now * 60 * 60 * 24 * 7;
		case 'm':
			return now * 60 * 60 * 24 * 31;
		case 'y':
			return now * 60 * 60 * 24 * 365;
		}
	}
	if (grabdate(s, &t)) {
		return t;
	}
	return (uint64_t)strtoll(s, NULL, 10);
}

/* get birthtime in seconds */
static int64_t
get_birthtime(char *s)
{
	int64_t	t;

	if (s == NULL) {
		return time(NULL);
	}
	if (grabdate(s, &t)) {
		return t;
	}
	return (uint64_t)strtoll(s, NULL, 10);
}

/* resolve the userid */
static const pgp_key_t *
resolve_userid(rnp_t *rnp, const pgp_keyring_t *keyring, const char *userid)
{
	const pgp_key_t	*key;
	pgp_io_t		*io;

	if (userid == NULL) {
		userid = rnp_getvar(rnp, "userid");
		if (userid == NULL)
			return NULL;
	} else if (userid[0] == '0' && userid[1] == 'x') {
		userid += 2;
	}
	io = rnp->io;
	if ((key = pgp_getkeybyname(io, keyring, userid)) == NULL) {
		(void) fprintf(io->errs, "cannot find key '%s'\n", userid);
	}
	return key;
}

/* append a key to a keyring */
static int
appendkey(pgp_io_t *io, pgp_key_t *key, char *ringfile)
{
	pgp_output_t	*create;
	const unsigned	 noarmor = 0;
	int		 fd;

	if ((fd = pgp_setup_file_append(&create, ringfile)) < 0) {
		fd = pgp_setup_file_write(&create, ringfile, 0);
	}
	if (fd < 0) {
		(void) fprintf(io->errs, "cannot open pubring '%s'\n", ringfile);
		return 0;
	}
	if (!pgp_write_xfer_pubkey(create, key, NULL, noarmor)) {
		(void) fprintf(io->errs, "cannot write pubkey\n");
		return 0;
	}
	pgp_teardown_file_write(create, fd);
	return 1;
}

/* return 1 if the file contains ascii-armoured text */
static unsigned
isarmoured(pgp_io_t *io, const char *f, const void *memory, const char *text)
{
	regmatch_t	 matches[10];
	unsigned	 armoured;
	regex_t		 r;
	FILE		*fp;
	char	 	 buf[BUFSIZ];

	armoured = 0;
	(void) regcomp(&r, text, REG_EXTENDED);
	if (f) {
		if ((fp = fopen(f, "r")) == NULL) {
			(void) fprintf(io->errs, "isarmoured: cannot open '%s'\n", f);
			regfree(&r);
			return 0;
		}
		if (fgets(buf, (int)sizeof(buf), fp) != NULL) {
			if (regexec(&r, buf, 10, matches, 0) == 0) {
				armoured = 1;
			}
		}
		(void) fclose(fp);
	} else {
		if (memory && regexec(&r, memory, 10, matches, 0) == 0) {
			armoured = 1;
		}
	}
	regfree(&r);
	return armoured;
}

/* vararg print function */
static void
p(FILE *fp, const char *s, ...)
{
	va_list	args;

	va_start(args, s);
	while (s != NULL) {
		(void) fprintf(fp, "%s", s);
		s = va_arg(args, char *);
	}
	va_end(args);
}

/* print a JSON object to the FILE stream */
static void
pobj(FILE *fp, mj_t *obj, int depth)
{
	unsigned	 i;
	char		*s;

	if (obj == NULL) {
		(void) fprintf(stderr, "No object found\n");
		return;
	}
	for (i = 0 ; i < (unsigned)depth ; i++) {
		p(fp, " ", NULL);
	}
	switch(obj->type) {
	case MJ_NULL:
	case MJ_FALSE:
	case MJ_TRUE:
		p(fp, (obj->type == MJ_NULL) ? "null" : (obj->type == MJ_FALSE) ? "false" : "true", NULL);
		break;
	case MJ_NUMBER:
		p(fp, obj->value.s, NULL);
		break;
	case MJ_STRING:
		if ((i = mj_asprint(&s, obj, MJ_HUMAN)) > 2) {
			(void) fprintf(fp, "%.*s", (int)i - 2, &s[1]);
			free(s);
		}
		break;
	case MJ_ARRAY:
		for (i = 0 ; i < obj->c ; i++) {
			pobj(fp, &obj->value.v[i], depth + 1);
			if (i < obj->c - 1) {
				(void) fprintf(fp, ", "); 
			}
		}
		(void) fprintf(fp, "\n"); 
		break;
	case MJ_OBJECT:
		for (i = 0 ; i < obj->c ; i += 2) {
			pobj(fp, &obj->value.v[i], depth + 1);
			p(fp, ": ", NULL); 
			pobj(fp, &obj->value.v[i + 1], 0);
			if (i < obj->c - 1) {
				p(fp, ", ", NULL); 
			}
		}
		p(fp, "\n", NULL); 
		break;
	default:
		break;
	}
}

/* return the time as a string */
static char * 
ptimestr(char *dest, size_t size, time_t t)
{
	struct tm      *tm;

	tm = gmtime(&t);
	(void) snprintf(dest, size, "%04d-%02d-%02d",
		tm->tm_year + 1900,
		tm->tm_mon + 1,
		tm->tm_mday);
	return dest;
}

/* format a JSON object */
static void
format_json_key(FILE *fp, mj_t *obj, const int psigs)
{
	int64_t	 birthtime;
	int64_t	 duration;
	time_t	 now;
	char	 tbuf[32];
	char	*s;
	mj_t	*sub;
	int	 i;

	if (pgp_get_debug_level(__FILE__)) {
		mj_asprint(&s, obj, MJ_HUMAN);
		(void) fprintf(stderr, "formatobj: json is '%s'\n", s);
		free(s);
	}
	if (obj->c == 2 && obj->value.v[1].type == MJ_STRING &&
	    strcmp(obj->value.v[1].value.s, "[REVOKED]") == 0) {
		/* whole key has been rovoked - just return */
		return;
	}
	pobj(fp, &obj->value.v[mj_object_find(obj, "header", 0, 2) + 1], 0);
	p(fp, " ", NULL);
	pobj(fp, &obj->value.v[mj_object_find(obj, "key bits", 0, 2) + 1], 0);
	p(fp, "/", NULL);
	pobj(fp, &obj->value.v[mj_object_find(obj, "pka", 0, 2) + 1], 0);
	p(fp, " ", NULL);
	pobj(fp, &obj->value.v[mj_object_find(obj, "key id", 0, 2) + 1], 0);
	birthtime = (int64_t)strtoll(obj->value.v[mj_object_find(obj, "birthtime", 0, 2) + 1].value.s, NULL, 10);
	p(fp, " ", ptimestr(tbuf, sizeof(tbuf), birthtime), NULL);
	duration = (int64_t)strtoll(obj->value.v[mj_object_find(obj, "duration", 0, 2) + 1].value.s, NULL, 10);
	if (duration > 0) {
		now = time(NULL);
		p(fp, " ", (birthtime + duration < now) ? "[EXPIRED " : "[EXPIRES ",
			ptimestr(tbuf, sizeof(tbuf), birthtime + duration), "]", NULL);
	}
	p(fp, "\n", "Key fingerprint: ", NULL);
	pobj(fp, &obj->value.v[mj_object_find(obj, "fingerprint", 0, 2) + 1], 0);
	p(fp, "\n", NULL);
	/* go to field after \"duration\" */
	for (i = mj_object_find(obj, "duration", 0, 2) + 2; i < mj_arraycount(obj) ; i += 2) {
		if (strcmp(obj->value.v[i].value.s, "uid") == 0) {
			sub = &obj->value.v[i + 1];
			p(fp, "uid", NULL);
			pobj(fp, &sub->value.v[0], (psigs) ? 4 : 14); /* human name */
			pobj(fp, &sub->value.v[1], 1); /* any revocation */
			p(fp, "\n", NULL);
		} else if (strcmp(obj->value.v[i].value.s, "encryption") == 0) {
			sub = &obj->value.v[i + 1];
			p(fp, "encryption", NULL);
			pobj(fp, &sub->value.v[0], 1);	/* size */
			p(fp, "/", NULL);
			pobj(fp, &sub->value.v[1], 0); /* alg */
			p(fp, " ", NULL);
			pobj(fp, &sub->value.v[2], 0); /* id */
			p(fp, " ", ptimestr(tbuf, sizeof(tbuf),
					(time_t)strtoll(sub->value.v[3].value.s, NULL, 10)),
				"\n", NULL);
		} else if (strcmp(obj->value.v[i].value.s, "sig") == 0) {
			sub = &obj->value.v[i + 1];
			p(fp, "sig", NULL);
			pobj(fp, &sub->value.v[0], 8);	/* size */
			p(fp, "  ", ptimestr(tbuf, sizeof(tbuf),
					(time_t)strtoll(sub->value.v[1].value.s, NULL, 10)),
				" ", NULL); /* time */
			pobj(fp, &sub->value.v[2], 0); /* human name */
			p(fp, "\n", NULL);
		} else {
			fprintf(stderr, "weird '%s'\n", obj->value.v[i].value.s);
			pobj(fp, &obj->value.v[i], 0); /* human name */
		}
	}
	p(fp, "\n", NULL);
}

/* save a pgp pubkey to a temp file */
static int
savepubkey(char *res, char *f, size_t size)
{
	size_t	len;
	int	cc;
	int	wc;
	int	fd;

	(void) snprintf(f, size, "/tmp/pgp2ssh.XXXXXXX");
	if ((fd = mkstemp(f)) < 0) {
		(void) fprintf(stderr, "cannot create temp file '%s'\n", f);
		return 0;
	}
	len = strlen(res);
	for (cc = 0 ; (wc = (int)write(fd, &res[cc], len - (size_t)cc)) > 0 ; cc += wc) {
	}
	(void) close(fd);
	return 1;
}

/* format a uint32_t */
static int
formatu32(uint8_t *buffer, uint32_t value)
{
	buffer[0] = (uint8_t)(value >> 24) & 0xff;
	buffer[1] = (uint8_t)(value >> 16) & 0xff;
	buffer[2] = (uint8_t)(value >> 8) & 0xff;
	buffer[3] = (uint8_t)value & 0xff;
	return sizeof(uint32_t);
}

/* format a string as (len, string) */
static int
formatstring(char *buffer, const uint8_t *s, size_t len)
{
	int	cc;

	cc = formatu32((uint8_t *)buffer, (uint32_t)len);
	(void) memcpy(&buffer[cc], s, len);
	return cc + (int)len;
}

/* format a bignum, checking for "interesting" high bit values */
static int
formatbignum(char *buffer, BIGNUM *bn)
{
	size_t	 len;
	uint8_t	*cp;
	int	 cc;

	len = (size_t) BN_num_bytes(bn);
	if ((cp = calloc(1, len + 1)) == NULL) {
		(void) fprintf(stderr, "calloc failure in formatbignum\n");
		return 0;
	}
	(void) BN_bn2bin(bn, cp + 1);
	cp[0] = 0x0;
	cc = (cp[1] & 0x80) ? formatstring(buffer, cp, len + 1) : formatstring(buffer, &cp[1], len);
	free(cp);
	return cc;
}

#define MAX_PASSPHRASE_ATTEMPTS	3
#define INFINITE_ATTEMPTS	-1

/* get the passphrase from the user */
static int
find_passphrase(FILE *passfp, const char *id, char *passphrase, size_t size, int attempts)
{
	char	 prompt[BUFSIZ];
	char	 buf[128];
	char	*cp;
	int	 cc;
	int	 i;

	if (passfp) {
		if (fgets(passphrase, (int)size, passfp) == NULL) {
			return 0;
		}
		return (int)strlen(passphrase);
	}
	for (i = 0 ; i < attempts ; i++) {
		(void) snprintf(prompt, sizeof(prompt), "Enter passphrase for %.16s: ", id);
		if ((cp = getpass(prompt)) == NULL) {
			break;
		}
		cc = snprintf(buf, sizeof(buf), "%s", cp);
		(void) snprintf(prompt, sizeof(prompt), "Repeat passphrase for %.16s: ", id);
		if ((cp = getpass(prompt)) == NULL) {
			break;
		}
		cc = snprintf(passphrase, size, "%s", cp);
		if (strcmp(buf, passphrase) == 0) {
			(void) memset(buf, 0x0, sizeof(buf));
			return cc;
		}
	}
	(void) memset(buf, 0x0, sizeof(buf));
	(void) memset(passphrase, 0x0, size);
	return 0;
}

#ifdef HAVE_SYS_RESOURCE_H

/* When system resource consumption limit controls are available this
 * can be used to attempt to disable core dumps which may leak
 * sensitive data.
 *
 * Returns 0 if disabling core dumps failed, returns 1 if disabling
 * core dumps succeeded, and returns -1 if an error occurred. errno
 * will be set to the result from setrlimit in the event of
 * failure.
 */
static int
disable_core_dumps(void)
{
	struct rlimit limit;
	int error;

	errno = 0;
	memset(&limit, 0, sizeof(limit));
	error = setrlimit(RLIMIT_CORE, &limit);
	return error != -1 && error > 0 ? 0 : -1;
}

/* Disable core dumps according to the coredumps setting variable.
 * Returns 0 if core dumps are definitely disabled or 1 if core dumps
 * are or are possibly enabled.
 *
 * This function could benefit from communicating error conditions
 * from disable_core_dumps.
 */
static int
set_core_dumps(rnp_t *rnp)
{
	int setting;

	setting = rnp_getvar(rnp, "coredumps") != NULL;
	if (! setting) {
		return disable_core_dumps() == 0 ? 0 : 1;
	}

	return 1;
}

#endif

/* Gets a passphrase from a file descriptor and set it in the RNP
 * context. Returns 1 on success and 0 on failure.
 *
 * TODO: Replace atoi(). This could create unexpected behaviour for users
 *       that enter nonsense and end up using stdin.
 *
 * TODO: Decouple this layer from the error reporting layer, which should
 *       be in or around rnp_init(). Because the error message requires
 *       passfd to be available this is complicated.
 */
static int
set_pass_fd(rnp_t *rnp)
{
	char *passfd = rnp_getvar(rnp, "pass-fd");
	pgp_io_t *io = rnp->io;

	if (passfd != NULL) {
		rnp->passfp = fdopen(atoi(passfd), "r");
		if (rnp->passfp == NULL) {
			fprintf(io->errs,
				"cannot open fd %s for reading\n", passfd);
			return 0;
		}
	}

	return 1;
}

/* Initialize a RNP context's io stream handles with a user-supplied
 * io struct. Returns 1 on success and 0 on failure. It is the caller's
 * responsibility to de-allocate a dynamically allocated io struct
 * upon failure.
 */
static int
init_io(rnp_t *rnp, pgp_io_t *io)
{
	char *stream;
	char *results;

	/* TODO: I think refactoring can go even further here. */

	/* Configure the output stream. */
	io->outs = stdout;
	if ((stream = rnp_getvar(rnp, "outs")) != NULL &&
			strcmp(stream, "<stderr>") == 0) {
		io->outs = stderr;
	}

	/* Configure the error stream. */
	io->errs = stderr;
	if ((stream = rnp_getvar(rnp, "errs")) != NULL &&
			strcmp(stream, "<stdout>") == 0) {
		io->errs = stdout;
	}

	/* Configure the results stream. */
	if ((results = rnp_getvar(rnp, "res")) == NULL) {
		io->res = io->errs;
	} else if (strcmp(results, "<stdout>") == 0) {
		io->res = stdout;
	} else if (strcmp(results, "<stderr>") == 0) {
		io->res = stderr;
	} else {
		if ((io->res = fopen(results, "w")) == NULL) {
			fprintf(io->errs,
				"cannot open results %s for writing\n",
				results);
			return 0;
		}
	}

	rnp->io = io;

	return 1;
}

/* Allocate a new io struct and initialize a rnp context with it.
 * Returns 1 on success and 0 on failure.
 *
 * TODO: Set errno with a suitable error code.
 */
static int
init_new_io(rnp_t *rnp)
{
	pgp_io_t *io = (pgp_io_t *) malloc(sizeof(*io));

	if (io != NULL) {
		if (init_io(rnp, io))
			return 1;
		free((void *) io);
	}

	return 0;
}

static int
parse_keyring_format(rnp_t *rnp, enum keyring_format_t *keyring_format, char *format)
{
	if (rnp_strcasecmp(format, "GPG") == 0) {
		*keyring_format = GPG_KEYRING;
	} else if (rnp_strcasecmp(format, "SSH") == 0) {
		*keyring_format = SSH_KEYRING;
	} else {
		fprintf(stderr, "rnp: unsupported keyring format: \"%s\"\n", format);
		return 0;
	}
	return 1;
}

static int
load_keys_gnupg(rnp_t *rnp, char *homedir)
{
	char     *userid;
	char      id[MAX_ID_LENGTH];
	pgp_io_t *io = rnp->io;

	/* TODO: Some of this might be split up into sub-functions. */
	/* TODO: Figure out what unhandled error is causing an
	 *       empty keyring to end up in get_first_ring
	 *       and ensure that it's not present in the
	 *       ssh implementation too.
	 */

	rnp->pubring = readkeyring(rnp, "pubring");

	if (rnp->pubring == NULL) {
		fprintf(io->errs, "cannot read pub keyring\n");
		return 0;
	}

	if (((pgp_keyring_t *) rnp->pubring)->keyc < 1) {
		fprintf(io->errs, "pub keyring is empty\n");
		return 0;
	}

	/* If a userid has been given, we'll use it. */
	if ((userid = rnp_getvar(rnp, "userid")) == NULL) {
		/* also search in config file for default id */
		memset(id, 0, sizeof(id));
		conffile(rnp, homedir, id, sizeof(id));
		if (id[0] != 0x0) {
			rnp_setvar(rnp, "userid", userid = id);
		}
	}

	/* Only read secret keys if we need to. */
	if (rnp_getvar(rnp, "need seckey")) {

		rnp->secring = readkeyring(rnp, "secring");

		if (rnp->secring == NULL) {
			fprintf(io->errs, "cannot read sec keyring\n");
			return 0;
		}

		if (((pgp_keyring_t *) rnp->secring)->keyc < 1) {
			fprintf(io->errs, "sec keyring is empty\n");
			return 0;
		}

		/* Now, if we don't have a valid user, use the first
		 * in secring.
		 */
		if (! userid && rnp_getvar(rnp,
				"need userid") != NULL) {

			if (! get_first_ring(rnp->secring, id,
					sizeof(id), 0)) {
				/* TODO: This is _temporary_. A more
				 *       suitable replacement will be
				 *       required.
				 */
				fprintf(io->errs, "failed to read id\n");
				return 0;
			}

			rnp_setvar(rnp, "userid", userid = id);
		}

	} else if (rnp_getvar(rnp, "need userid") != NULL) {
		/* encrypting - get first in pubring */
		if (! userid && get_first_ring(
				rnp->pubring, id, sizeof(id), 0)) {
			rnp_setvar(rnp, "userid", userid = id);
		}
	}

	if (! userid && rnp_getvar(rnp, "need userid")) {
		/* if we don't have a user id, and we need one, fail */
		fprintf(io->errs, "cannot find user id\n");
		return 0;
	}

	return 1;
}

static int
load_keys_ssh(rnp_t *rnp, char *homedir)
{
	int       last = (rnp->pubring != NULL);
	char      id[MAX_ID_LENGTH];
	char     *userid;
	pgp_io_t *io = rnp->io;

	/* TODO: Double-check whether or not ID needs to be zeroed. */

	if (! readsshkeys(rnp, homedir,
			rnp_getvar(rnp, "need seckey"))) {
		fprintf(io->errs, "cannot read ssh keys\n");
		return 0;
	}
	if ((userid = rnp_getvar(rnp, "userid")) == NULL) {
		/* TODO: Handle get_first_ring() failure. */
		get_first_ring(rnp->pubring, id,
				sizeof(id), last);
		rnp_setvar(rnp, "userid", userid = id);
	}
	if (userid == NULL) {
		if (rnp_getvar(rnp, "need userid") != NULL) {
			fprintf(io->errs, "cannot find user id\n");
			return 0;
		}
	} else {
		rnp_setvar(rnp, "userid", userid);
	}

	return 1;
}

/* Encapsulates setting `initialized` to the current time. */
static void
init_touch_initialized(rnp_t *rnp)
{
	time_t t;

	t = time(NULL);
	rnp_setvar(rnp, "initialised", ctime(&t));
}

static int
init_default_format(rnp_t *rnp)
{
	char *format = rnp_getvar(rnp, "keyring_format");

	// default format is GPG
	if (format == NULL) {
		format = "GPG";
	}

	// if provided "ssh keys" variable, switch to SSH format
	if (rnp_getvar(rnp, "ssh keys")) {
		format = "SSH";
	}

	return rnp_set_keyring_format(rnp, format);
}

static int
init_default_homedir(rnp_t *rnp)
{
	char *home = getenv("HOME");

	if (home == NULL) {
		fputs("rnp: HOME environment variable is not set\n", stderr);
		return 0;
	}
	return rnp_set_homedir(rnp, home, 1);
}

/*************************************************************************/
/* exported functions start here                                         */
/*************************************************************************/

/* Initialize a rnp_t structure */
int
rnp_init(rnp_t *rnp)
{
	int       coredumps;
	pgp_io_t *io;

    /* Before calling the init, the userdefined options are set. 
     * DONOT MEMSET*/
#if 0
    memset((void *) rnp, '\0', sizeof(rnp_t));
#endif

	/* Apply default settings. */
	rnp_setvar(rnp, "subdir_gpg", SUBDIRECTORY_GNUPG);
	rnp_setvar(rnp, "subdir_ssh", SUBDIRECTORY_SSH);

	/* Assume that core dumps are always enabled. */
	coredumps = 1;

	/* If system resource constraints are in effect then attempt to
	 * disable core dumps.
	 */
#ifdef HAVE_SYS_RESOURCE_H
	coredumps = set_core_dumps(rnp);
	if (coredumps) {
		fprintf(stderr,
			"rnp: warning - cannot turn off core dumps\n");
	}
#endif

	/* Initialize the context's io streams apparatus. */
	if (! init_new_io(rnp))
		return 0;
	io = rnp->io;

	/* If a password-carrying file descriptor is in use then
	 * load it.
	 */
	if (! set_pass_fd(rnp))
		return 0;

	if (coredumps) {
		fputs("rnp: warning: core dumps enabled, "
		      "sensitive data may be leaked to disk\n", io->errs);
	}

	/* Initialize the context with the default keyring format. */
	if (! init_default_format(rnp)) {
		return 0;
	}

	/* Initialize the context with the default home directory. */
	if (! init_default_homedir(rnp)) {
		fputs("rnp: bad homedir\n", io->errs);
		return 0;
	}

	init_touch_initialized(rnp);

	return 1;
}

/* finish off with the rnp_t struct */
int
rnp_end(rnp_t *rnp)
{
	unsigned	i;

	for (i = 0 ; i < rnp->c ; i++) {
		if (rnp->name[i] != NULL) {
			free(rnp->name[i]);
		}
		if (rnp->value[i] != NULL) {
			free(rnp->value[i]);
		}
	}
	if (rnp->name != NULL) {
		free(rnp->name);
	}
	if (rnp->value != NULL) {
		free(rnp->value);
	}
	if (rnp->pubring != NULL) {
		pgp_keyring_free(rnp->pubring);
	}
	if (rnp->secring != NULL) {
		pgp_keyring_free(rnp->secring);
	}
	free(rnp->io);
	return 1;
}

/* list the keys in a keyring */
int
rnp_list_keys(rnp_t *rnp, const int psigs)
{
	if (rnp->pubring == NULL) {
		(void) fprintf(stderr, "No keyring\n");
		return 0;
	}
	return pgp_keyring_list(rnp->io, rnp->pubring, psigs);
}

/* list the keys in a keyring, returning a JSON encoded string */
int
rnp_list_keys_json(rnp_t *rnp, char **json, const int psigs)
{
	mj_t	obj;
	int	ret;

	if (rnp->pubring == NULL) {
		(void) fprintf(stderr, "No keyring\n");
		return 0;
	}
	(void) memset(&obj, 0x0, sizeof(obj));
	if (!pgp_keyring_json(rnp->io, rnp->pubring, &obj, psigs)) {
		(void) fprintf(stderr, "No keys in keyring\n");
		return 0;
	}
	ret = mj_asprint(json, &obj, MJ_JSON_ENCODE);
	mj_delete(&obj);
	return ret;
}

int
rnp_load_keys(rnp_t *rnp)
{
	char path[MAXPATHLEN];

	errno = 0;

	if (use_ssh_keys(rnp)) {
		if (keydir_ssh(rnp, path, sizeof(path)) == -1)
			return 0;
		if (! load_keys_ssh(rnp, path))
			return 0;
	} else {
		if (keydir_gnupg(rnp, path, sizeof(path)) == -1)
			return 0;
		if (! load_keys_gnupg(rnp, path))
			return 0;
	}

	return 1;
}

DEFINE_ARRAY(strings_t, char *);

#ifndef HKP_VERSION
#define HKP_VERSION	1
#endif

/* find and list some keys in a keyring */
int
rnp_match_keys(rnp_t *rnp, char *name, const char *fmt, void *vp, const int psigs)
{
	const pgp_key_t	*key;
	unsigned		 k;
	strings_t		 pubs;
	FILE			*fp = (FILE *)vp;

	if (name[0] == '0' && name[1] == 'x') {
		name += 2;
	}
	(void) memset(&pubs, 0x0, sizeof(pubs));
	k = 0;
	do {
		key = pgp_getnextkeybyname(rnp->io, rnp->pubring,
						name, &k);
		if (key != NULL) {
			ALLOC(char *, pubs.v, pubs.size, pubs.c, 10, 10,
					"rnp_match_keys", return 0);
			if (strcmp(fmt, "mr") == 0) {
				pgp_hkp_sprint_keydata(rnp->io, rnp->pubring,
						key, &pubs.v[pubs.c],
						&key->key.pubkey, psigs);
			} else {
				pgp_sprint_keydata(rnp->io, rnp->pubring,
						key, &pubs.v[pubs.c],
						"signature ",
						&key->key.pubkey, psigs);
			}
			if (pubs.v[pubs.c] != NULL) {
				pubs.c += 1;
			}
			k += 1;
		}
	} while (key != NULL);
	if (strcmp(fmt, "mr") == 0) {
		(void) fprintf(fp, "info:%d:%d\n", HKP_VERSION, pubs.c);
	} else {
		(void) fprintf(fp, "%d key%s found\n", pubs.c,
			(pubs.c == 1) ? "" : "s");
	}
	for (k = 0 ; k < pubs.c ; k++) {
		(void) fprintf(fp, "%s%s", pubs.v[k], (k < pubs.c - 1) ? "\n" : "");
		free(pubs.v[k]);
	}
	free(pubs.v);
	return pubs.c;
}

/* find and list some keys in a keyring - return JSON string */
int
rnp_match_keys_json(rnp_t *rnp, char **json, char *name, const char *fmt, const int psigs)
{
	const pgp_key_t	*key;
	unsigned	 k;
	mj_t		 id_array;
	char		*newkey;
	int		 ret;

	if (name[0] == '0' && name[1] == 'x') {
		name += 2;
	}
	(void) memset(&id_array, 0x0, sizeof(id_array));
	k = 0;
	*json = NULL;
	mj_create(&id_array, "array");
	do {
		key = pgp_getnextkeybyname(rnp->io, rnp->pubring,
						name, &k);
		if (key != NULL) {
			if (strcmp(fmt, "mr") == 0) {
				pgp_hkp_sprint_keydata(rnp->io, rnp->pubring,
						key, &newkey,
						&key->key.pubkey, 0);
				if (newkey) {
					printf("%s\n", newkey);
					free(newkey);
				}
			} else {
				ALLOC(mj_t, id_array.value.v, id_array.size,
					id_array.c, 10, 10, "rnp_match_keys_json", return 0);
				pgp_sprint_mj(rnp->io, rnp->pubring,
						key, &id_array.value.v[id_array.c++],
						"signature ",
						&key->key.pubkey, psigs);
			}
			k += 1;
		}
	} while (key != NULL);
	ret = mj_asprint(json, &id_array, MJ_JSON_ENCODE);
	mj_delete(&id_array);
	return ret;
}

/* find and list some public keys in a keyring */
int
rnp_match_pubkeys(rnp_t *rnp, char *name, void *vp)
{
	const pgp_key_t	*key;
	unsigned	 k;
	ssize_t		 cc;
	char		 out[1024 * 64];
	FILE		*fp = (FILE *)vp;

	k = 0;
	do {
		key = pgp_getnextkeybyname(rnp->io, rnp->pubring,
						name, &k);
		if (key != NULL) {
			cc = pgp_sprint_pubkey(key, out, sizeof(out));
			(void) fprintf(fp, "%.*s", (int)cc, out);
			k += 1;
		}
	} while (key != NULL);
	return k;
}

/* find a key in a keyring */
int
rnp_find_key(rnp_t *rnp, char *id)
{
	pgp_io_t	*io;

	io = rnp->io;
	if (id == NULL) {
		(void) fprintf(io->errs, "NULL id to search for\n");
		return 0;
	}
	return pgp_getkeybyname(rnp->io, rnp->pubring, id) != NULL;
}

/* get a key in a keyring */
char *
rnp_get_key(rnp_t *rnp, const char *name, const char *fmt)
{
	const pgp_key_t	*key;
	char		*newkey;

	if ((key = resolve_userid(rnp, rnp->pubring, name)) == NULL) {
		return NULL;
	}
	if (strcmp(fmt, "mr") == 0) {
		return (pgp_hkp_sprint_keydata(rnp->io, rnp->pubring,
				key, &newkey,
				&key->key.pubkey,
				rnp_getvar(rnp, "subkey sigs") != NULL) > 0) ? newkey : NULL;
	}
	return (pgp_sprint_keydata(rnp->io, rnp->pubring,
				key, &newkey, "signature",
				&key->key.pubkey,
				rnp_getvar(rnp, "subkey sigs") != NULL) > 0) ? newkey : NULL;
}

/* export a given key */
char *
rnp_export_key(rnp_t *rnp, char *name)
{
	const pgp_key_t	*key;
	pgp_io_t		*io;

	io = rnp->io;
	if ((key = resolve_userid(rnp, rnp->pubring, name)) == NULL) {
		return NULL;
	}
	return pgp_export_key(io, key, NULL);
}

#define IMPORT_ARMOR_HEAD	"-----BEGIN PGP PUBLIC KEY BLOCK-----"

/* import a key into our keyring */
int
rnp_import_key(rnp_t *rnp, char *f)
{
	pgp_io_t	*io;
	unsigned	 realarmor;
	int		 done;

	io = rnp->io;
	realarmor = isarmoured(io, f, NULL, IMPORT_ARMOR_HEAD);
	done = pgp_keyring_fileread(rnp->pubring, realarmor, f);
	if (!done) {
		(void) fprintf(io->errs, "cannot import key from file %s\n", f);
		return 0;
	}
	return pgp_keyring_list(io, rnp->pubring, 0);
}

#define ID_OFFSET	38

/* generate a new key */
/* TODO: Does this need to take into account SSH keys? */
int
rnp_generate_key(rnp_t *rnp, char *id, int numbits)
{
	pgp_output_t		*create;
	const unsigned		 noarmor = 0;
	pgp_key_t		*key;
	pgp_io_t		*io;
	uint8_t			*uid;
	char			 passphrase[128];
	char			 newid[1024];
	char			 filename[MAXPATHLEN];
	char			 dir[MAXPATHLEN];
	char			*cp;
	char			*ringfile;
	char			*numtries;
	int             	 attempts;
	int             	 passc;
	int             	 fd;
	int             	 cc;
	int			 rv = 0;

	uid = NULL;
	io = rnp->io;
	/* generate a new key */
	if (id) {
		snprintf(newid, sizeof(newid), "%s", id);
	} else {
		snprintf(newid, sizeof(newid),
			"RSA %d-bit key <%s@localhost>", numbits, getenv("LOGNAME"));
	}
	uid = (uint8_t *)newid;
	key = pgp_rsa_new_selfsign_key(numbits, 65537UL, uid,
			rnp_getvar(rnp, "hash"),
			rnp_getvar(rnp, "cipher"));
	if (key == NULL) {
		(void) fprintf(io->errs, "cannot generate key\n");
		return 0;
	}
	cp = NULL;
	pgp_sprint_keydata(rnp->io, NULL, key, &cp, "signature ", &key->key.seckey.pubkey, 0);
	(void) fprintf(stdout, "%s", cp);

	/* write public key */

	keydir(rnp, dir, sizeof(dir));
	cc = strlen(dir);

	rnp_setvar(rnp, "generated userid", &dir[cc - 16]);

	/* TODO: This call competes with the mkdir() at
	 *       rnpkeys/rnpkeys.c:main:458, but that call doesn't
	 *       check for error conditions. For now this call is allowed
	 *       to succeed if the directory already exists, but an
	 *       error should be raised the existing directory's
	 *       permissions aren't 0700.
	 */
	if (mkdir(dir, 0700) == -1 && errno != EEXIST) {
		fprintf(io->errs, "cannot mkdir '%s' errno = %d \n", dir, errno);
		goto out;
	}

	(void) fprintf(io->errs, "rnp: generated keys in directory %s\n", dir);
	(void) snprintf(ringfile = filename, sizeof(filename), "%s/pubring.gpg", dir);
	if (!appendkey(io, key, ringfile)) {
		(void) fprintf(io->errs, "cannot write pubkey to '%s'\n", ringfile);
		goto out;
	}
	if (rnp->pubring != NULL) {
		pgp_keyring_free(rnp->pubring);
	}
	/* write secret key */
	(void) snprintf(ringfile = filename, sizeof(filename), "%s/secring.gpg", dir);
	if ((fd = pgp_setup_file_append(&create, ringfile)) < 0) {
		fd = pgp_setup_file_write(&create, ringfile, 0);
	}
	if (fd < 0) {
		(void) fprintf(io->errs, "cannot append secring '%s'\n", ringfile);
		goto out;
	}
	/* get the passphrase */
	if ((numtries = rnp_getvar(rnp, "numtries")) == NULL ||
	    (attempts = atoi(numtries)) <= 0) {
		attempts = MAX_PASSPHRASE_ATTEMPTS;
	} else if (strcmp(numtries, "unlimited") == 0) {
		attempts = INFINITE_ATTEMPTS;
	}
	passc = find_passphrase(rnp->passfp, &cp[ID_OFFSET], passphrase, sizeof(passphrase), attempts);
	if (!pgp_write_xfer_seckey(create, key, (uint8_t *)passphrase, (const unsigned)passc, NULL, noarmor)) {
		(void) fprintf(io->errs, "cannot write seckey\n");
		goto out1;
	}
	rv = 1;
out1:
	pgp_teardown_file_write(create, fd);
	if (rnp->secring != NULL) {
		pgp_keyring_free(rnp->secring);
	}
out:
	pgp_keydata_free(key);
	free(cp);
	return rv;
}

/* encrypt a file */
int
rnp_encrypt_file(rnp_t *rnp,
			const char *userid,
			const char *f,
			char *out,
			int armored)
{
	const pgp_key_t	*key;
	const unsigned		 overwrite = 1;
	const char		*suffix;
	pgp_io_t		*io;
	char			 outname[MAXPATHLEN];

	io = rnp->io;
	if (f == NULL) {
		(void) fprintf(io->errs,
			"rnp_encrypt_file: no filename specified\n");
		return 0;
	}
	suffix = (armored) ? ".asc" : ".gpg";
	/* get key with which to sign */
	if ((key = resolve_userid(rnp, rnp->pubring, userid)) == NULL) {
		return 0;
	}
	if (out == NULL) {
		(void) snprintf(outname, sizeof(outname), "%s%s", f, suffix);
		out = outname;
	}
	return (int)pgp_encrypt_file(io, f, out, key, (unsigned)armored,
				overwrite, rnp_getvar(rnp, "cipher"));
}

#define ARMOR_HEAD	"-----BEGIN PGP MESSAGE-----"

/* decrypt a file */
int
rnp_decrypt_file(rnp_t *rnp, const char *f, char *out, int armored)
{
	const unsigned	 overwrite = 1;
	pgp_io_t	*io;
	unsigned	 realarmor;
	unsigned	 sshkeys;
	char		*numtries;
	int            	 attempts;

	__PGP_USED(armored);
	io = rnp->io;
	if (f == NULL) {
		(void) fprintf(io->errs,
			"rnp_decrypt_file: no filename specified\n");
		return 0;
	}
	realarmor = isarmoured(io, f, NULL, ARMOR_HEAD);
	sshkeys = (unsigned)use_ssh_keys(rnp);
	if ((numtries = rnp_getvar(rnp, "numtries")) == NULL ||
	    (attempts = atoi(numtries)) <= 0) {
		attempts = MAX_PASSPHRASE_ATTEMPTS;
	} else if (strcmp(numtries, "unlimited") == 0) {
		attempts = INFINITE_ATTEMPTS;
	}
	return pgp_decrypt_file(rnp->io, f, out, rnp->secring,
				rnp->pubring,
				realarmor, overwrite, sshkeys,
				rnp->passfp, attempts, get_passphrase_cb);
}

/* sign a file */
int
rnp_sign_file(rnp_t *rnp,
		const char *userid,
		const char *f,
		char *out,
		int armored,
		int cleartext,
		int detached)
{
	const pgp_key_t		*keypair;
	const pgp_key_t		*pubkey;
	const unsigned		 overwrite = 1;
	pgp_seckey_t		*seckey;
	const char		*hashalg;
	pgp_io_t		*io;
	char			*numtries;
	int			 attempts;
	int			 ret;
	int			 i;

	io = rnp->io;
	if (f == NULL) {
		(void) fprintf(io->errs,
			"rnp_sign_file: no filename specified\n");
		return 0;
	}
	/* get key with which to sign */
	if ((keypair = resolve_userid(rnp, rnp->secring, userid)) == NULL) {
		return 0;
	}
	ret = 1;
	if ((numtries = rnp_getvar(rnp, "numtries")) == NULL ||
	    (attempts = atoi(numtries)) <= 0) {
		attempts = MAX_PASSPHRASE_ATTEMPTS;
	} else if (strcmp(numtries, "unlimited") == 0) {
		attempts = INFINITE_ATTEMPTS;
	}
	for (i = 0, seckey = NULL ; !seckey && (i < attempts || attempts == INFINITE_ATTEMPTS) ; i++) {
		if (rnp->passfp == NULL) {
			/* print out the user id */
			pubkey = pgp_getkeybyname(io, rnp->pubring, userid);
			if (pubkey == NULL) {
				(void) fprintf(io->errs,
					"rnp: warning - using pubkey from secring\n");
				pgp_print_keydata(io, rnp->pubring, keypair, "signature ",
					&keypair->key.seckey.pubkey, 0);
			} else {
				pgp_print_keydata(io, rnp->pubring, pubkey, "signature ",
					&pubkey->key.pubkey, 0);
			}
		}
		if (!use_ssh_keys(rnp)) {
			/* now decrypt key */
			seckey = pgp_decrypt_seckey(keypair, rnp->passfp);
			if (seckey == NULL) {
				(void) fprintf(io->errs, "Bad passphrase\n");
			}
		} else {
			pgp_keyring_t	*secring;

			secring = rnp->secring;
			seckey = &secring->keys[0].key.seckey;
		}
	}
	if (seckey == NULL) {
		(void) fprintf(io->errs, "Bad passphrase\n");
		return 0;
	}
	/* sign file */
	hashalg = rnp_getvar(rnp, "hash");
	if (seckey->pubkey.alg == PGP_PKA_DSA) {
		hashalg = "sha1";
	}
	if (detached) {
		ret = pgp_sign_detached(io, f, out, seckey, hashalg,
				get_birthtime(rnp_getvar(rnp, "birthtime")),
				get_duration(rnp_getvar(rnp, "duration")),
				(unsigned)armored,
				overwrite);
	} else {
		ret = pgp_sign_file(io, f, out, seckey, hashalg,
				get_birthtime(rnp_getvar(rnp, "birthtime")),
				get_duration(rnp_getvar(rnp, "duration")),
				(unsigned)armored, (unsigned)cleartext,
				overwrite);
	}
	pgp_forget(seckey, (unsigned)sizeof(*seckey));
	return ret;
}

#define ARMOR_SIG_HEAD	"-----BEGIN PGP (SIGNATURE|SIGNED MESSAGE)-----"

/* verify a file */
int
rnp_verify_file(rnp_t *rnp, const char *in, const char *out, int armored)
{
	pgp_validation_t	 result;
	pgp_io_t		*io;
	unsigned		 realarmor;

	__PGP_USED(armored);
	(void) memset(&result, 0x0, sizeof(result));
	io = rnp->io;
	if (in == NULL) {
		(void) fprintf(io->errs,
			"rnp_verify_file: no filename specified\n");
		return 0;
	}
	realarmor = isarmoured(io, in, NULL, ARMOR_SIG_HEAD);
	if (pgp_validate_file(io, &result, in, out, (const int)realarmor, rnp->pubring)) {
		resultp(io, in, &result, rnp->pubring);
		return 1;
	}
	if (result.validc + result.invalidc + result.unknownc == 0) {
		(void) fprintf(io->errs,
		"\"%s\": No signatures found - is this a signed file?\n",
			in);
	} else if (result.invalidc == 0 && result.unknownc == 0) {
		(void) fprintf(io->errs,
			"\"%s\": file verification failure: invalid signature time\n", in);
	} else {
		(void) fprintf(io->errs,
"\"%s\": verification failure: %u invalid signatures, %u unknown signatures\n",
			in, result.invalidc, result.unknownc);
	}
	return 0;
}

/* sign some memory */
int
rnp_sign_memory(rnp_t *rnp,
		const char *userid,
		char *mem,
		size_t size,
		char *out,
		size_t outsize,
		const unsigned armored,
		const unsigned cleartext)
{
	const pgp_key_t		*keypair;
	const pgp_key_t		*pubkey;
	pgp_seckey_t		*seckey;
	pgp_memory_t		*signedmem;
	const char		*hashalg;
	pgp_io_t		*io;
	char 			*numtries;
	int			 attempts;
	int			 ret;
	int			 i;

	io = rnp->io;
	if (mem == NULL) {
		(void) fprintf(io->errs,
			"rnp_sign_memory: no memory to sign\n");
		return 0;
	}
	if ((keypair = resolve_userid(rnp, rnp->secring, userid)) == NULL) {
		return 0;
	}
	ret = 1;
	if ((numtries = rnp_getvar(rnp, "numtries")) == NULL ||
	    (attempts = atoi(numtries)) <= 0) {
		attempts = MAX_PASSPHRASE_ATTEMPTS;
	} else if (strcmp(numtries, "unlimited") == 0) {
		attempts = INFINITE_ATTEMPTS;
	}
	for (i = 0, seckey = NULL ; !seckey && (i < attempts || attempts == INFINITE_ATTEMPTS) ; i++) {
		if (rnp->passfp == NULL) {
			/* print out the user id */
			pubkey = pgp_getkeybyname(io, rnp->pubring, userid);
			if (pubkey == NULL) {
				(void) fprintf(io->errs,
					"rnp: warning - using pubkey from secring\n");
				pgp_print_keydata(io, rnp->pubring, keypair, "signature ",
					&keypair->key.seckey.pubkey, 0);
			} else {
				pgp_print_keydata(io, rnp->pubring, pubkey, "signature ",
					&pubkey->key.pubkey, 0);
			}
		}
		if (!use_ssh_keys(rnp)) {
			/* now decrypt key */
			seckey = pgp_decrypt_seckey(keypair, rnp->passfp);
			if (seckey == NULL) {
				(void) fprintf(io->errs, "Bad passphrase\n");
			}
		} else {
			pgp_keyring_t	*secring;

			secring = rnp->secring;
			seckey = &secring->keys[0].key.seckey;
		}
	}
	if (seckey == NULL) {
		(void) fprintf(io->errs, "Bad passphrase\n");
		return 0;
	}
	/* sign file */
	(void) memset(out, 0x0, outsize);
	hashalg = rnp_getvar(rnp, "hash");
	if (seckey->pubkey.alg == PGP_PKA_DSA) {
		hashalg = "sha1";
	}
	signedmem = pgp_sign_buf(io, mem, size, seckey,
				get_birthtime(rnp_getvar(rnp, "birthtime")),
				get_duration(rnp_getvar(rnp, "duration")),
				hashalg, armored, cleartext);
	if (signedmem) {
		size_t	m;

		m = MIN(pgp_mem_len(signedmem), outsize);
		(void) memcpy(out, pgp_mem_data(signedmem), m);
		pgp_memory_free(signedmem);
		ret = (int)m;
	} else {
		ret = 0;
	}
	pgp_forget(seckey, (unsigned)sizeof(*seckey));
	return ret;
}

/* verify memory */
int
rnp_verify_memory(rnp_t *rnp, const void *in, const size_t size,
			void *out, size_t outsize, const int armored)
{
	pgp_validation_t	 result;
	pgp_memory_t		*signedmem;
	pgp_memory_t		*cat;
	pgp_io_t		*io;
	size_t			 m;
	int			 ret;

	(void) memset(&result, 0x0, sizeof(result));
	io = rnp->io;
	if (in == NULL) {
		(void) fprintf(io->errs,
			"rnp_verify_memory: no memory to verify\n");
		return 0;
	}
	signedmem = pgp_memory_new();
	pgp_memory_add(signedmem, in, size);
	if (out) {
		cat = pgp_memory_new();
	}
	ret = pgp_validate_mem(io, &result, signedmem,
				(out) ? &cat : NULL,
				armored, rnp->pubring);
	/* signedmem is freed from pgp_validate_mem */
	if (ret) {
		resultp(io, "<stdin>", &result, rnp->pubring);
		if (out) {
			m = MIN(pgp_mem_len(cat), outsize);
			(void) memcpy(out, pgp_mem_data(cat), m);
			pgp_memory_free(cat);
		} else {
			m = 1;
		}
		return (int)m;
	}
	if (result.validc + result.invalidc + result.unknownc == 0) {
		(void) fprintf(io->errs,
		"No signatures found - is this memory signed?\n");
	} else if (result.invalidc == 0 && result.unknownc == 0) {
		(void) fprintf(io->errs,
			"memory verification failure: invalid signature time\n");
	} else {
		(void) fprintf(io->errs,
"memory verification failure: %u invalid signatures, %u unknown signatures\n",
			result.invalidc, result.unknownc);
	}
	return 0;
}

/* encrypt some memory */
int
rnp_encrypt_memory(rnp_t *rnp,
			const char *userid,
			void *in,
			const size_t insize,
			char *out,
			size_t outsize,
			int armored)
{
	const pgp_key_t	*keypair;
	pgp_memory_t	*enc;
	pgp_io_t	*io;
	size_t		 m;

	io = rnp->io;
	if (in == NULL) {
		(void) fprintf(io->errs,
			"rnp_encrypt_buf: no memory to encrypt\n");
		return 0;
	}
	if ((keypair = resolve_userid(rnp, rnp->pubring, userid)) == NULL) {
		return 0;
	}
	if (in == out) {
		(void) fprintf(io->errs,
			"rnp_encrypt_buf: input and output bufs need to be different\n");
		return 0;
	}
	if (outsize < insize) {
		(void) fprintf(io->errs,
			"rnp_encrypt_buf: input size is larger than output size\n");
		return 0;
	}
	enc = pgp_encrypt_buf(io, in, insize, keypair, (unsigned)armored,
				rnp_getvar(rnp, "cipher"));
	m = MIN(pgp_mem_len(enc), outsize);
	(void) memcpy(out, pgp_mem_data(enc), m);
	pgp_memory_free(enc);
	return (int)m;
}

/* decrypt a chunk of memory */
int
rnp_decrypt_memory(rnp_t *rnp, const void *input, const size_t insize,
			char *out, size_t outsize, const int armored)
{
	pgp_memory_t	*mem;
	pgp_io_t	*io;
	unsigned	 realarmour;
	unsigned	 sshkeys;
	size_t		 m;
	char		*numtries;
	int            	 attempts;

	__PGP_USED(armored);
	io = rnp->io;
	if (input == NULL) {
		(void) fprintf(io->errs,
			"rnp_decrypt_memory: no memory\n");
		return 0;
	}
	realarmour = isarmoured(io, NULL, input, ARMOR_HEAD);
	sshkeys = (unsigned)use_ssh_keys(rnp);
	if ((numtries = rnp_getvar(rnp, "numtries")) == NULL ||
	    (attempts = atoi(numtries)) <= 0) {
		attempts = MAX_PASSPHRASE_ATTEMPTS;
	} else if (strcmp(numtries, "unlimited") == 0) {
		attempts = INFINITE_ATTEMPTS;
	}
	mem = pgp_decrypt_buf(rnp->io, input, insize, rnp->secring,
				rnp->pubring,
				realarmour, sshkeys,
				rnp->passfp,
				attempts,
				get_passphrase_cb);
	if (mem == NULL) {
		return -1;
	}
	m = MIN(pgp_mem_len(mem), outsize);
	(void) memcpy(out, pgp_mem_data(mem), m);
	pgp_memory_free(mem);
	return (int)m;
}

/* wrappers for the ops_debug_level functions we added to openpgpsdk */

/* set the debugging level per filename */
int
rnp_set_debug(const char *f)
{
	return pgp_set_debug_level(f);
}

/* get the debugging level per filename */
int
rnp_get_debug(const char *f)
{
	return pgp_get_debug_level(f);
}

/* return the version for the library */
const char *
rnp_get_info(const char *type)
{
	return pgp_get_info(type);
}

/* list all the packets in a file */
int
rnp_list_packets(rnp_t *rnp, char *f, int armor, char *pubringname)
{
	pgp_keyring_t	*keyring;
	const unsigned	 noarmor = 0;
	struct stat	 st;
	pgp_io_t	*io;
	char		 ringname[MAXPATHLEN];
	char		 homedir[MAXPATHLEN];
	int		 ret;

	io = rnp->io;
	if (f == NULL) {
		(void) fprintf(io->errs, "No file containing packets\n");
		return 0;
	}
	if (stat(f, &st) < 0) {
		(void) fprintf(io->errs, "No such file '%s'\n", f);
		return 0;
	}
	keydir(rnp, homedir, sizeof(homedir));
	if (pubringname == NULL) {
		(void) snprintf(ringname, sizeof(ringname),
				"%s/pubring.gpg", homedir);
		pubringname = ringname;
	}
	if ((keyring = calloc(1, sizeof(*keyring))) == NULL) {
		(void) fprintf(io->errs, "rnp_list_packets: bad alloc\n");
		return 0;
	}
	if (!pgp_keyring_fileread(keyring, noarmor, pubringname)) {
		free(keyring);
		(void) fprintf(io->errs, "cannot read pub keyring %s\n",
			pubringname);
		return 0;
	}
	rnp->pubring = keyring;
	rnp_setvar(rnp, "pubring", pubringname);
	ret = pgp_list_packets(io, f, (unsigned)armor,
					rnp->secring,
					rnp->pubring,
					rnp->passfp,
					get_passphrase_cb);
	free(keyring);
	return ret;
}

/* set a variable */
int
rnp_setvar(rnp_t *rnp, const char *name, const char *value)
{
	char	*newval;
	int	 i;

	/* protect against the case where 'value' is rnp->value[i] */
	newval = rnp_strdup(value);
	if ((i = findvar(rnp, name)) < 0) {
		/* add the element to the array */
		if (size_arrays(rnp, rnp->size + 15)) {
			rnp->name[i = rnp->c++] = rnp_strdup(name);
		}
	} else {
		/* replace the element in the array */
		if (rnp->value[i]) {
			free(rnp->value[i]);
			rnp->value[i] = NULL;
		}
	}
	/* sanity checks for range of values */
	if (strcmp(name, "hash") == 0 || strcmp(name, "algorithm") == 0) {
		if (pgp_str_to_hash_alg(newval) == PGP_HASH_UNKNOWN) {
                        fprintf(stderr, "Ignoring unknown hash algo '%s'\n", newval);
			free(newval);
			return 0;
		}
	}
	rnp->value[i] = newval;
	return 1;
}

/* unset a variable */
int
rnp_unsetvar(rnp_t *rnp, const char *name)
{
	int	i;

	if ((i = findvar(rnp, name)) >= 0) {
		if (rnp->value[i]) {
			free(rnp->value[i]);
			rnp->value[i] = NULL;
		}
		rnp->value[i] = NULL;
		return 1;
	}
	return 0;
}

/* get a variable's value (NULL if not set) */
char *
rnp_getvar(rnp_t *rnp, const char *name)
{
	int	i;

	return ((i = findvar(rnp, name)) < 0) ? NULL : rnp->value[i];
}

/* increment a value */
int
rnp_incvar(rnp_t *rnp, const char *name, const int delta)
{
	char *cp;
	char  num[16];
	int   val;

	val = 0;
	if ((cp = rnp_getvar(rnp, name)) != NULL) {
		val = atoi(cp);
	}
	(void) snprintf(num, sizeof(num), "%d", val + delta);
	rnp_setvar(rnp, name, num);
	return 1;
}

/* set keyring format information */
int
rnp_set_keyring_format(rnp_t *rnp, char *format)
{
	if (! parse_keyring_format(rnp, &rnp->keyring_format, format)) {
		return 0;
	}
	rnp_setvar(rnp, "keyring_format", format);
	return 1;
}

/* set the home directory value to "home/subdir" */
int
rnp_set_homedir(rnp_t *rnp, char *home, const int quiet)
{
	struct stat st;
        int ret;

	/* TODO: Replace `stderr` with the rnp context's error file when we
	 *       are sure that all utilities and bindings don't call
	 *       rnp_set_homedir ahead of rnp_init.
	 */

	/* Check that a NULL parameter wasn't passed. */
	if (home == NULL) {
		if (! quiet)
			fprintf(stderr, "rnp: null homedir\n");
		return 0;

	/* If the path is not a directory then fail. */
	} else if ((ret = stat(home, &st)) == 0 && !S_ISDIR(st.st_mode)) {
		if (! quiet)
			fprintf(stderr, "rnp: homedir \"%s\" is not a dir\n", home);
		return 0;

	/* If the path doesn't exist then fail. */
	} else if (ret != 0 && errno == ENOENT) {
		if (! quiet)
			fprintf(stderr, "rnp: warning homedir \"%s\" not found\n", home);
		return 0;

	/* If any other occurred then fail. */
	} else if (ret != 0) {
		if (! quiet)
			fprintf(stderr, "rnp: an unspecified error occurred\n");
		return 0;
	}

	/* Otherwise set the home directory. */
	rnp_setvar(rnp, "homedir", home);

	return 1;
}

/* validate all sigs in the pub keyring */
int
rnp_validate_sigs(rnp_t *rnp)
{
	pgp_validation_t	result;

	return (int)pgp_validate_all_sigs(&result, rnp->pubring, NULL);
}

/* print the json out on 'fp' */
int
rnp_format_json(void *vp, const char *json, const int psigs)
{
	mj_t	 ids;
	FILE	*fp;
	int	 from;
	int	 idc;
	int	 tok;
	int	 to;
	int	 i;

	if ((fp = (FILE *)vp) == NULL || json == NULL) {
		return 0;
	}
	/* ids is an array of strings, each containing 1 entry */
	(void) memset(&ids, 0x0, sizeof(ids));
	from = to = tok = 0;
	/* convert from string into an mj structure */
	(void) mj_parse(&ids, json, &from, &to, &tok);
	if ((idc = mj_arraycount(&ids)) == 1 && strchr(json, '{') == NULL) {
		idc = 0;
	}
	(void) fprintf(fp, "%d key%s found\n", idc, (idc == 1) ? "" : "s");
	for (i = 0 ; i < idc ; i++) {
		format_json_key(fp, &ids.value.v[i], psigs);
	}
	/* clean up */
	mj_delete(&ids);
	return idc;
}

/* find a key in keyring, and write it in ssh format */
int
rnp_write_sshkey(rnp_t *rnp, char *s, const char *userid, char *out, size_t size)
{
	const pgp_key_t	*key;
	pgp_keyring_t	*keyring;
	pgp_io_t	*io;
	unsigned	 k;
	size_t		 cc;
	char		 f[MAXPATHLEN];

	keyring = NULL;
	io = NULL;
	cc = 0;
	if ((io = calloc(1, sizeof(pgp_io_t))) == NULL) {
		(void) fprintf(stderr, "rnp_save_sshpub: bad alloc 1\n");
		goto done;
	}
	io->outs = stdout;
	io->errs = stderr;
	io->res = stderr;
	rnp->io = io;
	/* write new to temp file */
	savepubkey(s, f, sizeof(f));
	if ((keyring = calloc(1, sizeof(*keyring))) == NULL) {
		(void) fprintf(stderr, "rnp_save_sshpub: bad alloc 2\n");
		goto done;
	}
	if (!pgp_keyring_fileread(rnp->pubring = keyring, 1, f)) {
		(void) fprintf(stderr, "cannot import key\n");
		goto done;
	}
	/* get rsa key */
	k = 0;
	key = pgp_getnextkeybyname(rnp->io, rnp->pubring, userid, &k);
	if (key == NULL) {
		(void) fprintf(stderr, "no key found for '%s'\n", userid);
		goto done;
	}
	if (key->key.pubkey.alg != PGP_PKA_RSA) {
		/* we're not interested in supporting DSA either :-) */
		(void) fprintf(stderr, "key not RSA '%s'\n", userid);
		goto done;
	}
	/* XXX - check trust sigs */
	/* XXX - check expiry */
	/* XXX - check start */
	/* XXX - check not weak key */
	/* get rsa e and n */
	(void) memset(out, 0x0, size);
	cc = formatstring((char *)out, (const uint8_t *)"ssh-rsa", 7);
	cc += formatbignum((char *)&out[cc], key->key.pubkey.key.rsa.e);
	cc += formatbignum((char *)&out[cc], key->key.pubkey.key.rsa.n);
done:
	if (io) {
		free(io);
	}
	if (keyring) {
		free(keyring);
	}
	return (int)cc;
}
