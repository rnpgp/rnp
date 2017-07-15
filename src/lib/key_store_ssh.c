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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include "bufgap.h"

#include "bn.h"
#include "packet-parse.h"
#include "rnpdefs.h"
#include "rnpsdk.h"
#include "crypto.h"
#include "s2k.h"
#include "packet-key.h"
#include "key_store_internal.h"
#include "packet.h"

/* structure for earching for constant strings */
typedef struct str_t {
    const char *s;    /* string */
    size_t      len;  /* its length */
    int         type; /* return type */
} str_t;

#ifndef USE_ARG
#define USE_ARG(x) /*LINTED*/ (void) &x
#endif

static const uint8_t base64s[] =
  /* 000 */ "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            /* 016 */ "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            /* 032 */ "\0\0\0\0\0\0\0\0\0\0\0?\0\0\0@"
            /* 048 */ "56789:;<=>\0\0\0\0\0\0"
            /* 064 */ "\0\1\2\3\4\5\6\7\10\11\12\13\14\15\16\17"
            /* 080 */ "\20\21\22\23\24\25\26\27\30\31\32\0\0\0\0\0"
            /* 096 */ "\0\33\34\35\36\37 !\"#$%&'()"
            /* 112 */ "*+,-./01234\0\0\0\0\0"
            /* 128 */ "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            /* 144 */ "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            /* 160 */ "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            /* 176 */ "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            /* 192 */ "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            /* 208 */ "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            /* 224 */ "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            /* 240 */ "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/* short function to decode from base64 */
/* inspired by an ancient copy of b64.c, then rewritten, the bugs are all mine */
static int
frombase64(char *dst, const char *src, size_t size, int flag)
{
    uint8_t out[3];
    uint8_t in[4];
    uint8_t b;
    size_t  srcc;
    int     dstc;
    int     gotc;
    int     i;

    USE_ARG(flag);
    for (dstc = 0, srcc = 0; srcc < size;) {
        for (gotc = 0, i = 0; i < 4 && srcc < size; i++) {
            for (b = 0x0; srcc < size && b == 0x0;) {
                b = base64s[(unsigned) src[srcc++]];
            }
            if (srcc < size) {
                gotc += 1;
                if (b) {
                    in[i] = (uint8_t)(b - 1);
                }
            } else {
                in[i] = 0x0;
            }
        }
        if (gotc) {
            out[0] = (uint8_t)((unsigned) in[0] << 2 | (unsigned) in[1] >> 4);
            out[1] = (uint8_t)((unsigned) in[1] << 4 | (unsigned) in[2] >> 2);
            out[2] = (uint8_t)(((in[2] << 6) & 0xc0) | in[3]);
            for (i = 0; i < gotc - 1; i++) {
                *dst++ = out[i];
            }
            dstc += gotc - 1;
        }
    }
    return dstc;
}

/* get a bignum from the buffer gap */
static BIGNUM *
getbignum(bufgap_t *bg, char *buf, const char *header)
{
    uint32_t len;
    BIGNUM * bignum;

    (void) bufgap_getbin(bg, &len, sizeof(len));
    len = ntohl(len);
    (void) bufgap_seek(bg, sizeof(len), BGFromHere, BGByte);
    (void) bufgap_getbin(bg, buf, len);
    bignum = BN_bin2bn((const uint8_t *) buf, (int) len, NULL);
    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, header, (const uint8_t *) (void *) buf, len);
    }
    (void) bufgap_seek(bg, len, BGFromHere, BGByte);
    return bignum;
}

static str_t pkatypes[] = {{"ssh-rsa", 7, PGP_PKA_RSA},
                           {"ssh-dss", 7, PGP_PKA_DSA},
                           {"ssh-dsa", 7, PGP_PKA_DSA},
                           {NULL, 0, 0}};

/* look for a string in the given array */
static int
findstr(str_t *array, const char *name)
{
    str_t *sp;

    for (sp = array; sp->s; sp++) {
        if (strncmp(name, sp->s, sp->len) == 0) {
            return sp->type;
        }
    }
    return -1;
}

/* ssh-style fingerprint calculation, moved here from the pgp_fingerprint */
static int
ssh_fingerprint(pgp_fingerprint_t *fp, const pgp_pubkey_t *key)
{
    pgp_memory_t *mem;
    pgp_hash_t    hash = {0};
    const char *  type;
    uint32_t      len;

    if (!pgp_hash_create(&hash, PGP_HASH_MD5)) {
        (void) fprintf(stderr, "ssh_fingerprint: bad md5 alloc\n");
        return RNP_FAIL;
    }

    type = (key->alg == PGP_PKA_RSA) ? "ssh-rsa" : "ssh-dss";
    hash_string(&hash, (const uint8_t *) (const void *) type, (unsigned) strlen(type));
    switch (key->alg) {
    case PGP_PKA_RSA:
        hash_bignum(&hash, key->key.rsa.e);
        hash_bignum(&hash, key->key.rsa.n);
        break;
    case PGP_PKA_DSA:
        hash_bignum(&hash, key->key.dsa.p);
        hash_bignum(&hash, key->key.dsa.q);
        hash_bignum(&hash, key->key.dsa.g);
        hash_bignum(&hash, key->key.dsa.y);
        break;
    default:
        break;
    }

    fp->length = pgp_hash_finish(&hash, fp->fingerprint);
    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "md5 ssh fingerprint", fp->fingerprint, fp->length);
    }

    return RNP_OK;
}

static int
ssh_keyid(uint8_t *keyid, const size_t idlen, const pgp_pubkey_t *key)
{
    pgp_fingerprint_t finger;

    ssh_fingerprint(&finger, key);
    (void) memcpy(keyid, finger.fingerprint + finger.length - idlen, idlen);

    return RNP_OK;
}

/* convert an ssh (host) pubkey to a pgp pubkey */
static int
ssh2pubkey(pgp_io_t *io, const char *f, pgp_key_t *key)
{
    pgp_pubkey_t *pubkey;
    struct stat   st;
    bufgap_t      bg;
    uint32_t      len;
    int64_t       off;
    uint8_t *     userid;
    char          hostname[_POSIX_HOST_NAME_MAX + 1];
    char          owner[_POSIX_LOGIN_NAME_MAX + sizeof(hostname) + 1];
    char *        space;
    char *        buf;
    char *        bin;
    int           ok;
    int           cc;

    memset(&bg, 0x0, sizeof(bg));
    if (!bufgap_open(&bg, f)) {
        fprintf(stderr, "ssh2pubkey: can't open '%s'\n", f);
        return RNP_FAIL;
    }

    /* check the pub file exists */
    if (stat(f, &st) != 0) {
        (void) fprintf(stderr, "ssh2pubkey: bad filename '%s'\n", f);
        bufgap_close(&bg);
        return RNP_FAIL;
    }

    if ((buf = calloc(1, (size_t) st.st_size)) == NULL) {
        fprintf(stderr, "can't calloc %zu bytes for '%s'\n", (size_t) st.st_size, f);
        bufgap_close(&bg);
        return RNP_FAIL;
    }
    if ((bin = calloc(1, (size_t) st.st_size)) == NULL) {
        fprintf(stderr, "can't calloc %zu bytes for '%s'\n", (size_t) st.st_size, f);
        free((void *) buf);
        bufgap_close(&bg);
        return RNP_FAIL;
    }

    /* move past ascii type of key */
    while (bufgap_peek(&bg, 0) != ' ')
        bufgap_seek(&bg, 1, BGFromHere, BGByte);
    bufgap_seek(&bg, 1, BGFromHere, BGByte);
    off = bufgap_tell(&bg, BGFromBOF, BGByte);

    if (bufgap_size(&bg, BGByte) - off < 10) {
        fprintf(stderr, "bad key file '%s'\n", f);
        free((void *) buf);
        free((void *) bin);
        bufgap_close(&bg);
        return RNP_FAIL;
    }

    /* convert from base64 to binary */
    cc = bufgap_getbin(&bg, buf, (size_t) bg.bcc);
    if ((space = strchr(buf, ' ')) != NULL) {
        cc = (int) (space - buf);
    }
    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, NULL, (const uint8_t *) (const void *) buf, (size_t) cc);
    }
    cc = frombase64(bin, buf, (size_t) cc, 0);
    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "decoded base64:", (const uint8_t *) (const void *) bin, (size_t) cc);
    }
    bufgap_delete(&bg, (uint64_t) bufgap_tell(&bg, BGFromEOF, BGByte));
    bufgap_insert(&bg, bin, cc);
    bufgap_seek(&bg, off, BGFromBOF, BGByte);

    /* get the type of key */
    bufgap_getbin(&bg, &len, sizeof(len));
    len = ntohl(len);
    bufgap_seek(&bg, sizeof(len), BGFromHere, BGByte);
    bufgap_getbin(&bg, buf, len);
    bufgap_seek(&bg, len, BGFromHere, BGByte);

    memset(key, 0x0, sizeof(*key));
    pubkey = &key->key.seckey.pubkey;
    pubkey->version = PGP_V4;
    pubkey->birthtime = 0;
    /* get key type */
    ok = RNP_OK;
    switch (pubkey->alg = findstr(pkatypes, buf)) {
    case PGP_PKA_RSA:
        /* get the 'e' param of the key */
        pubkey->key.rsa.e = getbignum(&bg, buf, "RSA E");
        /* get the 'n' param of the key */
        pubkey->key.rsa.n = getbignum(&bg, buf, "RSA N");
        break;
    case PGP_PKA_DSA:
        /* get the 'p' param of the key */
        pubkey->key.dsa.p = getbignum(&bg, buf, "DSA P");
        /* get the 'q' param of the key */
        pubkey->key.dsa.q = getbignum(&bg, buf, "DSA Q");
        /* get the 'g' param of the key */
        pubkey->key.dsa.g = getbignum(&bg, buf, "DSA G");
        /* get the 'y' param of the key */
        pubkey->key.dsa.y = getbignum(&bg, buf, "DSA Y");
        break;
    default:
        fprintf(stderr, "Unrecognised pubkey type %d for '%s'\n", pubkey->alg, f);
        ok = RNP_FAIL;
        break;
    }

    /* check for stragglers */
    if (ok && bufgap_tell(&bg, BGFromEOF, BGByte) > 0) {
        printf("%" PRIi64 " bytes left\n", bufgap_tell(&bg, BGFromEOF, BGByte));
        printf("[%s]\n", bufgap_getstr(&bg));
        ok = RNP_FAIL;
    }
    if (ok) {
        memset(&userid, 0x0, sizeof(userid));
        gethostname(hostname, sizeof(hostname));
        if (strlen(space + 1) - 1 == 0) {
            snprintf(owner, sizeof(owner), "root@%s", hostname);
        } else {
            snprintf(owner, sizeof(owner), "%.*s", (int) strlen(space + 1) - 1, space + 1);
        }

        /* This overall function needs to be broken up and this
         * code brought back out.
         */
        {
            static const size_t buffer_size =
              sizeof(hostname) + sizeof(owner) + sizeof(f) + 64;

            char *buffer = (char *) malloc(buffer_size);

            if (buffer == NULL) {
                fputs("failed to allocate buffer: "
                      "insufficient memory\n",
                      stderr);
                free((void *) bin);
                free((void *) buf);
                bufgap_close(&bg);
                return RNP_FAIL;
            }
            snprintf(buffer, buffer_size, "%s (%s) <%s>", hostname, f, owner);
            userid = (uint8_t *) buffer;
        }
        ssh_keyid(key->sigid, sizeof(key->sigid), pubkey);
        pgp_add_userid(key, userid);
        ssh_fingerprint(&key->sigfingerprint, pubkey);

        free((void *) userid);

        if (rnp_get_debug(__FILE__)) {
            /*pgp_print_keydata(io, keyring, key, "pub", pubkey, 0);*/
            __PGP_USED(io); /* XXX */
        }
    }
    free((void *) bin);
    free((void *) buf);
    bufgap_close(&bg);
    return ok;
}

/* convert an ssh (host) seckey to a pgp seckey */
static int
ssh2seckey(pgp_io_t *io, const char *f, pgp_key_t *key, pgp_pubkey_t *pubkey)
{
    pgp_crypt_t crypted;
    uint8_t     sesskey[PGP_MAX_KEY_SIZE];
    unsigned    sesskey_len;

    __PGP_USED(io);
    /* XXX - check for rsa/dsa */
    if (!read_pem_seckey(f, key, "ssh-rsa", 0)) {
        return RNP_FAIL;
    }
    if (rnp_get_debug(__FILE__)) {
        /*pgp_print_keydata(io, key, "sec", &key->key.seckey.pubkey, 0);*/
        /* XXX */
    }
    /* let's add some sane defaults */
    (void) memcpy(&key->key.seckey.pubkey, pubkey, sizeof(*pubkey));
    key->key.seckey.pubkey.alg = PGP_PKA_RSA;
    key->key.seckey.s2k_usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
    key->key.seckey.alg = PGP_SA_CAST5;
    key->key.seckey.s2k_specifier = PGP_S2KS_SALTED;
    key->key.seckey.hash_alg = PGP_HASH_SHA1;

    if (pgp_random(key->key.seckey.salt, PGP_SALT_SIZE)) {
        (void) fprintf(stderr, "pgp_random failed\n");
        return RNP_FAIL;
    }

    if (key->key.seckey.pubkey.alg == PGP_PKA_RSA) {
        /* openssh and openssl have p and q swapped */
        BIGNUM *tmp = key->key.seckey.key.rsa.p;
        key->key.seckey.key.rsa.p = key->key.seckey.key.rsa.q;
        key->key.seckey.key.rsa.q = tmp;
    }

    sesskey_len = pgp_key_size(key->key.seckey.alg);

    if (pgp_s2k_salted(
          key->key.seckey.hash_alg, sesskey, sesskey_len, "", key->key.seckey.salt)) {
        (void) fprintf(stderr, "pgp_s2k_salted failed\n");
        return RNP_FAIL;
    }

    pgp_crypt_any(&crypted, key->key.seckey.alg);
    pgp_cipher_set_iv(&crypted, key->key.seckey.iv);
    pgp_cipher_set_key(&crypted, sesskey);
    pgp_encrypt_init(&crypted);
    ssh_fingerprint(&key->sigfingerprint, pubkey);
    ssh_keyid(key->sigid, sizeof(key->sigid), pubkey);
    return RNP_OK;
}

/* read a key from the ssh file, and add it to a keyring */
static int
ssh2_readkeys(pgp_io_t *       io,
              rnp_key_store_t *pubring,
              rnp_key_store_t *secring,
              const char *     pubfile,
              const char *     secfile)
{
    pgp_key_t *pubkey;
    pgp_key_t *seckey;
    pgp_key_t  key;

    pubkey = NULL;
    (void) memset(&key, 0x0, sizeof(key));
    if (pubfile) {
        if (rnp_get_debug(__FILE__)) {
            (void) fprintf(io->errs, "ssh2_readkeys: pubfile '%s'\n", pubfile);
        }
        if (!ssh2pubkey(io, pubfile, &key)) {
            (void) fprintf(io->errs, "ssh2_readkeys: can't read pubkeys '%s'\n", pubfile);
            return RNP_FAIL;
        }
        EXPAND_ARRAY(pubring, key);
        if (pubring->keys == NULL) {
            return RNP_FAIL;
        }
        pubkey = &pubring->keys[pubring->keyc++];
        (void) memcpy(pubkey, &key, sizeof(key));
        pubkey->type = PGP_PTAG_CT_PUBLIC_KEY;
    }
    if (secfile) {
        if (rnp_get_debug(__FILE__)) {
            (void) fprintf(io->errs, "ssh2_readkeys: secfile '%s'\n", secfile);
        }
        if (pubkey == NULL) {
            pubkey = &pubring->keys[0];
        }
        if (!ssh2seckey(io, secfile, &key, &pubkey->key.pubkey)) {
            (void) fprintf(io->errs, "ssh2_readkeys: can't read seckeys '%s'\n", secfile);
            return RNP_FAIL;
        }
        EXPAND_ARRAY(secring, key);
        if (secring->keys == NULL) {
            return RNP_FAIL;
        }
        seckey = &secring->keys[secring->keyc++];
        (void) memcpy(seckey, &key, sizeof(key));
        seckey->type = PGP_PTAG_CT_SECRET_KEY;
    }
    return RNP_OK;
}

/* read keys from ssh key files */
static int
readsshkeys(rnp_t *rnp, const char *pubpath, const char *secpath)
{
    rnp_key_store_t *pubring;
    rnp_key_store_t *secring;
    struct stat      st;

    /* check the pub file exists */
    if (stat(pubpath, &st) != 0) {
        (void) fprintf(stderr, "readsshkeys: bad pubkey filename '%s'\n", pubpath);
        return RNP_FAIL;
    }
    if ((pubring = calloc(1, sizeof(*pubring))) == NULL) {
        (void) fprintf(stderr, "readsshkeys: bad alloc\n");
        return RNP_FAIL;
    }
    /* openssh2 keys use md5 by default. actually this hashtype makes no sense and should be
     * removed later */
    pubring->hashtype = PGP_HASH_MD5;
    if (!ssh2_readkeys(rnp->io, pubring, NULL, pubpath, NULL)) {
        free(pubring);
        (void) fprintf(stderr, "readsshkeys: cannot read %s\n", pubpath);
        return RNP_FAIL;
    }
    if (rnp->pubring == NULL) {
        rnp->pubring = pubring;
    } else {
        rnp_key_store_append_keyring(rnp->pubring, pubring);
    }

    if (secpath) {
        if ((secring = calloc(1, sizeof(*secring))) == NULL) {
            free(pubring);
            (void) fprintf(stderr, "readsshkeys: bad alloc\n");
            return RNP_FAIL;
        }
        secring->hashtype = PGP_HASH_MD5;
        if (!ssh2_readkeys(rnp->io, pubring, secring, NULL, secpath)) {
            free(pubring);
            free(secring);
            (void) fprintf(stderr, "readsshkeys: cannot read sec %s\n", secpath);
            return RNP_FAIL;
        }
        rnp->secring = secring;
    }
    return RNP_OK;
}

int
rnp_key_store_ssh_load_keys(rnp_t *rnp, const char *pubpath, const char *secpath)
{
    if (!readsshkeys(rnp, pubpath, secpath)) {
        fprintf(rnp->io->errs, "cannot read ssh keys\n");
        return RNP_FAIL;
    }

    return RNP_OK;
}

int
rnp_key_store_ssh_from_file(pgp_io_t *io, rnp_key_store_t *keyring, const char *filename)
{
    char      f[MAXPATHLEN];
    pgp_key_t key;
    pgp_key_t pubkey;

    (void) memset(&key, 0x0, sizeof(key));
    (void) memset(&pubkey, 0x0, sizeof(pubkey));

    if (rnp_get_debug(__FILE__)) {
        (void) fprintf(
          io->errs, "rnp_key_store_ssh_from_file: read as pubkey '%s'\n", filename);
    }

    if (ssh2pubkey(io, filename, &key)) {
        (void) fprintf(io->errs, "rnp_key_store_ssh_from_file: it's pubkeys '%s'\n", filename);
        rnp_key_store_add_key(io, keyring, &key, PGP_PTAG_CT_PUBLIC_KEY);
        return RNP_OK;
    }

    if (rnp_get_debug(__FILE__)) {
        (void) fprintf(
          io->errs, "rnp_key_store_ssh_from_file: read as seckey '%s'\n", filename);
    }

    (void) snprintf(f, sizeof(f), "%s.pub", filename);
    if (!ssh2pubkey(io, filename, &pubkey)) {
        (void) fprintf(
          io->errs, "rnp_key_store_ssh_from_file: can't read pubkey from '%s'\n", f);
        return RNP_FAIL;
    }

    if (ssh2seckey(io, filename, &key, &pubkey.key.pubkey)) {
        (void) fprintf(io->errs, "rnp_key_store_ssh_from_file: it's seckey '%s'\n", filename);
        rnp_key_store_add_key(io, keyring, &key, PGP_PTAG_CT_SECRET_KEY);
        return RNP_OK;
    }

    return RNP_FAIL;
}

int
rnp_key_store_ssh_from_mem(pgp_io_t *io, rnp_key_store_t *key_store, pgp_memory_t *memory)
{
    // we can't read SSH key from memory because it doesn't keep two different part for public
    // and secret key
    fprintf(io->errs, "rnp hasn't support reading SSH key from memory yet\n");
    return RNP_FAIL;
}

int
rnp_key_store_ssh_to_file(pgp_io_t *       io,
                          rnp_key_store_t *key_store,
                          const uint8_t *  passphase,
                          const char *     file)
{
    fprintf(io->errs, "rnp hasn't support writing SSH key to file yet\n");
    return RNP_FAIL;
}

int
rnp_key_store_ssh_to_mem(pgp_io_t *       io,
                         rnp_key_store_t *key_store,
                         const uint8_t *  passphase,
                         pgp_memory_t *   memory)
{
    // we can't write SSH key to memory because it doesn't keep two different part for public
    // and secret key
    fprintf(io->errs, "rnp hasn't support writing SSH key to memory yet\n");
    return RNP_FAIL;
}
