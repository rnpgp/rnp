/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "pass-provider.h"

#include <stdio.h>
#include <string.h>
#include <termios.h>

#include <pgp-key.h>
#include <rnp/rnp_sdk.h>

#include "misc.h"

static bool
rnp_getpass(const char *prompt, char *buffer, size_t size)
{
    struct termios saved_flags, noecho_flags;
    bool           restore_ttyflags = false;
    bool           ok = false;
    FILE *         in, *out;

    // validate args
    if (!buffer) {
        goto end;
    }
    // doesn't hurt
    *buffer = '\0';

    in = fopen("/dev/tty", "w+ce");
    if (!in) {
        in = stdin;
        out = stderr;
    } else {
        out = in;
    }

    // save the original termios
    if (tcgetattr(fileno(in), &saved_flags) == 0) {
        noecho_flags = saved_flags;
        // disable echo in the local modes
        noecho_flags.c_lflag = (noecho_flags.c_lflag & ~ECHO) | ECHONL | ISIG;
        restore_ttyflags = (tcsetattr(fileno(in), TCSANOW, &noecho_flags) == 0);
    }
    if (prompt) {
        fputs(prompt, out);
    }
    if (fgets(buffer, size, in) == NULL) {
        goto end;
    }

    // strip trailing newline if needed
    size_t length = strlen(buffer);
    if (length >= 1 && buffer[length - 1] == '\n') {
        buffer[length - 1] = '\0';
    }

    ok = true;
end:
    if (restore_ttyflags) {
        tcsetattr(fileno(in), TCSAFLUSH, &saved_flags);
    }
    return ok;
}

bool
rnp_passphrase_provider_stdin(const pgp_passphrase_ctx_t *ctx,
                              char *                      passphrase,
                              size_t                      passphrase_size,
                              void *                      userdata)
{
    uint8_t keyid[PGP_KEY_ID_SIZE];
    char    keyidhex[PGP_KEY_ID_SIZE * 2 + 1];
    char    target[sizeof(keyidhex) + 16];
    char    prompt[128];
    char    buffer[MAX_PASSPHRASE_LENGTH];
    bool    ok = false;

    if (!ctx || !passphrase || !passphrase_size) {
        goto done;
    }
    if (!pgp_keyid(keyid, PGP_KEY_ID_SIZE, ctx->pubkey)) {
        goto done;
    }
    rnp_strhexdump(keyidhex, keyid, PGP_KEY_ID_SIZE, "");
    snprintf(target, sizeof(target), "key 0x%s", keyidhex);
start:
    snprintf(prompt, sizeof(prompt), "Enter passphrase for %s: ", target);
    if (!rnp_getpass(prompt, passphrase, passphrase_size)) {
        goto done;
    }
    if (ctx->op == PGP_OP_PROTECT) {
        snprintf(prompt, sizeof(prompt), "Repeat passphrase for %s: ", target);
        if (!rnp_getpass(prompt, buffer, sizeof(buffer))) {
            goto done;
        }
        if (strcmp(passphrase, buffer) != 0) {
            printf("Passphrases do not match!\n\n");
            // currently will loop forever
            goto start;
        }
    }
    ok = true;

done:
    pgp_forget(buffer, sizeof(buffer));
    return ok;
}

bool
rnp_passphrase_provider_file(const pgp_passphrase_ctx_t *ctx,
                             char *                      passphrase,
                             size_t                      passphrase_size,
                             void *                      userdata)
{
    FILE *fp = (FILE *) userdata;

    if (!ctx || !passphrase || !passphrase_size || !userdata) {
        return false;
    }
    if (!fgets(passphrase, passphrase_size, fp)) {
        return false;
    }
    size_t length = strlen(passphrase);
    if (passphrase[length - 1] == '\n') {
        passphrase[length - 1] = '\0';
    }
    return true;
}

bool
pgp_request_passphrase(const pgp_passphrase_provider_t *provider,
                       const pgp_passphrase_ctx_t *     ctx,
                       char *                           passphrase,
                       size_t                           passphrase_size)
{
    if (!provider || !provider->callback || !ctx || !passphrase || !passphrase_size) {
        return false;
    }
    return provider->callback(ctx, passphrase, passphrase_size, provider->userdata);
}
