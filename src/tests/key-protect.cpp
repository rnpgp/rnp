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

#include "../librekey/key_store_pgp.h"
#include "pgp-key.h"

#include "rnp_tests.h"
#include "support.h"
#include "utils.h"
#include "crypto/hash.h"

static bool
mpi_empty(const pgp_mpi_t *val)
{
    return val->len == 0;
}

/* This test loads a .gpg keyring and tests protect/unprotect functionality.
 * There is also some lock/unlock testing in here, since the two are
 * somewhat related.
 */
void
test_key_protect_load_pgp(void **state)
{
    rnp_test_state_t * rstate = (rnp_test_state_t *) *state;
    char               path[PATH_MAX];
    pgp_io_t           io = pgp_io_from_fp(stderr, stdout, stdout);
    pgp_key_t *        key = NULL;
    static const char *keyids[] = {"7bc6709b15c23a4a", // primary
                                   "1ed63ee56fadc34d",
                                   "1d7e8a5393c997a8",
                                   "8a05b89fad5aded1",
                                   "2fcadf05ffa501bb", // primary
                                   "54505a936a4a970e",
                                   "326ef111425d14a5"};

    // load our keyring and do some quick checks
    {
        rnp_key_store_t *ks = (rnp_key_store_t *) calloc(1, sizeof(*ks));
        assert_non_null(ks);

        pgp_memory_t mem = {0};
        paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/1/secring.gpg", NULL);
        assert_true(pgp_mem_readfile(&mem, path));
        assert_true(rnp_key_store_pgp_read_from_mem(&io, ks, &mem, NULL));
        pgp_memory_release(&mem);

        for (size_t i = 0; i < ARRAY_SIZE(keyids); i++) {
            pgp_key_t * key = NULL;
            const char *keyid = keyids[i];
            assert_non_null(key = rnp_key_store_get_key_by_name(&io, ks, keyid, NULL));
            assert_non_null(key);
            // all keys in this keyring are encrypted and thus should be both protected and
            // locked initially
            assert_true(pgp_key_is_protected(key));
            assert_true(pgp_key_is_locked(key));
        }

        pgp_key_t *tmp = NULL;
        assert_non_null(tmp = rnp_key_store_get_key_by_name(&io, ks, keyids[0], NULL));
        assert_non_null(tmp);

        // steal this key from the store
        key = (pgp_key_t *) calloc(1, sizeof(*key));
        assert_non_null(key);
        memcpy(key, tmp, sizeof(*key));
        assert_true(rnp_key_store_remove_key(&io, ks, tmp));
        rnp_key_store_free(ks);
    }

    // confirm that this key is indeed RSA
    assert_int_equal(pgp_get_key_alg(key), PGP_PKA_RSA);

    // confirm key material is currently all NULL (in other words, the key is locked)
    assert_true(mpi_empty(&pgp_get_key_material(key)->rsa.d));
    assert_true(mpi_empty(&pgp_get_key_material(key)->rsa.p));
    assert_true(mpi_empty(&pgp_get_key_material(key)->rsa.q));
    assert_true(mpi_empty(&pgp_get_key_material(key)->rsa.u));

    // try to unprotect with a failing password provider
    pgp_password_provider_t pprov = {.callback = failing_password_callback, .userdata = NULL};
    assert_false(pgp_key_unprotect(key, &pprov));

    // try to unprotect with an incorrect password
    pprov = {.callback = string_copy_password_callback, .userdata = (void *) "badpass"};
    assert_false(pgp_key_unprotect(key, &pprov));

    // unprotect with the correct password
    pprov = {.callback = string_copy_password_callback, .userdata = (void *) "password"};
    assert_true(pgp_key_unprotect(key, &pprov));
    assert_false(pgp_key_is_protected(key));

    // should still be locked
    assert_true(pgp_key_is_locked(key));

    // confirm secret key material is still NULL
    assert_true(mpi_empty(&pgp_get_key_material(key)->rsa.d));
    assert_true(mpi_empty(&pgp_get_key_material(key)->rsa.p));
    assert_true(mpi_empty(&pgp_get_key_material(key)->rsa.q));
    assert_true(mpi_empty(&pgp_get_key_material(key)->rsa.u));

    // unlock (no password required since the key is not protected)
    pprov = {.callback = asserting_password_callback, .userdata = NULL};
    assert_true(pgp_key_unlock(key, &pprov));
    assert_false(pgp_key_is_locked(key));

    // secret key material should be available
    assert_false(mpi_empty(&pgp_get_key_material(key)->rsa.d));
    assert_false(mpi_empty(&pgp_get_key_material(key)->rsa.p));
    assert_false(mpi_empty(&pgp_get_key_material(key)->rsa.q));
    assert_false(mpi_empty(&pgp_get_key_material(key)->rsa.u));

    // save the secret MPIs for some later comparisons
    pgp_mpi_t d = pgp_get_key_material(key)->rsa.d;
    pgp_mpi_t p = pgp_get_key_material(key)->rsa.p;
    pgp_mpi_t q = pgp_get_key_material(key)->rsa.q;
    pgp_mpi_t u = pgp_get_key_material(key)->rsa.u;

    // confirm that packets[0] is no longer encrypted
    {
        rnp_key_store_t *ks = (rnp_key_store_t *) calloc(1, sizeof(*ks));
        assert_non_null(ks);

        pgp_memory_t mem = {0};
        mem.buf = key->packets[0].raw;
        mem.length = key->packets[0].length;
        assert_true(rnp_key_store_pgp_read_from_mem(&io, ks, &mem, NULL));

        // grab the first key
        pgp_key_t *reloaded_key = NULL;
        assert_non_null(reloaded_key =
                          rnp_key_store_get_key_by_name(&io, ks, keyids[0], NULL));
        assert_non_null(reloaded_key);

        // should not be locked, nor protected
        assert_false(pgp_key_is_locked(reloaded_key));
        assert_false(pgp_key_is_protected(reloaded_key));
        // secret key material should not be NULL
        assert_false(mpi_empty(&pgp_get_key_material(reloaded_key)->rsa.d));
        assert_false(mpi_empty(&pgp_get_key_material(reloaded_key)->rsa.p));
        assert_false(mpi_empty(&pgp_get_key_material(reloaded_key)->rsa.q));
        assert_false(mpi_empty(&pgp_get_key_material(reloaded_key)->rsa.u));

        // compare MPIs of the reloaded key, with the unlocked key from earlier
        assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.d,
                              &pgp_get_key_material(reloaded_key)->rsa.d));
        assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.p,
                              &pgp_get_key_material(reloaded_key)->rsa.p));
        assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.q,
                              &pgp_get_key_material(reloaded_key)->rsa.q));
        assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.u,
                              &pgp_get_key_material(reloaded_key)->rsa.u));
        // negative test to try to ensure the above is a valid test
        assert_false(mpi_equal(&pgp_get_key_material(key)->rsa.d,
                               &pgp_get_key_material(reloaded_key)->rsa.p));

        // lock it
        assert_true(pgp_key_lock(reloaded_key));
        assert_true(pgp_key_is_locked(reloaded_key));
        // confirm that secret MPIs are NULL again
        assert_true(mpi_empty(&pgp_get_key_material(reloaded_key)->rsa.d));
        assert_true(mpi_empty(&pgp_get_key_material(reloaded_key)->rsa.p));
        assert_true(mpi_empty(&pgp_get_key_material(reloaded_key)->rsa.q));
        assert_true(mpi_empty(&pgp_get_key_material(reloaded_key)->rsa.u));
        // unlock it (no password, since it's not protected)
        pgp_password_provider_t pprov = {.callback = asserting_password_callback,
                                         .userdata = NULL};
        assert_true(pgp_key_unlock(reloaded_key, &pprov));
        assert_false(pgp_key_is_locked(reloaded_key));
        // compare MPIs of the reloaded key, with the unlocked key from earlier
        assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.d,
                              &pgp_get_key_material(reloaded_key)->rsa.d));
        assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.p,
                              &pgp_get_key_material(reloaded_key)->rsa.p));
        assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.q,
                              &pgp_get_key_material(reloaded_key)->rsa.q));
        assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.u,
                              &pgp_get_key_material(reloaded_key)->rsa.u));

        rnp_key_store_free(ks);
    }

    // lock
    assert_true(pgp_key_lock(key));

    // try to protect (will fail when key is locked)
    pprov = {.callback = string_copy_password_callback, .userdata = (void *) "newpass"};
    assert_false(rnp_key_add_protection(key,
                                        key->format, // same format
                                        NULL,        // default protection
                                        &pprov));
    assert_false(pgp_key_is_protected(key));

    // unlock
    pprov = {.callback = asserting_password_callback, .userdata = NULL};
    assert_true(pgp_key_unlock(key, &pprov));
    assert_false(pgp_key_is_locked(key));

    // try to protect with a failing password provider
    pprov = {.callback = failing_password_callback, .userdata = NULL};
    assert_false(rnp_key_add_protection(key,
                                        key->format, // same format
                                        NULL,        // default protection
                                        &pprov));
    assert_false(pgp_key_is_protected(key));

    // (re)protect with a new password
    pprov = {.callback = string_copy_password_callback, .userdata = (void *) "newpass"};
    assert_true(rnp_key_add_protection(key,
                                       key->format, // same format
                                       NULL,        // default protection
                                       &pprov));
    assert_true(pgp_key_is_protected(key));

    // lock
    assert_true(pgp_key_lock(key));
    assert_true(pgp_key_is_locked(key));

    // try to unlock with old password
    pprov = {.callback = string_copy_password_callback, .userdata = (void *) "password"};
    assert_false(pgp_key_unlock(key, &pprov));
    assert_true(pgp_key_is_locked(key));

    // unlock with new password
    pprov = {.callback = string_copy_password_callback, .userdata = (void *) "newpass"};
    assert_true(pgp_key_unlock(key, &pprov));
    assert_false(pgp_key_is_locked(key));

    // compare secret MPIs with those from earlier
    assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.d, &d));
    assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.p, &p));
    assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.q, &q));
    assert_true(mpi_equal(&pgp_get_key_material(key)->rsa.u, &u));

    // cleanup
    pgp_key_free(key);
}
