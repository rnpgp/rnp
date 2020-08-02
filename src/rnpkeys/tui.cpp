/*
 * Copyright (c) 2017-2020, [Ribose Inc](https://www.ribose.com).
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

#include <algorithm>
#ifdef _MSC_VER
#include "uniwin.h"
#else
#include <unistd.h>
#endif
#include <errno.h>
#include <iterator>
#include "rnp/rnpcfg.h"
#include "rnpkeys.h"
#include "defaults.h"
#include "utils.h"

/* -----------------------------------------------------------------------------
 * @brief   Reads input from file pointer and converts it securelly to ints
 *          Partially based on ERR34-C from SEI CERT C Coding Standarad
 *
 * @param   fp          pointer to opened pipe
 * @param   result[out] result read from file pointer and converted to int
 *
 * @returns true and value in result if integer was parsed correctly,
 *          otherwise false
 *
-------------------------------------------------------------------------------- */
static bool
rnp_secure_get_long_from_fd(FILE *fp, long *result, bool allow_empty)
{
    char  buff[BUFSIZ];
    char *end_ptr;
    long  num_long;
    bool  ret = false;

    if (!result) {
        goto end;
    }

    if (fgets(buff, sizeof(buff), fp) == NULL) {
        RNP_LOG("EOF or read error");
        goto end;
    } else {
        errno = 0;
        num_long = strtol(buff, &end_ptr, 10);

        if (ERANGE == errno) {
            RNP_LOG("Number out of range");
            goto end;
        } else if (end_ptr == buff) {
            ret = allow_empty;
            goto end;
        } else if ('\n' != *end_ptr && '\0' != *end_ptr) {
            RNP_LOG("Unexpected end of line");
            goto end;
        }
    }

    *result = num_long;
    ret = true;

end:
    return ret;
}

static bool
is_rsa_keysize_supported(uint32_t keysize)
{
    return ((keysize >= 1024) && (keysize <= 4096) && !(keysize % 8));
}

static const char *
ask_curve_name(FILE *input_fp)
{
    const char *              result = NULL;
    long                      val = 0;
    bool                      ok = false;
    std::vector<const char *> curves;
    static const char *const  known_curves[] = {
      "NIST P-256",
      "NIST P-384",
      "NIST P-521",
      "brainpoolP256r1",
      "brainpoolP384r1",
      "brainpoolP512r1",
      "secp256k1",
    };

    try {
        std::copy_if(known_curves,
                     known_curves + ARRAY_SIZE(known_curves),
                     std::back_inserter(curves),
                     [](const char *curve) {
                         bool supported = false;
                         return !rnp_supports_feature("elliptic curve", curve, &supported) &&
                                supported;
                     });
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return NULL;
    }
    const size_t ccount = curves.size();
    do {
        printf("Please select which elliptic curve you want:\n");
        for (size_t i = 0; i < ccount; i++) {
            printf("\t(%zu) %s\n", i + 1, curves[i]);
        }
        printf("(default %s)> ", DEFAULT_CURVE);
        ok = rnp_secure_get_long_from_fd(input_fp, &val, true) && (val > 0) &&
             (val <= (long) ccount);
        if (ok) {
            result = curves[val - 1];
        }
    } while (!ok);

    return result;
}

static long
ask_rsa_bitlen(FILE *input_fp)
{
    long result = 0;
    do {
        result = DEFAULT_RSA_NUMBITS;
        printf("Please provide bit length of the key (between 1024 and 4096):\n(default %d)> ",
               DEFAULT_RSA_NUMBITS);
    } while (!rnp_secure_get_long_from_fd(input_fp, &result, true) ||
             !is_rsa_keysize_supported(result));
    return result;
}

static long
ask_dsa_bitlen(FILE *input_fp)
{
    long result = 0;
    do {
        result = DSA_DEFAULT_P_BITLEN;
        printf(
          "Please provide bit length of the DSA key (between %d and %d):\n(default %d) > ",
          DSA_MIN_P_BITLEN,
          DSA_MAX_P_BITLEN,
          DSA_DEFAULT_P_BITLEN);
    } while (!rnp_secure_get_long_from_fd(input_fp, &result, true) ||
             (result < DSA_MIN_P_BITLEN) || (result > DSA_MAX_P_BITLEN));

    // round up to multiple of 1024
    result = ((result + 63) / 64) * 64;
    printf("Bitlen of the key will be %lu\n", result);
    return result;
}

static bool
rnpkeys_ask_generate_params(rnp_cfg_t *cfg, FILE *input_fp)
{
    long option = 0;
    bool res = true;
    do {
        printf("Please select what kind of key you want:\n"
               "\t(1)  RSA (Encrypt or Sign)\n"
               "\t(16) DSA + ElGamal\n"
               "\t(17) DSA + RSA\n" // TODO: See #584
               "\t(19) ECDSA + ECDH\n"
               "\t(22) EDDSA + X25519\n"
               "\t(99) SM2\n"
               "> ");
        if (!rnp_secure_get_long_from_fd(input_fp, &option, false)) {
            option = 0;
            continue;
        }
        switch (option) {
        case 1: {
            long bits = ask_rsa_bitlen(input_fp);
            res = res && rnp_cfg_setstr(cfg, CFG_KG_PRIMARY_ALG, RNP_ALGNAME_RSA) &&
                  rnp_cfg_setstr(cfg, CFG_KG_SUBKEY_ALG, RNP_ALGNAME_RSA) &&
                  rnp_cfg_setint(cfg, CFG_KG_PRIMARY_BITS, bits) &&
                  rnp_cfg_setint(cfg, CFG_KG_SUBKEY_BITS, bits);
            break;
        }
        case 16: {
            long bits = ask_dsa_bitlen(input_fp);
            res = res && rnp_cfg_setstr(cfg, CFG_KG_PRIMARY_ALG, RNP_ALGNAME_DSA) &&
                  rnp_cfg_setstr(cfg, CFG_KG_SUBKEY_ALG, RNP_ALGNAME_ELGAMAL) &&
                  rnp_cfg_setint(cfg, CFG_KG_PRIMARY_BITS, bits) &&
                  rnp_cfg_setint(cfg, CFG_KG_SUBKEY_BITS, bits);
            break;
        }
        case 17: {
            long bits = ask_dsa_bitlen(input_fp);
            res = res && rnp_cfg_setstr(cfg, CFG_KG_PRIMARY_ALG, RNP_ALGNAME_DSA) &&
                  rnp_cfg_setstr(cfg, CFG_KG_SUBKEY_ALG, RNP_ALGNAME_RSA) &&
                  rnp_cfg_setint(cfg, CFG_KG_PRIMARY_BITS, bits) &&
                  rnp_cfg_setint(cfg, CFG_KG_SUBKEY_BITS, bits);
            break;
        }
        case 19: {
            const char *curve = ask_curve_name(input_fp);
            res = res && rnp_cfg_setstr(cfg, CFG_KG_PRIMARY_ALG, RNP_ALGNAME_ECDSA) &&
                  rnp_cfg_setstr(cfg, CFG_KG_SUBKEY_ALG, RNP_ALGNAME_ECDH) &&
                  rnp_cfg_setstr(cfg, CFG_KG_PRIMARY_CURVE, curve) &&
                  rnp_cfg_setstr(cfg, CFG_KG_SUBKEY_CURVE, curve);
            break;
        }
        case 22: {
            res = res && rnp_cfg_setstr(cfg, CFG_KG_PRIMARY_ALG, RNP_ALGNAME_EDDSA) &&
                  rnp_cfg_setstr(cfg, CFG_KG_SUBKEY_ALG, RNP_ALGNAME_ECDH) &&
                  rnp_cfg_setstr(cfg, CFG_KG_SUBKEY_CURVE, "Curve25519");
            break;
        }
        case 99: {
            res = res && rnp_cfg_setstr(cfg, CFG_KG_PRIMARY_ALG, RNP_ALGNAME_SM2) &&
                  rnp_cfg_setstr(cfg, CFG_KG_SUBKEY_ALG, RNP_ALGNAME_SM2);
            if (!rnp_cfg_hasval(cfg, CFG_KG_HASH)) {
                res = res && rnp_cfg_setstr(cfg, CFG_KG_HASH, RNP_ALGNAME_SM3);
            }
            break;
        }
        default:
            option = 0;
            break;
        }
    } while (!option);

    return res;
}

bool
cli_rnp_set_generate_params(rnp_cfg_t *cfg)
{
    bool res = true;
    // hash algorithms for signing and protection
    if (rnp_cfg_hasval(cfg, CFG_HASH)) {
        res = res && rnp_cfg_setstr(cfg, CFG_KG_HASH, rnp_cfg_getstr(cfg, CFG_HASH)) &&
              rnp_cfg_setstr(cfg, CFG_KG_PROT_HASH, rnp_cfg_getstr(cfg, CFG_HASH));
    }

    // key and subkey algorithms, bit length/curve
    if (!rnp_cfg_getbool(cfg, CFG_EXPERT)) {
        res = res && rnp_cfg_setstr(cfg, CFG_KG_PRIMARY_ALG, RNP_ALGNAME_RSA);
        res =
          res && rnp_cfg_setint(cfg, CFG_KG_PRIMARY_BITS, rnp_cfg_getint(cfg, CFG_NUMBITS));
        res = res && rnp_cfg_setstr(cfg, CFG_KG_SUBKEY_ALG, RNP_ALGNAME_RSA);
        res = res && rnp_cfg_setint(cfg, CFG_KG_SUBKEY_BITS, rnp_cfg_getint(cfg, CFG_NUMBITS));
    } else {
        FILE *input = stdin;
        if (rnp_cfg_hasval(cfg, CFG_USERINPUTFD)) {
            int inputfd = dup(rnp_cfg_getint(cfg, CFG_USERINPUTFD));
            if (inputfd != -1) {
                input = fdopen(inputfd, "r");
                if (!input) {
                    close(inputfd);
                }
            }
        }
        res = res && input && rnpkeys_ask_generate_params(cfg, input);
        if (input && (input != stdin)) {
            fclose(input);
        }
    }

    // make sure hash algorithms are set
    if (!rnp_cfg_hasval(cfg, CFG_KG_HASH)) {
        res = res && rnp_cfg_setstr(cfg, CFG_KG_HASH, DEFAULT_HASH_ALG);
    }
    if (!rnp_cfg_hasval(cfg, CFG_KG_PROT_HASH)) {
        res = res && rnp_cfg_setstr(cfg, CFG_KG_PROT_HASH, DEFAULT_HASH_ALG);
    }

    // protection symmetric algorithm
    res =
      res && rnp_cfg_setstr(cfg,
                            CFG_KG_PROT_ALG,
                            rnp_cfg_hasval(cfg, CFG_CIPHER) ? rnp_cfg_getstr(cfg, CFG_CIPHER) :
                                                              DEFAULT_SYMM_ALG);
    // protection iterations count
    size_t iterations = rnp_cfg_getint(cfg, CFG_S2K_ITER);
    if (!iterations) {
        res = res && !rnp_calculate_iterations(rnp_cfg_getstr(cfg, CFG_KG_PROT_HASH),
                                               rnp_cfg_getint(cfg, CFG_S2K_MSEC),
                                               &iterations);
    }
    res = res && rnp_cfg_setint(cfg, CFG_KG_PROT_ITERATIONS, iterations);
    return res;
}
