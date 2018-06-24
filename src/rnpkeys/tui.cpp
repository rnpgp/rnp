#include <stdbool.h>
#include <errno.h>
#include "crypto.h"
#include "crypto/common.h"
#include "rnp/rnpcfg.h"
#include "rnpkeys.h"
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

static bool
is_keygen_supported_for_alg(pgp_pubkey_alg_t id)
{
    switch (id) {
    case PGP_PKA_RSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDSA:
    case PGP_PKA_DSA:
    case PGP_PKA_ELGAMAL:
        return true;
    default:
        return false;
    }
}

static pgp_curve_t
ask_curve(FILE *input_fp)
{
    pgp_curve_t result = PGP_CURVE_MAX;
    long        val = 0;
    bool        ok = false;
    do {
        printf("Please select which elliptic curve you want:\n");
        for (int i = 1; (i < PGP_CURVE_MAX) && (i != PGP_CURVE_ED25519); i++) {
            printf("\t(%u) %s\n", i, get_curve_desc((const pgp_curve_t) i)->pgp_name);
        }
        printf("(default %s)> ", get_curve_desc(DEFAULT_CURVE)->pgp_name);
        val = DEFAULT_CURVE;
        ok = rnp_secure_get_long_from_fd(input_fp, &val, true);
        ok &= (val > 0) && (val < PGP_CURVE_MAX);
    } while (!ok);

    if (ok) {
        result = (pgp_curve_t)(val);
    }

    return result;
}

static long
ask_algorithm(FILE *input_fp)
{
    long result = 0;
    do {
        printf("Please select what kind of key you want:\n"
               "\t(1)  RSA (Encrypt or Sign)\n"
               "\t(16) DSA + ElGamal\n"
               "\t(17) DSA + RSA\n" // TODO: See #584
               "\t(18) ECDH\n"
               "\t(19) ECDSA\n"
               "\t(22) EDDSA\n"
               "\t(99) SM2\n"
               "> ");

    } while (!rnp_secure_get_long_from_fd(input_fp, &result, false) ||
             !is_keygen_supported_for_alg((pgp_pubkey_alg_t) result));
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

/* -----------------------------------------------------------------------------
 * @brief   Asks user for details needed for the key to be generated (currently
 *          key type and key length only)
 *          This function should explicitly ask user for all details (not use
 *          getenv or something similar).
 *
 * @param   rnp [in]  Initialized rnp_t struture.
 *              [out] Function fills corresponding to key type and length
 * @param   cfg [in]  Requested configuration
 *
 * @returns RNP_SUCCESS on success
 *          RNP_ERROR_BAD_PARAMETERS unsupported parameters supplied
 *          RNP_ERROR_GENERIC indicates problem in implementation
 *
-------------------------------------------------------------------------------- */
rnp_result_t
rnp_generate_key_expert_mode(rnp_t *rnp)
{
    FILE *                      input_fd = rnp->user_input_fp ? rnp->user_input_fp : stdin;
    rnp_action_keygen_t *       action = &rnp->action.generate_key_ctx;
    rnp_keygen_primary_desc_t * primary_desc = &action->primary.keygen;
    rnp_keygen_crypto_params_t *crypto = &primary_desc->crypto;

    crypto->key_alg = (pgp_pubkey_alg_t) ask_algorithm(input_fd);
    // get more details about the key
    const pgp_pubkey_alg_t key_alg = crypto->key_alg;
    switch (key_alg) {
    case PGP_PKA_RSA:
        // Those algorithms must _NOT_ be supported
        //  case PGP_PKA_RSA_ENCRYPT_ONLY:
        //  case PGP_PKA_RSA_SIGN_ONLY:
        crypto->rsa.modulus_bit_len = ask_rsa_bitlen(input_fd);
        action->subkey.keygen.crypto = *crypto;
        break;

    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
        action->primary.keygen.crypto.key_alg = PGP_PKA_ECDSA;
        action->primary.keygen.crypto.ecc.curve = ask_curve(input_fd);
        if (key_alg == PGP_PKA_ECDH) {
            /* Generate ECDH as a subkey of ECDSA */
            action->subkey.keygen.crypto.key_alg = PGP_PKA_ECDH;
            action->subkey.keygen.crypto.hash_alg = action->primary.keygen.crypto.hash_alg;
            action->subkey.keygen.crypto.ecc.curve = action->primary.keygen.crypto.ecc.curve;
        }
        break;

    case PGP_PKA_EDDSA:
        crypto->ecc.curve = PGP_CURVE_ED25519;
        break;

    case PGP_PKA_SM2:
        crypto->hash_alg = PGP_HASH_SM3;
        crypto->ecc.curve = PGP_CURVE_SM2_P_256;
        action->subkey.keygen.crypto = *crypto;
        break;

    case PGP_PKA_DSA:
    case PGP_PKA_ELGAMAL:
        crypto->key_alg = PGP_PKA_DSA;
        crypto->dsa.p_bitlen = ask_dsa_bitlen(input_fd);
        crypto->dsa.q_bitlen = dsa_choose_qsize_by_psize(crypto->dsa.p_bitlen);
        if (key_alg == PGP_PKA_ELGAMAL) {
            /* Generate Elgamal as a subkey of DSA */
            action->subkey.keygen.crypto.key_alg = PGP_PKA_ELGAMAL;
            action->subkey.keygen.crypto.hash_alg = action->primary.keygen.crypto.hash_alg;
            action->subkey.keygen.crypto.elgamal.key_bitlen = crypto->dsa.p_bitlen;
        }
        break;

    default:
        return RNP_ERROR_BAD_PARAMETERS;
    }

    action->primary.protection.hash_alg = crypto->hash_alg;
    action->subkey.protection = action->primary.protection;
    return RNP_SUCCESS;
}
