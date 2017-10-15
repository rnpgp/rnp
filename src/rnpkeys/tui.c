#include <stdbool.h>
#include "crypto.h"
#include "crypto/ec.h"
#include "rnp/rnpcfg.h"
#include "rnpkeys.h"

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
rnp_secure_get_long_from_fd(FILE *fp, long *result)
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
            RNP_LOG("Invalid number");
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
        // Not yet really supported (at least key generation)
        //
        // case PGP_PKA_ELGAMAL:
        // case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        // case PGP_PKA_DSA:
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
            printf("\t(%u) %s\n", i, get_curve_desc(i)->pgp_name);
        }
        printf("> ");
        ok = rnp_secure_get_long_from_fd(input_fp, &val);
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
               "\t(18) ECDH\n"
               "\t(19) ECDSA\n"
               "\t(22) EDDSA\n"
               "\t(99) SM2\n"
               "> ");

    } while (!rnp_secure_get_long_from_fd(input_fp, &result) ||
             !is_keygen_supported_for_alg(result));
    return result;
}

static long
ask_bitlen(FILE *input_fp)
{
    long result = 0;
    do {
        result = 0;
        printf("Please provide bit length of the key (between 1024 and 4096):\n> ");
    } while (!rnp_secure_get_long_from_fd(input_fp, &result) ||
             !is_rsa_keysize_supported(result));
    return result;
}

static rnp_result_t
setup_ecdsa_key_params(rnp_keygen_crypto_params_t *params, FILE *input_fd)
{
    if (PGP_HASH_UNKNOWN == params->hash_alg) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    size_t digest_length = 0;
    if (!pgp_digest_length(params->hash_alg, &digest_length)) {
        // Implementation error
        return RNP_ERROR_BAD_PARAMETERS;
    }

    params->key_alg = PGP_PKA_ECDSA;
    params->ecc.curve = ask_curve(input_fd);
    /*
     * Adjust hash to curve - see point 14 of RFC 4880 bis 01
     * and/or ECDSA spec.
     *
     * Minimal size of digest for curve:
     *    P-256  32 bytes
     *    P-384  48 bytes
     *    P-521  64 bytes
     */
    switch (params->ecc.curve) {
    case PGP_CURVE_NIST_P_256:
        if (digest_length < 32) {
            params->hash_alg = PGP_HASH_SHA256;
        }
        break;
    case PGP_CURVE_NIST_P_384:
        if (digest_length < 48) {
            params->hash_alg = PGP_HASH_SHA384;
        }
        break;
    case PGP_CURVE_NIST_P_521:
        if (digest_length < 64) {
            params->hash_alg = PGP_HASH_SHA512;
        }
        break;
    default:
        // Should never happen as ask_curve checks it
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
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
        rnp_result_t ret;

    case PGP_PKA_RSA:
        // Those algorithms must _NOT_ be supported
        //  case PGP_PKA_RSA_ENCRYPT_ONLY:
        //  case PGP_PKA_RSA_SIGN_ONLY:
        crypto->rsa.modulus_bit_len = ask_bitlen(input_fd);
        action->subkey.keygen.crypto = *crypto;
        break;

    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
        ret = setup_ecdsa_key_params(&action->primary.keygen.crypto, input_fd);
        if (ret != RNP_SUCCESS) {
            return ret;
        }
        /* Generate ECDH as a subkey of ECDSA */
        action->subkey.keygen.crypto.key_alg = PGP_PKA_ECDH;
        action->subkey.keygen.crypto.hash_alg = action->primary.keygen.crypto.hash_alg;
        action->subkey.keygen.crypto.ecc.curve = action->primary.keygen.crypto.ecc.curve;
        break;

    case PGP_PKA_EDDSA:
        crypto->ecc.curve = PGP_CURVE_ED25519;
        break;

    case PGP_PKA_SM2:
        crypto->hash_alg = PGP_HASH_SM3;
        crypto->ecc.curve = PGP_CURVE_SM2_P_256;
        action->subkey.keygen.crypto = *crypto;
        break;

    default:
        return RNP_ERROR_BAD_PARAMETERS;
    }

    action->primary.protection.hash_alg = crypto->hash_alg;
    action->subkey.protection = action->primary.protection;
    return RNP_SUCCESS;
}
