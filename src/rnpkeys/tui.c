#include <stdbool.h>
#include <crypto.h>

extern ec_curve_desc_t ec_curves[PGP_CURVE_MAX];

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
rnp_secure_get_long_from_fd(const FILE *fp, long *result)
{
    char  buff[BUFSIZ];
    char *end_ptr;
    long  num_long;
    bool  ret = false;

    if (!result) {
        goto end;
    }

    if (fgets(buff, sizeof(buff), stdin) == NULL) {
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
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
        // Not yet really supported (at least key generation)
        //
        // case PGP_PKA_ECDH:
        // case PGP_PKA_ELGAMAL:
        // case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        // case PGP_PKA_DSA:
        return true;
    default:
        return false;
    }
}

static long
ask_curve()
{
    long result = 0;
    bool ok = false;
    do {
        printf("Please select which elliptic curve you want:\n");
        for (int i = 0; (i < PGP_CURVE_MAX) && (i != PGP_CURVE_ED25519); i++) {
            printf("\t(%u) %s\n", i + 1, ec_curves[i].pgp_name);
        }
        ok = rnp_secure_get_long_from_fd(stdin, &result);
        ok &= (result > 0) && (result < PGP_CURVE_MAX);
    } while (!ok);

    return result - 1;
}

static long
ask_algorithm()
{
    long result = 0;
    do {
        printf("Please select what kind of key you want:\n"
               "\t(1)  RSA (Encrypt or Sign)\n"
               // "\t(18) ECDH\n"
               "\t(19) ECDSA\n"
               "\t(22) EDDSA\n");

    } while (!rnp_secure_get_long_from_fd(stdin, &result) ||
             !is_keygen_supported_for_alg(result));
    return result;
}

static long
ask_bitlen()
{
    long result = 0;
    do {
        printf("Please provide bit length of the key (between 1024 and 4096):\n");
    } while (!rnp_secure_get_long_from_fd(stdin, &result) ||
             !is_rsa_keysize_supported(result));
    return result;
}

/* -----------------------------------------------------------------------------
 * @brief   Asks user for details needed for the key to be generated (currently
 *          key type and key length only)
 *          This function should explicitly ask user for all details (not use
 *          rnp_getvar or getenv).
 *
 * @param   rnp [in]  Initialized rnp_t struture.
 *              [out] Function fills corresponding to key type and length
 *
 * @returns PGP_E_OK on success
 *          PGP_E_ALG_UNSUPPORTED_PUBLIC_KEY_ALG algorithm not supported
 *
-------------------------------------------------------------------------------- */
pgp_errcode_t
rnp_generate_key_expert_mode(rnp_t *rnp)
{
    rnp->action.generate_key_ctx.key_alg = (pgp_pubkey_alg_t) ask_algorithm();

    // get more details about the key
    switch (rnp->action.generate_key_ctx.key_alg) {
    case PGP_PKA_RSA:
        // Those algorithms must _NOT_ be supported
        //  case PGP_PKA_RSA_ENCRYPT_ONLY:
        //  case PGP_PKA_RSA_SIGN_ONLY:
        rnp->action.generate_key_ctx.rsa.modulus_bit_len = ask_bitlen();
        break;
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
        rnp->action.generate_key_ctx.ecc.curve = (pgp_curve_t) ask_curve();
        break;
    case PGP_PKA_EDDSA:
        rnp->action.generate_key_ctx.ecc.curve = PGP_CURVE_ED25519;
        break;
    default:
        return PGP_E_ALG_UNSUPPORTED_PUBLIC_KEY_ALG;
    }

    return PGP_E_OK;
}
