/*
 * Copyright (c) 2023, [MTG AG](https://www.mtg.de).
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

#ifndef CRYPTO_KEM_COMBINER_H_
#define CRYPTO_KEM_COMBINER_H_

#include <repgp/repgp_def.h>
#include "types.h"
#include "config.h"
#include "pgp-key.h"

namespace rnp {
class PQC_KEM_COMBINER {
    /* KDF for PQC key combiner according to
     * https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-pqc */

  private:
    /*  The value of domSeparation is the UTF-8 encoding of the string
       "OpenPGPCompositeKDFv1" and MUST be the following octet sequence:

        domSeparation := 4F 70 65 6E 50 47 50 43 6F 6D 70 6F 73 69 74 65
                         4B 65 79 44 65 72 69 76 61 74 69 6F 6E 46 75 6E
                         63 74 69 6F 6E

    */
    static std::vector<uint8_t>
    domSeparation()
    {
        return std::vector<uint8_t>({0x4F, 0x70, 0x65, 0x6E, 0x50, 0x47, 0x50,
                                     0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x73, 0x69,
                                     0x74, 0x65, 0x4B, 0x44, 0x46, 0x76, 0x31});
    }

    /* counter - a 4 byte counter set to the value 1 */
    static std::vector<uint8_t>
    counter()
    {
        return std::vector<uint8_t>({0x00, 0x00, 0x00, 0x01});
    }

    static std::vector<uint8_t> fixedInfo(pgp_pubkey_alg_t alg_id);
    static std::vector<uint8_t> encData(const std::vector<uint8_t> &ecc_pub_key,
                                        const std::vector<uint8_t> &ecc_key_share,
                                        const std::vector<uint8_t> &ecc_ciphertext,
                                        const std::vector<uint8_t> &mlkem_pub_key,
                                        const std::vector<uint8_t> &mlkem_key_share,
                                        const std::vector<uint8_t> &mlkem_ciphertext,
                                        pgp_pubkey_alg_t            alg_id);

  public:
    /* PQC KEM Combiner interface for OpenPGP PQC composite algorithms */
    static void compute(const std::vector<uint8_t> &ecc_pub_key,
                        const std::vector<uint8_t> &ecc_key_share,
                        const std::vector<uint8_t> &ecc_ciphertext,
                        const std::vector<uint8_t> &mlkem_pub_key,
                        const std::vector<uint8_t> &mlkem_key_share,
                        const std::vector<uint8_t> &mlkem_ciphertext,
                        const pgp_pubkey_alg_t      alg_id,
                        std::vector<uint8_t> &      out);
};

} // namespace rnp

#endif
