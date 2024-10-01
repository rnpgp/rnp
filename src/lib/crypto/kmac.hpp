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

#ifndef CRYPTO_KMAC_H_
#define CRYPTO_KMAC_H_

#include <repgp/repgp_def.h>
#include "types.h"
#include "config.h"
#include "key.hpp"

namespace rnp {
class KMAC256 {
    /* KDF for PQC key combiner according to
     * https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-pqc-05 */

  protected:
    /*
      //   domSep          – the UTF-8 encoding of the string "OpenPGPCompositeKDFv1"
      //
      //  domSep given in hexadecimal encoding := 4F 70 65 6E 50 47 50 43 6F 6D 70
      //                                          6F 73 69 74 65 4B 44 46 76 31

    */
    const std::vector<uint8_t> domSeparation_ =
      std::vector<uint8_t>({0x4F, 0x70, 0x65, 0x6E, 0x50, 0x47, 0x50, 0x43, 0x6F, 0x6D, 0x70,
                            0x6F, 0x73, 0x69, 0x74, 0x65, 0x4B, 0x44, 0x46, 0x76, 0x31});

    std::vector<uint8_t> domSeparation() const;
    std::vector<uint8_t> Input_X(const std::vector<uint8_t> &ecc_ciphertext,
                                 const std::vector<uint8_t> &kyber_ciphertext,
                                 const std::vector<uint8_t> &ecc_pub,
                                 const std::vector<uint8_t> &kyber_pub,
                                 pgp_pubkey_alg_t            alg_id);
    std::vector<uint8_t> Key_K(const std::vector<uint8_t> &ecc_key_share,
                               const std::vector<uint8_t> &kyber_key_share);
    KMAC256(){};

  public:
    static std::unique_ptr<KMAC256> create();

    /* KMAC interface for OpenPGP PQC composite algorithms */
    virtual void compute(const std::vector<uint8_t> &ecc_key_share,
                         const std::vector<uint8_t> &ecc_key_ciphertext,
                         const std::vector<uint8_t> &ecc_pub,
                         const std::vector<uint8_t> &kyber_key_share,
                         const std::vector<uint8_t> &kyber_ciphertext,
                         const std::vector<uint8_t> &kyber_pub,
                         const pgp_pubkey_alg_t      alg_id,
                         std::vector<uint8_t> &      out) = 0;

    virtual ~KMAC256();
};

} // namespace rnp

#endif
