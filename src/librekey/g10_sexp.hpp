/*
 * Copyright (c) 2021, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE RIBOSE, INC. AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RNP_G10_SEXP_HPP
#define RNP_G10_SEXP_HPP


#include "sexp/sexp.h"

#define SXP_MAX_DEPTH 30

typedef sexp::sexp_object_t s_exp_element_t;

class s_exp_block_t : public sexp::sexp_string_t {
  public:
    s_exp_block_t(const uint8_t *bt, size_t ln) {
      data_string = sexp::sexp_simple_string_t(bt, ln);
     }
    s_exp_block_t(void) : sexp::sexp_string_t() { }
    s_exp_block_t(const uint8_t *bt) : sexp::sexp_string_t(bt) { }
    s_exp_block_t(unsigned u);
    s_exp_block_t(const std::string &str): sexp::sexp_string_t(str) { }
    s_exp_block_t(const pgp_mpi_t &mpi);

//    static bool  write(const s_exp_block_t &s_exp, pgp_dest_t &dst) noexcept;


};

class s_exp_t : public sexp::sexp_list_t {
    /* write s_exp_t contents, adding padding, for the further encryption */
    rnp::secure_vector<uint8_t> write_padded(size_t padblock) const;

  public:

    bool     parse(const char **r_bytes, size_t *r_length, size_t depth = 1);
    void     add(std::unique_ptr<s_exp_element_t> sptr);
    void     add(const std::string &str);
    void     add(const uint8_t *data, size_t size);
    void     add(unsigned u);
    s_exp_t &add_sub();
    bool     write(pgp_dest_t &dst) const noexcept;

//    static bool  write(const s_exp_t &s_exp, pgp_dest_t &dst) noexcept;

    void add_mpi(const std::string &name, const pgp_mpi_t &val);
    void add_curve(const std::string &name, const pgp_ec_key_t &key);
    void add_pubkey(const pgp_key_pkt_t &key);
    void add_seckey(const pgp_key_pkt_t &key);
    void add_protected_seckey(pgp_key_pkt_t &       seckey,
                              const std::string &   password,
                              rnp::SecurityContext &ctx);

};

#endif
