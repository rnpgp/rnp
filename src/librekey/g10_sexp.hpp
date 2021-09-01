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

#define SXP_MAX_DEPTH 30

class s_exp_element_t {
  protected:
    bool is_block_;

  public:
    s_exp_element_t(bool block) : is_block_(block){};
    virtual ~s_exp_element_t() = default;
    virtual bool
    write(pgp_dest_t &dst) const noexcept
    {
        return false;
    };

    bool
    is_block()
    {
        return is_block_;
    }
};

class s_exp_block_t : public s_exp_element_t {
  protected:
    std::vector<uint8_t> bytes_;

  public:
    s_exp_block_t(const uint8_t *bt = NULL, size_t ln = 0)
        : s_exp_element_t(true),
          bytes_(bt ? std::vector<uint8_t>(bt, bt + ln) : std::vector<uint8_t>()){};
    s_exp_block_t(unsigned u);
    s_exp_block_t(const std::string &str)
        : s_exp_element_t(true),
          bytes_((uint8_t *) str.data(), (uint8_t *) (str.data() + str.size())){};
    s_exp_block_t(const pgp_mpi_t &mpi);
    unsigned as_unsigned() const noexcept;
    bool     write(pgp_dest_t &dst) const noexcept;

    const std::vector<uint8_t> &
    bytes() const
    {
        return bytes_;
    }
};

class s_exp_t : public s_exp_element_t {
    std::vector<std::unique_ptr<s_exp_element_t>> elements_;
    /* write s_exp_t contents, adding padding, for the further encryption */
    rnp::secure_vector<uint8_t> write_padded(size_t padblock) const;

  public:
    s_exp_t() : s_exp_element_t(false){};
    bool     parse(const char **r_bytes, size_t *r_length, size_t depth = 1);
    void     add(std::unique_ptr<s_exp_element_t> sptr);
    void     add(const std::string &str);
    void     add(const uint8_t *data, size_t size);
    void     add(unsigned u);
    s_exp_t &add_sub();
    bool     write(pgp_dest_t &dst) const noexcept;

    size_t
    size() const
    {
        return elements_.size();
    }

    s_exp_element_t &
    at(size_t idx)
    {
        return *elements_[idx].get();
    }

    s_exp_t *      lookup_var(const std::string &name) noexcept;
    s_exp_block_t *lookup_var_data(const std::string &name) noexcept;

    bool read_mpi(const std::string &name, pgp_mpi_t &val) noexcept;
    bool read_curve(const std::string &name, pgp_ec_key_t &key) noexcept;
    void add_mpi(const std::string &name, const pgp_mpi_t &val);
    void add_curve(const std::string &name, const pgp_ec_key_t &key);
    void add_pubkey(const pgp_key_pkt_t &key);
    void add_seckey(const pgp_key_pkt_t &key);
    void add_protected_seckey(pgp_key_pkt_t &seckey, const std::string &password);

    void clear();
};

#endif
