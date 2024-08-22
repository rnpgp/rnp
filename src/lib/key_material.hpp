/*
 * Copyright (c) 2024 [Ribose Inc](https://www.ribose.com).
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

#ifndef RNP_KEY_MATERIAL_HPP_
#define RNP_KEY_MATERIAL_HPP_

#include "types.h"

typedef struct pgp_packet_body_t          pgp_packet_body_t;
typedef struct rnp_keygen_crypto_params_t rnp_keygen_crypto_params_t;
typedef struct pgp_encrypted_material_t   pgp_encrypted_material_t;
typedef struct pgp_signature_material_t   pgp_signature_material_t;

namespace pgp {
class KeyMaterial {
    pgp_validity_t validity_; /* key material validation status */
  protected:
    pgp_pubkey_alg_t alg_;    /* algorithm of the key */
    bool             secret_; /* secret part of the key material is populated */

    virtual void grip_update(rnp::Hash &hash) const = 0;
    virtual bool validate_material(rnp::SecurityContext &ctx, bool reset = true) = 0;
    bool         finish_generate();

  public:
    KeyMaterial(pgp_pubkey_alg_t kalg = PGP_PKA_NOTHING, bool secret = false)
        : validity_({}), alg_(kalg), secret_(secret){};
    virtual ~KeyMaterial();
    virtual std::unique_ptr<KeyMaterial> clone() = 0;

    pgp_pubkey_alg_t      alg() const noexcept;
    bool                  secret() const noexcept;
    void                  validate(rnp::SecurityContext &ctx, bool reset = true);
    const pgp_validity_t &validity() const noexcept;
    void                  set_validity(const pgp_validity_t &val);
    void                  reset_validity();
    bool                  valid() const;
    virtual bool          equals(const KeyMaterial &value) const noexcept;
    virtual void          clear_secret();
    virtual bool          parse(pgp_packet_body_t &pkt) noexcept = 0;
    virtual bool          parse_secret(pgp_packet_body_t &pkt) noexcept = 0;
    virtual void          write(pgp_packet_body_t &pkt) const = 0;
    virtual void          write_secret(pgp_packet_body_t &pkt) const = 0;
    virtual bool          generate(const rnp_keygen_crypto_params_t &params);
    virtual rnp_result_t  encrypt(rnp::SecurityContext &    ctx,
                                  pgp_encrypted_material_t &out,
                                  const uint8_t *           data,
                                  size_t                    len) const;
    virtual rnp_result_t  decrypt(rnp::SecurityContext &          ctx,
                                  uint8_t *                       out,
                                  size_t &                        out_len,
                                  const pgp_encrypted_material_t &in) const;
    virtual rnp_result_t  verify(const rnp::SecurityContext &       ctx,
                                 const pgp_signature_material_t &   sig,
                                 const rnp::secure_vector<uint8_t> &hash) const;
    virtual rnp_result_t  sign(rnp::SecurityContext &             ctx,
                               pgp_signature_material_t &         sig,
                               const rnp::secure_vector<uint8_t> &hash) const;

    /* Pick up hash algorithm, used for signing, to be compatible with key material. */
    virtual pgp_hash_alg_t adjust_hash(pgp_hash_alg_t hash) const;
    virtual bool           sig_hash_allowed(pgp_hash_alg_t hash) const;
    virtual size_t         bits() const noexcept = 0;
    virtual pgp_curve_t    curve() const noexcept;
    pgp_key_grip_t         grip() const;

    static std::unique_ptr<KeyMaterial> create(pgp_pubkey_alg_t alg);
    static std::unique_ptr<KeyMaterial> create(pgp_pubkey_alg_t alg, const pgp_rsa_key_t &key);
    static std::unique_ptr<KeyMaterial> create(const pgp_dsa_key_t &key);
    static std::unique_ptr<KeyMaterial> create(pgp_pubkey_alg_t alg, const pgp_eg_key_t &key);
    static std::unique_ptr<KeyMaterial> create(pgp_pubkey_alg_t alg, const pgp_ec_key_t &key);
};

class RSAKeyMaterial : public KeyMaterial {
  protected:
    pgp_rsa_key_t key_;

    void grip_update(rnp::Hash &hash) const override;
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    RSAKeyMaterial(pgp_pubkey_alg_t kalg) : KeyMaterial(kalg), key_{} {};
    RSAKeyMaterial(pgp_pubkey_alg_t kalg, const pgp_rsa_key_t &key, bool secret = false)
        : KeyMaterial(kalg, secret), key_(key){};
    std::unique_ptr<KeyMaterial> clone() override;

    bool         equals(const KeyMaterial &value) const noexcept override;
    void         clear_secret() override;
    bool         parse(pgp_packet_body_t &pkt) noexcept override;
    bool         parse_secret(pgp_packet_body_t &pkt) noexcept override;
    void         write(pgp_packet_body_t &pkt) const override;
    void         write_secret(pgp_packet_body_t &pkt) const override;
    bool         generate(const rnp_keygen_crypto_params_t &params) override;
    rnp_result_t encrypt(rnp::SecurityContext &    ctx,
                         pgp_encrypted_material_t &out,
                         const uint8_t *           data,
                         size_t                    len) const override;
    rnp_result_t decrypt(rnp::SecurityContext &          ctx,
                         uint8_t *                       out,
                         size_t &                        out_len,
                         const pgp_encrypted_material_t &in) const override;
    rnp_result_t verify(const rnp::SecurityContext &       ctx,
                        const pgp_signature_material_t &   sig,
                        const rnp::secure_vector<uint8_t> &hash) const override;
    rnp_result_t sign(rnp::SecurityContext &             ctx,
                      pgp_signature_material_t &         sig,
                      const rnp::secure_vector<uint8_t> &hash) const override;

    void   set_secret(const mpi &d, const mpi &p, const mpi &q, const mpi &u);
    size_t bits() const noexcept override;

    const mpi &n() const noexcept;
    const mpi &e() const noexcept;
    const mpi &d() const noexcept;
    const mpi &p() const noexcept;
    const mpi &q() const noexcept;
    const mpi &u() const noexcept;
};

class DSAKeyMaterial : public KeyMaterial {
  protected:
    pgp_dsa_key_t key_;

    void grip_update(rnp::Hash &hash) const override;
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    DSAKeyMaterial() : KeyMaterial(PGP_PKA_DSA), key_{} {};
    DSAKeyMaterial(const pgp_dsa_key_t &key, bool secret = false)
        : KeyMaterial(PGP_PKA_DSA, secret), key_(key){};
    std::unique_ptr<KeyMaterial> clone() override;

    bool           equals(const KeyMaterial &value) const noexcept override;
    void           clear_secret() override;
    bool           parse(pgp_packet_body_t &pkt) noexcept override;
    bool           parse_secret(pgp_packet_body_t &pkt) noexcept override;
    void           write(pgp_packet_body_t &pkt) const override;
    void           write_secret(pgp_packet_body_t &pkt) const override;
    bool           generate(const rnp_keygen_crypto_params_t &params) override;
    rnp_result_t   verify(const rnp::SecurityContext &       ctx,
                          const pgp_signature_material_t &   sig,
                          const rnp::secure_vector<uint8_t> &hash) const override;
    rnp_result_t   sign(rnp::SecurityContext &             ctx,
                        pgp_signature_material_t &         sig,
                        const rnp::secure_vector<uint8_t> &hash) const override;
    pgp_hash_alg_t adjust_hash(pgp_hash_alg_t hash) const override;
    void           set_secret(const mpi &x);
    size_t         bits() const noexcept override;
    size_t         qbits() const noexcept;

    const mpi &p() const noexcept;
    const mpi &q() const noexcept;
    const mpi &g() const noexcept;
    const mpi &y() const noexcept;
    const mpi &x() const noexcept;
};

class EGKeyMaterial : public KeyMaterial {
  protected:
    pgp_eg_key_t key_;

    void grip_update(rnp::Hash &hash) const override;
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    EGKeyMaterial(pgp_pubkey_alg_t kalg) : KeyMaterial(kalg), key_{} {};
    EGKeyMaterial(pgp_pubkey_alg_t kalg, const pgp_eg_key_t &key, bool secret = false)
        : KeyMaterial(kalg, secret), key_(key){};
    std::unique_ptr<KeyMaterial> clone() override;

    bool         equals(const KeyMaterial &value) const noexcept override;
    void         clear_secret() override;
    bool         parse(pgp_packet_body_t &pkt) noexcept override;
    bool         parse_secret(pgp_packet_body_t &pkt) noexcept override;
    void         write(pgp_packet_body_t &pkt) const override;
    void         write_secret(pgp_packet_body_t &pkt) const override;
    bool         generate(const rnp_keygen_crypto_params_t &params) override;
    rnp_result_t encrypt(rnp::SecurityContext &    ctx,
                         pgp_encrypted_material_t &out,
                         const uint8_t *           data,
                         size_t                    len) const override;
    rnp_result_t decrypt(rnp::SecurityContext &          ctx,
                         uint8_t *                       out,
                         size_t &                        out_len,
                         const pgp_encrypted_material_t &in) const override;
    rnp_result_t verify(const rnp::SecurityContext &       ctx,
                        const pgp_signature_material_t &   sig,
                        const rnp::secure_vector<uint8_t> &hash) const override;

    void   set_secret(const mpi &x);
    size_t bits() const noexcept override;

    const mpi &p() const noexcept;
    const mpi &g() const noexcept;
    const mpi &y() const noexcept;
    const mpi &x() const noexcept;
};

class ECKeyMaterial : public KeyMaterial {
  protected:
    pgp_ec_key_t key_;

    void         grip_update(rnp::Hash &hash) const override;
    rnp_result_t check_curve(size_t hash_len) const;

  public:
    ECKeyMaterial(pgp_pubkey_alg_t kalg) : KeyMaterial(kalg), key_{} {};
    ECKeyMaterial(pgp_pubkey_alg_t kalg, const pgp_ec_key_t &key, bool secret = false)
        : KeyMaterial(kalg, secret), key_(key){};

    bool        equals(const KeyMaterial &value) const noexcept override;
    void        clear_secret() override;
    bool        parse(pgp_packet_body_t &pkt) noexcept override;
    bool        parse_secret(pgp_packet_body_t &pkt) noexcept override;
    void        write(pgp_packet_body_t &pkt) const override;
    void        write_secret(pgp_packet_body_t &pkt) const override;
    bool        generate(const rnp_keygen_crypto_params_t &params) override;
    void        set_secret(const mpi &x);
    size_t      bits() const noexcept override;
    pgp_curve_t curve() const noexcept override;

    const mpi &p() const noexcept;
    const mpi &x() const noexcept;
};

class ECDSAKeyMaterial : public ECKeyMaterial {
  protected:
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    ECDSAKeyMaterial() : ECKeyMaterial(PGP_PKA_ECDSA){};
    ECDSAKeyMaterial(const pgp_ec_key_t &key, bool secret = false)
        : ECKeyMaterial(PGP_PKA_ECDSA, key, secret){};
    std::unique_ptr<KeyMaterial> clone() override;

    rnp_result_t   verify(const rnp::SecurityContext &       ctx,
                          const pgp_signature_material_t &   sig,
                          const rnp::secure_vector<uint8_t> &hash) const override;
    rnp_result_t   sign(rnp::SecurityContext &             ctx,
                        pgp_signature_material_t &         sig,
                        const rnp::secure_vector<uint8_t> &hash) const override;
    pgp_hash_alg_t adjust_hash(pgp_hash_alg_t hash) const override;
};

class ECDHKeyMaterial : public ECKeyMaterial {
  protected:
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    ECDHKeyMaterial() : ECKeyMaterial(PGP_PKA_ECDH){};
    ECDHKeyMaterial(const pgp_ec_key_t &key, bool secret = false)
        : ECKeyMaterial(PGP_PKA_ECDH, key, secret){};
    std::unique_ptr<KeyMaterial> clone() override;

    bool         parse(pgp_packet_body_t &pkt) noexcept override;
    void         write(pgp_packet_body_t &pkt) const override;
    bool         generate(const rnp_keygen_crypto_params_t &params) override;
    rnp_result_t encrypt(rnp::SecurityContext &    ctx,
                         pgp_encrypted_material_t &out,
                         const uint8_t *           data,
                         size_t                    len) const override;
    rnp_result_t decrypt(rnp::SecurityContext &          ctx,
                         uint8_t *                       out,
                         size_t &                        out_len,
                         const pgp_encrypted_material_t &in) const override;

    pgp_hash_alg_t kdf_hash_alg() const noexcept;
    pgp_symm_alg_t key_wrap_alg() const noexcept;
    bool           x25519_bits_tweaked() const noexcept;
    bool           x25519_tweak_bits() noexcept;
};

class EDDSAKeyMaterial : public ECKeyMaterial {
  protected:
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    EDDSAKeyMaterial() : ECKeyMaterial(PGP_PKA_EDDSA){};
    EDDSAKeyMaterial(const pgp_ec_key_t &key, bool secret = false)
        : ECKeyMaterial(PGP_PKA_EDDSA, key, secret){};
    std::unique_ptr<KeyMaterial> clone() override;

    bool         generate(const rnp_keygen_crypto_params_t &params) override;
    rnp_result_t verify(const rnp::SecurityContext &       ctx,
                        const pgp_signature_material_t &   sig,
                        const rnp::secure_vector<uint8_t> &hash) const override;
    rnp_result_t sign(rnp::SecurityContext &             ctx,
                      pgp_signature_material_t &         sig,
                      const rnp::secure_vector<uint8_t> &hash) const override;
};

class SM2KeyMaterial : public ECKeyMaterial {
  protected:
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    SM2KeyMaterial() : ECKeyMaterial(PGP_PKA_SM2){};
    SM2KeyMaterial(const pgp_ec_key_t &key, bool secret = false)
        : ECKeyMaterial(PGP_PKA_SM2, key, secret){};
    std::unique_ptr<KeyMaterial> clone() override;

    rnp_result_t encrypt(rnp::SecurityContext &    ctx,
                         pgp_encrypted_material_t &out,
                         const uint8_t *           data,
                         size_t                    len) const override;
    rnp_result_t decrypt(rnp::SecurityContext &          ctx,
                         uint8_t *                       out,
                         size_t &                        out_len,
                         const pgp_encrypted_material_t &in) const override;
    rnp_result_t verify(const rnp::SecurityContext &       ctx,
                        const pgp_signature_material_t &   sig,
                        const rnp::secure_vector<uint8_t> &hash) const override;
    rnp_result_t sign(rnp::SecurityContext &             ctx,
                      pgp_signature_material_t &         sig,
                      const rnp::secure_vector<uint8_t> &hash) const override;
    void         compute_za(rnp::Hash &hash) const;
};

#if defined(ENABLE_CRYPTO_REFRESH)
class Ed25519KeyMaterial : public KeyMaterial {
    pgp_ed25519_key_t key_;

  protected:
    void grip_update(rnp::Hash &hash) const override;
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    Ed25519KeyMaterial() : KeyMaterial(PGP_PKA_ED25519), key_{} {};
    std::unique_ptr<KeyMaterial> clone() override;

    bool         equals(const KeyMaterial &value) const noexcept override;
    void         clear_secret() override;
    bool         parse(pgp_packet_body_t &pkt) noexcept override;
    bool         parse_secret(pgp_packet_body_t &pkt) noexcept override;
    void         write(pgp_packet_body_t &pkt) const override;
    void         write_secret(pgp_packet_body_t &pkt) const override;
    bool         generate(const rnp_keygen_crypto_params_t &params) override;
    rnp_result_t verify(const rnp::SecurityContext &       ctx,
                        const pgp_signature_material_t &   sig,
                        const rnp::secure_vector<uint8_t> &hash) const override;
    rnp_result_t sign(rnp::SecurityContext &             ctx,
                      pgp_signature_material_t &         sig,
                      const rnp::secure_vector<uint8_t> &hash) const override;
    size_t       bits() const noexcept override;
    pgp_curve_t  curve() const noexcept override;

    const std::vector<uint8_t> &pub() const noexcept;
    const std::vector<uint8_t> &priv() const noexcept;
};

class X25519KeyMaterial : public KeyMaterial {
    pgp_x25519_key_t key_;

  protected:
    void grip_update(rnp::Hash &hash) const override;
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    X25519KeyMaterial() : KeyMaterial(PGP_PKA_X25519), key_{} {};
    std::unique_ptr<KeyMaterial> clone() override;

    bool         equals(const KeyMaterial &value) const noexcept override;
    void         clear_secret() override;
    bool         parse(pgp_packet_body_t &pkt) noexcept override;
    bool         parse_secret(pgp_packet_body_t &pkt) noexcept override;
    void         write(pgp_packet_body_t &pkt) const override;
    void         write_secret(pgp_packet_body_t &pkt) const override;
    bool         generate(const rnp_keygen_crypto_params_t &params) override;
    rnp_result_t encrypt(rnp::SecurityContext &    ctx,
                         pgp_encrypted_material_t &out,
                         const uint8_t *           data,
                         size_t                    len) const override;
    rnp_result_t decrypt(rnp::SecurityContext &          ctx,
                         uint8_t *                       out,
                         size_t &                        out_len,
                         const pgp_encrypted_material_t &in) const override;
    size_t       bits() const noexcept override;
    pgp_curve_t  curve() const noexcept override;

    const std::vector<uint8_t> &pub() const noexcept;
    const std::vector<uint8_t> &priv() const noexcept;
};
#endif

#if defined(ENABLE_PQC)
class MlkemEcdhKeyMaterial : public KeyMaterial {
    pgp_kyber_ecdh_key_t key_;

  protected:
    void grip_update(rnp::Hash &hash) const override;
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    MlkemEcdhKeyMaterial(pgp_pubkey_alg_t kalg) : KeyMaterial(kalg), key_{} {};
    std::unique_ptr<KeyMaterial> clone() override;

    bool         equals(const KeyMaterial &value) const noexcept override;
    void         clear_secret() override;
    bool         parse(pgp_packet_body_t &pkt) noexcept override;
    bool         parse_secret(pgp_packet_body_t &pkt) noexcept override;
    void         write(pgp_packet_body_t &pkt) const override;
    void         write_secret(pgp_packet_body_t &pkt) const override;
    bool         generate(const rnp_keygen_crypto_params_t &params) override;
    rnp_result_t encrypt(rnp::SecurityContext &    ctx,
                         pgp_encrypted_material_t &out,
                         const uint8_t *           data,
                         size_t                    len) const override;
    rnp_result_t decrypt(rnp::SecurityContext &          ctx,
                         uint8_t *                       out,
                         size_t &                        out_len,
                         const pgp_encrypted_material_t &in) const override;
    size_t       bits() const noexcept override;

    const pgp_kyber_ecdh_composite_public_key_t & pub() const noexcept;
    const pgp_kyber_ecdh_composite_private_key_t &priv() const noexcept;
};

class DilithiumEccKeyMaterial : public KeyMaterial {
    pgp_dilithium_exdsa_key_t key_;

  protected:
    void grip_update(rnp::Hash &hash) const override;
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    DilithiumEccKeyMaterial(pgp_pubkey_alg_t kalg) : KeyMaterial(kalg), key_{} {};
    std::unique_ptr<KeyMaterial> clone() override;

    /** @brief Check two key material for equality. Only public part is checked, so this may be
     * called on public/secret key material */
    bool           equals(const KeyMaterial &value) const noexcept override;
    void           clear_secret() override;
    bool           parse(pgp_packet_body_t &pkt) noexcept override;
    bool           parse_secret(pgp_packet_body_t &pkt) noexcept override;
    void           write(pgp_packet_body_t &pkt) const override;
    void           write_secret(pgp_packet_body_t &pkt) const override;
    bool           generate(const rnp_keygen_crypto_params_t &params) override;
    rnp_result_t   verify(const rnp::SecurityContext &       ctx,
                          const pgp_signature_material_t &   sig,
                          const rnp::secure_vector<uint8_t> &hash) const override;
    rnp_result_t   sign(rnp::SecurityContext &             ctx,
                        pgp_signature_material_t &         sig,
                        const rnp::secure_vector<uint8_t> &hash) const override;
    pgp_hash_alg_t adjust_hash(pgp_hash_alg_t hash) const override;
    size_t         bits() const noexcept override;

    const pgp_dilithium_exdsa_composite_public_key_t & pub() const noexcept;
    const pgp_dilithium_exdsa_composite_private_key_t &priv() const noexcept;
};

class SlhdsaKeyMaterial : public KeyMaterial {
    pgp_sphincsplus_key_t key_;

  protected:
    void grip_update(rnp::Hash &hash) const override;
    bool validate_material(rnp::SecurityContext &ctx, bool reset) override;

  public:
    SlhdsaKeyMaterial(pgp_pubkey_alg_t kalg) : KeyMaterial(kalg), key_{} {};
    std::unique_ptr<KeyMaterial> clone() override;

    bool           equals(const KeyMaterial &value) const noexcept override;
    void           clear_secret() override;
    bool           parse(pgp_packet_body_t &pkt) noexcept override;
    bool           parse_secret(pgp_packet_body_t &pkt) noexcept override;
    void           write(pgp_packet_body_t &pkt) const override;
    void           write_secret(pgp_packet_body_t &pkt) const override;
    bool           generate(const rnp_keygen_crypto_params_t &params) override;
    rnp_result_t   verify(const rnp::SecurityContext &       ctx,
                          const pgp_signature_material_t &   sig,
                          const rnp::secure_vector<uint8_t> &hash) const override;
    rnp_result_t   sign(rnp::SecurityContext &             ctx,
                        pgp_signature_material_t &         sig,
                        const rnp::secure_vector<uint8_t> &hash) const override;
    pgp_hash_alg_t adjust_hash(pgp_hash_alg_t hash) const override;
    bool           sig_hash_allowed(pgp_hash_alg_t hash) const override;
    size_t         bits() const noexcept override;

    const pgp_sphincsplus_public_key_t & pub() const noexcept;
    const pgp_sphincsplus_private_key_t &priv() const noexcept;
};
#endif
} // namespace pgp

#endif // RNP_KEY_MATERIAL_HPP_