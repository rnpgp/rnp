/*
 * Copyright (c) 2017-2024 [Ribose Inc](https://www.ribose.com).
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

#ifndef RNP_OSSL_UTILS_HPP_
#define RNP_OSSL_UTILS_HPP_

#include <cstdio>
#include <cstdint>
#include "config.h"
#include "mpi.h"
#include <cassert>
#include <memory>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#if defined(CRYPTO_BACKEND_OPENSSL3)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#else
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#endif

namespace rnp {
class bn {
    BIGNUM *      _bn;
    const BIGNUM *_c_bn;

  public:
    bn(BIGNUM *val = NULL) : _bn(val), _c_bn(NULL)
    {
    }

    bn(const BIGNUM *val) : _bn(NULL), _c_bn(val)
    {
    }

    bn(const pgp::mpi &val) : bn(&val)
    {
    }
    bn(const pgp::mpi *val) : _c_bn(NULL)
    {
        if (!val) {
            _bn = NULL;
            return;
        }

        _bn = BN_new();
        if (_bn && !BN_bin2bn(val->mpi, val->len, _bn)) {
            BN_free(_bn);
            _bn = NULL;
        }
    }

    bn(bn &&src)
    {
        _bn = src._bn;
        src._bn = NULL;
        _c_bn = src._c_bn;
        src._c_bn = NULL;
    }

    bn &
    operator=(bn &&src)
    {
        if (&src == this) {
            return *this;
        }
        BN_free(_bn);
        _bn = src._bn;
        src._bn = NULL;
        _c_bn = src._c_bn;
        src._c_bn = NULL;
        return *this;
    }

    ~bn()
    {
        BN_free(_bn);
    }

    explicit operator bool() const
    {
        return c_get();
    }

    BIGNUM **
    ptr() noexcept
    {
        BN_free(_bn);
        _bn = NULL;
        return &_bn;
    }

    const BIGNUM **
    cptr() noexcept
    {
        return &_c_bn;
    }

    BIGNUM *
    get() noexcept
    {
        return _bn;
    }

    const BIGNUM *
    c_get() const noexcept
    {
        return _bn ? _bn : _c_bn;
    }

    BIGNUM *
    own() noexcept
    {
        auto res = _bn;
        _bn = NULL;
        return res;
    }

    size_t
    bytes() const noexcept
    {
        return BN_num_bytes(c_get());
    }

    bool
    bin(uint8_t *b) const noexcept
    {
        return b && BN_bn2bin(c_get(), b) >= 0;
    }

    static bool
    mpi(const BIGNUM *num, pgp::mpi &mpi) noexcept
    {
        assert((size_t) BN_num_bytes(num) <= sizeof(mpi.mpi));
        if (BN_bn2bin(num, mpi.mpi) < 0) {
            return false;
        }
        mpi.len = BN_num_bytes(num);
        return true;
    }

    bool
    mpi(pgp::mpi &mpi) const noexcept
    {
        return bn::mpi(c_get(), mpi);
    }
};

namespace ossl {

struct BNCtxDeleter {
    void
    operator()(BN_CTX *ptr) const
    {
        BN_CTX_free(ptr);
    }
};

using BNCtx = std::unique_ptr<BN_CTX, BNCtxDeleter>;

struct BNRecpCtxDeleter {
    void
    operator()(BN_RECP_CTX *ptr) const
    {
        BN_RECP_CTX_free(ptr);
    }
};

using BNRecpCtx = std::unique_ptr<BN_RECP_CTX, BNRecpCtxDeleter>;

struct BNMontCtxDeleter {
    void
    operator()(BN_MONT_CTX *ptr) const
    {
        BN_MONT_CTX_free(ptr);
    }
};

using BNMontCtx = std::unique_ptr<BN_MONT_CTX, BNMontCtxDeleter>;

namespace evp {
class PKey {
    EVP_PKEY *key_;

  public:
    PKey(EVP_PKEY *val = NULL) : key_(val)
    {
    }

    PKey(PKey &&src)
    {
        key_ = src.key_;
        src.key_ = NULL;
    }

    ~PKey()
    {
        EVP_PKEY_free(key_);
    }

    PKey &
    operator=(PKey &&src)
    {
        if (&src == this) {
            return *this;
        }
        EVP_PKEY_free(key_);
        key_ = src.key_;
        src.key_ = NULL;
        return *this;
    }

    explicit operator bool() const
    {
        return key_;
    }

    EVP_PKEY *
    get() noexcept
    {
        return key_;
    }

    const EVP_PKEY *
    get() const noexcept
    {
        return key_;
    }

#if defined(CRYPTO_BACKEND_OPENSSL3)
    bn
    get_bn(const char *name) noexcept
    {
        bn val;
        EVP_PKEY_get_bn_param(key_, name, val.ptr());
        return val;
    }

    bool
    get_bn(const char *name, pgp::mpi &bn) noexcept
    {
        return get_bn(name).mpi(bn);
    }
#endif

    EVP_PKEY *
    own() noexcept
    {
        auto res = key_;
        key_ = NULL;
        return res;
    }

    EVP_PKEY **
    ptr(bool free = true) noexcept
    {
        if (free) {
            EVP_PKEY_free(key_);
            key_ = NULL;
        }
        return &key_;
    }
};

class Ctx {
    EVP_PKEY_CTX *ctx_;

  public:
    Ctx() : ctx_(NULL){};

    Ctx(int id)
    {
        ctx_ = EVP_PKEY_CTX_new_id(id, NULL);
    }

    Ctx(PKey &key)
    {
        ctx_ = EVP_PKEY_CTX_new(key.get(), NULL);
    }

    Ctx(Ctx &&src)
    {
        ctx_ = src.ctx_;
        src.ctx_ = NULL;
    }

    ~Ctx()
    {
        EVP_PKEY_CTX_free(ctx_);
    }

    explicit operator bool() const
    {
        return ctx_;
    }

    EVP_PKEY_CTX *
    get() noexcept
    {
        return ctx_;
    }

    EVP_PKEY_CTX **
    ptr() noexcept
    {
        return &ctx_;
    }

    EVP_PKEY_CTX *
    own() noexcept
    {
        auto res = ctx_;
        ctx_ = NULL;
        return res;
    }
};

struct MDCtxDeleter {
    void
    operator()(EVP_MD_CTX *ptr) const
    {
        EVP_MD_CTX_free(ptr);
    }
};

using MDCtx = std::unique_ptr<EVP_MD_CTX, MDCtxDeleter>;
} // namespace evp

#if !defined(CRYPTO_BACKEND_OPENSSL3)
class RSA {
    ::RSA *rsa_;

  public:
    RSA()
    {
        rsa_ = RSA_new();
    }

    RSA(const RSA &) = delete;

    ~RSA()
    {
        RSA_free(rsa_);
    }

    ::RSA *
    get() noexcept
    {
        return rsa_;
    }
};

class DSA {
    ::DSA *dsa_;

  public:
    DSA()
    {
        dsa_ = DSA_new();
    }

    DSA(const DSA &) = delete;

    ~DSA()
    {
        DSA_free(dsa_);
    }

    ::DSA *
    get() noexcept
    {
        return dsa_;
    }
};

class DH {
    ::DH *      dh_;
    const ::DH *dh_c_;

  public:
    DH() : dh_(DH_new()), dh_c_(NULL)
    {
    }

    DH(const ::DH *dh) : dh_(NULL), dh_c_(dh)
    {
    }

    DH(const DH &) = delete;

    ~DH()
    {
        DH_free(dh_);
    }

    ::DH *
    get() noexcept
    {
        return dh_;
    }

    const ::DH *
    get() const noexcept
    {
        return dh_c_ ? dh_c_ : dh_;
    }
};

class ECKey {
    ::EC_KEY *key_;

  public:
    ECKey(int nid) : key_(EC_KEY_new_by_curve_name(nid))
    {
    }

    ECKey(const ECKey &) = delete;

    ~ECKey()
    {
        EC_KEY_free(key_);
    }

    ::EC_KEY *
    get() noexcept
    {
        return key_;
    }
};

class ECPoint {
    ::EC_POINT *pt_;

  public:
    ECPoint(const EC_GROUP *grp) : pt_(EC_POINT_new(grp))
    {
    }

    ECPoint(const ECPoint &) = delete;

    ~ECPoint()
    {
        EC_POINT_free(pt_);
    }

    ::EC_POINT *
    get() noexcept
    {
        return pt_;
    }
};

#else

struct ParamDeleter {
    void
    operator()(OSSL_PARAM *ptr) const
    {
        OSSL_PARAM_free(ptr);
    }
};

using Param = std::unique_ptr<OSSL_PARAM, ParamDeleter>;

struct ParamBldDeleter {
    void
    operator()(OSSL_PARAM_BLD *ptr) const
    {
        OSSL_PARAM_BLD_free(ptr);
    }
};

using ParamBld = std::unique_ptr<OSSL_PARAM_BLD, ParamBldDeleter>;

#endif

inline const char *
latest_err()
{
    return ERR_error_string(ERR_peek_last_error(), NULL);
}

} // namespace ossl

} // namespace rnp

#endif