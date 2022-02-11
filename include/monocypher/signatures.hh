//
//  monocypher/signatures.hh
//
//  Unofficial idiomatic C++17 wrapper for Monocypher
//  <https://monocypher.org>
//
//  Copyright (c) 2022 Jens Alfke. All rights reserved.
//
// --- Standard 2-clause BSD licence follows ---
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once
#include "base.hh"
#include "key_exchange.hh"

namespace monocypher {
    using namespace MONOCYPHER_CPP_NAMESPACE;

    struct EdDSA;


    /// A digital signature. (For <Algorithm> use <EdDSA> or <Ed25519>.)
    template <class Algorithm = EdDSA>
    struct signature : public byte_array<64> {
        signature()                                           :byte_array<64>(0) { }
        explicit signature(const std::array<uint8_t,64> &a)   :byte_array<64>(a) { }
        signature(const void *data, size_t size)              :byte_array<64>(data, size) { }
    };


    /// A public key for verifying signatures. (For <Algorithm> use <EdDSA> or <Ed25519>.)
    template <class Algorithm = EdDSA>
    struct public_key : public byte_array<32> {
        public_key()                                           :byte_array<32>(0) { }
        explicit public_key(const std::array<uint8_t,32> &a)   :byte_array<32>(a) { }
        public_key(const void *data, size_t size)              :byte_array<32>(data, size) { }
        explicit public_key(input_bytes k)                      :public_key(k.data, k.size) { }

        /// Verifies a signature.
        [[nodiscard]]
        bool check(const signature<Algorithm> &sig, const void *msg, size_t msg_size) const {
            return 0 == Algorithm::check_fn(sig.data(), this->data(), u8(msg), msg_size);
        }

        [[nodiscard]]
        bool check(const signature<Algorithm> &sig, input_bytes msg) const {
            return check(sig, msg.data, msg.size);
        }

        /// Converts a public signature-verification key to a Curve25519 public key,
        /// for key exchange or encryption.
        /// @warning "It is generally considered poor form to reuse the same key for different
        ///     purposes. While this conversion is technically safe, avoid these functions
        ///     nonetheless unless you are particularly resource-constrained or have some other
        ///     kind of hard requirement. It is otherwise an unnecessary risk factor."
        explicit operator key_exchange<X25519_HChaCha20>::public_key() const {
            key_exchange<X25519_HChaCha20>::public_key pk;
            Algorithm::public_to_kx_fn(pk.data(), this->data());
            return pk;
        }
    };


    /// A secret/private key for generating signatures. (For <Algorithm> use <EdDSA> or <Ed25519>.)
    template <class Algorithm = EdDSA>
    struct signing_key : public secret_byte_array<32> {
        using public_key = monocypher::public_key<Algorithm>;
        using signature = monocypher::signature<Algorithm>;

        explicit signing_key(const std::array<uint8_t,32> &a) :secret_byte_array<32>(a) { }
        signing_key(const void *data, size_t size)            :secret_byte_array<32>(data, size) { }

        /// Creates a random secret key.
        static signing_key generate() {
            return signing_key();
        }

        /// Computes and returns the matching public key.
        public_key get_public_key() const {
            public_key pub;
            Algorithm::public_key_fn(pub.data(), this->data());
            return pub;
        }

        /// Signs a message. (Passing in the public key speeds up the computation.)
        [[nodiscard]]
        signature sign(const void *message, size_t message_size,
                       const public_key &pubKey) const {
            signature sig;
            Algorithm::sign_fn(sig.data(), this->data(), pubKey.data(), u8(message), message_size);
            return sig;
        }

        /// Signs a message. (Passing in the public key speeds up the computation.)
        [[nodiscard]]
        signature sign(input_bytes message, const public_key &pubKey) const {
            return sign(message.data, message.size, pubKey);
        }

        /// Signs a message.
        /// @note This has to first recompute the public key, which makes it a bit slower.
        [[nodiscard]]
        signature sign(const void *message, size_t message_size) const {
            signature sig;
            Algorithm::sign_fn(sig.data(), this->data(), nullptr, u8(message), message_size);
            return sig;
        }

        /// Signs a message.
        /// @note This has to first recompute the public key, which makes it a bit slower.
        [[nodiscard]]
        signature sign(input_bytes message) const {
            return sign(message.data, message.size);
        }

    private:
        signing_key() {randomize();}
    };


    /// A `signing_key` together with its `public_key`.
    /// Takes up more space, but is faster because the public key doesn't have to be derived.
    template <class Algorithm = EdDSA>
    struct key_pair {
        using signing_key = monocypher::signing_key<Algorithm>;
        using public_key = monocypher::public_key<Algorithm>;
        using signature = monocypher::signature<Algorithm>;

        /// Creates a new key-pair at random.
        static key_pair generate() {
            return key_pair(signing_key::generate());
        }

        explicit key_pair(const signing_key &sk,
                          const public_key &pk)             :_signingKey(sk), _publicKey(pk) { }
        explicit key_pair(const signing_key &sk)            :key_pair(sk, sk.get_public_key()) { }
        explicit key_pair(const std::array<uint8_t,32> &sa) :key_pair(signing_key(sa)) { }
        key_pair(const void *sk_data, size_t size)          :key_pair(signing_key(sk_data, size)) { }

        /// Returns the signing key.
        const signing_key& get_signing_key() const          {return _signingKey;}

        /// Returns the public key.
        const public_key& get_public_key() const            {return _publicKey;}

        /// Signs a message.
        [[nodiscard]]
        signature sign(const void *message, size_t message_size) const {
            return _signingKey.sign(message, message_size, _publicKey);
        }

        /// Signs a message.
        [[nodiscard]]
        signature sign(input_bytes msg) const               {return sign(msg.data, msg.size);}

        /// Verifies a signature.
        [[nodiscard]]
        bool check(const signature &sig, const void *msg, size_t msg_size) const {
            return _publicKey.check(sig, msg, msg_size);
        }

        [[nodiscard]]
        bool check(const signature &sig, input_bytes msg) const {
            return check(sig, msg.data, msg.size);
        }

    private:
        signing_key _signingKey;
        public_key  _publicKey;
    };


    /// EdDSA with Curve25519 and Blake2b.
    /// (Use as `<Algorithm>` parameter to `signature`, `public_key`, `signing_key`.)
    /// \note  This is not the same as the commonly-used Ed25519, which uses SHA-512.
    ///        An `Ed25519` struct is declared in `Monocypher-ed25519.hh`.
    struct EdDSA {
        static constexpr const char* name      = "EdDSA";
        static constexpr auto check_fn         = c::crypto_check;
        static constexpr auto sign_fn          = c::crypto_sign;
        static constexpr auto public_key_fn    = c::crypto_sign_public_key;
        static constexpr auto public_to_kx_fn  = c::crypto_from_eddsa_public;
        static constexpr auto private_to_kx_fn = c::crypto_from_eddsa_private;

        // Convenient type aliases for those who don't like angle brackets
        using signature   = monocypher::signature<EdDSA>;
        using public_key  = monocypher::public_key<EdDSA>;
        using signing_key = monocypher::signing_key<EdDSA>;
        using key_pair    = monocypher::key_pair<EdDSA>;
    };


    // Forward-declared template functions:

    template <class A>
    template <class SA>
    key_exchange<A>::key_exchange(const monocypher::signing_key<SA> &signingKey) {
        SA::private_to_kx_fn(_secret_key.data(), signingKey.data());
    }

    template <class A>
    template <class SA>
    key_exchange<A>::public_key::public_key(const monocypher::public_key<SA> &publicKey) {
        SA::public_to_kx_fn(this->data(), publicKey.data());
    }

}
