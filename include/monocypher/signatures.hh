//
//  monocypher/signatures.hh
//
//  Monocypher-Cpp: Unofficial idiomatic C++17 wrapper for Monocypher
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
    };


    /// A key-pair for generating signatures. (For <Algorithm> use <EdDSA> or <Ed25519>.)
    template <class Algorithm = EdDSA>
    struct key_pair : public secret_byte_array<64> {
        using public_key = monocypher::public_key<Algorithm>;
        using signature = monocypher::signature<Algorithm>;

        /// Creates a new key-pair at random.
        static key_pair generate() {
            return key_pair(seed());
        }

        explicit key_pair(const std::array<uint8_t,64> &a)   :secret_byte_array<64>(a) { }
        key_pair(const void *data, size_t size)              :secret_byte_array<64>(data, size) { }
        explicit key_pair(input_bytes k)                     :secret_byte_array<64>(k.data, k.size) { }

        /// Returns the public key.
        const public_key& get_public_key() const {
            // "Now the private key is 64 bytes, and is the concatenation of the seed and the public
            // key just like Libsodium." --Loup Vaillant, commit da7b5407
            return reinterpret_cast<public_key const&>(range<32,32>());
        }

        /// Signs a message.
        [[nodiscard]]
        signature sign(const void *message, size_t message_size) const {
            signature sig;
            Algorithm::sign_fn(sig.data(), data(), u8(message), message_size);
            return sig;
        }

        /// Signs a message.
        [[nodiscard]]
        signature sign(input_bytes message) const {
            return sign(message.data, message.size);
        }

        /// Verifies a signature.
        [[nodiscard]]
        bool check(const signature &sig, const void *msg, size_t msg_size) const {
            return get_public_key().check(sig, msg, msg_size);
        }

        [[nodiscard]]
        bool check(const signature &sig, input_bytes msg) const {
            return check(sig, msg.data, msg.size);
        }

        /// The random data that a key_pair is derived from; also known as the secret key.
        struct seed : public secret_byte_array<32> {
            seed()                                          {randomize();}
            explicit seed(const std::array<uint8_t,32> &a)  :secret_byte_array<32>(a) { }
            seed(const void *data, size_t size)             :secret_byte_array<32>(data, size) { }

            /// Computes and returns the matching public key.
            inline public_key get_public_key() const{
                return key_pair(*this).get_public_key();
            }

            /// Signs a message.
            /// @note This has to first recompute the public key, which makes it a bit slower.
            [[nodiscard]]
            inline signature sign(const void *message, size_t message_size) const{
                return key_pair(*this).sign(message, message_size);
            }

            /// Signs a message.
            /// @note This has to first recompute the public key, which makes it a bit slower.
            [[nodiscard]]
            signature sign(input_bytes message) const {
                return sign(message.data, message.size);
            }
        };

        explicit key_pair(const seed &sk) {
            // "Users who can't afford the overhead of storing 32 additional bytes for
            //  the secret key (say they need to burn the key into expensive fuses),
            //  they can always only store the first 32 bytes, and re-derive the entire
            //  key pair when they need it." --Loup Vaillant, commit da7b5407
            secret_byte_array<32> seed = sk;
            public_key pub; // ignored
            Algorithm::generate_fn(data(), pub.data(), seed.data());
        }

        /// Returns the 32-byte seed, or secret key. The key_pair can be recreated from this.
        const seed& get_seed() const {
            return reinterpret_cast<seed const&>(range<0,32>());
        }

    private:
        key_pair() = default;
    };


    // compatibility alias for clients that used to use the `signing_key` class.
    template <class Algorithm = EdDSA>
    using signing_key = typename key_pair<Algorithm>::seed;



    /// EdDSA with Curve25519 and Blake2b.
    /// (Use as `<Algorithm>` parameter to `signature`, `public_key`, `key_pair`.)
    /// \note  This is not the same as the commonly-used Ed25519, which uses SHA-512.
    ///        An `Ed25519` struct is declared in `Monocypher-ed25519.hh`.
    struct EdDSA {
        static constexpr const char* name      = "EdDSA";
        static constexpr auto generate_fn      = c::crypto_eddsa_key_pair;
        static constexpr auto check_fn         = c::crypto_eddsa_check;
        static constexpr auto sign_fn          = c::crypto_eddsa_sign;
        static constexpr auto public_to_kx_fn  = c::crypto_eddsa_to_x25519;

        // Convenient type aliases for those who don't like angle brackets
        using signature   = monocypher::signature<EdDSA>;
        using public_key  = monocypher::public_key<EdDSA>;
        using key_pair    = monocypher::key_pair<EdDSA>;
    };

}
