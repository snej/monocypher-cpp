//
//  monocypher/key_exchange.hh
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

namespace monocypher {
    using namespace MONOCYPHER_CPP_NAMESPACE;

    template <class SigAlg> struct public_key;
    template <class SigAlg> struct key_pair;


    /// Raw Curve25519 key exchange algorithm for `key_exchange`; use only if you know what
    /// you're doing!
    /// @warning Shared secrets are not quite random. Hash them to derive an actual shared key;
    ///     X25519_HChaCha20 does this.
    struct X25519_Raw {
        static constexpr const char* name = "X25519";
        static constexpr auto get_public_key_fn = c::crypto_x25519_public_key;
        static constexpr auto key_exchange_fn   = c::crypto_x25519;
    };

    /// Curve25519 key exchange, with the output shared key run through the HChaCha20 hash function
    /// to improve its randomness.
    struct X25519_HChaCha20 {
        static constexpr const char* name = "X25519+HChaCha20";
        static constexpr auto get_public_key_fn = c::crypto_x25519_public_key;

        static void key_exchange_fn (uint8_t       shared_key[32],
                                     const uint8_t your_secret_key [32],
                                     const uint8_t their_public_key[32])
        {
            c::crypto_x25519(shared_key, your_secret_key, their_public_key);
            byte_array<16> zero {0};
            c::crypto_chacha20_h(shared_key, shared_key, zero.data());
        }
    };


    /// Performs a Diffie-Hellman key exchange with another party, combining your secret key with
    /// the other's public key to create a shared secret known to both of you.
    template <class Algorithm>
    class key_exchange {
    public:
        /// A secret key for key exchange.
        struct secret_key : public secret_byte_array<32> { };

        /// A public key generated from the secret key, to be exchanged with the peer.
        struct public_key : public byte_array<32> {
            public_key()                                           :byte_array<32>(0) { }
            explicit public_key(const std::array<uint8_t,32> &a)   :byte_array<32>(a) { }
            public_key(const void *data, size_t size)              :byte_array<32>(data, size) { }

            /// Creates a key-exchange (Curve25519) public key from a signing (Ed25519) public key.
            template <class SigAlg> explicit public_key(const monocypher::public_key<SigAlg>&);
        };

        /// A secret value derived from two parties' keys, which will be the same for both.
        struct shared_secret : public secret_byte_array<32> { };


        /// Initializes a key exchange, generating a random secret key.
        key_exchange() {
            _secret_key.randomize();
        }

        /// Initializes a key exchange, using an existing secret key.
        explicit key_exchange(const secret_key &key)
        :_secret_key(key) { }

        /// Initializes a Curve25519 key-exchange context from an Ed25519 signing key-pair.
        template <class SigAlg> explicit key_exchange(const key_pair<SigAlg>&);

        /// Returns the public key to send to the other party.
        public_key get_public_key() const {
            public_key pubkey;
            Algorithm::get_public_key_fn(pubkey.data(), _secret_key.data());
            return pubkey;
        }

        /// Returns the secret key, in case you want to reuse it later.
        secret_key get_secret_key() const {
            return _secret_key;
        }

        /// Given the other party's public key, computes the shared secret.
        shared_secret get_shared_secret(const public_key &their_public_key) const {
            shared_secret shared;
            Algorithm::key_exchange_fn(shared.data(), _secret_key.data(), their_public_key.data());
            return shared;
        }

    private:
        secret_key _secret_key;
    };


    // Overloaded `*` for Curve25519 scalar multiplication:
    static inline key_exchange<X25519_Raw>::shared_secret
    operator* (key_exchange<X25519_Raw> const& k, key_exchange<X25519_Raw>::public_key const& pk) {
        return k.get_shared_secret(pk);
    }

}
