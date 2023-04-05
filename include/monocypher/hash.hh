//
//  monocypher/hash.hh
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

    /// Cryptographic hash class, templated by algorithm and size.
    /// The only `Algorithm` currently available is `Blake2b`.
    /// The `Size` is in bytes and must be between 1 and 64. Sizes below 32 are not recommended.
    template <class HashAlgorithm>
    class hash : public byte_array<HashAlgorithm::hash_size> {
    public:
        static constexpr size_t Size = HashAlgorithm::hash_size;

        hash()                                           :byte_array<Size>(0) { }
        explicit hash(const std::array<uint8_t,Size> &a) :byte_array<Size>(a) { }
        hash(const void *data, size_t size)              :byte_array<Size>(data, size) { }

        /// Returns the Blake2b hash of a message.
        static hash create(const void *message, size_t message_size) noexcept {
            hash result;
            HashAlgorithm::create_fn(result.data(), u8(message), message_size);
            return result;
        }

        static hash create(input_bytes message) noexcept {
            return create(message.data, message.size);
        }

        /// Returns the hash of a message and a secret key, for use as a MAC.
        template <size_t KeySize>
        static hash createMAC(const void *message, size_t message_size,
                              const byte_array<KeySize> &key) noexcept {
            hash result;
            HashAlgorithm::mac::create_fn(result.data(),
                                          key.data(), key.size(),
                                          u8(message), message_size);
            return result;
        }

        template <size_t KeySize>
        static hash createMAC(input_bytes message,
                              const byte_array<KeySize> &key) noexcept {
            return createMAC(message.data, message.size, key);
        }


        template <class BuilderAlg>
        class _builder {
        public:
            /// Hashes more data.
            _builder& update(const void *message, size_t message_size) {
                BuilderAlg::update_fn(&_ctx, u8(message), message_size);
                return *this;
            }

            _builder& update(input_bytes message) {
                return update(message.data, message.size);
            }

            /// Returns the final hash of all the data passed to `update`.
            [[nodiscard]]
            hash final() {
                hash result;
                BuilderAlg::final_fn(&_ctx, result.data());
                return result;
            }

        protected:
            typename BuilderAlg::context _ctx;
        };

        /// Incrementally constructs a hash.
        class builder : public _builder<HashAlgorithm> {
        public:
            /// Constructs a Blake2b builder.
            /// Call `update` one or more times to hash data, then `final` to get the hash.
            builder() {
                HashAlgorithm::init_fn(&this->_ctx);
            }
        };

        /// Incrementally constructs a MAC.
        class mac_builder : public _builder<typename HashAlgorithm::mac> {
        public:
            /// Constructs a Blake2b builder with a secret key, for creating MACs.
            /// Call `update` one or more times to hash data, then `final` to get the hash.
            template <size_t KeySize>
            mac_builder(const byte_array<KeySize> &key) {
                HashAlgorithm::mac::init_fn(&this->_ctx, key.data(), key.size());
            }
        };
    };


    /// Blake2b algorithm; use as `<HashAlgorithm>` in the `hash` template.
    template <size_t Size>
    struct Blake2b {
        static constexpr const char* name = "Blake2b";
        static constexpr size_t hash_size = Size;

        using context = c::crypto_blake2b_ctx;

        static void create_fn(uint8_t *hash, const uint8_t *message, size_t message_size) {
            c::crypto_blake2b(hash, hash_size, message, message_size);
        }
        static void init_fn(context *ctx) {
            c::crypto_blake2b_init(ctx, hash_size);
        }
        static constexpr auto update_fn     = c::crypto_blake2b_update;
        static constexpr auto final_fn      = c::crypto_blake2b_final;

        struct mac {
            using context = c::crypto_blake2b_ctx;

            static void create_fn(uint8_t *hash, const uint8_t *key, size_t key_size,
                                  const uint8_t *message, size_t message_size)
            {
                c::crypto_blake2b_keyed(hash, hash_size, key, key_size, message, message_size);
            }
            static void init_fn(context *ctx, const uint8_t *key, size_t key_size) {
                c::crypto_blake2b_keyed_init(ctx, hash_size, key, key_size);
            }
            static constexpr auto update_fn     = c::crypto_blake2b_update;
            static constexpr auto final_fn      = c::crypto_blake2b_final;
        };
    };


    /// Blake2b-64 hash class.
    using blake2b64 = hash<Blake2b<64>>;

    /// Blake2b-32 hash class.
    using blake2b32 = hash<Blake2b<32>>;

    // Note: See Monocypher-ed25519.hh for SHA-512, and Monocypher+sha256.hh for SHA-256.


}
