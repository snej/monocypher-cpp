//
//  monocypher/ext/blake3.hh
//
//  Monocypher-Cpp: Unofficial idiomatic C++17 wrapper for Monocypher
//  <https://monocypher.org>
//
//  Copyright (c) 2024 Jens Alfke. All rights reserved.
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
#include "../hash.hh"
#include <memory>

namespace monocypher::ext {

    struct Blake3Base {
        static constexpr const char* name = "BLAKE3";
        using context = byte_array<1912>;
        static void init_fn  (context *ctx);
        static void update_fn(context *ctx, const uint8_t *message, size_t  message_size);
    protected:
        static void final_fn(context *ctx, uint8_t *hash, size_t hash_size);
        static void create_fn(uint8_t *hash, size_t hash_size, const uint8_t *msg, size_t msg_size);
        static void init_mac_fn(context *ctx, const uint8_t *key, size_t key_size);
        static void create_mac_fn(uint8_t *hash, size_t hash_size,
                                  const uint8_t *key, size_t key_size,
                                  const uint8_t *message, size_t message_size);
    };

    /// The BLAKE3 digest algorithm, for use as the template parameter to `hash`.
    ///
    /// @note This functionality is NOT part of Monocypher itself.
    /// It uses the C reference implementation, <https://github.com/BLAKE3-team/BLAKE3>
    template <size_t Size = 32>
    struct Blake3 : public Blake3Base {
        static constexpr size_t hash_size = Size;

        static void final_fn (context *ctx, uint8_t hash[Size]) {
            Blake3Base::final_fn(ctx, hash, hash_size);
        }
        static void create_fn(uint8_t hash[Size], const uint8_t *message, size_t message_size) {
            Blake3Base::create_fn(hash, hash_size, message, message_size);
        }

        /// Note: BLAKE3's HMAC algorithm requires the key to be exactly 32 bytes.
        struct mac {
            using context = Blake3::context;

            static void create_fn(uint8_t *hash, const uint8_t *key, size_t key_size,
                                  const uint8_t *message, size_t message_size)
            {
                Blake3Base::create_mac_fn(hash, hash_size, key, key_size, message, message_size);
            }
            static void init_fn(context *ctx, const uint8_t *key, size_t key_size) {
                Blake3Base::init_mac_fn(ctx, key, key_size);
            }
            static constexpr auto update_fn     = Blake3::update_fn;
            static constexpr auto final_fn      = Blake3::final_fn;
        };
    };

    /// Blake3 hash class with default 256-bit (32-byte) hash size..
    using blake3 = hash<Blake3<>>;
}
