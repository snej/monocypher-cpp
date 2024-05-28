//
//  monocypher/Monocypher+blake3.cc
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

#include "monocypher/ext/blake3.hh"
#include "blake3.h"
#include <stdexcept>

namespace monocypher::ext {
    using namespace std;

    // Verify that the size of `context` matches the actual hasher's size:
    static_assert(sizeof(Blake3Base::context) == sizeof(blake3_hasher));

    static blake3_hasher* hasher(Blake3Base::context *ctx) {
        return reinterpret_cast<blake3_hasher*>(ctx);
    }

    void Blake3Base::init_fn(context *ctx) {
        blake3_hasher_init(hasher(ctx));
    }

    void Blake3Base::update_fn(context *ctx, const uint8_t *message, size_t  message_size) {
        blake3_hasher_update(hasher(ctx), message, message_size);
    }

    void Blake3Base::final_fn(context *ctx, uint8_t* hash, size_t hash_size) {
        blake3_hasher_finalize(hasher(ctx), hash, hash_size);
    }

    void Blake3Base::create_fn(uint8_t* hash, size_t hash_size, const uint8_t *message, size_t message_size) {
        blake3_hasher ctx;
        blake3_hasher_init(&ctx);
        blake3_hasher_update(&ctx, message, message_size);
        blake3_hasher_finalize(&ctx, hash, hash_size);
    }

    void Blake3Base::init_mac_fn(context *ctx, const uint8_t *key, size_t key_size) {
        if (key_size != 32)
            throw std::invalid_argument("Blake3 MAC requires a 32-byte key");
        blake3_hasher_init_keyed(hasher(ctx), key);
    }

    void Blake3Base::create_mac_fn(uint8_t *hash, size_t hash_size,
                              const uint8_t *key, size_t key_size,
                              const uint8_t *message, size_t message_size) {
        if (key_size != 32)
            throw std::invalid_argument("Blake3 MAC requires a 32-byte key");
        blake3_hasher ctx;
        blake3_hasher_init_keyed(&ctx, key);
        blake3_hasher_update(&ctx, message, message_size);
        blake3_hasher_finalize(&ctx, hash, hash_size);
    }

}
