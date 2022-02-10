//
// Monocypher+sha256.cc
//
// Copyright © 2022 Jens Alfke. All rights reserved.
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

#include "monocypher/ext/sha256.hh"

// Wrap 3rd party sha256.c in a namespace to avoid messing with global namespace:
namespace monocypher::b_con {
#include "../vendor/B-Con/sha256.c"
}

namespace monocypher::ext {
    using namespace monocypher::b_con;

    // Make sure my `context` type can serve as a `SHA256_CTX` for the implementation:
    static_assert(sizeof(SHA256::context)  == sizeof(SHA256_CTX));
    static_assert(alignof(SHA256::context) == alignof(SHA256_CTX));

    void SHA256::create_fn(uint8_t hash[32], const uint8_t *message, size_t message_size) {
        context ctx;
        init_fn(&ctx);
        update_fn(&ctx, message, message_size);
        final_fn(&ctx, hash);
    }

    void SHA256::init_fn(context *ctx) {
        sha256_init((SHA256_CTX*)ctx);
    }

    void SHA256::update_fn(context *ctx, const uint8_t *message, size_t  message_size) {
        sha256_update((SHA256_CTX*)ctx, message, message_size);
    }

    void SHA256::final_fn(context *ctx, uint8_t hash[32]) {
        sha256_final((SHA256_CTX*)ctx, hash);
    }


}
