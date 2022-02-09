//
// Monocypher+sha256.hh
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
#include "Monocypher.hh"

namespace monocypher::ext {

    /// SHA-256 algorithm, for use as the template parameter to `hash`.
    ///
    /// @note This functionality is NOT part of Monocypher itself. It's provided for compatibility.
    /// The implementation is Brad Conte, from <https://github.com/B-Con/crypto-algorithms>
    struct SHA256 {
        static constexpr const char* name = "SHA-256";
        static constexpr size_t hash_size = 256 / 8;

        using context = std::array<uint64_t, 14>;

        static void init_fn  (context *ctx);
        static void update_fn(context *ctx, const uint8_t *message, size_t  message_size);
        static void final_fn (context *ctx, uint8_t hash[32]);
        static void create_fn(uint8_t hash[32], const uint8_t *message, size_t message_size);
        // (no MAC support, sorry)
    };

    using sha256 = hash<SHA256>;
}
