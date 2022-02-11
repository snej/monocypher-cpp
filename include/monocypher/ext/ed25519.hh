//
//  monocypher/ext/ed25519.hh
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
#include "../hash.hh"
#include "../signatures.hh"
#include "../../../vendor/monocypher/src/optional/monocypher-ed25519.h"

namespace monocypher {

    // This functionality is an extension that comes with Monocypher.
    // It's not considered part of the core API, but is provided for compatibility.

    /// EdDSA with Curve25519 and SHA-512.
    /// \note This algorithm is more widely used than `EdDSA`, but slower and brings in more code.
    /// (Use as `<Algorithm>` parameter to `signature`, `public_key`, `signing_key`.)
    struct Ed25519 {
        static constexpr const char* name = "Ed25519";
        static constexpr auto check_fn         = c::crypto_ed25519_check;
        static constexpr auto sign_fn          = c::crypto_ed25519_sign;
        static constexpr auto public_key_fn    = c::crypto_ed25519_public_key;
        static constexpr auto public_to_kx_fn  = c::crypto_from_ed25519_public;
        static constexpr auto private_to_kx_fn = c::crypto_from_ed25519_private;

        // Convenient type aliases for those who don't like angle brackets
        using signature   = monocypher::signature<Ed25519>;
        using public_key  = monocypher::public_key<Ed25519>;
        using signing_key = monocypher::signing_key<Ed25519>;
        using key_pair    = monocypher::key_pair<Ed25519>;
    };


    /// SHA-512 algorithm, for use as the template parameter to `hash`.
    struct SHA512 {
        static constexpr const char* name = "SHA-512";
        static constexpr size_t hash_size = 512 / 8;

        using context = c::crypto_sha512_ctx;
        static constexpr auto create_fn = c::crypto_sha512;
        static constexpr auto init_fn   = c::crypto_sha512_init;
        static constexpr auto update_fn = c::crypto_sha512_update;
        static constexpr auto final_fn  = c::crypto_sha512_final;

        struct mac {
            using context = c::crypto_hmac_sha512_ctx;
            static constexpr auto create_fn = c::crypto_hmac_sha512;
            static constexpr auto init_fn   = c::crypto_hmac_sha512_init;
            static constexpr auto update_fn = c::crypto_hmac_sha512_update;
            static constexpr auto final_fn  = c::crypto_hmac_sha512_final;
        };
    };

    using sha512 = hash<SHA512>;
}
