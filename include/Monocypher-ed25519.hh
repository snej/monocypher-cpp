//
// Monocypher-ed25519.hh
//
// Copyright © 2022 Jens Alfke. All rights reserved.
//

#pragma once
#include "Monocypher.hh"
#include "../vendor/monocypher/src/optional/monocypher-ed25519.h"

namespace monocypher {

    /// EdDSA with Curve25519 and SHA-512.
    /// \note This algorithm is more widely used than `EdDSA`, but slower and brings in a bit more code.
    /// (Use as `<Algorithm>` parameter to `signature`, `public_key`, `signing_key`.)
    struct Ed25519 {
        static constexpr auto check_fn      = crypto_ed25519_check;
        static constexpr auto sign_fn       = crypto_ed25519_sign;
        static constexpr auto public_key_fn = crypto_ed25519_public_key;

        // Convenient type aliases for those who don't like angle brackets
        using signature   = monocypher::signature<Ed25519>;
        using public_key  = monocypher::public_key<Ed25519>;
        using signing_key = monocypher::signing_key<Ed25519>;
    };

}
