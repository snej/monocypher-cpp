//
//  monocypher/key_derivation.hh
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
#include <memory>  // for std::make_unique
#include <utility> // for std::pair

namespace monocypher {
    using namespace MONOCYPHER_CPP_NAMESPACE;

    enum ArgonAlgorithm {
        Argon2d,
        Argon2i,
        Argon2id,
    };

    /// Argon2 is a password key derivation scheme: given an arbitrary password string,
    /// it produces a 32- or 64-bit value derived from it, for use as a cryptographic key.
    /// It is deliberately slow and memory-intensive, to deter brute-force attacks.
    /// 
    /// The template parameters adjust performance, but must be fixed ahead of time before any
    /// passwords are hashed, since changing them changes the derived keys.
    ///
    /// - `Algorithm` selects the variant of Argon2, defaulting to Argon2i.
    /// - `Size` is the size of the hash in bytes, and should be either 32 or 64.
    /// - `NBlocks` is the "number of blocks for the work area. Must be at least 8.
    ///    A value of 100000 (one hundred megabytes) is a good starting point.
    ///    If the computation takes too long, reduce this number.
    ///    If it is too fast, increase it.
    ///    If it is still too fast with all available memory, increase nb_passes."
    /// - `NIterations` is the "number of passes. Must be at least 1.
    ///    A value of 3 is strongly recommended when using Argon2i;
    ///    any value lower than 3 enables significantly more efficient attacks."
    template <ArgonAlgorithm Algorithm = Argon2i,
              size_t Size=64,
              uint32_t NBlocks = 100000,
              uint32_t NIterations = 3>
    struct argon2 {
        /// An Argon2 hash generated from a password.
        struct hash : public secret_byte_array<Size> {
            hash()                                           :secret_byte_array<Size>(0) { }
            explicit hash(const std::array<uint8_t,Size> &a) :secret_byte_array<Size>(a) { }
            hash(const void *data, size_t size)              :secret_byte_array<Size>(data, size) { }
        };

        /// The per-password "salt" input used to deter multi-password attacks.
        struct salt : public secret_byte_array<16> {
            salt()                                           :secret_byte_array<16>(0) { }
            explicit salt(const std::array<uint8_t,16> &a)   :secret_byte_array<16>(a) { }
            salt(const void *data, size_t size)              :secret_byte_array<16>(data, size) { }
            salt(const char *str)                            {fillWithString(str);}
        };

        /// Generates an Argon2 hash from a password and a given salt value.
        /// \note This function is _deliberately_ slow. It's intended to take at least 0.5sec.
        /// \warning This _deliberately_ allocates a lot of memory while running: 100MB with the default
        ///     `NBlocks`. Throws `std::bad_alloc` on allocation failure, unless you've disabled
        ///      exceptions, in which case it aborts.
        static hash create(const void *password, size_t password_size, const salt &s4lt) {
            assert(password_size <= UINT32_MAX);
            hash result;
            auto work_area = std::make_unique<uint8_t[]>(NBlocks * 1024);
            if (!work_area)
                abort();  // exceptions must be disabled, but we cannot continue.
            c::crypto_argon2_config config = {
                Algorithm,  // algorithm; Argon2d, Argon2i, Argon2id
                NBlocks,    // nb_blocks; memory hardness, >= 8 * nb_lanes
                NIterations,// nb_passes; CPU hardness, >= 1 (>= 3 recommended for Argon2i)
                1,          // nb_lanes;  parallelism level (single threaded anyway)
            };
            c::crypto_argon2_inputs inputs = {
                (const uint8_t*)password,
                s4lt.data(),
                uint32_t(password_size),
                sizeof(s4lt),
            };
            c::crypto_argon2_extras extras = {};
            c::crypto_argon2(result.data(), Size, work_area.get(), config, inputs, extras);
            return result;
        }

        static hash create(input_bytes password, const salt &s4lt) {
            return create(password.data, password.size, s4lt);
        }

        /// Generates an Argon2 hash from the input password and a randomly-generated salt value,
        /// and returns both.
        /// \note This function is _deliberately_ slow. It's intended to take at least 0.5sec.
        /// \warning This _deliberately_ allocates a lot of memory while running: 100MB with the default
        ///     `NBlocks`. Throws `std::bad_alloc` on allocation failure, unless you've disabled
        ///      exceptions, in which case it aborts.
        static std::pair<hash, salt> create(const void *password, size_t password_size) {
            salt s4lt;
            s4lt.randomize();
            return {create(password, password_size, s4lt), s4lt};
        }

        static std::pair<hash, salt> create(input_bytes password) {
            return create(password.data, password.size);
        }
    };


    template <size_t Size=64, uint32_t NBlocks = 100000, uint32_t NIterations = 3>
    using argon2i = argon2<Argon2i,Size,NBlocks,NIterations>;

}
