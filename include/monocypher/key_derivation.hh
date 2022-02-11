//
//  monocypher/key_derivation.hh
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
#include "base.hh"
#include <memory>  // for std::make_unique
#include <utility> // for std::pair

namespace monocypher {
    using namespace MONOCYPHER_CPP_NAMESPACE;

    /// Argon2i is a password key derivation scheme. It is deliberately slow and memory-intensive,
    /// to deter brute-force attacks.
    /// `Size` is the size of the hash in bytes, and should be either 32 or 64.
    /// The `NBlocks` and `NIterations` parameters can tune the memory usage and time, but read
    /// the Monocypher documentation so you know what you're doing.
    template <size_t Size=64, uint32_t NBlocks = 100000, uint32_t NIterations = 3>
    struct argon2i {
        /// An Argon2i hash generated from a password.
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
            salt(const char *str)                 { ::strncpy((char*)data(), str, sizeof(*this)); }
        };

        /// Generates an Argon2i hash from a password and a given salt value.
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
            c::crypto_argon2i(result.data(), Size,
                              work_area.get(), NBlocks, NIterations,
                              u8(password), uint32_t(password_size),
                              s4lt.data(), sizeof(s4lt));
            return result;
        }

        static hash create(input_bytes password, const salt &s4lt) {
            return create(password.data, password.size, s4lt);
        }

        /// Generates an Argon2i hash from the input password and a randomly-generated salt value,
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

}
