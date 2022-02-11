//
//  monocypher/base.hh
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
#define MONOCYPHER_CPP_NAMESPACE monocypher::c
#include "../../vendor/monocypher/src/monocypher.h"

#include <array>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <cassert>

namespace monocypher {

//======== Utilities:

    static inline const uint8_t* u8(const void *p)  {return reinterpret_cast<const uint8_t*>(p);}
    static inline uint8_t* u8(void *p)              {return reinterpret_cast<uint8_t*>(p);}


    /// Fills the array with cryptographically-secure random bytes.
    /// \warning On platforms where `arc4random` is unavailable, this uses `std::random_device`.
    ///    The C++ standard says "random_device may be implemented in terms of an implementation-
    ///    defined pseudo-random number engine if a non-deterministic source (e.g. a hardware
    ///    device) is not available to the implementation." In that situation you should try to use
    ///    some other source of randomization.
    void randomize(void *dst, size_t size);

    /// Securely fills memory with zeroes.
    /// Unlike a regular `memset` this cannot be optimized away by the compiler.
    static inline void wipe(void *dst, size_t size)             {c::crypto_wipe(dst, size);}

    /// Constant-time memory comparison, used to avoid timing attacks.
    /// @note  This returns `bool`, not `int` like `memcmp` or `crypto_verify`!
    bool constant_time_compare(const void *a, const void *b, size_t size);


    /// General-purpose byte array. Used for hashes, nonces, MACs, etc.
    template <size_t Size>
    class byte_array: public std::array<uint8_t, Size> {
    public:
        explicit byte_array() { }
        explicit byte_array(uint8_t b)                           {::memset(this->data(), b, Size);}
        explicit byte_array(const std::array<uint8_t,Size> &a)   :std::array<uint8_t,Size>(a) { }
        explicit byte_array(const void *bytes, size_t size)      {fillWith(bytes, size);}

        /// Fills the array with cryptographically-secure random bytes.
        /// \warning See the above warning on the standalone `randomize` function.
        void randomize()                            {monocypher::randomize(this->data(), Size);}

        /// Securely fills the array with zeroes. Unlike a regular `memset` this cannot be optimized
        /// away even if the array is about to be destructed.
        void wipe()                                 {c::crypto_wipe(this->data(), Size);}

        /// Idiomatic synonym for `wipe`.
        void clear()                                {this->wipe();}

        void fill(uint8_t b) {  // "overridden" to use `wipe` first
            this->wipe();
            if (b != 0) std::array<uint8_t,Size>::fill(b);  // (wipe already fills with 0)
        }

        void fillWith(const void *bytes, size_t size) {
            assert(size == sizeof(*this));
            ::memcpy(this->data(), bytes, sizeof(*this));
        }

        /// Returns a subrange of this array, as a mutable reference.
        template<size_t Pos, size_t Len>
        byte_array<Len>& range() {
            static_assert(Pos + Len <= Size);
            return reinterpret_cast<byte_array<Len>&>((*this)[Pos]);
        }

        /// Returns a subrange of this array, as a reference.
        template<size_t Pos, size_t Len>
        byte_array<Len> const& range() const {
            static_assert(Pos + Len <= Size);
            return reinterpret_cast<byte_array<Len> const&>((*this)[Pos]);
        }

        /// The `|` operator concatenates two arrays. It's mathematical!
        template <size_t Size2>
        byte_array<Size+Size2> operator| (byte_array<Size2> const& other) const {
            byte_array<Size+Size2> result;
            result.template range<0,Size>() = *this;
            result.template range<Size,Size2>() = other;
            return result;
        }

        explicit operator uint8_t*()                         {return this->data();}
        explicit operator const uint8_t*() const             {return this->data();}
    };


    /// Byte-array of secret data. Its destructor securely erases the contents.
    /// Used for private keys and shared secrets.
    template <size_t Size>
    class secret_byte_array: public byte_array<Size> {
    public:
        explicit secret_byte_array() { }
        explicit secret_byte_array(uint8_t b)                           :byte_array<Size>(b) { }
        explicit secret_byte_array(const std::array<uint8_t,Size> &a)   :byte_array<Size>(a) { }
        explicit secret_byte_array(const void *p, size_t s)             :byte_array<Size>(p, s) { }
        ~secret_byte_array()                                            {this->wipe();}

        template <size_t Size2>
        secret_byte_array<Size+Size2> operator| (byte_array<Size2> const& other) const {
            secret_byte_array<Size+Size2> result;
            result.template range<0,Size>() = *this;
            result.template range<Size,Size2>() = other;
            return result;
        }
    };



    // byte_arrays use constant-time comparison.
    template <size_t Size>
    static inline bool operator== (const byte_array<Size> &a, const byte_array<Size> &b) {
        static_assert(Size % 16 == 0);
        return constant_time_compare(a.data(), b.data(), Size);
    }

    template <size_t Size>
    static inline bool operator!= (const byte_array<Size> &a, const byte_array<Size> &b) {
        return !(a == b);
    }

    // specialized comparisons for common sizes
    template<> inline bool operator== (const byte_array<16> &a, const byte_array<16> &b) {
        return 0 == c::crypto_verify16(a.data(), b.data());
    }
    template<> inline bool operator== (const byte_array<24> &a, const byte_array<24> &b) {
        return 0 == c::crypto_verify16(a.data(), b.data()) && 0 == c::crypto_verify16(&a[8], &b[8]);
    }
    template<> inline bool operator== (const byte_array<32> &a, const byte_array<32> &b) {
        return 0 == c::crypto_verify32(a.data(), b.data());
    }
    template<> inline bool operator== (const byte_array<64> &a, const byte_array<64> &b) {
        return 0 == c::crypto_verify64(a.data(), b.data());
    }


    /// Variable-length data input to a function. Implicit conversion from string and array.
    struct input_bytes {
        uint8_t const* const data;
        size_t const         size;

        input_bytes(const void *d, size_t s)    :data(u8(d)), size(s) { }
        input_bytes(std::string_view str)       :input_bytes(str.data(), str.size()) { }
        input_bytes(std::string const& str)     :input_bytes(str.data(), str.size()) { }

        template <size_t Size>
        input_bytes(byte_array<Size> const& a)  :data(a.data()), size(a.size()) { }
    };


    /// Variable-length mutable data to be returned from a function.
    struct output_bytes {
        void*  data;
        size_t size;

        output_bytes()                          :data(nullptr), size(0) { }
        output_bytes(void *d, size_t s)         :data(d), size(s) { }

        template <size_t Size>
        output_bytes(byte_array<Size> &a)       :data(a.data()), size(a.size()) { }

        output_bytes shrunk_to(size_t s) const  {assert(s <= size); return {data, s};}

        explicit operator bool() const          {return data != nullptr;}
    };

}
