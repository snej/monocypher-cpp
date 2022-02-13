//
// Monocypher.cc
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

#include "Monocypher.hh"

// Bring in the monocypher implementation, still wrapped in a C++namespace:
#include "../vendor/monocypher/src/monocypher.c"


// On Apple platforms, `arc4random_buf()` is declared in <stdlib.h>.
// On Linux, it _may_ be in <bsd/stdlib.h> if the BSD compatibility lib is present.
// If it isn't available, we fall back to using C++ `std::random_device` (but see warning below.)
#ifdef __APPLE__
#  define MONOCYPHER_HAS_ARC4RANDOM
#elif defined __has_include
#  if __has_include (<arc4random.h>)
#    include <arc4random.h>
#    define MONOCYPHER_HAS_ARC4RANDOM
#  elif __has_include (<bsd/stdlib.h>)
#    include <bsd/stdlib.h>
#    define MONOCYPHER_HAS_ARC4RANDOM
#  endif
#endif

#ifndef MONOCYPHER_HAS_ARC4RANDOM
#include <random>
#endif


namespace monocypher {

    void randomize(void *dst, size_t size) {
#ifdef MONOCYPHER_HAS_ARC4RANDOM
#  undef MONOCYPHER_HAS_ARC4RANDOM
        ::arc4random_buf(dst, size);
#else
        assert(size % sizeof(unsigned) == 0);   // TODO: Handle odd sizes
        std::random_device rng;
        auto start = (uint8_t*)dst, end = start + size;
        for (uint8_t *i = start; i != end; i += sizeof(unsigned)) {
            unsigned r = rng();
            memcpy(i, &r, sizeof(unsigned));
        }
#endif
    }


    bool constant_time_compare(const void *xa, const void *xb, size_t size) {
        auto a = (const uint8_t*)xa, b = (const uint8_t*)xb;
        size_t i = 0;
        while (i + 64 <= size) {
            if (0 != crypto_verify64(a+i, b+i))
                return false;
            i += 64;
        }
        while (i + 32 <= size) {
            if (0 != crypto_verify32(a+i, b+i))
                return false;
            i += 32;
        }
        while (i + 16 <= size) {
            if (0 != crypto_verify16(a+i, b+i))
                return false;
            i += 16;
        }
        if (i < size) {
            if (size >= 16) {
                // Handle any remaining bytes by comparing the _last_ 16 bytes:
                return 0 == crypto_verify16(a + size - 16, b + size - 16);
            } else {
                // Kludge to handle size less than 16:
                uint8_t buf1[16] = {}, buf2[16] = {};
                memcpy(buf1, a, size);
                memcpy(buf2, b, size);
                return 0 == crypto_verify16(buf1, buf2);
            }
        }
        return true;
    }
}
