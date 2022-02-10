//
// Monocypher.cc
//

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

}
