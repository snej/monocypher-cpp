//
// Monocypher+xsalsa20.cc
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

#include "monocypher/ext/xsalsa20.hh"
#include <memory>
#include <cstring>

// Wrap 3rd party tweetnacl.c in a namespace to avoid messing with global namespace:
namespace monocypher::tweetnacl {
    #include "../vendor/tweetnacl/tweetnacl.c"

    // tweetnacl leaves this undefined. The code below doesn't require it, but in a debug build
    // without dead-stripping, we get link errors without it.
    void randombytes(uint8_t *bytes, unsigned long long size) {
        monocypher::randomize(bytes, size_t(size));
    }
}


namespace monocypher::ext {
    using namespace monocypher::tweetnacl;

    // NaCL's `secretbox` C API is batshit crazy:  https://nacl.cr.yp.to/secretbox.html 🤯
    // It requires 32 zero bytes before the plaintext,
    // and writes 16 zero bytes before the mac-and-ciphertext.
    // The size parameter needs to include those 32 bytes.
    // Unboxing is the reverse.
    // WTF.

    void XSalsa20_Poly1305::lock(uint8_t *out,
                                 uint8_t mac[16],
                                 const uint8_t key[32],
                                 const uint8_t nonce[24],
                                 const uint8_t *ad, size_t ad_size,
                                 const uint8_t *plaintext, size_t size)
    {
        assert(ad_size == 0); // XSalsa20_Poly1305 does not support additional authenticated data
        //TODO: Find a way to do this without having to allocate temporary buffers.
        auto inBuffer = std::make_unique<uint8_t[]>(32 + size);
        memset(&inBuffer[ 0], 0, 32);
        memcpy(&inBuffer[32], plaintext, size);

        auto outBuffer = std::make_unique<uint8_t[]>(32 + size);

        crypto_secretbox_xsalsa20poly1305_tweet(outBuffer.get(),
                                                inBuffer.get(),
                                                size + 32,
                                                nonce, key);

        memcpy(mac, &outBuffer[16], 16);
        memcpy(out, &outBuffer[32], size);

//      Self-test:
//        assert(0 == unlock(&inBuffer[0], key, nonce, mac, out, size)
//               && 0 == memcmp(plaintext, &inBuffer[0], size));
        crypto_wipe(&inBuffer[32], size);
    }

    int XSalsa20_Poly1305::unlock(uint8_t *out,
                                  const uint8_t mac[16],
                                  const uint8_t key[32],
                                  const uint8_t nonce[24],
                                  const uint8_t *ad, size_t ad_size,
                                  const uint8_t *ciphertext, size_t size)
    {
        assert(ad_size == 0); // XSalsa20_Poly1305 does not support additional authenticated data
        //TODO: Find a way to do this without having to allocate temporary buffers.
        auto inBuffer = std::make_unique<uint8_t[]>(32 + size);
        memset(&inBuffer[0], 0, 16);
        memcpy(&inBuffer[16], mac, 16);
        memcpy(&inBuffer[32], ciphertext, size);

        auto outBuffer = std::make_unique<uint8_t[]>(32 + size);

        if (0 != crypto_secretbox_xsalsa20poly1305_tweet_open(outBuffer.get(),
                                                              inBuffer.get(), size + 32,
                                                              nonce, key))
            return -1;
        memcpy(out, &outBuffer[32], size);
        crypto_wipe(&outBuffer[32], size);
        return 0;
    }
}
