//
// Monocypher+xsalsa20.hh
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

    /// Alternative algorithm for session::encryption_key --
    /// XSalsa20 encryption (instead of XChaCha20) and Poly1305 authentication.
    /// This is compatible with libSodium and NaCl.
    ///
    /// @note This functionality is NOT part of Monocypher itself. It's provided for compatibility.
    /// The implementation is from TweetNaCl, by Daniel J. Bernstein et al.
    /// <https://tweetnacl.cr.yp.to>
    struct XSalsa20_Poly1305 {
        static constexpr const char* name = "XSalsa20+Poly1305";

        static void lock(uint8_t mac[16],
                         uint8_t *cipher_text,
                         const uint8_t key[32],
                         const uint8_t nonce[24],
                         const uint8_t *plain_text,
                         size_t text_size);
        
        static int unlock(uint8_t *plain_text,
                          const uint8_t key[32],
                          const uint8_t nonce[24],
                          const uint8_t mac[16],
                          const uint8_t *cipher_text,
                          size_t text_size);
    };

}
