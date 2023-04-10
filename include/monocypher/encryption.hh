//
//  monocypher/encryption.hh
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

namespace monocypher {
    using namespace MONOCYPHER_CPP_NAMESPACE;

    struct XChaCha20_Poly1305;

    namespace session {

        /// A one-time-use value to be sent along with an encrypted message.
        /// @warning A nonce value should never be used more than once with any one session key!
        struct nonce : public byte_array<24> {
            /// Constructs a randomized nonce.
            nonce() {randomize();}

            /// Constructs a nonce containing the number `n` in little-endian encoding.
            /// @note Only 64 bits are set; the last 128 bits of the nonce are set to 0.
            explicit nonce(uint64_t n) {
                for (size_t i = 0; i < 24; ++i, n >>= 8)
                    (*this)[i] = uint8_t(n & 0xFF);
            }

            explicit nonce(const std::array<uint8_t,24> &a)             :byte_array<24>(a) { }

            nonce& operator= (uint64_t n) {*this = nonce(n); return *this;}

            /// Convenience function to increment a nonce (interpreted as 192-bit little-endian.)
            nonce& operator++ () {
                increment();
                return *this;
            }
        };


        /// A Message Authentication Code, to be sent along with an encrypted message.
        /// (Like a signature, but can only be verified by someone who knows the session key.)
        struct mac : public byte_array<16> { };


        static constexpr size_t boxedSize(size_t plaintextSize) {
            return plaintextSize + sizeof(mac);
        }

        static constexpr size_t unboxedSize(size_t ciphertextSize) {
            return std::max(ciphertextSize, sizeof(mac)) - sizeof(mac);
        }


        /// A session key for _symmetric_ encryption/decryption -- both sides must use the same key.
        /// Consider using the shared secret produced by `key_exchange` as the key.
        template <typename Algorithm = XChaCha20_Poly1305>
        struct encryption_key : public secret_byte_array<32> {
            encryption_key()                                           {randomize();}
            explicit encryption_key(const std::array<uint8_t,32> &a)   :secret_byte_array<32>(a) { }
            encryption_key(const void *data, size_t size)              :secret_byte_array<32>(data, size) { }
            explicit encryption_key(input_bytes k3y)                   :encryption_key(k3y.data, k3y.size) { }

            /// Encrypts `plain_text`, writing the result to `cipher_text` and producing a `mac`.
            /// The MAC _must_ be sent along with the ciphertext.
            ///
            /// The nonce used must be known to the recipient; you can send it too, or you can use
            /// a protocol that ensures both parties start with the same nonce and keep them in
            /// sync, e.g. by incrementing.
            /// Just remember that you must **never reuse a nonce** with the same key!
            /// @param nonce  One-time value that must never have been used with this key before.
            /// @param plain_text  The input data to be encrypted.
            /// @param text_size  The length in bytes of the input data.
            /// @param cipher_text  Where to write the encrypted output; will be the same size as
            ///                     the input. It's OK to pass the same address as `plain_text`.
            /// @return  The Message Authentication Code. Must be sent along with the ciphertext.
            [[nodiscard]]
            mac lock(const nonce &nonce,
                     const void *plain_text, size_t text_size,
                     void *cipher_text) const {
                return lock(nonce, {plain_text, text_size}, input_bytes{nullptr, 0}, cipher_text);
            }

            [[nodiscard]]
            mac lock(const nonce &nonce,
                     input_bytes plain_text,
                     void *cipher_text) const {
                return lock(nonce, plain_text, input_bytes{nullptr, 0}, cipher_text);
            }

            /// Enhanced version of `lock` that includes additional data, also known as
            /// "authenticated data", in calculating the MAC.
            [[nodiscard]]
            mac lock(const nonce &nonce,
                     input_bytes plain_text,
                     input_bytes additional_data,
                     void *cipher_text) const {
                fixOverlap(plain_text, cipher_text);
                mac out_mac;
                Algorithm::lock(u8(cipher_text),
                                out_mac.data(),
                                this->data(),
                                nonce.data(),
                                additional_data.data, additional_data.size,
                                plain_text.data, plain_text.size);
                return out_mac;
            }

            /// Authenticates `cipher_text` using the `mac`, then decrypts it, writing the result to
            /// `plain_text` (which may be the same address.)
            /// @param nonce  The same nonce value used by the `lock` call.
            /// @param mac  The Message Authentication Code produced by the `lock` call.
            /// @param cipher_text  The input encrypted data.
            /// @param text_size  The length in bytes of the input data.
            /// @param plain_text  Where to write the decrypted output; will be the same size as the
            ///                    input. It's OK to pass the same address as `cipher_text`.
            /// @return  True on success, false if the data has been altered or corrupted.
            [[nodiscard]]
            bool unlock(const nonce &nonce,
                        const mac &mac,
                        const void *cipher_text, size_t text_size,
                        void *plain_text) const
            {
                return unlock(nonce, mac, {cipher_text, text_size}, plain_text);
            }

            [[nodiscard]]
            bool unlock(const nonce &nonce,
                        mac in_mac,
                        input_bytes cipher_text,
                        void *plain_text) const
            {
                return unlock(nonce, in_mac, cipher_text, input_bytes{nullptr, 0}, plain_text);
            }

            /// Enhanced version of `unlock` that takes additional data, also known as
            /// "authenticated data", used when verifying the MAC. If this data doesn't match
            /// that given when encrypting, the MAC will not match and decryption will fail.
            [[nodiscard]]
            bool unlock(const nonce &nonce,
                        mac in_mac,
                        input_bytes cipher_text,
                        input_bytes additional_data,
                        void *plain_text) const
            {
                fixOverlap(cipher_text, plain_text);
                return 0 == Algorithm::unlock(u8(plain_text),
                                              in_mac.data(),
                                              this->data(),
                                              nonce.data(),
                                              additional_data.data, additional_data.size,
                                              cipher_text.data, cipher_text.size);
            }


            //-------- Higher-level "box" convenience API


            /// Encrypts `plain_text`, writing the MAC and ciphertext to `output_buffer`.
            /// Returns `output_buffer` resized to the actual output size, which is
            /// `sizeof(mac) + plain_text.size`.
            /// \note  This function is compatible with libSodium's `crypto_box_easy`.
            output_bytes box(const nonce &nonce,
                             input_bytes plain_text,
                             output_bytes output_buffer) const
            {
                output_buffer = output_buffer.shrunk_to(boxedSize(plain_text.size));
                auto mac_p = (mac*)output_buffer.data;
                *mac_p = lock(nonce, plain_text, mac_p + 1);
                return output_buffer;
            }

            /// A version of `box` that returns the output as a `byte_array`.
            /// The array **must** be the exact size of the output.
            template <size_t OutputSize>
            byte_array<OutputSize> box(const nonce &nonce,
                                       input_bytes plain_text) const
            {
                assert(OutputSize == boxedSize(plain_text.size));
                byte_array<OutputSize> result;
                box(nonce, plain_text, result);
                return result;
            }

            /// Decrypts a MAC-and-ciphertext produced by `box`, into `output_buffer`.
            /// Returns `output_buffer` resized to the actual output size, which is
            /// `boxed_cipher_text.size - sizeof(mac)`, or {NULL,0} if the ciphertext is invalid.
            /// \note  This function is compatible with libSodium's `crypto_unbox_easy`.
            [[nodiscard]]
            output_bytes unbox(const nonce &nonce,
                               input_bytes boxed_cipher_text,
                               output_bytes output_buffer) const
            {
                if (boxed_cipher_text.size < sizeof(mac))
                    return {};
                output_buffer = output_buffer.shrunk_to(unboxedSize(boxed_cipher_text.size));
                auto mac_p = (const mac*)boxed_cipher_text.data;
                if (!unlock(nonce, *mac_p, mac_p + 1,
                            output_buffer.size,
                            output_buffer.data))
                    return {};
                return output_buffer;
            }

            /// A version of `unbox` that returns the output as a `byte_array`.
            template <size_t OutputSize>
            bool unbox(const nonce &nonce,
                       input_bytes boxed_cipher_text,
                       byte_array<OutputSize> &output) const
            {
                output_bytes out = unbox(nonce, boxed_cipher_text, {output.data(), output.size()});
                return out.size == output.size();
            }

        private:
            // `crypto_lock` only allows input and output buffers to overlap if they're identical.
            // If the src and dst ranges overlap but are not identical, copy src to dst and set
            // src.data to dst.
            static void fixOverlap(input_bytes &src, void *dst) {
                if ((src.data > dst && src.data < (uint8_t*)dst + src.size)
                        || (src.data < dst && src.data + src.size > dst)) {
                    ::memmove(dst, src.data, src.size);
                    src.data = (const uint8_t*)dst;
                }
            }
        };

        using key = encryption_key<XChaCha20_Poly1305>;

    } // end 'session'


    /// Default algorithm for `session::encryption_key` --
    /// XChaCha20 encryption and Poly1305 authentication.
    /// @note  This is not compatible with libSodium or NaCl, which use the XSalsa20 cipher.
    ///        But see `XSalsa20_Poly1305`, in `Monocypher+xsalsa20.hh`.
    struct XChaCha20_Poly1305 {
        static constexpr const char* name = "XChaCha20+Poly1305";

        static constexpr auto lock   = c::crypto_aead_lock;
        static constexpr auto unlock = c::crypto_aead_unlock;
    };

}
