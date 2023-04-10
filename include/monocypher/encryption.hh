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

    // Namespace for symmetric session-key-based encryption.
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


        namespace { // internal stuff
            static constexpr size_t boxedSize(size_t plaintextSize) {
                return plaintextSize + sizeof(mac);
            }

            static constexpr size_t unboxedSize(size_t ciphertextSize) {
                return std::max(ciphertextSize, sizeof(mac)) - sizeof(mac);
            }

            // callback signature is `mac cb(uint8_t *out)`
            template <typename Callback>
            output_bytes _box(output_bytes output_buffer, size_t msg_size, Callback cb) {
                output_buffer = output_buffer.shrunk_to(boxedSize(msg_size));
                auto mac_p = (mac*)output_buffer.data;
                *mac_p = cb(mac_p + 1);
                return output_buffer;
            }

            // callback signature is `bool cb(mac const&, input_buffer, uint8_t* out)`
            template <typename Callback>
            [[nodiscard]]
            output_bytes _unbox(output_bytes output_buffer, input_bytes boxed_cipher_text, Callback cb) {
                if (boxed_cipher_text.size < sizeof(mac))
                    return {};
                output_buffer = output_buffer.shrunk_to(unboxedSize(boxed_cipher_text.size));
                auto mac_p = (const mac*)boxed_cipher_text.data;
                if (!cb(*mac_p, input_bytes{mac_p + 1, output_buffer.size}, output_buffer.data))
                    return {};
                return output_buffer;
            }
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
            /// \note  The output data is compatible with that of libSodium's `crypto_box_easy`.
            output_bytes box(const nonce &nonce,
                             input_bytes plain_text,
                             output_bytes output_buffer) const
            {
                return _box(output_buffer, plain_text.size,
                            [&](void *out) {return lock(nonce, plain_text, out);});
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
                return _unbox(output_buffer, boxed_cipher_text,
                              [&](mac const& m, input_bytes cipher, void* plain) {
                    return unlock(nonce, m, cipher, plain);
                });
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


        /// Lets you send a stream as a series of symmetrically-encrypted "chunks",
        /// which can be decrypted by an `encrypted_reader` initialized with the same key & nonce.
        ///
        /// The encryption key is changed between each chunk, providing a symmetric ratchet
        /// that prevents an attacker from reordering messages unnoticed.
        ///
        /// Truncation however is not detected. You must detect the last chunk manually.
        /// Possible methods include:
        /// - Putting an end-of-data marker in the plaintext of the final chunk
        /// - Putting a length value in the first chunk
        /// - Add 'additional data' to the final chunk; the reader won't be able to decrypt it
        ///   without additional data, but will with it, signalling that this is the last.
        template <typename Algorithm = XChaCha20_Poly1305>
        struct encrypted_writer {
            /// Constructs an encrypted_writer from a symmetric key and a nonce.
            encrypted_writer(encryption_key<Algorithm> const& key, nonce const& n) {
                Algorithm::init_stream(&_context, key.data(), n.data());
            }

            ~encrypted_writer() {c::crypto_wipe(&_context, sizeof(_context));}

            /// Encrypts a chunk, producing ciphertext of the same size and a MAC.
            /// (It's OK to to encrypt in place.)
            mac write(input_bytes plain_text,
                      void *out_ciphertext) {
                return write(plain_text, {nullptr, 0}, out_ciphertext);
            }

            /// Encrypts a chunk, producing ciphertext of the same size and a MAC.
            /// The `additional_data` is not sent, but it affects the MAC such that the reader
            /// must present the same data when decrypting.
            mac write(input_bytes plain_text,
                      input_bytes additional_data,
                      void *out_ciphertext) {
                mac m;
                Algorithm::write_stream(&_context, (uint8_t*)out_ciphertext, m.data(),
                                        additional_data.data, additional_data.size,
                                        plain_text.data, plain_text.size);
                return m;
            }

            /// Encrypts `plain_text`, writing the MAC and ciphertext to `output_buffer`.
            /// Returns `output_buffer` resized to the actual output size, which is
            /// `sizeof(mac) + plain_text.size`.
            output_bytes box(input_bytes plain_text,
                             output_bytes output_buffer) {
                return _box(output_buffer, plain_text.size,
                            [&](void *out) {return write(plain_text, out);});
            }

            /// A version of `box` that takes `additional_data`.
            output_bytes box(input_bytes plain_text,
                             input_bytes additional_data,
                             output_bytes output_buffer) {
                return _box(output_buffer, plain_text.size,
                            [&](void *out) {return write(plain_text, additional_data, out);});
            }

        private:
            typename Algorithm::stream_context _context;
        };


        /// Decrypts a series of symmetrically-encrypted "chunks" generated by `encrypted_writer`.
        /// The chunks must be decrypted in the same order in which they were written.
        template <typename Algorithm = XChaCha20_Poly1305>
        struct encrypted_reader {
            /// Constructs an encrypted_reader from a symmetric key and a nonce, which must be
            /// the same ones used by the sender.
            encrypted_reader(encryption_key<Algorithm> const& key, nonce const& n) {
                Algorithm::init_stream(&_context, key.data(), n.data());
            }

            ~encrypted_reader() {c::crypto_wipe(&_context, sizeof(_context));}

            /// Decrypts a chunk given its ciphertext and MAC.
            /// (It's OK to to decrypt in place.)
            /// @return  True on success, false if authentication fails.
            [[nodiscard]]
            bool read(mac mac,
                      input_bytes ciphertext,
                      void *out_plaintext) {
                return read(mac, ciphertext, {nullptr, 0}, out_plaintext);
            }

            /// Decrypts a chunk given its ciphertext, MAC,
            /// and additional data that must match that given by the writer.
            /// @return  True on success, false if authentication fails.
            [[nodiscard]]
            bool read(mac mac,
                      input_bytes ciphertext,
                      input_bytes additional_data,
                      void *out_plaintext) {
                return Algorithm::read_stream(&_context, (uint8_t*)out_plaintext, mac.data(),
                                              additional_data.data, additional_data.size,
                                              ciphertext.data, ciphertext.size) == 0;
            }

            /// Decrypts a MAC-and-ciphertext produced by `encrypted_writer::box`,
            /// writing the plaintext to `output_buffer`.
            /// Returns `output_buffer` resized to the actual plaintext size, which is
            /// `boxed_ciphertext.size - sizeof(mac)`.
            /// If the ciphertext is invalid, returns `{nullptr, 0}`.
            [[nodiscard]]
            output_bytes unbox(input_bytes boxed_ciphertext,
                               output_bytes output_buffer) {
                return _unbox(output_buffer, boxed_ciphertext,
                              [&](mac const& m, input_bytes cipher, void* plain) {
                    return read(m, cipher, plain);
                });
            }

            /// A version of `unbox` that takes `additional_data`.
            [[nodiscard]]
            output_bytes unbox(input_bytes boxed_ciphertext,
                               input_bytes additional_data,
                               output_bytes output_buffer) {
                return _unbox(output_buffer, boxed_ciphertext,
                              [&](mac const& m, input_bytes cipher, void* plain) {
                    return read(m, cipher, additional_data, plain);
                });
            }

        private:
            typename Algorithm::stream_context _context;
        };

    } // end 'session'


    /// Default algorithm for `session::encryption_key` --
    /// XChaCha20 encryption and Poly1305 authentication.
    /// @note  This is not compatible with libSodium or NaCl, which use the XSalsa20 cipher.
    ///        But see `XSalsa20_Poly1305`, in `Monocypher+xsalsa20.hh`.
    struct XChaCha20_Poly1305 {
        static constexpr const char* name = "XChaCha20+Poly1305";

        static constexpr auto lock   = c::crypto_aead_lock;
        static constexpr auto unlock = c::crypto_aead_unlock;

        static constexpr auto init_stream = c::crypto_aead_init_x;
        static constexpr auto write_stream = c::crypto_aead_write;
        static constexpr auto read_stream = c::crypto_aead_read;
        using stream_context = c::crypto_aead_ctx;
    };

}
