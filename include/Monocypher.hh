//
//  Monocypher.hh
//
//  Unofficial header-only idiomatic C++14 wrapper for Monocypher
//  <https://monocypher.org>
//
//  Copyright (c) 2020 Jens Alfke. All rights reserved.
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
#include "../vendor/monocypher/src/monocypher.h"

#include <array>
#include <cstdlib>
#include <cstring>
#include <memory>  // for std::make_unique
#include <string>
#include <string_view>
#include <utility> // for std::pair
#include <cassert>

namespace monocypher {
    using namespace MONOCYPHER_CPP_NAMESPACE;

    template <class Algorithm> struct public_key;    // (forward reference)
    template <class Algorithm> struct signing_key;   // (forward reference)
    template <class Algorithm> struct key_pair;      // (forward reference)


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
        void wipe()                                 {crypto_wipe(this->data(), Size);}

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


    /// Byte-array of secret data. Its destructor erases itself. Used for private keys and shared secrets.
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
    static inline bool operator== (const byte_array<Size> &a, const byte_array<Size> &b);

    template <size_t Size>
    static inline bool operator!= (const byte_array<Size> &a, const byte_array<Size> &b) {
        return !(a == b);
    }

    template<> inline bool operator== (const byte_array<16> &a, const byte_array<16> &b) {
        return 0 == crypto_verify16(a.data(), b.data());
    }
    template<> inline bool operator== (const byte_array<24> &a, const byte_array<24> &b) {
        return 0 == crypto_verify16(a.data(), b.data()) && 0 == crypto_verify16(&a[8], &b[8]);
    }
    template<> inline bool operator== (const byte_array<32> &a, const byte_array<32> &b) {
        return 0 == crypto_verify32(a.data(), b.data());
    }
    template<> inline bool operator== (const byte_array<64> &a, const byte_array<64> &b) {
        return 0 == crypto_verify64(a.data(), b.data());
    }
    //TODO: Implement for other sizes


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


//======== General purpose hash (Blake2b)


    /// Cryptographic hash class, templated by algorithm and size.
    /// The only `Algorithm` currently available is `Blake2b`.
    /// The `Size` is in bytes and must be between 1 and 64. Sizes below 32 are not recommended.
    template <class HashAlgorithm>
    class hash : public byte_array<HashAlgorithm::hash_size> {
    public:
        static constexpr size_t Size = HashAlgorithm::hash_size;

        hash()                                           :byte_array<Size>(0) { }
        explicit hash(const std::array<uint8_t,Size> &a) :byte_array<Size>(a) { }
        hash(const void *data, size_t size)              :byte_array<Size>(data, size) { }

        /// Returns the Blake2b hash of a message.
        static hash create(const void *message, size_t message_size) noexcept {
            hash result;
            HashAlgorithm::create_fn(result.data(), u8(message), message_size);
            return result;
        }

        static hash create(input_bytes message) noexcept {
            return create(message.data, message.size);
        }

        /// Returns the hash of a message and a secret key, for use as a MAC.
        template <size_t KeySize>
        static hash createMAC(const void *message, size_t message_size,
                              const byte_array<KeySize> &key) noexcept {
            hash result;
            HashAlgorithm::mac::create_fn(result.data(),
                                          key.data(), key.size(),
                                          u8(message), message_size);
            return result;
        }

        template <size_t KeySize>
        static hash createMAC(input_bytes message,
                              const byte_array<KeySize> &key) noexcept {
            return createMAC(message.data, message.size, key);
        }


        template <class BuilderAlg>
        class _builder {
        public:
            /// Hashes more data.
            _builder& update(const void *message, size_t message_size) {
                BuilderAlg::update_fn(&_ctx, u8(message), message_size);
                return *this;
            }

            _builder& update(input_bytes message) {
                return update(message.data, message.size);
            }

            /// Returns the final hash of all the data passed to `update`.
            [[nodiscard]]
            hash final() {
                hash result;
                BuilderAlg::final_fn(&_ctx, result.data());
                return result;
            }
            
        protected:
            typename BuilderAlg::context _ctx;
        };

        /// Incrementally constructs a hash.
        class builder : public _builder<HashAlgorithm> {
        public:
            /// Constructs a Blake2b builder.
            /// Call `update` one or more times to hash data, then `final` to get the hash.
            builder() {
                HashAlgorithm::init_fn(&this->_ctx);
            }
        };

        /// Incrementally constructs a MAC.
        class mac_builder : public _builder<typename HashAlgorithm::mac> {
        public:
            /// Constructs a Blake2b builder with a secret key, for creating MACs.
            /// Call `update` one or more times to hash data, then `final` to get the hash.
            template <size_t KeySize>
            mac_builder(const byte_array<KeySize> &key) {
                HashAlgorithm::mac::init_fn(&this->_ctx, key.data(), key.size());
            }
        };
    };


    /// Blake2b algorithm; use as `<HashAlgorithm>` in the `hash` template.
    template <size_t Size>
    struct Blake2b {
        static constexpr const char* name = "Blake2b";
        static constexpr size_t hash_size = Size;

        using context = crypto_blake2b_ctx;

        static void create_fn(uint8_t *hash, const uint8_t *message, size_t message_size) {
            crypto_blake2b_general(hash, Size, nullptr, 0, message, message_size);
        }
        static void init_fn(context *ctx) {
            crypto_blake2b_general_init(ctx, Size, nullptr, 0);
        }
        static constexpr auto update_fn     = crypto_blake2b_update;
        static constexpr auto final_fn      = crypto_blake2b_final;

        struct mac {
            using context = crypto_blake2b_ctx;

            static void create_fn(uint8_t *hash, const uint8_t *key, size_t key_size,
                                  const uint8_t *message, size_t message_size)
            {
                crypto_blake2b_general(hash, Size, key, key_size, message, message_size);
            }
            static void init_fn(context *ctx, const uint8_t *key, size_t key_size) {
                crypto_blake2b_general_init(ctx, Size, key, key_size);
            }
            static constexpr auto update_fn     = crypto_blake2b_update;
            static constexpr auto final_fn      = crypto_blake2b_final;
        };
    };


    /// Blake2b-64 hash class.
    using blake2b64 = hash<Blake2b<64>>;

    /// Blake2b-32 hash class.
    using blake2b32 = hash<Blake2b<32>>;

    // Note: See Monocypher-ed25519.hh for SHA-512, and Monocypher+sha256.hh for SHA-256.


//======== Password Key Derivation


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
            crypto_argon2i(result.data(), Size,
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


//======== Key Exchange


    /// Default `Algorithm` template parameter for `key_exchange`.
    struct X25519_HChaCha20 {
        static constexpr const char* name = "X25519+HChaCha20";
        static constexpr auto get_public_key_fn = crypto_key_exchange_public_key;
        static constexpr auto key_exchange_fn   = crypto_key_exchange;
    };

    /// Raw Curve25519 key exchange algorithm for `key_exchange`; use only if you know what
    /// you're doing!
    /// @warning Shared secrets are not quite random. Hash them to derive an actual shared key.
    struct X25519_Raw {
        static constexpr const char* name = "X25519";
        static constexpr auto get_public_key_fn = crypto_x25519_public_key;
        static constexpr auto key_exchange_fn   = crypto_x25519;
    };


    /// Performs a Diffie-Hellman key exchange with another party, combining your secret key with
    /// the other's public key to create a shared secret known to both of you.
    template <class Algorithm = X25519_HChaCha20>
    class key_exchange {
    public:
        /// A secret key for key exchange.
        struct secret_key : public secret_byte_array<32> { };

        /// A public key generated from the secret key, to be exchanged with the peer.
        struct public_key : public byte_array<32> {
            public_key()                                           :byte_array<32>(0) { }
            explicit public_key(const std::array<uint8_t,32> &a)   :byte_array<32>(a) { }
            public_key(const void *data, size_t size)              :byte_array<32>(data, size) { }

            /// Converts a signing public key to a key-exchange public key.
            /// Internally this converts the EdDSA or Ed25519 key to its Curve25519 equivalent.
            /// @warning "It is generally considered poor form to reuse the same key for different
            ///     purposes. While this conversion is technically safe, avoid these functions
            ///     nonetheless unless you are particularly resource-constrained or have some other
            ///     kind of hard requirement. It is otherwise an unnecessary risk factor."
            template <class SigningAlgorithm>
            explicit public_key(const monocypher::public_key<SigningAlgorithm>&);
        };

        /// A secret value derived from two parties' keys, which will be the same for both.
        struct shared_secret : public secret_byte_array<32> { };


        /// Initializes a key exchange, generating a random secret key.
        key_exchange() {
            _secret_key.randomize();
        }

        /// Initializes a key exchange, using an existing secret key.
        explicit key_exchange(const secret_key &key)
        :_secret_key(key) { }

        /// Initializes a key exchange, using an existing signing key-pair.
        /// Internally this converts the EdDSA or Ed25519 signing key to its Curve25519 equivalent.
        /// @warning "It is generally considered poor form to reuse the same key for different
        ///     purposes. While this conversion is technically safe, avoid these functions
        ///     nonetheless unless you are particularly resource-constrained or have some other
        ///     kind of hard requirement. It is otherwise an unnecessary risk factor."
        template <class SigningAlgorithm>
        explicit key_exchange(const signing_key<SigningAlgorithm>&);

        template <class SigningAlgorithm>
        explicit key_exchange(const key_pair<SigningAlgorithm>& kp)
        :key_exchange(kp.get_signing_key())
        { }

        /// Returns the public key to send to the other party.
        public_key get_public_key() const {
            public_key pubkey;
            Algorithm::get_public_key_fn(pubkey.data(), _secret_key.data());
            return pubkey;
        }

        /// Returns the secret key, in case you want to reuse it later.
        secret_key get_secret_key() const {
            return _secret_key;
        }

        /// Given the other party's public key, computes the shared secret.
        shared_secret get_shared_secret(const public_key &their_public_key) const {
            shared_secret shared;
            Algorithm::key_exchange_fn(shared.data(), _secret_key.data(), their_public_key.data());
            return shared;
        }

    private:
        secret_key _secret_key;
    };


//======== Authenticated Encryption

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

            nonce& operator= (uint64_t n) {*this = nonce(n); return *this;}

            /// Convenience function to increment a nonce (interpreted as 192-bit little-endian.)
            nonce& operator++ () {
                for (size_t i = 0; i < 24; ++i) {
                    if (++(*this)[i] != 0)
                        break;
                }
                return *this;
            }
        };


        /// A Message Authentication Code, to be sent along with an encrypted message.
        /// (Like a signature, but can only be verified by someone who knows the session key.)
        struct mac : public byte_array<16> { };


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
                mac out_mac;
                Algorithm::lock(out_mac.data(), u8(cipher_text), this->data(), nonce.data(),
                                u8(plain_text), text_size);
                return out_mac;
            }

            [[nodiscard]]
            mac lock(const nonce &nonce,
                     input_bytes plain_text,
                     void *cipher_text) const {
                return lock(nonce, plain_text.data, plain_text.size, cipher_text);
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
                        void *plain_text) const {
                return 0 == Algorithm::unlock(u8(plain_text), this->data(), nonce.data(),
                                              mac.data(), u8(cipher_text), text_size);
            }

            [[nodiscard]]
            bool unlock(const nonce &nonce,
                        const mac &mac,
                        input_bytes cipher_text,
                        void *plain_text) const {
                return unlock(nonce, mac, cipher_text.data, cipher_text.size, plain_text);
            }


            /// Encrypts `plain_text`, writing the MAC and ciphertext to `output_buffer`.
            /// Returns `output_buffer` resized to the actual output size, which is
            /// `sizeof(mac) + plain_text.size`.
            /// \note  This function is compatible with libSodium's `crypto_box_easy`.
            output_bytes box(const nonce &nonce,
                             input_bytes plain_text,
                             output_bytes output_buffer) const
            {
                output_buffer = output_buffer.shrunk_to(sizeof(mac) + plain_text.size);
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
                assert(OutputSize == sizeof(mac) + plain_text.size);
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
                output_buffer = output_buffer.shrunk_to(boxed_cipher_text.size - sizeof(mac));
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

        };

        using key = encryption_key<XChaCha20_Poly1305>;

    } // end 'session'


    /// Default algorithm for `session::encryption_key` --
    /// XChaCha20 encryption and Poly1305 authentication.
    /// @note  This is not compatible with libSodium or NaCl, which use the XSalsa20 cipher.
    ///        But see `XSalsa20_Poly1305`, in `Monocypher+xsalsa20.hh`.
    struct XChaCha20_Poly1305 {
        static constexpr const char* name = "XChaCha20+Poly1305";
        static constexpr auto lock   = crypto_lock;
        static constexpr auto unlock = crypto_unlock;
    };


//======== Signatures


    struct EdDSA;


    /// A digital signature. (For <Algorithm> use <EdDSA> or <Ed25519>.)
    template <class Algorithm = EdDSA>
    struct signature : public byte_array<64> {
        signature()                                           :byte_array<64>(0) { }
        explicit signature(const std::array<uint8_t,64> &a)   :byte_array<64>(a) { }
        signature(const void *data, size_t size)              :byte_array<64>(data, size) { }
    };


    /// A public key for verifying signatures. (For <Algorithm> use <EdDSA> or <Ed25519>.)
    template <class Algorithm = EdDSA>
    struct public_key : public byte_array<32> {
        public_key()                                           :byte_array<32>(0) { }
        explicit public_key(const std::array<uint8_t,32> &a)   :byte_array<32>(a) { }
        public_key(const void *data, size_t size)              :byte_array<32>(data, size) { }
        explicit public_key(input_bytes k)                      :public_key(k.data, k.size) { }

        /// Verifies a signature.
        [[nodiscard]]
        bool check(const signature<Algorithm> &sig, const void *msg, size_t msg_size) const {
            return 0 == Algorithm::check_fn(sig.data(), this->data(), u8(msg), msg_size);
        }

        [[nodiscard]]
        bool check(const signature<Algorithm> &sig, input_bytes msg) const {
            return check(sig, msg.data, msg.size);
        }

        /// Converts a public signature-verification key to a Curve25519 public key,
        /// for key exchange or encryption.
        /// @warning "It is generally considered poor form to reuse the same key for different
        ///     purposes. While this conversion is technically safe, avoid these functions
        ///     nonetheless unless you are particularly resource-constrained or have some other
        ///     kind of hard requirement. It is otherwise an unnecessary risk factor."
        explicit operator key_exchange<X25519_HChaCha20>::public_key() const {
            key_exchange<X25519_HChaCha20>::public_key pk;
            Algorithm::public_to_kx_fn(pk.data(), this->data());
            return pk;
        }
    };


    /// A secret/private key for generating signatures. (For <Algorithm> use <EdDSA> or <Ed25519>.)
    template <class Algorithm = EdDSA>
    struct signing_key : public secret_byte_array<32> {
        using public_key = monocypher::public_key<Algorithm>;
        using signature = monocypher::signature<Algorithm>;

        explicit signing_key(const std::array<uint8_t,32> &a) :secret_byte_array<32>(a) { }
        signing_key(const void *data, size_t size)            :secret_byte_array<32>(data, size) { }

        /// Creates a random secret key.
        static signing_key generate() {
            return signing_key();
        }

        /// Computes and returns the matching public key.
        public_key get_public_key() const {
            public_key pub;
            Algorithm::public_key_fn(pub.data(), this->data());
            return pub;
        }

        /// Signs a message. (Passing in the public key speeds up the computation.)
        [[nodiscard]]
        signature sign(const void *message, size_t message_size,
                       const public_key &pubKey) const {
            signature sig;
            Algorithm::sign_fn(sig.data(), this->data(), pubKey.data(), u8(message), message_size);
            return sig;
        }

        /// Signs a message. (Passing in the public key speeds up the computation.)
        [[nodiscard]]
        signature sign(input_bytes message, const public_key &pubKey) const {
            return sign(message.data, message.size, pubKey);
        }

        /// Signs a message.
        /// @note This has to first recompute the public key, which makes it a bit slower.
        [[nodiscard]]
        signature sign(const void *message, size_t message_size) const {
            signature sig;
            Algorithm::sign_fn(sig.data(), this->data(), nullptr, u8(message), message_size);
            return sig;
        }

        /// Signs a message.
        /// @note This has to first recompute the public key, which makes it a bit slower.
        [[nodiscard]]
        signature sign(input_bytes message) const {
            return sign(message.data, message.size);
        }

    private:
        signing_key() {randomize();}
    };


    /// A `signing_key` together with its `public_key`.
    /// Takes up more space, but is faster because the public key doesn't have to be derived.
    template <class Algorithm = EdDSA>
    struct key_pair {
        using signing_key = monocypher::signing_key<Algorithm>;
        using public_key = monocypher::public_key<Algorithm>;
        using signature = monocypher::signature<Algorithm>;

        /// Creates a new key-pair at random.
        static key_pair generate() {
            return key_pair(signing_key::generate());
        }

        explicit key_pair(const signing_key &sk,
                          const public_key &pk)             :_signingKey(sk), _publicKey(pk) { }
        explicit key_pair(const signing_key &sk)            :key_pair(sk, sk.get_public_key()) { }
        explicit key_pair(const std::array<uint8_t,32> &sa) :key_pair(signing_key(sa)) { }
        key_pair(const void *sk_data, size_t size)          :key_pair(signing_key(sk_data, size)) { }

        /// Returns the signing key.
        const signing_key& get_signing_key() const          {return _signingKey;}

        /// Returns the public key.
        const public_key& get_public_key() const            {return _publicKey;}

        /// Signs a message.
        [[nodiscard]]
        signature sign(const void *message, size_t message_size) const {
            return _signingKey.sign(message, message_size, _publicKey);
        }

        /// Signs a message.
        [[nodiscard]]
        signature sign(input_bytes msg) const               {return sign(msg.data, msg.size);}

        /// Verifies a signature.
        [[nodiscard]]
        bool check(const signature &sig, const void *msg, size_t msg_size) const {
            return _publicKey.check(sig, msg, msg_size);
        }

        [[nodiscard]]
        bool check(const signature &sig, input_bytes msg) const {
            return check(sig, msg.data, msg.size);
        }

    private:
        signing_key _signingKey;
        public_key  _publicKey;
    };


    /// EdDSA with Curve25519 and Blake2b.
    /// (Use as `<Algorithm>` parameter to `signature`, `public_key`, `signing_key`.)
    /// \note  This is not the same as the commonly-used Ed25519, which uses SHA-512.
    ///        An `Ed25519` struct is declared in `Monocypher-ed25519.hh`.
    struct EdDSA {
        static constexpr const char* name      = "EdDSA";
        static constexpr auto check_fn         = crypto_check;
        static constexpr auto sign_fn          = crypto_sign;
        static constexpr auto public_key_fn    = crypto_sign_public_key;
        static constexpr auto public_to_kx_fn  = crypto_from_eddsa_public;
        static constexpr auto private_to_kx_fn = crypto_from_eddsa_private;

        // Convenient type aliases for those who don't like angle brackets
        using signature   = monocypher::signature<EdDSA>;
        using public_key  = monocypher::public_key<EdDSA>;
        using signing_key = monocypher::signing_key<EdDSA>;
        using key_pair    = monocypher::key_pair<EdDSA>;
    };




    // Forward-declared template functions:

    template <class A>
    template <class SA>
    key_exchange<A>::key_exchange(const monocypher::signing_key<SA> &signingKey) {
        SA::private_to_kx_fn(_secret_key.data(), signingKey.data());
    }

    template <class A>
    template <class SA>
    key_exchange<A>::public_key::public_key(const monocypher::public_key<SA> &publicKey) {
        SA::public_to_kx_fn(this->data(), publicKey.data());
    }

}
