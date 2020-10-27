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
#include "monocypher.h"
#include "monocypher-ed25519.h"

#include <array>
#include <cstdlib>
#include <cstring>
#include <memory>  // for std::make_unique
#include <string>
#include <utility> // for std::pair
#include <cassert>

// On Apple platforms, `arc4random_buf()` is declared in <cstdlib>, above.
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

//======== Utilities:


    static inline const uint8_t* u8(const void *p)  {return reinterpret_cast<const uint8_t*>(p);}
    static inline uint8_t* u8(void *p)              {return reinterpret_cast<uint8_t*>(p);}


    /// General-purpose byte array. Used for hashes, nonces, MACs, etc.
    template <size_t Size>
    class byte_array: public std::array<uint8_t, Size> {
    public:
        /// Fills the array with cryptographically-secure random bytes.
        /// \warning On platforms where `arc4random` is unavailable, this uses C++'s `std::random_device`.
        ///    The C++ standard says "random_device may be implemented in terms of an implementation-defined
        ///    pseudo-random number engine if a non-deterministic source (e.g. a hardware device) is not
        ///    available to the implementation." In that situation you should try to use some other source
        ///    of randomization.
        void randomize() {
#ifdef MONOCYPHER_HAS_ARC4RANDOM
#  undef MONOCYPHER_HAS_ARC4RANDOM
            ::arc4random_buf(this->data(), Size);
#else
            static_assert(Size % sizeof(unsigned) == 0, "randomize() doesn't support this size");
            std::random_device rng;
            for (auto i = this->begin(); i != this->end(); i += sizeof(unsigned)) {
                unsigned r = rng();
                memcpy(&*i, &r, sizeof(unsigned));
            }
#endif
        }

        /// Securely fills the array with zeroes. Unlike a regular `memset` this cannot be optimized
        /// away even if the array is about to be destructed.
        void wipe()                                 {::crypto_wipe(this->data(), Size);}

        /// Idiomatic synonym for `wipe`.
        void clear()                                {this->wipe();}

        void fill(uint8_t b) {  // overridden to use `wipe` first
            this->wipe();
            if (b != 0) std::array<uint8_t,Size>::fill(b);  // (wipe already fills with 0)
        }

        void fillWith(const void *bytes, size_t size) {
            assert(size == sizeof(*this));
            ::memcpy(this->data(), bytes, sizeof(*this));
        }

        explicit operator uint8_t*()                         {return this->data();}
        explicit operator const uint8_t*() const             {return this->data();}
    };


    /// Byte-array of secret data. Its destructor erases itself. Used for private keys and shared secrets.
    template <size_t Size>
    class secret_byte_array: public byte_array<Size> {
    public:
        ~secret_byte_array()                        {this->wipe();}
    };


    // byte_arrays use constant-time comparison.
    template <size_t Size>
    static inline bool operator== (const byte_array<Size> &a, const byte_array<Size> &b);

    template <size_t Size>
    static inline bool operator!= (const byte_array<Size> &a, const byte_array<Size> &b) {
        return !(a == b);
    }

    template<> inline bool operator== (const byte_array<16> &a, const byte_array<16> &b) {
        return 0 == ::crypto_verify16(a.data(), b.data());
    }
    template<> inline bool operator== (const byte_array<32> &a, const byte_array<32> &b) {
        return 0 == ::crypto_verify32(a.data(), b.data());
    }
    template<> inline bool operator== (const byte_array<64> &a, const byte_array<64> &b) {
        return 0 == ::crypto_verify64(a.data(), b.data());
    }


//======== General purpose hash (Blake2b)


    /// Cryptographic hash class, templated by algorithm.
    /// The `Size` is in bytes and must be between 1 and 64. Sizes below 32 are not recommended.
    template <class HashAlgorithm, size_t Size=64>
    class hash : public byte_array<Size> {
    public:

        /// Returns the Blake2b hash of a message.
        static hash create(const void *message, size_t message_size) noexcept {
            hash result;
            HashAlgorithm::create_fn(result.data(), Size,
                                     u8(message), message_size);
            return result;
        }

        static hash create(const std::string &message) noexcept {
            return create(message.data(), message.size());
        }


        /// Returns the Blake2b hash of a message and a secret key, for use as a MAC.
        template <size_t KeySize>
        static hash createMAC(const void *message, size_t message_size,
                              const secret_byte_array<KeySize> &key) noexcept {
            hash result;
            HashAlgorithm::create_mac_fn(result, Size,
                                         key, KeySize,
                                         u8(message), message_size);
            return result;
        }

        template <size_t KeySize>
        static hash createMAC(const std::string &message,
                              const secret_byte_array<KeySize> &key) noexcept {
            return createMAC(message.data(), message.size(), key);
        }


        /// Incrementally constructs a hash.
        class builder {
        public:
            /// Constructs a Blake2b builder.
            /// Call `update` one or more times to hash data, then `final` to get the hash.
            builder() {
                HashAlgorithm::init_fn(&_ctx, Size);
            }

            /// Constructs a Blake2b builder with a secret key, for creating MACs.
            /// Call `update` one or more times to hash data, then `final` to get the hash.
            template <size_t KeySize>
            builder(const secret_byte_array<KeySize> &key) {
                HashAlgorithm::init_mac_fn(&_ctx, Size, key, KeySize);
            }

            /// Hashes more data.
            builder& update(const void *message, size_t message_size) {
                HashAlgorithm::update_fn(&_ctx, u8(message), message_size);
                return *this;
            }

            builder& update(const std::string &message, size_t message_size) {
                return update(message.data(), message.size());
            }

            /// Returns the final Blake2b hash of all the data passed to `update`.
            hash final() {
                hash result;
                HashAlgorithm::final_fn(&_ctx, result.data());
                return result;
            }

        private:
            typename HashAlgorithm::context _ctx;
        };
    };


    /// Blake2b algorithm; use as `<HashAlgorithm>` in the `hash` template.
    struct Blake2b {
        using context = ::crypto_blake2b_ctx;

        static void create_fn(uint8_t *hash, size_t hash_size,
                              const uint8_t *message, size_t message_size) {
            ::crypto_blake2b_general(hash, hash_size, nullptr, 0, message, message_size);
        }
        static void init_fn(context *ctx, size_t hash_size) {
            ::crypto_blake2b_general_init(ctx, hash_size, nullptr, 0);
        }
        static constexpr auto create_mac_fn = ::crypto_blake2b_general;
        static constexpr auto init_mac_fn   = ::crypto_blake2b_general_init;
        static constexpr auto update_fn     = ::crypto_blake2b_update;
        static constexpr auto final_fn      = ::crypto_blake2b_final;
    };
    // TODO: Add SHA-512


    /// Blake2b-64 hash class.
    using blake2b64 = hash<Blake2b,64>;

    /// Blake2b-32 hash class.
    using blake2b32 = hash<Blake2b,32>;


//======== Password Key Derivation


    /// Argon2i is a password key derivation scheme. It is deliberately slow and memory-intensive,
    /// to deter brute-force attacks.
    /// `Size` is the size of the hash in bytes, and should be either 32 or 64.
    /// The `NBlocks` and `NIterations` parameters can tune the memory usage and time, but read
    /// the Monocypher documentation so you know what you're doing.
    template <size_t Size=64, uint32_t NBlocks = 100000, uint32_t NIterations = 3>
    struct argon2i {
        /// An Argon2i hash generated from a password.
        struct hash : public secret_byte_array<Size> { };

        /// The per-password "salt" input used to deter multi-password attacks.
        struct salt : public secret_byte_array<16> {
            salt() {::memset(data(), 0, sizeof(*this));}
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
            ::crypto_argon2i(result.data(), Size,
                             work_area.get(), NBlocks, NIterations,
                             u8(password), uint32_t(password_size),
                             s4lt.data(), sizeof(s4lt));
            return result;
        }

        static hash create(const std::string &password, const salt &s4lt) {
            return create(password.data(), password.size(), s4lt);
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

        static std::pair<hash, salt> create(const std::string &password) {
            return create(password.data(), password.size());
        }
    };


//======== Key Exchange


    /// Performs a Diffie-Hellman key exchange with another party, using X25519 and HChaCha20.
    class key_exchange {
    public:
        /// A secret key for key exchange.
        struct secret_key : public secret_byte_array<32> { };

        /// A public key generated from the secret key, to be exchanged with the peer.
        struct public_key : public byte_array<32> { };

        /// A secret value produced from both public keys, which will be the same for both parties.
        struct shared_secret : public secret_byte_array<32> { };


        /// Initializes a key exchange, generating a random secret key.
        key_exchange() {
            _secret_key.randomize();
        }

        /// Initializes a key exchange, using an existing secret key.
        explicit key_exchange(const secret_key &key)
        :_secret_key(key) { }

        /// Returns the public key to send to the other party.
        public_key get_public_key() const {
            public_key pubkey;
            ::crypto_key_exchange_public_key(pubkey.data(), _secret_key.data());
            return pubkey;
        }

        /// Returns the secret key, in case you want to reuse it later.
        secret_key get_secret_key() const {
            return _secret_key;
        }

        /// Given the other party's public key, computes the shared secret.
        shared_secret get_shared_secret(const public_key &their_public_key) const {
            shared_secret shared;
            ::crypto_key_exchange(shared.data(), _secret_key.data(), their_public_key.data());
            return shared;
        }

    private:
        secret_key _secret_key;
    };


//======== Authenticated Encryption


    namespace session {

        /// A one-time-use value to be sent along with an encrypted message.
        /// A nonce value should never be used more than once with any one session key!
        struct nonce : public byte_array<24> {
            /// Constructs a randomized nonce.
            nonce() {randomize();}

            /// Constructs a nonce containing the number `n` in little-endian encoding.
            explicit nonce(uint64_t n) {
                for (size_t i = 0; i < 24; ++i, n >>= 8)
                    (*this)[i] = uint8_t(n & 0xFF);
            }
        };


        /// A Message Authentication Code, to be sent along with an encrypted message.
        /// (This is like a signature, but can only be verified by someone who knows the session key.)
        struct mac : public byte_array<16> { };


        /// A session key for symmetric encryption/decryption.
        struct key : public secret_byte_array<32> {
            /// Constructs a randomized session key.
            key()                                       {randomize();}

            /// Constructs a key containing the given bytes. `key_size` must be 32, i.e. `sizeof(key)`.
            explicit key(const void *key_bytes, size_t key_size) {
                fillWith(key_bytes, key_size);
            }

            explicit key(const std::string &k3y)
            :key(k3y.data(), k3y.size()) { }

            /// Constructs a key from the shared secret created during key exchange.
            explicit key(const key_exchange::shared_secret &secret)
                                                        :secret_byte_array<32>(secret) { }

            /// Encrypts `plain_text`, writing the result to `cipher_text` (which may be the same address.)
            /// Produces a `mac` that should be sent along with the ciphertext to authenticate it.
            mac lock(const nonce &nonce,
                     const void *plain_text, size_t text_size,
                     void *cipher_text) const {
                mac out_mac;
                ::crypto_lock(out_mac.data(), u8(cipher_text), this->data(), nonce.data(),
                              u8(plain_text), text_size);
                return out_mac;
            }

            mac lock(const nonce &nonce,
                     const std::string &plain_text,
                     void *cipher_text) const {
                return lock(nonce, plain_text.data(), plain_text.size(), cipher_text);
            }

            /// Authenticates `cipher_text` using the `mac`, then decrypts it, writing the result to
            ///  `plain_text` (which may be the same address.)
            /// Returns false if the authentication fails.
            bool unlock(const nonce &nonce,
                        const mac &mac,
                        const void *cipher_text, size_t text_size,
                        void *plain_text) const {
                return 0 == ::crypto_unlock(u8(plain_text), this->data(), nonce.data(),
                                            mac.data(), u8(cipher_text), text_size);
            }

            bool unlock(const nonce &nonce,
                        const mac &mac,
                        const std::string &cipher_text,
                        void *plain_text) const {
                return unlock(nonce, mac, cipher_text.data(), cipher_text.size(), plain_text);
            }
        };

    } // end 'session'


//======== Signatures


    template <class Algorithm> struct signing_key;   // (forward reference)


    /// A digital signature. (For <Algorithm> use <EdDSA> or <Ed25519>.)
    template <class Algorithm>
    struct signature : public byte_array<64> { };


    /// A public key for verifying signatures. (For <Algorithm> use <EdDSA> or <Ed25519>.)
    template <class Algorithm>
    struct public_key : public byte_array<32> {
        public_key() { }

        /// Constructs an instance given the key data. `key_size` must be 32, i.e. `sizeof(public_key)`.
        explicit public_key(const void *key_bytes, size_t key_size) {
            fillWith(key_bytes, key_size);
        }

        explicit public_key(const std::string &key)
        :public_key(key.data(), key.size()) { }

        /// Verifies a signature.
        bool check(const signature<Algorithm> &sig, const void *msg, size_t msg_size) const {
            return 0 == Algorithm::check_fn(sig.data(), this->data(), u8(msg), msg_size);
        }

        bool check(const signature<Algorithm> &sig, const std::string &msg) const {
            return check(sig, msg.data(), msg.size());
        }

        bool operator== (const public_key<Algorithm> &b) const {
            return 0 == ::crypto_verify32(this->data(), b.data());
        }
    };


    /// A secret/private key for generating signatures. (For <Algorithm> use <EdDSA> or <Ed25519>.)
    template <class Algorithm>
    struct signing_key : public secret_byte_array<32> {
        using public_key = monocypher::public_key<Algorithm>;
        using signature = monocypher::signature<Algorithm>;

        /// Constructs an instance given the key data. `key_size` must be 32, i.e. `sizeof(signing_key)`.
        explicit signing_key(const void *key_bytes, size_t key_size) {
            fillWith(key_bytes, key_size);
        }

        explicit signing_key(const std::string &key)
        :signing_key(key.data(), key.size()) { }

        /// Constructs a signing_key from the shared secret created during key exchange.
        explicit signing_key(const key_exchange::shared_secret &secret)
        :secret_byte_array<32>(secret) { }

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
        signature sign(const void *message, size_t message_size,
                       const public_key &pubKey) const {
            signature sig;
            Algorithm::sign_fn(sig.data(), this->data(), pubKey.data(), u8(message), message_size);
            return sig;
        }

        signature sign(const std::string &message, const public_key &pubKey) const {
            return sign(message.data(), message.size(), pubKey);
        }

        /// Signs a message.
        /// (This is a bit slower than the version that takes the public key, because it has to recompute it.)
        signature sign(const void *message, size_t message_size) const {
            signature sig;
            Algorithm::sign_fn(sig.data(), this->data(), nullptr, u8(message), message_size);
            return sig;
        }

        signature sign(const std::string &message) const {
            return sign(message.data(), message.size());
        }

    private:
        signing_key() {randomize();}
    };


    /// EdDSA with Curve25519 and Blake2b.
    /// (Use as `<Algorithm>` parameter to `signature`, `public_key`, `signing_key`.)
    struct EdDSA {
        static constexpr auto check_fn      = ::crypto_check;
        static constexpr auto sign_fn       = ::crypto_sign;
        static constexpr auto public_key_fn = ::crypto_sign_public_key;

        // Convenient type aliases for those who don't like angle brackets
        using signature   = monocypher::signature<EdDSA>;
        using public_key  = monocypher::public_key<EdDSA>;
        using signing_key = monocypher::signing_key<EdDSA>;
    };

    /// EdDSA with Curve25519 and SHA-512.
    /// \note This algorithm is more widely used than `EdDSA`, but slower and brings in a bit more code.
    /// (Use as `<Algorithm>` parameter to `signature`, `public_key`, `signing_key`.)
    struct Ed25519 {
        static constexpr auto check_fn      = ::crypto_ed25519_check;
        static constexpr auto sign_fn       = ::crypto_ed25519_sign;
        static constexpr auto public_key_fn = ::crypto_ed25519_public_key;

        // Convenient type aliases for those who don't like angle brackets
        using signature   = monocypher::signature<Ed25519>;
        using public_key  = monocypher::public_key<Ed25519>;
        using signing_key = monocypher::signing_key<Ed25519>;
    };


}
