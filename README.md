![Build+Test](https://github.com/snej/monocypher-cpp/workflows/Build+Test/badge.svg)

# Monocypher C++ API

This is an idiomatic C++ API for [Monocypher](https://monocypher.org). Monocypher is:

> an easy to use, easy to deploy, auditable crypto library written in portable C.
> It approaches the size of TweetNaCl and the speed of Libsodium.

This API here is:

**Unofficial:** It's not part of Monocypher, but for convenience includes it as a Git submodule.

**C++:** Requires C++17 or later.

**Idiomatic:**  Cryptographic entities are C++ classes, mostly subclasses of `std::array`. Arrays can be easily concatenated or sliced. Options like key sizes and algorithms are template parameters. Operations are methods.

**Namespaced:** All symbols are in the C++ namespace `monocypher`. Nothing is defined at global scope, not even the Monocypher C API. This prevents symbol collisions in binaries that also use libSodium or OpenSSL, all of which use the same C `crypto_` prefix as regular Monocypher.

**Safe:** 

* All keys, hashes, nonces and seeds are distinct types. For example, you can't accidentally pass a Diffie-Hellman public key (`monocypher::key_exchange::public_key`) to a function expecting an Ed25519 public key (`monocypher::public_key`).
* Values are C++ `std::array` objects, which are value types, so you can't accidentally pass invalid pointers, pass a pointer to data of the wrong size, or return a dangling pointer to a local array.
* Private keys and other sensitive data are automaticaly zeroed out when destructed, to avoid leaving secrets in memory.
* The `==` and `!=` operators use constant-time comparisons instead of regular `memcmp`, to avoid timing attacks.
* Concatenating data in memory (to encrypt or digest it) is easy and safe thanks to the `|` operator, unlike the typical series of fragile `memcpy` operations used in C, where it's too easy to get offsets or array sizes wrong.

## Features

| Functionality               | Algorithm(s)                             |
| --------------------------- | ---------------------------------------- |
| Cryptographic digests       | Blake2b, SHA-512, *Blake3\**, *SHA-256\**|
| Password-to-key derivation  | Argon2i                                  |
| Diffie-Hellman key exchange | Curve25519 (raw or with HChaCha20)       |
| Authenticated encryption    | XChaCha20 *or XSalsa20\**, with Poly1305 |
| Digital signatures          | Ed25519 (with Blake2b or SHA-512)        |

\* denotes optional algorithms not implemented in Monocypher itself. XSalsa20 is from [tweetnacl](https://tweetnacl.cr.yp.to), SHA-256 is from Brad Conte’s [crypto-algorithms](https://github.com/B-Con/crypto-algorithms) (both public-domain), and Blake3 is from the [reference C implementation](https://github.com/BLAKE3-team/BLAKE3/blob/master/c) (Apache2 or CC).

## Using it

You should be OK on recent versions of Linux, Windows, and Apple platforms, using up-to-date versions of Clang, GCC or MSVC, and CMake 3.16 or later. That's what the CI tests cover. 

1. If you haven't already, get the Monocypher submodule by running `git submodule update --init`.
2. Run the script `build_and_test.sh`. This uses CMake to build the library and some unit tests, and runs the tests.

If your project uses CMake to build, all you hve to do is update your `CMakeLists.txt`, adding the line `add_subdirectory(monocypher-cpp)` and adding `MonocypherCpp` to your target's `target_link_libraries`.

If you don't use CMake:
1. Add the `include` directory to your compiler's include path.
2. Add `src/Monocypher.cc` to your project's source file list.
3. `#include "Monocypher.hh"` in source files where you want to use Monocypher.
4. If you need to use Ed25519 signatures or SHA-512 digests, also compile `src/Monocypher-ed25519.cc` and `#include "Monocypher-ed25519.hh"`. Ditto for SHA-256, XSalsa20, which have their own headers and source files.
5. Blake3 is somewhat harder to build because you also need to build the code in `vendor/BLAKE3/c`, which has some specializations for different CPU types.

After building, read the [Monocypher documentation](https://monocypher.org/manual/) to learn how to use the API! The correspondence between the functions documented there, and the classes/methods here, should be clear. You can also consult `tests/MonocypherCppTests.cc` as a source of examples.

> ⚠️ You do _not_ need to compile or include the Monocypher C files in `vendor/monocypher/`. The C++ source files compile and include them for you indirectly, wrapping their symbols in a C++ namespace.

## Change Log

### 28 May 2024 -- Added Blake3

### 24 Oct 2023 -- Monocypher 4.0.2

### 10 April 2023 -- Monocypher 4.0.1

Upgraded the Monocypher library from 3.1.3 to 4.0.1. There were a lot of API changes in the C API, but most of them don't affect the C++ API. I've even added (trivial) wrappers for some functionality that was removed.

The change you _will_ notice is to the signature API. Monocypher used to keep the Ed25519 secret and public keys separate. But in 4.0 Loup decided to include the public key in the secret key, as libSodium does. This is because signing and verification use both keys, and there was a danger that application code might accidentally pass a mismatched pair, producing garbage results. The C API now only takes the secret key, which is actually both keys in one.

I already had a `key_pair` struct that combined the two keys, so that stays the same. The breaking change is that **`signing_key` is now renamed `key_pair::seed`**, and you can't use it directly to sign and verify anymore; only the `key_pair` does that. Wherever you were signing and verifying with the `signing_key`, alone, you'll now need to construct a `key_pair` from it and then call the `key_pair`. Also consider changing your code to use `key_pair` instead of `seed`; it's only 32 bytes larger and you'll save time on every signature or verification.

PS: When reading the Monocypher C API docs, keep in mind that what they call the "secret key" corresponds to the `key_pair` struct in the C++ API.

## To-Do

* iostream adapters for incremental operations.
* A clean way to get a `byte_array` pointing to crypto data at some address. Currently you can just do e.g. `((public_key*)keyPtr)->check(...)`.

## Caveats

* Monocypher doesn't supply its own random-number generator API. I've provided `byte_array::randomize()`, which tries to call `arc4_randombuf` where available. The fallback is `std::random_device`, which usually wraps the platform's RNG. But if your platform has no secure RNG (probably only true on embedded systems...) then `random_device` will happily provide low-entry pseudorandom output, which could lead to security problems. In that case you'll need to find your own source of randomness and modify the `randomize()` method to call it instead.
* The tests in this repository are far from exhaustive. Since Monocypher itself does the hard work, and is well-tested, my tests mostly just ensure that the C++ wrappers themselves are usable and seem to provide sane output.
