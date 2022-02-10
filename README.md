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

**Safe:** Strong typing makes the API safer. For example, you can't accidentally pass a Diffie-Hellman public key (`monocypher::key_exchange::public_key`) to a function expecting an Ed25519 public key (`monocypher::public_key`).
Moreover, objects are zeroed out when destructed, to avoid leaving secrets in memory, and the `==` and `!=` operators use constant-time comparisons instead of regular memcmp, to avoid timing attacks.

**Immature:** There had to be a downside :) This API is fairly new, only partly tested, and has not yet been used in production code. However, it's just a very thin wrapper around Monocypher 3.1.2, which is well-tested and audited.

## Features

| Functionality               | Algorithm(s)                             |
| --------------------------- | ---------------------------------------- |
| Cryptographic digests       | Blake2b, SHA-512, *SHA-256\**            |
| Password-to-key derivation  | Argon2i                                  |
| Diffie-Hellman key exchange | Curve25519 (raw or with HChaCha20)       |
| Authenticated encryption    | XChaCha20 *or XSalsa20\**, with Poly1305 |
| Digital signatures          | Ed25519 (with Blake2b or SHA-512)        |

\* denotes optional algorithms not implemented in Monocypher itself. XSalsa20 is from [tweetnacl](https://tweetnacl.cr.yp.to) and SHA-256 is from Brad Conte’s [crypto-algorithms](https://github.com/B-Con/crypto-algorithms) (both public-domain.)

## Using it

You should be OK on recent versions of Linux, Windows, and Apple platforms, using up-to-date versions of Clang, GCC or MSVC. That's what the CI tests cover. 

0. If you haven't already, get the Monocypher submodule by running `git submodule update --init`.
1. Run the script `run_tests.sh`. This just compiles & runs `test/tests.cc`, some simple tests.
2. Add the directories `include` and `vendor/monocypher/src` to your compiler's include path.
3. Add `src/Monocypher.cc` to your project's source file list.
4. `#include "Monocypher.hh"` in source files where you want to use Monocypher.
5. If you need to use Ed25519 signatures, also compile `src/Monocypher-ed25519.cc` and `#include "Monocypher-ed25519.hh"`.
5. Read the [Monocypher documentation](https://monocypher.org/manual/) to learn how to use the API! The correspondence between the functions documented there, and the classes/methods here, should be clear. You can also consult `test/tests.cc` as a source of examples.

> Note that you do _not_ need to compile the Monocypher C source files in `vendor/monocypher/src/`. The C++ source files compile them for you indirectly, wrapping their symbols in a C++ namespace.

## To-Do

* iostream adapters for incremental operations.
* A clean way to get a `byte_array` pointing to crypto data at some address. Currently you can just do e.g. `((public_key*)keyPtr)->check(...)`.

## Caveats

* Monocypher doesn't supply its own random-number generator API. I've provided `byte_array::randomize()`, which tries to call `arc4_randombuf` where available. The fallback is `std::random_device`, which usually wraps the platform's RNG. But if your platform has no secure RNG (probably only true on embedded systems...) then `random_device` will happily provide low-entry pseudorandom output, which could lead to security problems. In that case you'll need to find your own source of randomness and modify the `randomize()` method to call it instead.
* The tests in this repository are far from exhaustive. Since Monocypher itself does the hard work, and is well-tested, my tests mostly just ensure that the C++ wrappers themselves are usable and seem to provide sane output.
