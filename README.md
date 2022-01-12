![Build+Test](https://github.com/snej/monocypher-cpp/workflows/Build+Test/badge.svg)

# Monocypher C++ API

This is an idiomatic C++ API for [Monocypher](https://monocypher.org). Monocypher is:

> an easy to use, easy to deploy, auditable crypto library written in portable C.
> It approaches the size of TweetNaCl and the speed of Libsodium.

This API here is:

**Unofficial:** It's not part of Monocypher, but for convenience includes it as a Git submodule.

**C++:** Requires C++17 or later.

**Header-only:** It consists only of the file `Monocypher.hh`. No extra source files to add to your build (besides the Monocypher C library of course.)

**Idiomatic:**  Cryptographic entities are C++ classes, mostly subclasses of `std::array`. Options like key sizes and algorithms are template parameters. Operations are methods.

**Safe:** Strong typing makes the API safer. For example, you can't accidentally pass a Diffie-Hellman public key (`monocypher::key_exchange::public_key`) to a function expecting an Ed25519 public key (`monocypher::public_key`).
Moreover, objects are zeroed out when destructed, to avoid leaving secrets in memory, and the `==` and `!=` operators use constant-time comparisons instead of regular memcmp, to avoid timing attacks.

**Immature:** There had to be a downside :) This API is fairly new, only partly tested, and has not yet been used much. However, it's just a very thin wrapper around Monocypher 3.1.2, which is well-tested and audited.

## Using it

You should be OK on recent versions of Linux, Windows, and Apple platforms, using up-to-date versions of Clang, GCC or MSVC. That's what the CI tests cover. 

0. If you haven't already, get the Monocypher submodule by running `git submodule update --init`.
1. Run `run_tests.sh`. This just compiles & runs `test/tests.cc`, some simple tests.
2. Add the directories `include`, `vendor/monocypher/src` and `vendor/monocypher/src/optional` to your compiler's include path.
3. Add `vendor/monocypher/src/monocypher.c` and `vendor/monocypher/src/optional/monocypher-ed25519.c` to your project's source file list.
4. `#include "Monocypher.hh"` in source files where you want to use Monocypher.
5. Read the [Monocypher documentation](https://monocypher.org/manual/) to learn how to use the API! The correspondence between the functions documented there, and the classes/methods here, should be clear. You can also consult `test/tests.cc` as a source of examples.

## To-Do

* Higher-level, more C++like API for variable-length data, e.g. messages to be hashed/encrypted. There are many options, like `string`, `string_view`, `istream`, or a pair of begin/end iterators, none of which are entirely compatible with each other and some of which have significant overhead. So I threw up my hand and used good ol' (`const void*, size_t)`. Will the new Range features of C++20 help?
* A clean way to get a `byte_array` pointing to crypto data at some address. Currently you can just do e.g. `((public_key*)keyPtr)->check(...)`.

## Caveats

* Monocypher doesn't supply its own random-number generator API. I've provided `byte_array::randomize()`, which tries to call `arc4_randombuf` where available. The fallback is `std::random_device`, which usually wraps the platform's RNG. But if your platform has no secure RNG (probably only true on embedded systems...) then `random_device` will happily provide low-entry pseudorandom output, which could lead to security problems. In that case you'll need to find your own source of randomness and modify the `randomize()` method to call it insteaed.
* The tests in this repository are far from exhaustive. Since Monocypher itself does the hard work, and is well-tested, my tests mostly just endure that the C++ wrappers themselves are useable and seem to provide sane output.
* Did I mention this is new code?
