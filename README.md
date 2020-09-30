# Monocypher C++ API

This is an idiomatic C++ API for [Monocypher](https://monocypher.org). Monocypher is:

> an easy to use, easy to deploy, auditable crypto library written in portable C.
> It approaches the size of TweetNaCl and the speed of Libsodium.

This API here is:

**Unofficial:** It's not part of Monocypher, but for convenience includes it as a Git submodule.

**C++:** Requires C++14 or later.

**Header-only:** It consists only of the file `Monocypher.hh`. No extra source files to add to your build (besides the Monocypher C library of course.)

**Idiomatic:**  Cryptographic entities are C++ classes, mostly subclasses of `std::array`. Options like byte-sizes and algorithms are template parameters. Operations are methods.

**Safe:** Strong typing makes the API safer. For example, you can't accidentally pass a Diffie-Hellman public key (`monocypher::key_exchange::public_key`) to a function expecting an Ed25519 public key (`monocypher::public_key`).
Moreover, objects are zeroed out when destructed, to avoid leaving secrets in memory, and the `==` and `!=` operators use constant-time comparisons instead of regular memcmp, to avoid timing attacks.

**Immature:** There had to be a downside :) This API is very new (as of late Sept 2020), is only partly tested, and has not yet been used much. However, it's just a very thin wrapper around Monocypher 3.1.1, which is well-tested and audited.

## Using it

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

* The only platform dependency I know of is the use of `arc4random_buf`. This function is available on macOS and Linux. On other platforms you may need to substitute an equivalent call to fill a buffer with cryptographically-random bytes. (It would be nice to add `#ifdefs` here to make it cross-platform. Patches welcome!)
* This code has so far only been compiled with Clang on macOS. It should work with GCC and MSVC, but you never know.
* Did I mention this is new code?
