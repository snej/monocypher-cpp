//
//  tests.hh
//  Monocypher-Cpp
//
//  Created by Jens Alfke on 9/24/20.
//

#pragma once
#include "Monocypher.hh"
#include <cstdio>
#include <string>

using namespace std;
using namespace monocypher;


static string hexString(const void *buf, size_t size) {
    auto hex = make_unique<char[]>(2*size + size/4 + 1);
    char *dst = hex.get();
    for (size_t i = 0; i < size; i++) {
        if (i > 0 && (i % 4) == 0) *dst++ = ' ';
        dst += sprintf(dst, "%02X", ((const uint8_t*)buf)[i]);
    }
    return string(hex.get());
}


template <size_t Size>
string hexString(const byte_array<Size> &a) {
    return hexString(a.data(), Size);
}


template <size_t Size>
string hexString(const void *buf) {
    return hexString(buf, Size);
}
