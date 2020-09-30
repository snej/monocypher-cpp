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
    char hex[2*size + size/4 + 1];
    char *dst = hex;
    for (size_t i = 0; i < size; i++) {
        if (i > 0 && (i % 4) == 0) *dst++ = ' ';
        dst += sprintf(dst, "%02X", ((const uint8_t*)buf)[i]);
    }
    return hex;
}


template <size_t Size>
string hexString(const byte_array<Size> &a) {
    return hexString(a, Size);
}


template <size_t Size>
string hexString(const void *buf) {
    return hexString(buf, Size);
}
