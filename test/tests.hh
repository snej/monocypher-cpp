//
//  tests.hh
//  Monocypher-Cpp
//
//  Created by Jens Alfke on 9/24/20.
//

#pragma once
#include <array>
#include <cstdio>
#include <string>

using namespace std;


static inline std::string hexString(const void *buf, size_t size, bool spaces =true) {
    std::string hex;
    hex.resize(size * 2 + size / 4);
    char *dst = hex.data();
    for (size_t i = 0; i < size; i++) {
        if (spaces && i > 0 && (i % 4) == 0) 
            *dst++ = ' ';
        dst += sprintf(dst, "%02X", ((const uint8_t*)buf)[i]);
    }
    hex.resize(dst - hex.data());
    return hex;
}


template <size_t Size>
static std::string hexString(const void *buf) {
    return hexString(buf, Size);
}


template <size_t Size>
static std::string hexString(const std::array<uint8_t,Size> &a) {
    return hexString<Size>(a.data());
}


