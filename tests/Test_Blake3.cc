//
// Created by Jens Alfke on 5/28/24.
//

#include "hexString.hh"
#include "Monocypher.hh"
#include "monocypher/ext/blake3.hh"
#include <iostream>
#include <tuple>    // for `tie`

#include "catch.hpp"

using namespace std;
using namespace monocypher;

// Digest and HMAC of empty string taken from the official test vectors,
// https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json

TEST_CASE("Blake3") {
    auto h1 = ext::blake3::create(""sv);
    string str1 = hexString(h1);
    cout << str1 << "\n";
    CHECK(str1 == "AF1349B9 F5F9A1A6 A0404DEA 36DCC949 9BCB25C9 ADC112B7 CC9A93CA E41F3262");

    h1 = ext::blake3::create("hello world"sv);
    str1 = hexString(h1);
    cout << str1 << "\n";
    CHECK(str1 == "D74981EF A70A0C88 0B8D8C19 85D075DB CBF679B9 9A5F9914 E5AAF96B 831A9E24");

    ext::blake3::builder b;
    b.update("hello"sv).update(" "sv).update("world"sv);
    ext::blake3 h2 = b.final();

    string str2 = hexString(h2);
    cout << str2 << "\n";
    CHECK(str2 == str1);
    CHECK(h2 == h1);

    // (No HMAC support in Blake3 yet)
}

TEST_CASE("Blake3 HMAC") {
    secret_byte_array<32> key("whats the Elvish word for friend", 32);

    auto mac = ext::blake3::createMAC(""sv, key);
    string macStr = hexString(mac);
    cout << "HMAC = " << macStr << endl;
    CHECK(macStr == "92B2B756 04ED3C76 1F9D6F62 392C8A92 27AD0EA3 F09573E7 83F1498A 4ED60D26");

    mac = ext::blake3::createMAC("hello world"sv, key);
    macStr = hexString(mac);
    cout << "HMAC = " << macStr << endl;
    CHECK(macStr == "546A11CF 08472EE6 8FB83C3F 28AB2DC2 1EF620A6 F03A64B4 29E4BAC4 E454D2B2");

    typename ext::blake3::mac_builder hm(key);
    hm.update("hello"sv).update(" "sv).update("world"sv);
    ext::blake3 mac2 = hm.final();
    cout << "HMAC = " << hexString(mac2) << endl;
    CHECK(mac2 == mac);

}
