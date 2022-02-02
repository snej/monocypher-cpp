//
//  tests.cc
//  Monocypher-Cpp
//
//  Created by Jens Alfke on 9/24/20.
//

#include "tests.hh"
#include <iostream>
#include <tuple>    // for `tie`


// These are some incomplete tests of the Monocypher.hh C++ API.


static void test_randomize() {
    // _Really_ testing a RNG is difficult and involves statistics. At this level all I want to
    // verify is that randomize() is touching every byte of the array.

    cout << "--- test_randomize ---\n";
    session::key key;
    // First wipe the key and verify it's zeroed:
    key.wipe();
    cout << "Before: " << hexString(key) << "\n";
    for (size_t i = 0; i < sizeof(key); ++i)
        assert(key[i] == 0);

    // Randomize 'key', then heck that all bytes have changed (from 00.)
    // Obviously this can fail even with a real RNG, so try multiple times.
    // (Chance of one failure is 12%; ten in a row is less than one in a billion.)
    bool changed = false;
    for (int attempt = 0; attempt < 10; ++attempt) {
        key.randomize();
        cout << "After:  " << hexString(key) << "\n";
        changed = true;
        for (size_t i = 0; i < sizeof(key); ++i) {
            if (key[i] == 0) {
                cout << "    nope, byte[" << i << "] is still 00...\n";
                changed = false;
                break;
            }
        }
        if (changed)
            break;
    }
    assert(changed);
    cout << "✔︎ randomize passed\n\n";
}


static void test_blake2b() {
    cout << "--- test_blake2b ---\n";
    monocypher::hash<Blake2b> h1 = blake2b64::create("hello world", 11);
    string str1 = hexString(h1);
    cout << str1 << "\n";
    assert(str1 == "021CED87 99296CEC A557832A B941A50B 4A11F834 78CF141F 51F933F6 53AB9FBC "
                   "C05A037C DDBED06E 309BF334 942C4E58 CDF1A46E 237911CC D7FCF978 7CBC7FD0");

    blake2b64::builder b;
    b.update("hello", 5).update(" ", 1).update("world", 5);
    blake2b64 h2 = b.final();

    string str2 = hexString(h2);
    cout << str2 << "\n";
    assert(str2 == str1);

    assert(h2 == h1);
    cout << "✔︎ Blake2b passed\n\n";
}


static void test_argon2i() {
    cout << "--- test_argon2i ---\n";

    using FastArgon = argon2i<64, 1000, 3>;
    // Note: I deliberately made NBlocks unrealistically small, to avoid slowing down tests.

    static const char *password = "password69";
    FastArgon::hash h1;
    FastArgon::salt salt;
    tie(h1, salt) = FastArgon::create(password, strlen(password));
    string str1 = hexString(h1);
    cout << "Argon2i hash = " << str1 << "\n";
    cout << "Salt         = " << hexString(salt) << "\n";

    auto h2 = FastArgon::create(password, strlen(password), salt);
    string str2 = hexString(h2);
    cout << "Rebuilt hash = " << str2 << "\n";
    assert(h1 == h2);
    assert(str1 == str2);

    // Try a known non-random salt:
    FastArgon::salt mySalt;
    strcpy((char*)mySalt.data(), "Morton's");
    cout << "Fixed salt      = " << hexString(mySalt) << "\n";
    auto h3 = FastArgon::create(password, strlen(password), mySalt);
    string str3 = hexString(h3);
    cout << "Pre-salted hash = " << str3 << "\n";
    assert(str3 == "35388F22 9FF73B11 D9E04E59 853547CC CA11A05E 3A67670F B5CA02AD BB52062D "
                   "53CD02A5 DE5611B1 2D10B5E4 DBF28A48 A389F791 4F05F532 728DF45D 4283470F");
    cout << "✔︎ Argon2i passed\n\n";
}


static void test_key_exchange() {
    cout << "--- test_key_exchange ---\n";
    key_exchange kx1, kx2;

    auto pk1 = kx1.get_public_key();
    auto pk2 = kx2.get_public_key();
    cout << "public key 1 = " << hexString(pk1) << "\n";
    cout << "public key 2 = " << hexString(pk2) << "\n";

    auto secret1 = kx1.get_shared_secret(pk2);
    auto secret2 = kx2.get_shared_secret(pk1);
    cout << "shared secret 1 = " << hexString(secret1) << "\n";
    cout << "shared secret 2 = " << hexString(secret2) << "\n";
    assert(secret1 == secret2);
    cout << "✔︎ Key exchange passed\n\n";
}


static void test_key_exchange_raw() {
    cout << "--- test_key_exchange_raw ---\n";
    key_exchange<X25519_Raw> kx1, kx2;

    auto pk1 = kx1.get_public_key();
    auto pk2 = kx2.get_public_key();
    cout << "public key 1 = " << hexString(pk1) << "\n";
    cout << "public key 2 = " << hexString(pk2) << "\n";

    auto secret1 = kx1.get_shared_secret(pk2);
    auto secret2 = kx2.get_shared_secret(pk1);
    cout << "shared secret 1 = " << hexString(secret1) << "\n";
    cout << "shared secret 2 = " << hexString(secret2) << "\n";
    assert(secret1 == secret2);
    cout << "✔︎ Key exchange passed\n\n";
}


static void test_encryption() {
    cout << "--- test_encryption ---\n";
    const string message = "ATTACK AT DAWN";

    session::key key;       // random key
    session::nonce nonce;   // random nonce
    char ciphertext[14];
    assert(sizeof(ciphertext) == message.size());
    session::mac mac = key.lock(nonce, message.c_str(), message.size(), ciphertext);
    cout << "locked: " << hexString<14>(ciphertext) << "\n";
    cout << "nonce:  " << hexString(nonce) << "\n";
    cout << "MAC:    " << hexString(mac) << "\n";

    char plaintext[14];
    bool valid = key.unlock(nonce, mac, ciphertext, sizeof(ciphertext), plaintext);
    assert(valid);
    string plaintextStr(plaintext, sizeof(plaintext));
    cout << "unlocked: '" << plaintextStr << "'\n";
    assert(plaintextStr == message);

    // Test integer nonce:
    nonce = 0x12345678FF;
    auto nonceStr = hexString(nonce);
    cout << "Integer Nonce = " << nonceStr << "\n";
    assert(nonceStr == "FF785634 12000000 00000000 00000000 00000000 00000000");
    // Increment it:
    ++nonce;
    nonceStr = hexString(nonce);
    cout << "Incr'd Nonce  = " << nonceStr << "\n";
    assert(nonceStr == "00795634 12000000 00000000 00000000 00000000 00000000");
    cout << "✔︎ Encryption passed\n\n";
}


static void test_signatures() {
    static const char *message = "THIS IS FINE. I'M OKAY WITH THE EVENTS THAT ARE UNFOLDING"
                                 " CURRENTLY. THAT'S OKAY, THINGS ARE GOING TO BE OKAY.";
    cout << "--- test_signatures ---\n";
    auto key = EdDSA::signing_key::generate();
    cout << "secret key: " << hexString(key) << "\n";
    auto pubKey = key.get_public_key();
    cout << "public key: " << hexString(pubKey) << "\n";
    auto signature = key.sign(message, strlen(message), pubKey);
    cout << "signature: " << hexString(signature) << "\n";

    bool ok = pubKey.check(signature, message, strlen(message));
    assert(ok);
    cout << "✔︎ signature is valid.\n";

    signature[0] += 1;
    ok = pubKey.check(signature, message, strlen(message));
    assert(!ok);
    cout << "✔︎ modified signature is not valid.\n";
    cout << "✔︎ Signatures passed\n\n";
}


static void test_signatures_to_kx() {
    cout << "--- test_signatures_to_kx ---\n";
    auto keyPair1 = EdDSA::key_pair::generate();
    auto keyPair2 = EdDSA::key_pair::generate();

    // Convert the signing key-pairs to key-exchange key-pairs:
    key_exchange kx1(keyPair1.get_signing_key());
    key_exchange kx2(keyPair2.get_signing_key());

    // Check that we can derive KX public keys from signing public keys:
    auto pk1 = kx1.get_public_key();
    auto pk2 = kx2.get_public_key();

    assert(pk1 == key_exchange<X25519_HChaCha20>::public_key(keyPair1.get_public_key()));
    assert(pk2 == key_exchange<X25519_HChaCha20>::public_key(keyPair2.get_public_key()));
    cout << "✔︎ KX public keys derived from signing public keys are correct.\n";

    // Generate the shared secrets:
    auto secret1 = kx1.get_shared_secret(pk2);
    auto secret2 = kx2.get_shared_secret(pk1);
    cout << "shared secret 1 = " << hexString(secret1) << "\n";
    cout << "shared secret 2 = " << hexString(secret2) << "\n";
    assert(secret1 == secret2);
    cout << "✔︎ shared secrets match.\n";
    cout << "✔︎ Key exchange passed\n\n";
}


int main(int argc, const char * argv[]) {
    cout << "Testing Monocypher-C++ wrapper...\n\n";
    test_randomize();
    test_blake2b();
    test_argon2i();
    test_key_exchange();
    test_key_exchange_raw();
    test_encryption();
    test_signatures();
    test_signatures_to_kx();
    cout << "✔︎✔︎✔︎ ALL C++ WRAPPER TESTS PASSED ✔︎✔︎✔︎ (but this is not a full test of Monocypher itself)\n";
    return 0;
}
