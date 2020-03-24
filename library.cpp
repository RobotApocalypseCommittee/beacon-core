#include "library.h"

#include <iostream>
#include <sha.h>
#include <hex.h>
#include <aes.h>

#include "crypto/keys.h"
#include "crypto/encrypt.h"

std::string hex_string(byte *bytes, size_t length) {
    std::string result;
    HexEncoder encoder(new StringSink(result));

    encoder.Put(bytes, length);
    encoder.MessageEnd();

    return result;
}

int main() {
    byte password[] = "epic gmaer";
    size_t plen = strlen((const char *) password);

    byte email[] = "joe.bell@notcool.com";
    size_t elen = strlen((const char *) email);

    byte key[SHA256::DIGESTSIZE];

    derive_master_key(key, email, elen, password, plen);

    std::cout << "MK: " << hex_string(key, sizeof(key)) << std::endl;

    byte priv[2000];
    byte pub[500];

    const size_t klen = generate_private_key(priv);
    const size_t pklen = derive_public_key(pub, priv, klen);

    std::cout << "Priv: " << hex_string(priv, klen) << std::endl;
    std::cout << "Pub: " << hex_string(pub, pklen) << std::endl;

    byte out[10000];
    byte in[] = "Secret sauce";
    // +1 for null terminator!
    size_t inlen = strlen((const char *) in) + 1;
    byte iv[AES::BLOCKSIZE];

    std::cout << "ORIG: " << in << std::endl;

    encrypt_aes256(out, iv, in, inlen, key);

    std::cout << "ENC AES: " << hex_string(out, inlen) << std::endl;
    //std::cout << "ENC: " << out << std::endl;

    byte out2[200];
    decrypt_aes256(out2, out, inlen, iv, key);

    std::cout << "DEC AES: " << out2 << std::endl;

    size_t outlen = encrypt_rsa(out, in, inlen, pub, pklen);

    std::cout << "ENC RSA: " << hex_string(out, outlen) << std::endl;
    //std::cout << "ENC: " << out << std::endl;

    decrypt_rsa(out2, out, outlen, priv, klen);

    std::cout << "DEC RSA: " << out2 << std::endl;

    std::cout << "Hello, World!" << std::endl;
}
