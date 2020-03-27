#include "library.h"

#include <iostream>
#include <sha.h>
#include <hex.h>
#include <aes.h>

#include "crypto/keys.h"
#include "crypto/encrypt.h"

#include "message.pb.h"

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

    byte pubdA[384];
    byte privdA[384];

    generate_DH_keypair(privdA, pubdA);

    std::cout << "DH Priv: " << hex_string(privdA, 384) << std::endl;
    std::cout << "DH Pub: " << hex_string(pubdA, 384) << std::endl;

    byte pubdB[384];
    byte privdB[384];

    generate_DH_keypair(privdB, pubdB);

    byte shared[384];
    byte shared2[384];

    calculate_DH_output(shared, privdA, pubdB);
    calculate_DH_output(shared2, privdB, pubdA);

    std::cout << "Agreed key 1: " << hex_string(shared, 100) << std::endl;
    std::cout << "Agreed key 2: " << hex_string(shared2, 100) << std::endl;

    byte rk[SHA256::DIGESTSIZE];
    byte ck[SHA256::DIGESTSIZE];
    byte mk[SHA256::DIGESTSIZE];
    byte ck2[SHA256::DIGESTSIZE];
    byte rk2[SHA256::DIGESTSIZE];

    generate_root_key(rk);

    update_root_key(rk2, ck, rk, shared);

    update_chain_key(ck2, mk, ck);

    std::cout << "RK: " << hex_string(rk, sizeof(rk)) << std::endl;
    std::cout << "CK: " << hex_string(ck, sizeof(ck)) << std::endl;
    std::cout << "MK: " << hex_string(mk, sizeof(mk)) << std::endl;
    std::cout << "CK2: " << hex_string(ck2, sizeof(ck2)) << std::endl;
    std::cout << "RK2: " << hex_string(rk2, sizeof(rk2)) << std::endl;

    std::cout << "Hello, World!" << std::endl;
}
