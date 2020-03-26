//
// Created by Attoa on 23/03/2020.
//

#include "../../include/crypto/keys.h"

#include <iostream>

#include <pwdbased.h>
#include <osrng.h>
#include <dh.h>
#include <hkdf.h>

using namespace CryptoPP;

unsigned int derive_master_key(byte *key, const byte *email, const size_t email_length, const byte *password,
                               const size_t password_length) {
    // key should be of size SHA256::DIGESTSIZE

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    byte unused = 0;

    pbkdf.DeriveKey(key, SHA256::DIGESTSIZE, unused, password, password_length, email, email_length, 16384, 0.0f);

    return 0;
}

size_t get_bytes_from_key(byte *key_bytes, const PublicKey &key) {
    ByteQueue queue(0);
    key.Save(queue);

    size_t length = queue.Get(key_bytes, queue.MaxRetrievable());


    return length;
}

RSA::PublicKey load_public_key_from_bytes(const byte *key_bytes, const size_t length) {
    ByteQueue queue(length);
    queue.Put2(key_bytes, length, -1, true);

    RSA::PublicKey key;
    key.Load(queue);
    return key;
}

RSA::PrivateKey load_private_key_from_bytes(const byte *key_bytes, const size_t length) {
    ByteQueue queue(length);
    queue.Put2(key_bytes, length, -1, true);

    RSA::PrivateKey key;
    key.Load(queue);
    return key;
}


size_t generate_private_key(byte *privkey) {
    AutoSeededRandomPool prng;
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(prng, RSA_KEYLEN);

    size_t length = get_bytes_from_key(privkey, privateKey);

    return length;
}

size_t derive_public_key(byte *pubkey, const byte *privkey, const size_t p_length) {
    RSA::PrivateKey privateKey = load_private_key_from_bytes(privkey, p_length);
    RSA::PublicKey publicKey(privateKey); // NOLINT(performance-unnecessary-copy-initialization)

    size_t length = get_bytes_from_key(pubkey, publicKey);

    return length;
}

unsigned int generate_root_key(byte *root_key) {
    AutoSeededRandomPool rnd;

    // AES256 -> 32 bytes
    rnd.GenerateBlock(root_key, 32);

    return 0;
}

unsigned int generate_DH_keypair(byte *dh_privkey, byte *dh_pubkey) {
    // Both are of size 384 bytes!
    AutoSeededRandomPool rng;
    DH dh;
    dh.AccessGroupParameters().Initialize(DH_P, DH_G);

    dh.GenerateKeyPair(rng, dh_privkey, dh_pubkey);

    return 0;
}

unsigned int calculate_DH_output(byte *dh_out, const byte *dh_privkey, const byte *dh_pubkey) {
    // All are of size 384 bytes!
    DH dh;
    dh.AccessGroupParameters().Initialize(DH_P, DH_G);

    dh.Agree(dh_out, dh_privkey, dh_pubkey);

    return 0;
}

unsigned int update_root_key(byte *root_key_out, byte *chain_key_out, const byte *root_key_in, const byte *dh_output) {
    HKDF<SHA256> hkdf;

    // That just is the dh_output length
    hkdf.DeriveKey(root_key_out, SHA256::DIGESTSIZE, root_key_in, SHA256::DIGESTSIZE, dh_output, 384, RK_INFO, 1);
    hkdf.DeriveKey(chain_key_out, SHA256::DIGESTSIZE, root_key_in, SHA256::DIGESTSIZE, dh_output, 384, CK_INFO, 1);
    // TODO check right length output

    return 0;
}

unsigned int update_chain_key(byte *chain_key_out, byte *message_key_out, const byte *chain_key_in) {
    HKDF<SHA256> hkdf;

    // Salt is just the "constant", no need for randomisation
    hkdf.DeriveKey(chain_key_out, SHA256::DIGESTSIZE, chain_key_in, SHA256::DIGESTSIZE, CK_INFO2, 1, nullptr, 0);
    hkdf.DeriveKey(message_key_out, SHA256::DIGESTSIZE, chain_key_in, SHA256::DIGESTSIZE, MK_INFO, 1, nullptr, 0);
    // TODO check right length output

    return 0;
}
