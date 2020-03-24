//
// Created by Attoa on 23/03/2020.
//

#include "../../include/crypto/keys.h"

#include <pwdbased.h>
#include <osrng.h>

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
