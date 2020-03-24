//
// Created by Attoa on 23/03/2020.
//

#ifndef BEACON_CORE_KEYS_H
#define BEACON_CORE_KEYS_H

#include <sha.h>
#include <rsa.h>

#define RSA_KEYLEN 3072

using namespace CryptoPP;

unsigned int derive_master_key(byte *key, const byte *email, const size_t email_length, const byte *password,
                               const size_t password_length);

size_t get_bytes_from_key(byte *key_bytes, const PublicKey &key);

RSA::PublicKey load_public_key_from_bytes(const byte *key_bytes, const size_t length);

RSA::PrivateKey load_private_key_from_bytes(const byte *key_bytes, const size_t length);

size_t generate_private_key(byte *privkey);

size_t derive_public_key(byte *pubkey, const byte *privkey, const size_t p_length);

#endif //BEACON_CORE_KEYS_H
