//
// Created by Attoa on 24/03/2020.
//

#ifndef BEACON_CORE_ENCRYPT_H
#define BEACON_CORE_ENCRYPT_H

#include <hex.h>

using namespace CryptoPP;

unsigned int encrypt_aes256(byte *out, byte *iv, const byte *in, const size_t length, const byte *key);

unsigned int decrypt_aes256(byte *out, const byte *in, const size_t length, const byte *iv, const byte *key);

size_t encrypt_rsa(byte *out, const byte *in, const size_t length, const byte *pubkey, const size_t pubkey_length);

size_t decrypt_rsa(byte *out, const byte *in, const size_t length, const byte *privkey, const size_t privkey_length);

size_t sign_rsa(byte *out, const byte *in, const size_t length, const byte *privkey, const size_t privkey_length);

bool verify_rsa(const byte *sig, const size_t sig_length, const byte *message, const size_t message_length,
                const byte *pubkey, const size_t pubkey_length);

#endif //BEACON_CORE_ENCRYPT_H
