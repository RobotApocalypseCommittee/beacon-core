//
// Created by Attoa on 23/03/2020.
//

#include "../../include/crypto/keys.h"

#include <pwdbased.h>

using namespace CryptoPP;

unsigned int generate_master_key(byte *key, byte *email, size_t email_length, byte *password, size_t password_length) {
    // key should be of size SHA512::DIGESTSIZE

    PKCS5_PBKDF2_HMAC<SHA512> pbkdf;
    byte unused = 0;

    pbkdf.DeriveKey(key, SHA512::DIGESTSIZE, unused, password, password_length, email, email_length, 16384, 0.0f);

    return 0;
}
