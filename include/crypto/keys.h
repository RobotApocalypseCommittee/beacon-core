//
// Created by Attoa on 23/03/2020.
//

#ifndef BEACON_CORE_KEYS_H
#define BEACON_CORE_KEYS_H

#include <sha.h>

using namespace CryptoPP;

unsigned int generate_master_key(byte *key, byte *email, size_t email_length, byte *password, size_t password_length);

#endif //BEACON_CORE_KEYS_H
