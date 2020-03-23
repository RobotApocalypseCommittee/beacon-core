#include "library.h"

#include <iostream>
#include <filters.h>
#include <sha.h>
#include <hex.h>

int main() {
    using namespace CryptoPP;

    byte password[] ="password";
    size_t plen = strlen((const char*)password);

    byte salt[] = "salt";
    size_t slen = strlen((const char*)salt);

    byte derived[SHA256::DIGESTSIZE];

    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    byte unused = 0;

    pbkdf.DeriveKey(derived, sizeof(derived), unused, password, plen, salt, slen, 1024, 0.0f);

    std::string result;
    HexEncoder encoder(new StringSink(result));

    encoder.Put(derived, sizeof(derived));
    encoder.MessageEnd();

    std::cout << "Derived: " << result << std::endl;

    std::cout << "Hello, World!" << std::endl;
}
