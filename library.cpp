#include "library.h"

#include <iostream>
#include <sha.h>
#include <hex.h>

#include "crypto/keys.h"

int main() {
    byte password[] = "epic gmaer";
    size_t plen = strlen((const char *) password);

    byte email[] = "joe.bell@notcool.com";
    size_t elen = strlen((const char *) email);

    byte key[SHA512::DIGESTSIZE];

    generate_master_key(key, email, elen, password, plen);

    std::string result;
    HexEncoder encoder(new StringSink(result));

    encoder.Put(key, sizeof(key));
    encoder.MessageEnd();

    std::cout << "Derived: " << result << std::endl;

    std::cout << "Hello, World!" << std::endl;
}
