//
// Created by Attoa on 24/03/2020.
//

#include "crypto/encrypt.h"

#include <aes.h>
#include <osrng.h>
#include <modes.h>
#include <rsa.h>

#include "crypto/keys.h"

unsigned int encrypt_aes256(byte *out, byte *iv, const byte *in, const size_t length, const byte *key) {
    AutoSeededRandomPool rnd;

    // IV MUST be this size!
    rnd.GenerateBlock(iv, AES::BLOCKSIZE);

    // AES 256: 32 bytes
    CFB_Mode<AES>::Encryption cfbEncryption(key, 32, iv);
    cfbEncryption.ProcessData(out, in, length);

    return 0;
}

unsigned int decrypt_aes256(byte *out, const byte *in, const size_t length, const byte *iv, const byte *key) {
    // AES 256: 32 bytes
    CFB_Mode<AES>::Decryption cfbDecryption(key, 32, iv);
    cfbDecryption.ProcessData(out, in, length);

    return 0;
}

size_t encrypt_rsa(byte *out, const byte *in, const size_t length, const byte *pubkey, const size_t pubkey_length) {
    AutoSeededRandomPool rnd;

    RSA::PublicKey publicKey = load_public_key_from_bytes(pubkey, pubkey_length);
    RSAES<OAEP<SHA256>>::Encryptor encryptor(publicKey);

    // TODO check not 0
    size_t cipherTextSize = encryptor.CiphertextLength(length);

    encryptor.Encrypt(rnd, in, length, out);

    return cipherTextSize;
}

size_t decrypt_rsa(byte *out, const byte *in, const size_t length, const byte *privkey, const size_t privkey_length) {
    AutoSeededRandomPool rnd;

    RSA::PrivateKey privateKey = load_private_key_from_bytes(privkey, privkey_length);
    RSAES<OAEP<SHA256>>::Decryptor decryptor(privateKey);

    // TODO check not 0
    //size_t maxPlainTextSize = encryptor.MaxPlaintextLength(length);

    DecodingResult result = decryptor.Decrypt(rnd, in, length, out);

    return result.messageLength;
}

size_t sign_rsa(byte *out, const byte *in, const size_t length, const byte *privkey, const size_t privkey_length) {
    // Probably always 384 bytes (3072 bits)
    AutoSeededRandomPool rnd;

    RSA::PrivateKey privateKey = load_private_key_from_bytes(privkey, privkey_length);
    RSASS<PKCS1v15, SHA256>::Signer signer(privateKey);

    return signer.SignMessage(rnd, in, length, out);
}

bool verify_rsa(const byte *sig, const size_t sig_length, const byte *message, const size_t message_length,
                const byte *pubkey, const size_t pubkey_length) {
    RSA::PublicKey publicKey = load_public_key_from_bytes(pubkey, pubkey_length);
    RSASS<PKCS1v15, SHA256>::Verifier verifier(publicKey);

    return verifier.VerifyMessage(message, message_length, sig, sig_length);
}
