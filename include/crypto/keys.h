//
// Created by Attoa on 23/03/2020.
//

#ifndef BEACON_CORE_KEYS_H
#define BEACON_CORE_KEYS_H

#include <sha.h>
#include <rsa.h>

#define RSA_KEYLEN 3072

// From RFC 3526: 3072-bit MODP Group, id 15
#define DH_P Integer("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF")
#define DH_G Integer("2")

// Random stuff
#define RK_INFO (const byte *)"1"
#define CK_INFO (const byte *)"2"
#define CK_INFO2 (const byte *)"a"
#define MK_INFO (const byte *)"b"

using namespace CryptoPP;

unsigned int derive_master_key(byte *key, const byte *email, const size_t email_length, const byte *password,
                               const size_t password_length);

size_t get_bytes_from_key(byte *key_bytes, const PublicKey &key);

RSA::PublicKey load_public_key_from_bytes(const byte *key_bytes, const size_t length);

RSA::PrivateKey load_private_key_from_bytes(const byte *key_bytes, const size_t length);

size_t generate_private_key(byte *privkey);

size_t derive_public_key(byte *pubkey, const byte *privkey, const size_t p_length);

unsigned int generate_root_key(byte *root_key);

unsigned int generate_DH_keypair(byte *dh_privkey, byte *dh_pubkey);

unsigned int calculate_DH_output(byte *dh_out, const byte *dh_priv, const byte *dh_pub);

unsigned int update_root_key(byte *root_key_out, byte *chain_key_out, const byte *root_key_in, const byte *dh_output);

unsigned int update_chain_key(byte *chain_key_out, byte *message_key_out, const byte *chain_key_in);

#endif //BEACON_CORE_KEYS_H
