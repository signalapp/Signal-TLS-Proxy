#ifndef VPN_COMMON_H
#define VPN_COMMON_H

#include <openssl/rsa.h>
#include <openssl/sha.h>

#define RSA_KEY_LENGTH 4096
#define MAX_PASSWORD_LENGTH 128
#define MAX_USERNAME_LENGTH 64
#define ENCRYPTED_PASSWORD_LENGTH 512

// Function prototypes
void handle_errors();
RSA *generate_rsa_keypair();
void save_private_key(RSA *rsa, const char *filename);
void hash_password(const char *password, unsigned char *output_hash);
int rsa_encrypt(RSA *rsa, unsigned char *input, int input_len, unsigned char *output);
int rsa_decrypt(RSA *rsa, unsigned char *input, int input_len, unsigned char *output);

#endif /* VPN_COMMON_H */

