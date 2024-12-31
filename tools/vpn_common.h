#ifndef VPN_COMMON_H
#define VPN_COMMON_H

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

#define RSA_KEY_LENGTH 4096
#define MAX_PASSWORD_LENGTH 128
#define MAX_USERNAME_LENGTH 64
#define ENCRYPTED_PASSWORD_LENGTH 512
#define MAX_CERT_PATH 256

// ==========================
// 🛡️ Error Handling
// ==========================
void handle_errors(void);

// ==========================
// 🔑 RSA Key Management
// ==========================
EVP_PKEY *generate_rsa_keypair(void);
void save_private_key(EVP_PKEY *pkey, const char *filename);
void save_encrypted_certificate(X509 *cert, const char *filename, const unsigned char *key);


// ==========================
// 🔐 Password Handling
// ==========================
void hash_password(const char *password, unsigned char *output_hash);

// ==========================
// 🔒 Encryption/Decryption
// ==========================
int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext);
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext);

// ==========================
// 📜 Certificate Management
// ==========================
X509 *generate_certificate(EVP_PKEY *pkey, const char *username);
void save_encrypted_certificate(X509 *cert, const char *filename, const unsigned char *key);

// ==========================
// 🔄 Collision Handling
// ==========================
void generate_unique_cert_filename(const char *username, char *out_filename);

// ==========================
// 🧑‍💻 VPN User Management
// ==========================
void create_vpn_user_with_cert(const char *username, const char *password);

// ==========================
// 🧪 Test Utilities
// ==========================
int file_exists(const char *filename);

#endif /* VPN_COMMON_H */
