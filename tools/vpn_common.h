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
#define MAX_HASH_LEN 8 // For hash-based filenames

// ==========================
// 🛡️ Error Handling
// ==========================
/**
 * Print OpenSSL error messages and terminate the program.
 */
void handle_errors(void);

// ==========================
// 🔑 RSA Key Management
// ==========================
/**
 * Generate an RSA keypair.
 * @return Pointer to EVP_PKEY containing the RSA keypair.
 */
EVP_PKEY *generate_rsa_keypair(void);

/**
 * Save the RSA private key to a file.
 * @param pkey Pointer to the EVP_PKEY containing the keypair.
 * @param filename File path to save the private key.
 */
void save_private_key(EVP_PKEY *pkey, const char *filename);

/**
 * Save an encrypted X.509 certificate.
 * @param cert Pointer to the X.509 certificate.
 * @param filename File path to save the certificate.
 * @param key Encryption key for securing the certificate.
 */
void save_encrypted_certificate(X509 *cert, const char *filename, const unsigned char *key);

// ==========================
// 🔐 Password Handling
// ==========================
/**
 * Hash a password using SHA-256.
 * @param password Plaintext password.
 * @param output_hash Buffer to store the resulting hash.
 */
void hash_password(const char *password, unsigned char *output_hash);

// ==========================
// 🔒 Encryption/Decryption
// ==========================
/**
 * Encrypt plaintext using AES-256-CBC.
 * @param plaintext Pointer to plaintext.
 * @param plaintext_len Length of plaintext.
 * @param key AES encryption key.
 * @param iv AES initialization vector.
 * @param ciphertext Buffer to store the encrypted data.
 * @return Length of ciphertext or -1 on failure.
 */
int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext);

/**
 * Decrypt ciphertext using AES-256-CBC.
 * @param ciphertext Pointer to ciphertext.
 * @param ciphertext_len Length of ciphertext.
 * @param key AES decryption key.
 * @param iv AES initialization vector.
 * @param plaintext Buffer to store the decrypted data.
 * @return Length of plaintext or -1 on failure.
 */
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext);

// ==========================
// 📜 Certificate Management
// ==========================
/**
 * Generate an X.509 certificate.
 * @param pkey Pointer to the RSA keypair.
 * @param username Common name (CN) to include in the certificate.
 * @return Pointer to X.509 certificate.
 */
X509 *generate_certificate(EVP_PKEY *pkey, const char *username);

/**
 * Save an encrypted certificate file.
 * @param cert Pointer to X.509 certificate.
 * @param filename File path to save the certificate.
 * @param key AES encryption key for certificate.
 */
void save_encrypted_certificate(X509 *cert, const char *filename, const unsigned char *key);

// ==========================
// 🔄 Collision Handling
// ==========================
/**
 * Check if the user has write permission to a directory.
 * @param dir Directory path.
 * @return 0 if writable, -1 otherwise.
 */
int check_write_permission(const char *dir);

/**
 * Generate a hash-based certificate filename.
 * @param cert_data Certificate data for hashing.
 * @param out_filename Buffer to store the generated filename.
 * @param index Index to avoid collisions.
 * @param is_crl Flag indicating if the file is a CRL (Certificate Revocation List).
 */
void generate_cert_filename(const char *cert_data, char *out_filename, int index, int is_crl);

/**
 * Remove old hash-based symbolic links or files.
 * @param dir Directory containing the certificates.
 */
void remove_old_links(const char *dir);

/**
 * Compute SHA-256 hash of data using FIPS-compliant EVP interface.
 * @param data Input data.
 * @param hash Output buffer for the SHA-256 hash.
 */
void compute_sha256(const char *data, unsigned char *hash);

/**
 * Check for duplicate certificates based on SHA-256 hash comparison.
 * @param cert_path Path to the certificate file.
 * @param cert_data Certificate data for hashing.
 * @return 1 if duplicate, 0 otherwise.
 */
int is_duplicate_certificate(const char *cert_path, const char *cert_data);

/**
 * Generate a unique certificate file while avoiding collisions.
 * @param cert_data Certificate data for hashing.
 * @param is_crl Flag indicating if the file is a CRL.
 */
void generate_unique_cert_file(const char *cert_data, int is_crl, char *out_filename);


// ==========================
// 🧑‍💻 VPN User Management
// ==========================
/**
 * Create a VPN user with an encrypted certificate.
 * @param username VPN username.
 * @param password VPN password.
 */
void create_vpn_user_with_cert(const char *username, const char *password);

// ==========================
// 🧪 Test Utilities
// ==========================
/**
 * Check if a file exists on the filesystem.
 * @param filename File path to check.
 * @return 1 if file exists, 0 otherwise.
 */
int file_exists(const char *filename);

// ==========================
// 🛡️ Helper Functions
// ==========================

// Write user data to vpn_users.txt securely
void log_vpn_user(const char *username, const char *hashed_password_hex, const char *cert_filename);

#endif /* VPN_COMMON_H */
