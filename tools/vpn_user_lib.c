#include "vpn_common.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

// ==========================
// 🛡️ Error Handling
// ==========================
void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// ==========================
// 🔑 RSA Key Management
// ==========================
EVP_PKEY *generate_rsa_keypair(void) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!ctx) handle_errors();

    if (EVP_PKEY_keygen_init(ctx) <= 0) handle_errors();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_LENGTH) <= 0) handle_errors();
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handle_errors();

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void save_private_key(EVP_PKEY *pkey, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Failed to open private key file");
        exit(EXIT_FAILURE);
    }

    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        handle_errors();
    }

    fclose(fp);
}

void save_encrypted_certificate(X509 *cert, const char *filename, const unsigned char *key) {
    (void)key; // Explicitly mark 'key' as unused to silence the compiler

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Failed to open certificate file");
        exit(EXIT_FAILURE);
    }

    if (!PEM_write_X509(fp, cert)) {
        handle_errors();
    }

    fclose(fp);
}



// ==========================
// 🔐 Password Handling
// ==========================
void hash_password(const char *password, unsigned char *output_hash) {
    SHA256((const unsigned char *)password, strlen(password), output_hash);
}

// ==========================
// 🔒 AES Encryption/Decryption
// ==========================
int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    int len;
    int ciphertext_len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handle_errors();

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        handle_errors();
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        handle_errors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    int len;
    int plaintext_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handle_errors();

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        handle_errors();
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        handle_errors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}


// ==========================
// 📜 Certificate Management
// ==========================
X509 *generate_certificate(EVP_PKEY *pkey, const char *username) {
    X509 *cert = X509_new();
    if (!cert) handle_errors();

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)username, -1, -1, 0);

    X509_set_issuer_name(cert, name);
    X509_set_pubkey(cert, pkey);

    if (!X509_sign(cert, pkey, EVP_sha256()))
        handle_errors();

    return cert;
}
// ==========================
// 🔄 Collision Handling
// ==========================
void generate_unique_cert_filename(const char *username, char *out_filename) {
    snprintf(out_filename, MAX_CERT_PATH, "certs/%s_cert.pem", username);
}

// ==========================
// 🧑‍💻 VPN User Management
// ==========================
void create_vpn_user_with_cert(const char *username, const char *password) {
    EVP_PKEY *pkey = generate_rsa_keypair();
    X509 *cert = generate_certificate(pkey, username);

    unsigned char hashed_password[SHA256_DIGEST_LENGTH];
    hash_password(password, hashed_password);

    char cert_filename[MAX_CERT_PATH];
    generate_unique_cert_filename(username, cert_filename);

    save_encrypted_certificate(cert, cert_filename, hashed_password);

    EVP_PKEY_free(pkey);
    X509_free(cert);
    printf("✅ VPN user '%s' created with secure certificate.\n", username);
}

int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

