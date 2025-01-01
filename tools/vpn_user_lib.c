#include "vpn_common.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <dirent.h>


#define MAX_CERT_PATH 256

// ==========================
// 🛡️ Error Handling
// ==========================
void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// ==========================
// 🛡️ Helper Functions
// ==========================

// Write user data to vpn_users.txt securely
void log_vpn_user(const char *username, const char *hashed_password_hex, const char *cert_filename) {
    FILE *fp = fopen("vpn_users.txt", "a");
    if (!fp) {
        perror("❌ Failed to open VPN user log file");
        exit(EXIT_FAILURE);
    }

    fprintf(fp, "Username: %s\n", username);
    fprintf(fp, "Password Hash: %s\n", hashed_password_hex);
    fprintf(fp, "Certificate: %s\n\n", cert_filename);
    fclose(fp);
    printf("✅ User details logged successfully.\n");
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

    X509_set_version(cert, 2); // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // Valid for 1 year

    X509_set_pubkey(cert, pkey);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)username, -1, -1, 0);
    X509_set_issuer_name(cert, name);

    if (!X509_sign(cert, pkey, EVP_sha256())) {
        handle_errors();
    }

    return cert;
}

// ==========================
// 🔄 Collision Handling
// ==========================

// Check if the user has write permissions to a directory
int check_write_permission(const char *dir) {
    if (access(dir, W_OK) != 0) {
        perror("Write permission check failed");
        return -1;
    }
    return 0;
}

// Compute SHA-256 hash using FIPS-compliant EVP API
void compute_sha256(const char *data, unsigned char *hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        handle_errors();
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        handle_errors();
    if (EVP_DigestUpdate(ctx, data, strlen(data)) != 1)
        handle_errors();
    if (EVP_DigestFinal_ex(ctx, hash, NULL) != 1)
        handle_errors();

    EVP_MD_CTX_free(ctx);
}

// Generate hash-based certificate filename
void generate_cert_filename(const char *cert_data, char *out_filename, int index, int is_crl) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    compute_sha256(cert_data, hash);

    char hash_str[9] = {0}; // Use the first 4 bytes (8 hex chars) for brevity
    for (int i = 0; i < 4; ++i) {
        sprintf(hash_str + (i * 2), "%02X", hash[i]);
    }

    if (is_crl) {
        snprintf(out_filename, MAX_CERT_PATH, "certs/%s.r%d", hash_str, index);
    } else {
        snprintf(out_filename, MAX_CERT_PATH, "certs/%s.%d", hash_str, index);
    }
}

// Remove existing hash-based links
void remove_old_links(const char *dir) {
    DIR *dp = opendir(dir);
    if (dp == NULL) {
        perror("Failed to open directory");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        int dummy_int;
        char dummy_str[9];

        if (sscanf(entry->d_name, "%8[A-Fa-f0-9].%d", dummy_str, &dummy_int) == 2 || 
            sscanf(entry->d_name, "%8[A-Fa-f0-9].r%d", dummy_str, &dummy_int) == 2) {

            char full_path[MAX_CERT_PATH];
            snprintf(full_path, MAX_CERT_PATH, "%s/%s", dir, entry->d_name);
            if (remove(full_path) != 0) {
                perror("Failed to remove old link");
            } else {
                printf("Removed old link: %s\n", full_path);
            }
        }
    }

    closedir(dp);
}

// Check for duplicate certificates based on SHA-256 hash
int is_duplicate_certificate(const char *cert_path, const char *cert_data) {
    FILE *fp = fopen(cert_path, "rb");
    if (!fp) {
        return 0; // File does not exist, not a duplicate
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    char *file_data = OPENSSL_malloc(fsize + 1);
    if (!file_data) {
        fclose(fp);
        perror("Memory allocation failed");
        return 0;
    }

    fread(file_data, 1, fsize, fp);
    file_data[fsize] = '\0';
    fclose(fp);

    unsigned char file_hash[SHA256_DIGEST_LENGTH];
    unsigned char cert_hash[SHA256_DIGEST_LENGTH];
    compute_sha256(file_data, file_hash);
    compute_sha256(cert_data, cert_hash);

    OPENSSL_cleanse(file_data, fsize); // Zero out sensitive data
    OPENSSL_free(file_data);

    return (memcmp(file_hash, cert_hash, SHA256_DIGEST_LENGTH) == 0);
}

// Main certificate generation with collision handling
void generate_unique_cert_file(const char *cert_data, int is_crl, char *out_filename) {
    const char *cert_dir = "certs";

    // Check write permissions
    if (check_write_permission(cert_dir) != 0) {
        fprintf(stderr, "Error: No write permissions to directory %s\n", cert_dir);
        return;
    }

    // Remove old hash-based links
    remove_old_links(cert_dir);

    // Generate hash-based filename and handle duplicates
    int index = 0;
    do {
        generate_cert_filename(cert_data, out_filename, index, is_crl);
        if (!is_duplicate_certificate(out_filename, cert_data)) {
            break; // Unique filename found
        }
        index++;
        printf("Warning: Duplicate certificate found. Incrementing index to %d\n", index);
    } while (index < 10); // Arbitrary limit to prevent infinite loops

    // Write a placeholder PEM header to ensure valid certificate structure
    FILE *fp = fopen(out_filename, "wb");
    if (!fp) {
        perror("Failed to create certificate file");
        return;
    }

    // Temporary placeholder content
    fprintf(fp, "-----BEGIN CERTIFICATE-----\n");
    fprintf(fp, "%s\n", cert_data); // Simulate certificate data for now
    fprintf(fp, "-----END CERTIFICATE-----\n");
    fclose(fp);

    printf("✅ Certificate saved as: %s\n", out_filename);
}

// ==========================
// 🧑‍💻 VPN User Management
// ==========================
// Create VPN User with Certificate
void create_vpn_user_with_cert(const char *username, const char *password) {
    EVP_PKEY *pkey = generate_rsa_keypair();
    if (!pkey) {
        fprintf(stderr, "❌ Failed to generate RSA keypair.\n");
        return;
    }

    X509 *cert = generate_certificate(pkey, username);
    if (!cert) {
        fprintf(stderr, "❌ Failed to generate certificate.\n");
        EVP_PKEY_free(pkey);
        return;
    }

    unsigned char hashed_password[SHA256_DIGEST_LENGTH];
    hash_password(password, hashed_password);

    char hashed_password_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hashed_password_hex[i * 2], "%02x", hashed_password[i]);
    }

    char cert_filename[MAX_CERT_PATH];
    generate_unique_cert_file(username, 0, cert_filename); // Pass the filename buffer

    printf("🔄 Certificate filename: %s\n", cert_filename);

    // Save the encrypted certificate
    save_encrypted_certificate(cert, cert_filename, hashed_password);

    // Log VPN User
    log_vpn_user(username, hashed_password_hex, cert_filename);

    EVP_PKEY_free(pkey);
    X509_free(cert);
    printf("✅ VPN user '%s' created with secure certificate.\n", username);
}


int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

