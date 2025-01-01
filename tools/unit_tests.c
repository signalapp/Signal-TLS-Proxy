#include "vpn_common.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// Test: Password Hashing
void test_password_hashing() {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    hash_password("test_password", hash1);
    hash_password("test_password", hash2);

    assert(memcmp(hash1, hash2, SHA256_DIGEST_LENGTH) == 0 && "❌ Password hashes do not match!");
    printf("✅ Password hashing test passed.\n");
}

// Test: AES Encryption/Decryption
void test_aes_encryption_decryption() {
    unsigned char key[32] = "01234567890123456789012345678901";
    unsigned char iv[16] = "1234567890123456";
    unsigned char plaintext[] = "This is a test message.";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];

    int ciphertext_len = aes_encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);
    assert(ciphertext_len > 0 && "❌ AES encryption failed!");

    int decrypted_len = aes_decrypt(ciphertext, ciphertext_len, key, iv, decrypted);
    assert(decrypted_len > 0 && "❌ AES decryption failed!");

    decrypted[decrypted_len] = '\0';
    assert(strcmp((char *)plaintext, (char *)decrypted) == 0 && "❌ AES decryption did not return original plaintext!");
    printf("✅ AES encryption/decryption test passed.\n");
}

// Test: Certificate Generation
void test_certificate_generation() {
    EVP_PKEY *pkey = generate_rsa_keypair();
    assert(pkey != NULL && "❌ RSA keypair generation failed!");

    X509 *cert = generate_certificate(pkey, "test_user");
    assert(cert != NULL && "❌ Certificate generation failed!");

    char filename[MAX_CERT_PATH] = "certs/test_user_cert.pem";
    unsigned char test_password[] = "test_password";
    save_encrypted_certificate(cert, filename, test_password);

    assert(file_exists(filename) && "❌ Certificate file not created!");
    printf("✅ Certificate generation test passed.\n");

    EVP_PKEY_free(pkey);
    X509_free(cert);
    remove(filename);
}

// Test: SHA-256 Hash Collision Detection (FIPS-Compliant)
void test_sha256_collision_detection() {
    const char *data1 = "Test Certificate Data 1";
    const char *data2 = "Test Certificate Data 2";

    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];

    // Use FIPS-compliant EVP API for hashing
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    assert(ctx != NULL && "❌ Failed to create EVP_MD_CTX for SHA-256");

    // Hash data1
    assert(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 && "❌ SHA-256 DigestInit failed");
    assert(EVP_DigestUpdate(ctx, data1, strlen(data1)) == 1 && "❌ SHA-256 DigestUpdate failed");
    assert(EVP_DigestFinal_ex(ctx, hash1, NULL) == 1 && "❌ SHA-256 DigestFinal failed");

    // Hash data2
    assert(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 && "❌ SHA-256 DigestInit failed");
    assert(EVP_DigestUpdate(ctx, data2, strlen(data2)) == 1 && "❌ SHA-256 DigestUpdate failed");
    assert(EVP_DigestFinal_ex(ctx, hash2, NULL) == 1 && "❌ SHA-256 DigestFinal failed");

    EVP_MD_CTX_free(ctx);

    assert(memcmp(hash1, hash2, SHA256_DIGEST_LENGTH) != 0 && "❌ SHA-256 collision detected with different data!");
    printf("✅ SHA-256 collision detection test passed.\n");
}

// Test: Directory Write Permission
void test_directory_write_permission() {
    const char *cert_dir = "certs";

    // Ensure the certs directory exists
    mkdir(cert_dir, 0755);

    // Check write permission
    assert(check_write_permission(cert_dir) == 0 && "❌ Write permission check failed for certs directory!");

    printf("✅ Directory write permission test passed.\n");
}

// Test: Certificate Collision Handling
void test_certificate_collision_handling() {
    printf("🔄 Testing certificate collision handling...\n");

    const char *cert_data1 = "Test Certificate Data 1";
    const char *cert_data2 = "Test Certificate Data 2";

    char filename1[MAX_CERT_PATH];
    char filename2[MAX_CERT_PATH];

    // Generate first certificate
    generate_unique_cert_file(cert_data1, 0, filename1); // Pass buffer for filename
    FILE *fp1 = fopen(filename1, "w");
    assert(fp1 != NULL && "❌ Failed to create first certificate file!");
    fputs(cert_data1, fp1);
    fclose(fp1);

    // Generate second certificate with different data but same hash index
    generate_unique_cert_file(cert_data2, 0, filename2); // Pass buffer for filename
    FILE *fp2 = fopen(filename2, "w");
    assert(fp2 != NULL && "❌ Failed to create second certificate file!");
    fputs(cert_data2, fp2);
    fclose(fp2);

    // Validate filenames are unique
    assert(strcmp(filename1, filename2) != 0 && "❌ Collision handling failed; filenames are not unique!");
    printf("✅ Certificate collision handling test passed.\n");

    // Cleanup
    remove(filename1);
    remove(filename2);
}


// Main Unit Test Suite
int main() {
    printf("\n🔍 Starting Unit Tests...\n");

    test_password_hashing();
    test_aes_encryption_decryption();
    test_certificate_generation();
    test_sha256_collision_detection();
    test_directory_write_permission();
    test_certificate_collision_handling();

    printf("\n🎯 All Unit Tests Passed Successfully!\n");
    return 0;
}
