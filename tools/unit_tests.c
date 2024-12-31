#include "vpn_common.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

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

// Main Unit Test Suite
int main() {
    printf("\n🔍 Starting Unit Tests...\n");

    test_password_hashing();
    test_aes_encryption_decryption();
    test_certificate_generation();

    printf("\n🎯 All Unit Tests Passed Successfully!\n");
    return 0;
}
