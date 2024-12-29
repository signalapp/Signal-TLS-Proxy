#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include "vpn_common.h"

void hash_password(const char *password, unsigned char *output_hash);
int rsa_encrypt(RSA *rsa, unsigned char *input, int input_len, unsigned char *output);
int rsa_decrypt(RSA *rsa, unsigned char *input, int input_len, unsigned char *output);

// Test: Password Hashing
void test_password_hashing() {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    hash_password("test_password", hash1);
    hash_password("test_password", hash2);
    assert(memcmp(hash1, hash2, SHA256_DIGEST_LENGTH) == 0);
    printf("✅ Password hashing test passed\n");
}

// Test: RSA Encryption/Decryption
void test_rsa_encryption_decryption() {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, NULL);

    unsigned char plaintext[] = "test";
    unsigned char encrypted[ENCRYPTED_PASSWORD_LENGTH];
    unsigned char decrypted[ENCRYPTED_PASSWORD_LENGTH];

    int enc_len = rsa_encrypt(rsa, plaintext, strlen((char *)plaintext), encrypted);
    int dec_len = rsa_decrypt(rsa, encrypted, enc_len, decrypted);

    decrypted[dec_len] = '\0';
    assert(strcmp((char *)plaintext, (char *)decrypted) == 0);

    RSA_free(rsa);
    BN_free(bn);

    printf("✅ RSA encryption/decryption test passed\n");
}

int main() {
    test_password_hashing();
    test_rsa_encryption_decryption();
    printf("All unit tests passed successfully!\n");
    return 0;
}

