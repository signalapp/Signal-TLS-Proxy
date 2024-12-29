#include "vpn_common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Error Handling
void handle_errors() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Generate RSA Keypair
RSA *generate_rsa_keypair() {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    if (!BN_set_word(bn, RSA_F4)) handle_errors();
    if (!RSA_generate_key_ex(rsa, RSA_KEY_LENGTH, bn, NULL)) handle_errors();
    BN_free(bn);
    return rsa;
}

// Save RSA Private Key
void save_private_key(RSA *rsa, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Failed to open private key file");
        exit(EXIT_FAILURE);
    }
    PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
}

// Hash Password with SHA-256
void hash_password(const char *password, unsigned char *output_hash) {
    SHA256((const unsigned char *)password, strlen(password), output_hash);
}

// Encrypt Data with RSA Public Key
int rsa_encrypt(RSA *rsa, unsigned char *input, int input_len, unsigned char *output) {
    return RSA_public_encrypt(input_len, input, output, rsa, RSA_PKCS1_OAEP_PADDING);
}

// Decrypt Data with RSA Private Key
int rsa_decrypt(RSA *rsa, unsigned char *input, int input_len, unsigned char *output) {
    return RSA_private_decrypt(input_len, input, output, rsa, RSA_PKCS1_OAEP_PADDING);
}

