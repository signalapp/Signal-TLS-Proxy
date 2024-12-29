#include "vpn_common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Create VPN User
void create_vpn_user(const char *username, const char *password) {
    RSA *rsa = generate_rsa_keypair();
    save_private_key(rsa, "vpn_user_private.pem");

    unsigned char hashed_password[SHA256_DIGEST_LENGTH];
    hash_password(password, hashed_password);

    unsigned char encrypted_password[ENCRYPTED_PASSWORD_LENGTH];
    int encrypted_len = rsa_encrypt(rsa, hashed_password, SHA256_DIGEST_LENGTH, encrypted_password);
    if (encrypted_len == -1) handle_errors();

    FILE *fp = fopen("vpn_users.txt", "a");
    if (!fp) {
        perror("Failed to open VPN user file");
        exit(EXIT_FAILURE);
    }
    fprintf(fp, "Username: %s\n", username);
    fprintf(fp, "Encrypted Password: ");
    for (int i = 0; i < encrypted_len; i++) {
        fprintf(fp, "%02x", encrypted_password[i]);
    }
    fprintf(fp, "\n\n");
    fclose(fp);

    RSA_free(rsa);
    printf("✅ VPN user '%s' created successfully.\n", username);
}

int main() {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];

    printf("Enter VPN username: ");
    fgets(username, MAX_USERNAME_LENGTH, stdin);
    username[strcspn(username, "\n")] = 0;

    printf("Enter VPN password: ");
    fgets(password, MAX_PASSWORD_LENGTH, stdin);
    password[strcspn(password, "\n")] = 0;

    create_vpn_user(username, password);
    return 0;
}

