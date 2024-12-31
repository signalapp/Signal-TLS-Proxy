#include "vpn_common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Create VPN User with Encrypted Certificate
void create_vpn_user(const char *username, const char *password) {
    printf("🔑 Generating VPN user with certificate for '%s'...\n", username);

    // Step 1: Generate and Encrypt Certificate
    create_vpn_user_with_cert(username, password);

    // Step 2: Hash Password
    unsigned char hashed_password[SHA256_DIGEST_LENGTH];
    hash_password(password, hashed_password);

    char hashed_password_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hashed_password_hex[i * 2], "%02x", hashed_password[i]);
    }

    // Step 3: Log User Information
    FILE *fp = fopen("vpn_users.txt", "a");
    if (!fp) {
        perror("Failed to open VPN user log file");
        exit(EXIT_FAILURE);
    }

    fprintf(fp, "Username: %s\n", username);
    fprintf(fp, "Password Hash: %s\n", hashed_password_hex);
    fprintf(fp, "Certificate: certs/%s_cert.pem\n\n", username);
    fclose(fp);

    printf("✅ VPN user '%s' created successfully with certificate and password hash.\n", username);
}

// Main Program Entry
int main() {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];

    printf("🔒 Enter VPN username: ");
    if (!fgets(username, MAX_USERNAME_LENGTH, stdin)) {
        fprintf(stderr, "❌ Failed to read username.\n");
        exit(EXIT_FAILURE);
    }
    username[strcspn(username, "\n")] = 0;

    printf("🔑 Enter VPN password: ");
    if (!fgets(password, MAX_PASSWORD_LENGTH, stdin)) {
        fprintf(stderr, "❌ Failed to read password.\n");
        exit(EXIT_FAILURE);
    }
    password[strcspn(password, "\n")] = 0;

    if (strlen(username) == 0 || strlen(password) == 0) {
        fprintf(stderr, "❌ Username and password cannot be empty.\n");
        exit(EXIT_FAILURE);
    }

    create_vpn_user(username, password);
    return 0;
}
