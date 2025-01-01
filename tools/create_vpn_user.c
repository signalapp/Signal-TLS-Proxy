#include "vpn_common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <unistd.h>


// ==========================
// 🎯 Main Program Entry
// ==========================
int main(int argc, char *argv[]) {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];

    // Check if username and password are provided as command-line arguments
    if (argc == 3) {
        // Command-line mode
        strncpy(username, argv[1], MAX_USERNAME_LENGTH - 1);
        strncpy(password, argv[2], MAX_PASSWORD_LENGTH - 1);
        username[MAX_USERNAME_LENGTH - 1] = '\0';
        password[MAX_PASSWORD_LENGTH - 1] = '\0';

        printf("🔄 Using CLI-provided username and password.\n");
    } else {
        // Interactive mode
        printf("🔒 Enter VPN username: ");
        if (!fgets(username, MAX_USERNAME_LENGTH, stdin)) {
            fprintf(stderr, "❌ Failed to read username.\n");
            exit(EXIT_FAILURE);
        }
        username[strcspn(username, "\n")] = 0; // Remove trailing newline

        printf("🔑 Enter VPN password: ");
        if (!fgets(password, MAX_PASSWORD_LENGTH, stdin)) {
            fprintf(stderr, "❌ Failed to read password.\n");
            exit(EXIT_FAILURE);
        }
        password[strcspn(password, "\n")] = 0; // Remove trailing newline
    }

    // Input Validation
    if (strlen(username) == 0 || strlen(password) == 0) {
        fprintf(stderr, "❌ Username and password cannot be empty.\n");
        exit(EXIT_FAILURE);
    }

    // Validate write permission for certificate directory
    const char *cert_dir = "certs";
    mkdir(cert_dir, 0755); // Ensure certs directory exists
    if (check_write_permission(cert_dir) != 0) {
        fprintf(stderr, "❌ No write permissions for '%s'.\n", cert_dir);
        exit(EXIT_FAILURE);
    }

    // Create VPN User
    create_vpn_user_with_cert(username, password);

    return 0;
}