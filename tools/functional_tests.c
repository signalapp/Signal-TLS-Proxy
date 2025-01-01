#include "vpn_common.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

// ==========================
// 🛠️ VPN User Workflow Test
// ==========================
// Test: VPN User Workflow
void test_vpn_user_workflow() {
    printf("🛠️ Testing VPN user creation workflow...\n");

    // Create VPN User
    int ret = system("./create_vpn_user <<EOF\n"
                     "test_user\n"
                     "test_password\n"
                     "EOF");
    assert(ret == 0 && "❌ VPN user creation script failed!");

    // Check if vpn_users.txt contains the new user
    FILE *fp = fopen("vpn_users.txt", "r");
    if (!fp) {
        perror("Failed to open vpn_users.txt");
        assert(0 && "❌ Failed to open vpn_users.txt!");
    }

    char buffer[512];
    int user_found = 0;
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "Username: test_user")) {
            user_found = 1;
            break;
        }
    }
    fclose(fp);

    if (!user_found) {
        printf("❌ Username 'test_user' not found in vpn_users.txt!\n");
        system("cat vpn_users.txt"); // Print the file for debugging
    }

    assert(user_found && "❌ Username entry not found in vpn_users.txt!");

    // Validate certificate file exists
    const char *cert_path = "certs/11601308.0";
    if (!file_exists(cert_path)) {
        printf("❌ Certificate file missing: %s\n", cert_path);
        assert(0 && "❌ Certificate file missing!");
    }

    printf("✅ VPN user workflow test passed.\n");
}



// ==========================
// 🛡️ Directory Write Permission Test
// ==========================
void test_directory_write_permission() {
    printf("🛡️ Testing directory write permission...\n");

    const char *cert_dir = "certs";

    // Ensure directory exists
    mkdir(cert_dir, 0755);

    // Check write permission
    assert(check_write_permission(cert_dir) == 0 && "❌ Write permission check failed for certs directory!");

    printf("✅ Directory write permission test passed.\n");
}

// ==========================
// 🔄 Certificate Collision Handling Test
// ==========================
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


// ==========================
// 🔑 SHA-256 Certificate Hash Verification Test
// ==========================
void test_certificate_hash_verification() {
    printf("🔑 Testing SHA-256 certificate hash verification...\n");

    const char *cert_data = "Certificate Data for Hash Test";
    char cert_path[MAX_CERT_PATH];
    snprintf(cert_path, MAX_CERT_PATH, "certs/hash_test_cert.pem");

    FILE *fp = fopen(cert_path, "w");
    assert(fp != NULL && "❌ Failed to create certificate file!");
    fputs(cert_data, fp);
    fclose(fp);

    // Verify hash
    assert(is_duplicate_certificate(cert_path, cert_data) && "❌ Certificate hash mismatch detected!");

    printf("✅ SHA-256 certificate hash verification test passed.\n");

    // Cleanup
    remove(cert_path);
}

// ==========================
// 🎯 Main Functional Test Suite
// ==========================
int main() {
    printf("\n🔍 Starting Functional Tests...\n");

    // Run tests
    test_vpn_user_workflow();
    test_directory_write_permission();
    test_certificate_collision_handling();
    test_certificate_hash_verification();

    printf("\n🎯 All Functional Tests Passed Successfully!\n");
    return 0;
}
