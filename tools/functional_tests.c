#include "vpn_common.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Test: VPN User Workflow
void test_vpn_user_workflow() {
    printf("🛠️ Testing VPN user creation workflow...\n");

    system("./create_vpn_user <<EOF\n"
           "test_user\n"
           "test_password\n"
           "EOF");

    // Check vpn_users.txt
    FILE *fp = fopen("vpn_users.txt", "r");
    assert(fp != NULL && "❌ Failed to open vpn_users.txt!");

    char buffer[256];
    int found = 0;
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "Username: test_user")) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    assert(found == 1 && "❌ Username entry not found in vpn_users.txt!");

    // Check certificate file
    assert(file_exists("certs/test_user_cert.pem") && "❌ Certificate file missing!");

    printf("✅ VPN user workflow test passed.\n");
}

// Main Functional Test Suite
int main() {
    printf("\n🔍 Starting Functional Tests...\n");
    test_vpn_user_workflow();
    printf("\n🎯 All Functional Tests Passed Successfully!\n");
    return 0;
}
