#include "vpn_common.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

void test_vpn_user_workflow() {
    printf("🛠️ Testing VPN user creation workflow...\n");

    // Create VPN User
    system("./create_vpn_user <<EOF\n"
           "test_user\n"
           "test_password\n"
           "EOF");

    FILE *fp = fopen("vpn_users.txt", "r");
    assert(fp != NULL);

    char buffer[256];
    int found = 0;
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "Username: test_user")) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    assert(found == 1);

    printf("✅ Functional test passed: User workflow completed successfully.\n");
}

int main() {
    test_vpn_user_workflow();
    return 0;
}

