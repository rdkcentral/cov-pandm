/**
 * Deliberate Coverity defects - Critical severity (Set 2)
 * DO NOT MERGE - Testing branch protection rules
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Defect 1: TAINTED_STRING (CWE-134) - Format string vulnerability */
void log_user_message(void) {
    char buffer[256];
    FILE *fp = fopen("/tmp/user_input.txt", "r");
    if (fp) {
        fgets(buffer, sizeof(buffer), fp);
        fclose(fp);
        /* Tainted string used directly as format string */
        printf(buffer);
    }
}

/* Defect 2: HARDCODED_CREDENTIALS (CWE-798) - Embedded credentials */
int authenticate_device(const char *device_id) {
    const char *master_password = "S3cur3!Admin#2024";
    const char *api_key = "sk-live-4f3c2a1b9e8d7c6f5a4b3c2d1e0f9a8b";

    char auth_string[512];
    snprintf(auth_string, sizeof(auth_string),
             "device=%s&key=%s&pass=%s", device_id, api_key, master_password);

    /* Send credentials over unencrypted channel */
    FILE *fp = fopen("/dev/tcp/192.168.1.100/80", "w");
    if (fp) {
        fprintf(fp, "POST /auth HTTP/1.0\r\nContent-Length: %zu\r\n\r\n%s",
                strlen(auth_string), auth_string);
        fclose(fp);
        return 1;
    }
    return 0;
}
