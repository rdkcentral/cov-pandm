/**
 * Test file: Deliberate defects for Coverity branch protection testing.
 * Severity: MEDIUM (security-severity 4.0-6.9)
 *
 * Defect 5: NULL_RETURNS - Dereference of null pointer returned by function
 * Defect 6: RESOURCE_LEAK - File handle leaked on error path
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Defect 5: NULL_RETURNS (FORWARD_NULL)
 * CWE-476: NULL Pointer Dereference
 * Return value of malloc not checked before use.
 */
char *duplicate_config(const char *config_path)
{
    FILE *fp = fopen(config_path, "r");
    if (!fp)
        return NULL;

    /* COVERITY[NULL_RETURNS] - malloc may return NULL */
    char *buf = (char *)malloc(4096);
    size_t n = fread(buf, 1, 4096, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

/* Defect 6: RESOURCE_LEAK
 * CWE-404: Improper Resource Shutdown or Release
 * File descriptor leaked when early return occurs.
 */
int validate_firmware(const char *path, const char *expected_hash)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    char header[16];
    if (fread(header, 1, 16, fp) != 16) {
        /* COVERITY[RESOURCE_LEAK] - fp not closed on this path */
        return -2;
    }

    if (memcmp(header, "FWIMG", 5) != 0) {
        /* COVERITY[RESOURCE_LEAK] - fp not closed on this path */
        return -3;
    }

    fclose(fp);
    return 0;
}
