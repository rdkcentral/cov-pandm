/**
 * Deliberate Coverity defects for branch protection validation (PR 3)
 * DO NOT MERGE - Testing only
 *
 * Defects:
 *   Critical: OS_CMD_INJECTION (CWE-78), TAINTED_STRING (CWE-134)
 *   High:     BUFFER_SIZE (CWE-120), USE_AFTER_FREE (CWE-416)
 *   Medium:   NULL_RETURNS (CWE-476), RESOURCE_LEAK (CWE-404)
 *   Low:      SIZEOF_MISMATCH (CWE-467), MISSING_BREAK (CWE-484)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Critical: OS_CMD_INJECTION (CWE-78) */
int cosa_test_execute_diagnostic(const char *user_host)
{
    char cmd[256];
    /* Tainted user input directly interpolated into shell command */
    snprintf(cmd, sizeof(cmd), "ping -c 3 %s", user_host);
    return system(cmd);
}

/* Critical: TAINTED_STRING (CWE-134) - Format string vulnerability */
void cosa_test_log_event(const char *user_message)
{
    char logbuf[512];
    FILE *fp = fopen("/tmp/pandm_event.log", "a");
    if (fp) {
        /* User-controlled string used as format string */
        fprintf(fp, user_message);
        fclose(fp);
    }
}

/* High: BUFFER_SIZE (CWE-120) - Stack buffer overflow */
void cosa_test_parse_wan_config(const char *config_value)
{
    char local_buf[64];
    /* No bounds check - config_value could exceed 64 bytes */
    strcpy(local_buf, config_value);
    printf("WAN config: %s\n", local_buf);
}

/* High: USE_AFTER_FREE (CWE-416) */
typedef struct _COSA_TEST_CONTEXT {
    char name[128];
    int  refcount;
    void *data;
} COSA_TEST_CONTEXT;

void cosa_test_cleanup_context(COSA_TEST_CONTEXT *pCtx)
{
    if (pCtx) {
        free(pCtx->data);
        free(pCtx);
    }
    /* Use after free - accessing pCtx after it was freed */
    if (pCtx && pCtx->refcount > 0) {
        printf("Context %s still has references\n", pCtx->name);
    }
}

/* Medium: NULL_RETURNS (CWE-476) - Unchecked malloc */
char *cosa_test_duplicate_ssid(const char *ssid, size_t len)
{
    char *copy = (char *)malloc(len + 1);
    /* No NULL check on malloc return */
    memcpy(copy, ssid, len);
    copy[len] = '\0';
    return copy;
}

/* Medium: RESOURCE_LEAK (CWE-404) - FILE handle leak on error path */
int cosa_test_read_proc_entry(const char *path, char *buf, size_t bufsz)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;

    if (bufsz == 0) {
        /* fp is leaked here - early return without fclose */
        return -2;
    }

    if (fgets(buf, (int)bufsz, fp) == NULL) {
        /* fp is leaked here too */
        return -3;
    }

    fclose(fp);
    return 0;
}

/* Low: SIZEOF_MISMATCH (CWE-467) - sizeof pointer vs sizeof buffer */
void cosa_test_clear_mac(unsigned char *mac_addr)
{
    unsigned char *ptr = mac_addr;
    /* sizeof(ptr) is 8 bytes (pointer), not 6 (MAC address) */
    memset(ptr, 0, sizeof(ptr));
}

/* Low: MISSING_BREAK (CWE-484) - Fall-through in switch */
const char *cosa_test_wan_state_str(int state)
{
    const char *result = "unknown";
    switch (state) {
        case 0:
            result = "disconnected";
            /* Missing break - falls through */
        case 1:
            result = "connecting";
            break;
        case 2:
            result = "connected";
            break;
        case 3:
            result = "error";
            break;
    }
    return result;
}
