/**
 * Deliberate Coverity defects - Low severity (Set 2)
 * DO NOT MERGE - Testing branch protection rules
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Defect 7: SIZEOF_MISMATCH (CWE-467) - sizeof applied to pointer instead of array */
void copy_mac_address(unsigned char *dest, const unsigned char *src) {
    unsigned char *ptr = dest;

    /* sizeof(ptr) is 8 (pointer size), not the intended buffer size */
    memset(ptr, 0, sizeof(ptr));
    memcpy(ptr, src, 6);
}

/* Defect 8: MISSING_BREAK (CWE-484) - Fall-through in switch without break */
typedef enum { STATE_INIT, STATE_RUNNING, STATE_PAUSED, STATE_STOPPED } state_t;

const char *state_to_string(state_t state) {
    const char *result = "unknown";

    switch (state) {
        case STATE_INIT:
            result = "initializing";
            /* Missing break - falls through to RUNNING */
        case STATE_RUNNING:
            result = "running";
            break;
        case STATE_PAUSED:
            result = "paused";
            break;
        case STATE_STOPPED:
            result = "stopped";
            break;
    }

    return result;
}
