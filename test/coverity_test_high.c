/**
 * Test file: Deliberate defects for Coverity branch protection testing.
 * Severity: HIGH (security-severity 7.0-8.9)
 *
 * Defect 3: BUFFER_SIZE - Stack buffer overflow
 * Defect 4: USE_AFTER_FREE - Use of memory after it has been freed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Defect 3: BUFFER_SIZE (OVERRUN)
 * CWE-120: Buffer Copy without Checking Size of Input
 * Fixed-size buffer overflowed by unbounded strcpy.
 */
void process_message(const char *input)
{
    char buffer[64];
    /* COVERITY[BUFFER_SIZE] - input may exceed 64 bytes */
    strcpy(buffer, input);
    printf("Processed: %s\n", buffer);
}

/* Defect 4: USE_AFTER_FREE
 * CWE-416: Use After Free
 * Pointer used after the memory it references has been freed.
 */
struct Connection {
    int fd;
    char *hostname;
};

void close_and_log(struct Connection *conn)
{
    free(conn->hostname);
    conn->fd = -1;
    free(conn);

    /* COVERITY[USE_AFTER_FREE] - conn accessed after free */
    printf("Closed connection to %s (fd=%d)\n", conn->hostname, conn->fd);
}
