/**
 * Test file: Deliberate defects for Coverity branch protection testing.
 * Severity: CRITICAL (security-severity >= 9.0)
 *
 * Defect 1: OS_CMD_INJECTION - Command injection via unsanitized user input
 * Defect 2: SQL_INJECTION - SQL injection via string concatenation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Defect 1: OS_CMD_INJECTION
 * CWE-78: Improper Neutralization of Special Elements used in an OS Command
 * User-controlled input passed directly to system() without sanitization.
 */
void restart_service(const char *service_name)
{
    char cmd[256];
    /* COVERITY[OS_CMD_INJECTION] - service_name is user-controlled */
    snprintf(cmd, sizeof(cmd), "systemctl restart %s", service_name);
    system(cmd);
}

/* Defect 2: SQL_INJECTION
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command
 * User input concatenated directly into SQL query string.
 */
void lookup_device(const char *device_id, char *query_buf, size_t buf_size)
{
    /* COVERITY[SQL_INJECTION] - device_id is user-controlled */
    snprintf(query_buf, buf_size,
             "SELECT * FROM devices WHERE id = '%s'", device_id);
}
