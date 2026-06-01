/**
 * Test file: Deliberate defects for Coverity branch protection testing.
 * Severity: LOW (security-severity <= 3.9)
 *
 * Defect 7: COPY_INSTEAD_OF_MOVE - Unnecessary copy of a value
 * Defect 8: DEADCODE - Code that can never be executed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Defect 7: COPY_INSTEAD_OF_MOVE (performance)
 * No CWE mapping - performance inefficiency.
 * Large struct copied when it could be passed by pointer.
 */
struct DeviceInfo {
    char name[256];
    char model[256];
    char firmware[128];
    int  ports[64];
};

struct DeviceInfo get_device_copy(struct DeviceInfo *original)
{
    /* COVERITY[COPY_INSTEAD_OF_MOVE] - unnecessary copy of large struct */
    struct DeviceInfo copy = *original;
    return copy;
}

void print_device(struct DeviceInfo info)
{
    /* Takes struct by value (512+ bytes on stack) */
    printf("Device: %s, Model: %s, FW: %s\n",
           info.name, info.model, info.firmware);
}

/* Defect 8: DEADCODE
 * No CWE mapping - code quality issue.
 * Code after unconditional return can never execute.
 */
int check_status(int code)
{
    if (code > 0)
        return 1;
    else
        return 0;

    /* COVERITY[DEADCODE] - unreachable code after unconditional return */
    printf("This line is never reached\n");
    return -1;
}
