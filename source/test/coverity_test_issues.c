#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test file with intentional Coverity-detectable issues */

void process_user_input(const char *input)
{
    char buffer[64];
    /* CWE-120: STRING_OVERFLOW - no bounds checking on strcpy */
    strcpy(buffer, input);
    printf("Processed: %s\n", buffer);
}

int read_config_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    char line[256];

    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "exit")) {
            return 0;  /* RESOURCE_LEAK: fp not closed on this path */
        }
    }

    fclose(fp);
    return 0;
}

void allocate_and_use(int count)
{
    int *values;
    int total;  /* UNINIT: used before initialization */

    if (count > 0) {
        values = (int *)malloc(count * sizeof(int));
        total = 0;
    }

    /* If count <= 0, total is uninitialized */
    printf("Total: %d\n", total);
    free(values);
}
