/**
 * Deliberate Coverity defects - Medium severity (Set 2)
 * DO NOT MERGE - Testing branch protection rules
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Defect 5: UNINIT (CWE-457) - Uninitialized variable used */
int compute_checksum(const unsigned char *data, size_t len) {
    int checksum;
    int i;

    if (len > 0) {
        checksum = 0;
        for (i = 0; i < (int)len; i++) {
            checksum ^= data[i];
        }
    }

    /* checksum may be uninitialized if len == 0 */
    return checksum;
}

/* Defect 6: REVERSE_INULL (CWE-476) - Null check after dereference */
typedef struct {
    char name[64];
    int value;
    struct config_node *next;
} config_node;

void process_config(config_node *node) {
    /* Dereference first */
    printf("Processing: %s = %d\n", node->name, node->value);

    /* Then null-check - too late, already dereferenced above */
    if (node == NULL) {
        fprintf(stderr, "Error: null config node\n");
        return;
    }

    /* More work with the node */
    node->value += 1;
}
