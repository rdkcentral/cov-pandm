/**
 * Deliberate Coverity defects - High severity (Set 2)
 * DO NOT MERGE - Testing branch protection rules
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Defect 3: OVERRUN (CWE-787) - Stack buffer overflow via unbounded write */
void parse_config_line(const char *input) {
    char key[32];
    char value[32];

    /* No bounds checking - input could overflow both buffers */
    sscanf(input, "%s = %s", key, value);

    char output[64];
    /* Concatenation can exceed output buffer */
    strcpy(output, key);
    strcat(output, "=");
    strcat(output, value);

    printf("Config: %s\n", output);
}

/* Defect 4: ATOMICITY (CWE-362) - Race condition / TOCTOU */
static int shared_counter = 0;
static FILE *shared_log = NULL;

void *increment_counter(void *arg) {
    /* Non-atomic read-modify-write without synchronization */
    int local = shared_counter;
    local++;
    shared_counter = local;

    /* TOCTOU: check then act without lock */
    if (shared_log != NULL) {
        fprintf(shared_log, "Counter: %d\n", shared_counter);
    }
    return NULL;
}

void run_threads(void) {
    pthread_t threads[10];
    shared_log = fopen("/tmp/counter.log", "a");

    for (int i = 0; i < 10; i++) {
        pthread_create(&threads[i], NULL, increment_counter, NULL);
    }
    for (int i = 0; i < 10; i++) {
        pthread_join(threads[i], NULL);
    }
    fclose(shared_log);
}
