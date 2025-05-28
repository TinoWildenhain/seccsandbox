#include "sandbox.h"
#include <time.h>  // Add missing header

void log_message(const char *logfile, const char *message) {
    FILE *fp = fopen(logfile, "a");
    if (fp == NULL) {
        return;
    }

    time_t now = time(NULL);
    char *timestr = ctime(&now);
    timestr[strlen(timestr) - 1] = '\0'; // Remove newline

    fprintf(fp, "[%s] %s\n", timestr, message);
    fclose(fp);
}

void add_essential_system_paths(struct sandbox_config *config) {
    // Essential read paths for most programs
    const char *essential_read_paths[] = {
        "/usr/lib", "/lib", "/lib64", "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu", "/etc", NULL
    };

    // Essential exec paths for dynamically linked programs
    const char *essential_exec_paths[] = {
        "/usr/bin", "/bin", "/lib64", "/lib/x86_64-linux-gnu", NULL
    };

    printf("Adding essential system paths...\n");

    // Add essential read paths if not already present
    for (int i = 0; essential_read_paths[i] != NULL && config->read_count < MAX_PATHS; i++) {
        int exists = 0;
        for (int j = 0; j < config->read_count; j++) {
            if (strcmp(config->read_paths[j], essential_read_paths[i]) == 0) {
                exists = 1;
                break;
            }
        }
        if (!exists) {
            struct stat st;
            if (stat(essential_read_paths[i], &st) == 0 && S_ISDIR(st.st_mode)) {
                strncpy(config->read_paths[config->read_count], essential_read_paths[i], MAX_PATH_LEN - 1);
                config->read_count++;
                printf("Auto-added read path: %s\n", essential_read_paths[i]);
            }
        }
    }

    // Add essential exec paths if not already present
    for (int i = 0; essential_exec_paths[i] != NULL && config->exec_count < MAX_PATHS; i++) {
        int exists = 0;
        for (int j = 0; j < config->exec_count; j++) {
            if (strcmp(config->exec_paths[j], essential_exec_paths[i]) == 0) {
                exists = 1;
                break;
            }
        }
        if (!exists) {
            struct stat st;
            if (stat(essential_exec_paths[i], &st) == 0 && S_ISDIR(st.st_mode)) {
                strncpy(config->exec_paths[config->exec_count], essential_exec_paths[i], MAX_PATH_LEN - 1);
                config->exec_count++;
                printf("Auto-added exec path: %s\n", essential_exec_paths[i]);
            }
        }
    }
}
