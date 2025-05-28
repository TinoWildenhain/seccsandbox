#include "sandbox.h"

int parse_arguments(int argc, char *argv[], struct sandbox_config *config) {
    int i;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--read=", 7) == 0) {
            if (config->read_count >= MAX_PATHS) {
                fprintf(stderr, "Too many read paths\n");
                return -1;
            }
            strncpy(config->read_paths[config->read_count], argv[i] + 7, MAX_PATH_LEN - 1);
            config->read_count++;
        }
        else if (strncmp(argv[i], "--write=", 8) == 0) {
            if (config->write_count >= MAX_PATHS) {
                fprintf(stderr, "Too many write paths\n");
                return -1;
            }
            strncpy(config->write_paths[config->write_count], argv[i] + 8, MAX_PATH_LEN - 1);
            config->write_count++;
        }
        else if (strncmp(argv[i], "--exec=", 7) == 0) {
            if (config->exec_count >= MAX_PATHS) {
                fprintf(stderr, "Too many exec paths\n");
                return -1;
            }
            strncpy(config->exec_paths[config->exec_count], argv[i] + 7, MAX_PATH_LEN - 1);
            config->exec_count++;
        }
        else if (strncmp(argv[i], "--logfile=", 10) == 0) {
            strncpy(config->logfile, argv[i] + 10, MAX_PATH_LEN - 1);
            config->has_logfile = 1;
        }
        else if (argv[i][0] != '-') {
            // This is the executable
            strncpy(config->executable, argv[i], MAX_PATH_LEN - 1);

            // Remaining arguments are for the executable
            config->exec_args = &argv[i];
            break;
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return -1;
        }
    }

    if (strlen(config->executable) == 0) {
        fprintf(stderr, "No executable specified\n");
        return -1;
    }

    return 0;
}

int execute_sandboxed(struct sandbox_config *config) {
    pid_t pid = fork();

    if (pid == 0) {
        // Child process - execute the target program
        if (config->has_logfile) {
            log_message(config->logfile, "Starting sandboxed execution");
        }

        execvp(config->executable, config->exec_args);
        perror("execvp failed");
        exit(1);
    }
    else if (pid > 0) {
        // Parent process - wait for child
        int status;
        waitpid(pid, &status, 0);

        if (config->has_logfile) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Sandboxed process exited with status %d",
                    WEXITSTATUS(status));
            log_message(config->logfile, msg);
        }

        return WEXITSTATUS(status);
    }
    else {
        perror("fork failed");
        return 1;
    }
}
