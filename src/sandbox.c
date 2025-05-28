#include "sandbox.h"

int parse_arguments(int argc, char *argv[], struct sandbox_config *config) {
    int i;

    // Set default seccomp mode
    config->seccomp_mode = SECCOMP_MODE_KILL;

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
        else if (strncmp(argv[i], "--seccomp-block=", 16) == 0) {
            const char *mode = argv[i] + 16;
            if (strcmp(mode, "kill") == 0) {
                config->seccomp_mode = SECCOMP_MODE_KILL;
            } else if (strcmp(mode, "log") == 0) {
                config->seccomp_mode = SECCOMP_MODE_LOG;
            } else if (strcmp(mode, "errno") == 0) {
                config->seccomp_mode = SECCOMP_MODE_ERRNO;
            } else {
                fprintf(stderr, "Invalid seccomp block mode: %s (use: kill, log, errno)\n", mode);
                return -1;
            }
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
    printf("Forking to create sandboxed process...\n");

    pid_t pid = fork();

    if (pid == 0) {
        // Child process - apply restrictions and execute the target program
        printf("Child process started, applying restrictions...\n");

        if (config->has_logfile) {
            log_message(config->logfile, "Starting sandboxed execution");
        }

        // Apply Landlock filesystem restrictions FIRST
        printf("Setting up Landlock filesystem restrictions...\n");
        if (setup_landlock(config) != 0) {
            fprintf(stderr, "Failed to setup Landlock restrictions\n");
            exit(1);
        }

        // Apply seccomp syscall filtering SECOND
        printf("Setting up seccomp syscall filtering (mode: %s)...\n",
               config->seccomp_mode == SECCOMP_MODE_KILL ? "kill" :
               config->seccomp_mode == SECCOMP_MODE_LOG ? "log" : "errno");
        if (setup_seccomp(config) != 0) {
            fprintf(stderr, "Failed to setup seccomp filtering\n");
            exit(1);
        }

        printf("Restrictions applied, executing: %s\n", config->executable);

        // Execute the target program
        execvp(config->executable, config->exec_args);
        perror("execvp failed");
        exit(1);
    }
    else if (pid > 0) {
        // Parent process - wait for child
        printf("Parent waiting for child process %d...\n", pid);
        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("Child process killed by signal %d", sig);

            if (sig == SIGSYS) {
                printf(" (SIGSYS - seccomp violation)");
                if (config->has_logfile) {
                    log_message(config->logfile, "Process killed by seccomp - syscall violation detected");
                }
            }
            printf("\n");
        } else if (WIFEXITED(status)) {
            printf("Child process exited normally with status %d\n", WEXITSTATUS(status));
        }

        return WEXITSTATUS(status);
    }
    else {
        perror("fork failed");
        return 1;
    }
}
