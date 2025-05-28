#ifndef SANDBOX_H
#define SANDBOX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/landlock.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#define MAX_PATHS 256
#define MAX_PATH_LEN 4096

struct sandbox_config {
    char read_paths[MAX_PATHS][MAX_PATH_LEN];
    char write_paths[MAX_PATHS][MAX_PATH_LEN];
    char exec_paths[MAX_PATHS][MAX_PATH_LEN];
    char logfile[MAX_PATH_LEN];
    char executable[MAX_PATH_LEN];
    char **exec_args;
    int read_count;
    int write_count;
    int exec_count;
    int has_logfile;
};

// Function declarations
int parse_arguments(int argc, char *argv[], struct sandbox_config *config);
int setup_landlock(struct sandbox_config *config);
int setup_seccomp(void);
int execute_sandboxed(struct sandbox_config *config);
void log_message(const char *logfile, const char *message);
void print_usage(const char *program_name);

#endif
