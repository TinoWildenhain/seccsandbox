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

// Seccomp blocking modes
typedef enum {
    SECCOMP_MODE_KILL = 0,     // Kill process (default)
    SECCOMP_MODE_LOG = 1,      // Log violations but allow
    SECCOMP_MODE_ERRNO = 2     // Return EPERM error
} seccomp_block_mode_t;

// Add these definitions if not available
#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#endif

// Only define LANDLOCK_RULE_PATH_BENEATH if not already defined
#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif

// Remove the struct definitions entirely since they're already in system headers
// The system headers already provide these structs, so we don't need to redefine them

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
    seccomp_block_mode_t seccomp_mode;
};

// Function declarations
int parse_arguments(int argc, char *argv[], struct sandbox_config *config);
int setup_landlock(struct sandbox_config *config);
int setup_seccomp(struct sandbox_config *config);
int execute_sandboxed(struct sandbox_config *config);
void log_message(const char *logfile, const char *message);
void print_usage(const char *program_name);
void add_essential_system_paths(struct sandbox_config *config);

#endif
