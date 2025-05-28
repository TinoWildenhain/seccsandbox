#include "sandbox.h"

// Landlock syscall numbers (if not defined)
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

int setup_landlock(struct sandbox_config *config) {
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE |
                            LANDLOCK_ACCESS_FS_WRITE_FILE |
                            LANDLOCK_ACCESS_FS_READ_FILE |
                            LANDLOCK_ACCESS_FS_READ_DIR,
    };

    int ruleset_fd = syscall(__NR_landlock_create_ruleset, &ruleset_attr,
                             sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        if (errno == ENOSYS) {
            printf("Warning: Landlock not supported by kernel, skipping filesystem restrictions\n");
            return 0;  // Continue without Landlock
        } else {
            perror("landlock_create_ruleset");
            return -1;
        }
    }

    // Add read-only paths
    for (int i = 0; i < config->read_count; i++) {
        int path_fd = open(config->read_paths[i], O_PATH | O_CLOEXEC);
        if (path_fd < 0) {
            fprintf(stderr, "Warning: Cannot open read path %s: %s\n",
                   config->read_paths[i], strerror(errno));
            continue;
        }

        struct landlock_path_beneath_attr path_beneath = {
            .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR,
            .parent_fd = path_fd,
        };

        if (syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                   &path_beneath, 0) != 0) {
            perror("landlock_add_rule (read)");
        }

        close(path_fd);
        printf("Added read access: %s\n", config->read_paths[i]);
    }

    // Add write paths
    for (int i = 0; i < config->write_count; i++) {
        int path_fd = open(config->write_paths[i], O_PATH | O_CLOEXEC);
        if (path_fd < 0) {
            fprintf(stderr, "Warning: Cannot open write path %s: %s\n",
                   config->write_paths[i], strerror(errno));
            continue;
        }

        struct landlock_path_beneath_attr path_beneath = {
            .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR |
                             LANDLOCK_ACCESS_FS_WRITE_FILE,
            .parent_fd = path_fd,
        };

        if (syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                   &path_beneath, 0) != 0) {
            perror("landlock_add_rule (write)");
        }

        close(path_fd);
        printf("Added write access: %s\n", config->write_paths[i]);
    }

    // Add executable paths - CRITICAL FIX HERE
    for (int i = 0; i < config->exec_count; i++) {
        int path_fd = open(config->exec_paths[i], O_PATH | O_CLOEXEC);
        if (path_fd < 0) {
            fprintf(stderr, "Warning: Cannot open exec path %s: %s\n",
                   config->exec_paths[i], strerror(errno));
            continue;
        }

        struct landlock_path_beneath_attr path_beneath = {
            .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE |
                             LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR,
            .parent_fd = path_fd,
        };

        if (syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                   &path_beneath, 0) != 0) {
            perror("landlock_add_rule (exec)");
        }

        close(path_fd);
        printf("Added exec access: %s\n", config->exec_paths[i]);
    }

    // Enforce the ruleset
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return -1;
    }

    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
        perror("landlock_restrict_self");
        return -1;
    }

    close(ruleset_fd);
    printf("Landlock filesystem restrictions applied successfully\n");
    return 0;
}
