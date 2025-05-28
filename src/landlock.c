#include "sandbox.h"

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION 1
#endif

int setup_landlock(struct sandbox_config *config) {
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE |
                            LANDLOCK_ACCESS_FS_WRITE_FILE |
                            LANDLOCK_ACCESS_FS_READ_FILE |
                            LANDLOCK_ACCESS_FS_READ_DIR |
                            LANDLOCK_ACCESS_FS_REMOVE_DIR |
                            LANDLOCK_ACCESS_FS_REMOVE_FILE |
                            LANDLOCK_ACCESS_FS_MAKE_CHAR |
                            LANDLOCK_ACCESS_FS_MAKE_DIR |
                            LANDLOCK_ACCESS_FS_MAKE_REG |
                            LANDLOCK_ACCESS_FS_MAKE_SOCK |
                            LANDLOCK_ACCESS_FS_MAKE_FIFO |
                            LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                            LANDLOCK_ACCESS_FS_MAKE_SYM,
    };

    int ruleset_fd = syscall(__NR_landlock_create_ruleset, &ruleset_attr,
                             sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        if (errno == ENOSYS) {
            fprintf(stderr, "Landlock not supported by kernel\n");
        } else {
            perror("landlock_create_ruleset");
        }
        return -1;
    }

    // Add read-only paths
    for (int i = 0; i < config->read_count; i++) {
        int path_fd = open(config->read_paths[i], O_PATH | O_CLOEXEC);
        if (path_fd < 0) {
            fprintf(stderr, "Cannot open read path %s: %s\n",
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
    }

    // Add write paths
    for (int i = 0; i < config->write_count; i++) {
        int path_fd = open(config->write_paths[i], O_PATH | O_CLOEXEC);
        if (path_fd < 0) {
            fprintf(stderr, "Cannot open write path %s: %s\n",
                   config->write_paths[i], strerror(errno));
            continue;
        }

        struct landlock_path_beneath_attr path_beneath = {
            .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR |
                             LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_REMOVE_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_FILE |
                             LANDLOCK_ACCESS_FS_MAKE_CHAR |
                             LANDLOCK_ACCESS_FS_MAKE_DIR |
                             LANDLOCK_ACCESS_FS_MAKE_REG |
                             LANDLOCK_ACCESS_FS_MAKE_SOCK |
                             LANDLOCK_ACCESS_FS_MAKE_FIFO |
                             LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                             LANDLOCK_ACCESS_FS_MAKE_SYM,
            .parent_fd = path_fd,
        };

        if (syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                   &path_beneath, 0) != 0) {
            perror("landlock_add_rule (write)");
        }

        close(path_fd);
    }

    // Add executable paths
    for (int i = 0; i < config->exec_count; i++) {
        int path_fd = open(config->exec_paths[i], O_PATH | O_CLOEXEC);
        if (path_fd < 0) {
            fprintf(stderr, "Cannot open exec path %s: %s\n",
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
    return 0;
}
