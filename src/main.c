#include "sandbox.h"

int main(int argc, char *argv[]) {
    struct sandbox_config config = {0};

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (parse_arguments(argc, argv, &config) != 0) {
        fprintf(stderr, "Error parsing arguments\n");
        return 1;
    }

    printf("Setting up sandbox...\n");

    // Setup Landlock filesystem restrictions
    if (setup_landlock(&config) != 0) {
        fprintf(stderr, "Failed to setup Landlock restrictions\n");
        return 1;
    }

    // Setup seccomp syscall filtering
    if (setup_seccomp() != 0) {
        fprintf(stderr, "Failed to setup seccomp filtering\n");
        return 1;
    }

    printf("Executing sandboxed process: %s\n", config.executable);

    // Execute the target program
    return execute_sandboxed(&config);
}

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] executable [args...]\n\n", program_name);
    printf("Options:\n");
    printf("  --read=PATH        Allow read access to PATH\n");
    printf("  --write=PATH       Allow write access to PATH\n");
    printf("  --exec=PATH        Allow execution from PATH\n");
    printf("  --logfile=PATH     Log sandbox events to PATH\n\n");
    printf("Example:\n");
    printf("  %s --read=/usr/lib --read=/etc --write=/tmp --exec=/usr/bin python3 script.py\n", program_name);
}
