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

    // Add essential system paths automatically
    add_essential_system_paths(&config);

    printf("Setting up sandbox for: %s\n", config.executable);
    printf("Read paths: %d, Write paths: %d, Exec paths: %d\n",
           config.read_count, config.write_count, config.exec_count);
    printf("Seccomp mode: %s\n",
           config.seccomp_mode == SECCOMP_MODE_KILL ? "kill" :
           config.seccomp_mode == SECCOMP_MODE_LOG ? "log" : "errno");

    return execute_sandboxed(&config);
}

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] executable [args...]\n\n", program_name);
    printf("Options:\n");
    printf("  --read=PATH              Allow read access to PATH\n");
    printf("  --write=PATH             Allow write access to PATH\n");
    printf("  --exec=PATH              Allow execution from PATH\n");
    printf("  --logfile=PATH           Log sandbox events to PATH\n");
    printf("  --seccomp-block=MODE     Seccomp blocking mode (kill|log|errno)\n");
    printf("                           kill:  Kill process on violation (default)\n");
    printf("                           log:   Log violations but allow syscall\n");
    printf("                           errno: Return EPERM error\n\n");
    printf("Examples:\n");
    printf("  %s --read=/usr/lib --write=/tmp python3 script.py\n", program_name);
    printf("  %s --seccomp-block=log mpv video.mp4\n", program_name);
    printf("  %s --seccomp-block=errno --read=/home/user python3 -i\n", program_name);
}
