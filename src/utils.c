#include "sandbox.h"
#include <time.h>

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
