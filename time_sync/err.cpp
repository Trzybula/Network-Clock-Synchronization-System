#include "err.h"

[[noreturn]] void syserr(const char* fmt, ...) {
    va_list fmt_args;
    int org_errno = errno;

    std::fprintf(stderr, "ERROR: ");

    va_start(fmt_args, fmt);
    std::vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);

    std::fprintf(stderr, " (%d; %s)\n", org_errno, std::strerror(org_errno));
    std::exit(1);
}

[[noreturn]] void fatal(const char* fmt, ...) {
    va_list fmt_args;

    std::fprintf(stderr, "ERROR: ");

    va_start(fmt_args, fmt);
    std::vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);

    std::fprintf(stderr, "\n");
    std::exit(1);
}
