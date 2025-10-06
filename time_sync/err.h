#ifndef MIM_ERR_H
#define MIM_ERR_H

#include <cstdarg>   // dla va_list
#include <cstdio>    // dla fprintf
#include <cstdlib>   // dla exit
#include <cerrno>    // dla errno
#include <cstring>   // dla strerror

// Print information about a system error and quit.
[[noreturn]] void syserr(const char* fmt, ...);

// Print information about an error and quit.
[[noreturn]] void fatal(const char* fmt, ...);

#endif // MIM_ERR_H
