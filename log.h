#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>

int vlogmsg(FILE* fp, const char* fmt, va_list ap);
int logmsg(FILE* fp, const char* fmt, ...);

#endif /* LOG_H */
