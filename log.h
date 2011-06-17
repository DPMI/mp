#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>

extern FILE* verbose;    /* stdout if verbose is enabled, /dev/null otherwise */
extern int verbose_flag; /* True if verbose output is requested */

int vlogmsg(FILE* fp, const char* fmt, va_list ap);
int logmsg(FILE* fp, const char* fmt, ...);

#endif /* LOG_H */
