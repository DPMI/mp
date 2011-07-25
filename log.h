#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>

extern FILE* verbose;    /* stdout if verbose is enabled, /dev/null otherwise */
extern int verbose_flag; /* True if verbose output is requested */

extern const char* MAIN;
extern const char* SENDER;
extern const char* CAPTURE;
extern const char* CONTROL;
extern const char* FILTER;

int vlogmsg(FILE* fp, const char* tag, const char* fmt, va_list ap);
int logmsg(FILE* fp, const char* tag, const char* fmt, ...) __attribute__ ((format (printf, 3, 4)));

#endif /* LOG_H */
