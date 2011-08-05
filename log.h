#ifndef LOG_H
#define LOG_H

#include <caputils/log.h>

extern FILE* verbose;    /* stdout if verbose is enabled, /dev/null otherwise */
extern int verbose_flag; /* True if verbose output is requested */

extern const char* MAIN;
extern const char* SENDER;
extern const char* CAPTURE;
extern const char* CONTROL;
extern const char* FILTER;

#endif /* LOG_H */
