#ifndef MP_CONFIG_H
#define MP_CONFIG_H

#include <getopt.h>

/**
 * Reads configuration file and converts commands into CLI arguments (later
 * parsed with getopt or whatever)
 */
int parse_config(const char* filename, int* argc, char** argv[], struct option options[]);

#endif /* MP_CONFIG_H */
