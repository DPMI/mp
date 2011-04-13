#ifndef MP_FILTER_H
#define MP_FILTER_H

#include <libmarc/filter.h>
#include <caputils/filter.h>
#include <stdio.h>

int addFilter(struct FPI *newRule);
int delFilter(int filter_id);
void printFilter(FILE* fp, const struct FPI *F); // Print One filter

struct FPI *myRules;
unsigned int noRules;

#endif /* MP_FILTER_H */
