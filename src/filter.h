#ifndef MP_FILTER_H
#define MP_FILTER_H

#include <caputils/filter.h>
#include <stdio.h>

/**
 * Insert a filter to the rule chain.
 *
 * @param filter Filter to insert. A copy of the filter is made.
 * @return Zero if successful or errno on error.
 */
int mprules_add(const struct filter* filter);

/**
 * Delete filter from rule chain.
 */
int mprules_del(unsigned int filter_id);

/**
 * Delete all rules from the chain.
 */
int mprules_clear();

struct rule {
	struct filter filter;
	struct destination* destination;
	struct rule* next;
};

/**
 * Pointer to the first rule in the chain. Iterate by using rule->next
 */
struct rule* mprules();

/**
 * Tell how many rules exists in the chain.
 */
size_t mprules_count();

#endif /* MP_FILTER_H */
