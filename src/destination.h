#ifndef MP_DESTINATION_H
#define MP_DESTINATION_H

#include <caputils/stream.h>
#include <caputils/filter.h>

enum state {
	IDLE,           /* unused destination */
	BUSY,           /* used */
	STOP,           /* used but is about to stop */
};

/**
 * MP send destination.
 */
struct destination {
	struct stream* stream;
	struct filter* filter;
	int index;

	enum state state;                  /* state of this consumer */
	int want_ethhead;                  // 1 if consumer want the ethernet header or 0 if just the payload (implies want_sendhead)
	int want_sendhead;                 // 1 if consumer want the sendheader or 0 if just the payload
	int sendcount;                     // number of packets recieved but not sent
	void* sendpointer;                 // pointer to packet in sendmem
	void* sendptrref;                  // pointer to packet in sendmem, REFERENCE!!!
	struct sendhead* shead;            // pointer to sendheaders.
	struct ethhdr* ethhead;            // pointer to ethernet header
	struct timespec last_sent;         // timestamp of the last flush
};

void destination_init(struct destination* dst, int index, unsigned char* buffer);
void destination_init_all();

extern struct destination MAsd[MAX_FILTERS];

#endif /* MP_DESTINATION_H */
